//! Minimal ptrace-based kernel compatibility shim.
//!
//! Two classes of problem when running a modern (Arch-built, `--enable-kernel=4.4`)
//! glibc on very old kernels:
//!
//! 1. Instructions. Old kernels lack CPU/XSAVE support, so `XGETBV` (and friends)
//!    raise `#UD` -> `SIGILL`. We catch the signal and emulate the instruction.
//! 2. Syscalls. glibc assumes futex ops added after the target kernel exists
//!    (`FUTEX_WAIT_BITSET`/`FUTEX_WAKE_BITSET`, 2.6.25). On older kernels they
//!    return `ENOSYS` and glibc calls `futex_fatal_error()`. We rewrite those
//!    ops to their older equivalents at syscall-entry.
//!
//! Enable with `SHARUN_OLD_KERNEL_COMPAT=1`; `0` disables. When unset it decides
//! automatically: on for kernels older than 4.0, or when `statx` (4.11) is
//! missing.
//!
//! x86_64 only for now; per-architecture register handling would be required
//! for the others.

#![cfg(target_arch = "x86_64")]

use std::{collections::{HashMap, HashSet}, env, ffi::CStr, process::exit};

use nix::{
	errno::Errno,
	sys::{
		ptrace::{self, AddressType, Options},
		signal::{raise, Signal},
		wait::{waitpid, WaitPidFlag, WaitStatus},
	},
	unistd::{fork, ForkResult, Pid},
	libc,
};

const ENV_ENABLE: &str = "SHARUN_OLD_KERNEL_COMPAT";
const ENV_DEBUG: &str = "SHARUN_OLD_KERNEL_COMPAT_DEBUG";

// futex op encoding
const FUTEX_CMD_MASK: u32 = 0x7f;
const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;
const FUTEX_WAIT_BITSET: u32 = 9;
const FUTEX_WAKE_BITSET: u32 = 10;
const FUTEX_CLOCK_REALTIME: u32 = 256;

fn debug() -> bool {
	matches!(env::var(ENV_DEBUG), Ok(v) if v == "1")
}

fn kernel_lt(want_major: u64, want_minor: u64, want_patch: u64) -> bool {
	let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
	if unsafe { libc::uname(&mut uts) } != 0 {
		return false
	}
	let release = unsafe { CStr::from_ptr(uts.release.as_ptr()) }.to_string_lossy();
	let mut parts = release.split(|c: char| !c.is_ascii_digit());
	let a = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
	let b = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
	let c = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
	(a, b, c) < (want_major, want_minor, want_patch)
}

/// Whether the compatibility tracer should run for this launch.
pub fn enabled() -> bool {
	match env::var(ENV_ENABLE) {
		Ok(v) if v == "0" => false,
		Ok(_) => true,
		Err(_) => needs_compat(),
	}
}

/// Auto mode: run the tracer when the kernel is old enough to plausibly need it.
/// Cheap checks, so modern kernels never pay the ptrace cost.
///
/// Triggered outright for kernels older than 4.0, and otherwise by a missing
/// `statx` (4.11) -- e.g. Qt6 has no fallback when it returns ENOSYS.
///
/// The `statx` probe runs here, in the AppRun process, *before* the application
/// starts: apps may install seccomp filters that reject `statx` (returning
/// ENOSYS), which would be indistinguishable from an old kernel if probed
/// later. That is also why the tracer is only ever set up from AppRun and never
/// from the `bin/*` hardlinks.
fn needs_compat() -> bool {
	if kernel_lt(4, 0, 0) {
		return true
	}
	syscall_missing(libc::SYS_statx)
}

/// True if `nr` is not implemented by this kernel (returns -ENOSYS).
fn syscall_missing(nr: libc::c_long) -> bool {
	let mut stx = [0u8; 256];
	let path = b"/\0";
	let rc = unsafe {
		libc::syscall(
			nr,
			libc::AT_FDCWD,
			path.as_ptr(),
			0i32,
			0u32,
			stx.as_mut_ptr() as *mut libc::c_void,
		)
	};
	rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS)
}

/// Run `apprun::run_as_apprun` for `(sharun_dir, bin_dir, exec_args)` under the
/// tracer. Never returns.
pub fn run_apprun_traced(sharun_dir: &str, bin_dir: &str, exec_args: &[String]) -> ! {
	// If ptrace is blocked (e.g. a container's seccomp policy), don't turn a
	// runnable app into a failure: run it untraced, exactly as if this layer
	// were disabled. On a genuinely ancient kernel glibc dies on its own, which
	// is no worse than running without the feature.
	if !ptrace_permitted() {
		eprintln!("[sharun] ptrace unavailable, running without old kernel compatibility");
		crate::apprun::run_as_apprun(sharun_dir, bin_dir, exec_args);
	}

	// Handshake pipe: the child reports whether it could install the seccomp
	// filter, so the parent knows whether to stop only on the translated
	// syscalls (seccomp, cheap) or on every syscall (fallback).
	let mut pipe_fds = [0i32; 2];
	let have_pipe = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } == 0;

	match unsafe { fork() } {
		Ok(ForkResult::Child) => {
			if have_pipe {
				unsafe { libc::close(pipe_fds[0]) };
			}
			if ptrace::traceme().is_err() {
				if have_pipe {
					unsafe { libc::close(pipe_fds[1]) };
				}
				crate::apprun::run_as_apprun(sharun_dir, bin_dir, exec_args)
			}
			let seccomp = install_seccomp_filter();
			if have_pipe {
				let byte = [u8::from(seccomp)];
				unsafe {
					libc::write(pipe_fds[1], byte.as_ptr() as *const libc::c_void, 1);
					libc::close(pipe_fds[1]);
				}
			}
			// Let the parent install PTRACE_SETOPTIONS before we run.
			let _ = raise(Signal::SIGSTOP);
			crate::apprun::run_as_apprun(sharun_dir, bin_dir, exec_args)
		},
		Ok(ForkResult::Parent { child }) => {
			let mut use_seccomp = false;
			if have_pipe {
				unsafe { libc::close(pipe_fds[1]) };
				let mut byte = [0u8; 1];
				let n = unsafe {
					libc::read(pipe_fds[0], byte.as_mut_ptr() as *mut libc::c_void, 1)
				};
				use_seccomp = n == 1 && byte[0] == 1;
				unsafe { libc::close(pipe_fds[0]) };
			}
			eprintln!("[sharun] enabled old kernel compatibility mode");
			supervise(child, use_seccomp)
		},
		// Could not fork the tracer: run untraced rather than fail.
		Err(_) => crate::apprun::run_as_apprun(sharun_dir, bin_dir, exec_args),
	}
}

/// Cheap probe for whether `PTRACE_TRACEME` is permitted here.
fn ptrace_permitted() -> bool {
	match unsafe { fork() } {
		Ok(ForkResult::Child) => {
			let ok = ptrace::traceme().is_ok();
			exit(if ok { 0 } else { 1 })
		},
		Ok(ForkResult::Parent { child }) => {
			matches!(waitpid(child, None), Ok(WaitStatus::Exited(_, 0)))
		},
		Err(_) => false,
	}
}

/// Install a seccomp-bpf filter that has the tracer stop (`SECCOMP_RET_TRACE`)
/// on only the syscalls we rewrite, allowing everything else. Requires Linux
/// 3.5+; returns false on older kernels or where seccomp is unavailable, in
/// which case the caller falls back to tracing every syscall.
#[cfg(target_arch = "x86_64")]
fn install_seccomp_filter() -> bool {
	const BPF_LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
	const BPF_JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
	const BPF_RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
	// ELF machine for x86_64 (libc does not export AUDIT_ARCH_X86_64 here).
	const AUDIT_ARCH_X86_64: u32 = 0xc000003e;
	let stmt = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
	let jump = |k: u32, jt: u8, jf: u8| libc::sock_filter { code: BPF_JEQ_K, jt, jf, k };
	let filter = [
		stmt(BPF_LD_W_ABS, 4), // seccomp_data.arch
		jump(AUDIT_ARCH_X86_64, 1, 0),
		stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW),
		stmt(BPF_LD_W_ABS, 0), // seccomp_data.nr
		jump(libc::SYS_futex as u32, 2, 0),
		jump(libc::SYS_pipe2 as u32, 1, 0),
		jump(libc::SYS_statx as u32, 0, 1),
		stmt(BPF_RET_K, libc::SECCOMP_RET_TRACE),
		stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW),
	];
	let prog = libc::sock_fprog {
		len: filter.len() as u16,
		filter: filter.as_ptr() as *mut libc::sock_filter,
	};
	if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
		return false
	}
	let rc = unsafe {
		libc::prctl(
			libc::PR_SET_SECCOMP,
			libc::SECCOMP_MODE_FILTER,
			&prog as *const _ as libc::c_ulong,
		)
	};
	rc == 0
}

/// Set as many of `wanted` as this kernel supports, one bit at a time.
fn install_options(pid: Pid, wanted: &[Options]) -> Options {
	let mut acc = Options::empty();
	for &opt in wanted {
		if ptrace::setoptions(pid, acc | opt).is_ok() {
			acc |= opt;
		} else {
			let _ = ptrace::setoptions(pid, acc);
			if debug() {
				eprintln!("kernel-compat: option {:?} unsupported, skipped", opt);
			}
		}
	}
	acc
}

fn tracer_options(seccomp: bool) -> Vec<Options> {
	// No PTRACE_O_EXITKILL: when the traced main process exits we either exit
	// (detaching descendants) or, in seccomp mode, keep waiting for them.
	// EXITKILL would SIGKILL any still-traced descendant (e.g. a daemon).
	let mut opts = vec![
		Options::PTRACE_O_TRACESYSGOOD,
		Options::PTRACE_O_TRACEFORK,
		Options::PTRACE_O_TRACEVFORK,
		Options::PTRACE_O_TRACECLONE,
		Options::PTRACE_O_TRACEEXEC,
	];
	if seccomp {
		opts.push(Options::PTRACE_O_TRACESECCOMP);
	}
	opts
}

struct Tracer {
	child: Pid,
	configured: HashSet<Pid>,
	in_syscall: HashMap<Pid, bool>,
	last_syscall: HashMap<Pid, u64>,
	statx: HashMap<Pid, StatxState>,
	/// rsp to restore at syscall-exit for tracees whose translated syscall
	/// needed scratch space carved below the stack pointer.
	reserved: HashMap<Pid, u64>,
	/// true when tracing every syscall (fallback); false in seccomp mode.
	syscall_mode: bool,
	/// true when the seccomp filter is installed, so we only stop on the
	/// translated syscalls.
	seccomp_mode: bool,
	/// exit status of the main tracee, remembered so we can keep running for
	/// seccomp participants (daemons) until every tracee is gone.
	main_code: Option<i32>,
}

struct StatxState {
	statxbuf: u64,
	scratch: u64,
}

impl Tracer {
	fn resume(&self, pid: Pid, sig: Option<Signal>) {
		let res = if self.syscall_mode {
			ptrace::syscall(pid, sig)
		} else {
			ptrace::cont(pid, sig)
		};
		let _ = res;
	}

	fn supervise(&mut self) -> ! {
		if debug() {
			eprintln!(
				"kernel-compat: mode {}",
				if self.seccomp_mode {
					"seccomp (only translated syscalls)"
				} else if self.syscall_mode {
					"ptrace (every syscall)"
				} else {
					"signals only"
				}
			);
		}
		self.resume(self.child, None);

		loop {
			match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL)) {
				Ok(WaitStatus::Exited(pid, code)) => {
					if debug() {
						eprintln!("kernel-compat: pid {pid} exited {code}");
					}
					if pid == self.child {
						// In seccomp mode the filter outlives us, so keep
						// running until every tracee is gone.
						if self.seccomp_mode {
							self.main_code = Some(code);
						} else {
							exit(code)
						}
					}
				},
				Ok(WaitStatus::Signaled(pid, sig, _)) => {
					if debug() {
						eprintln!("kernel-compat: pid {pid} killed by {sig:?}");
					}
					if pid == self.child {
						if self.seccomp_mode {
							self.main_code = Some(128 + sig as i32);
						} else {
							exit(128 + sig as i32)
						}
					}
				},
				Ok(WaitStatus::Stopped(pid, sig)) => {
					if debug() {
						eprintln!("kernel-compat: pid {pid} stopped: {sig:?}");
					}
					// A newly traced child stops once so we can configure it.
					if pid != self.child && !self.configured.contains(&pid) {
						install_options(pid, &tracer_options(self.seccomp_mode));
						self.configured.insert(pid);
						if sig == Signal::SIGSTOP {
							self.resume(pid, None);
							continue;
						}
					}
					// In seccomp mode a signal delivered while a translated
					// syscall's exit stop is pending must not be resumed with
					// PTRACE_CONT: that clears the syscall-trace flag and the
					// exit stop (which restores rsp) would never fire.
					let pending = self.seccomp_mode && self.reserved.contains_key(&pid);
					let suppress = sig == Signal::SIGILL && emulate_sigill(pid);
					if pending {
						let _ = ptrace::syscall(pid, if suppress { None } else { Some(sig) });
					} else if suppress {
						self.resume(pid, None);
					} else {
						self.resume(pid, Some(sig));
					}
				},
				Ok(WaitStatus::PtraceEvent(pid, _sig, event))
					if event == libc::PTRACE_EVENT_SECCOMP =>
				{
					// A filtered syscall: translate it, then continue. statx
					// also needs its exit stop to convert the result struct.
					if self.on_seccomp_stop(pid) {
						let _ = ptrace::syscall(pid, None);
					} else {
						self.resume(pid, None);
					}
				},
				Ok(WaitStatus::PtraceEvent(pid, _sig, _event)) => {
					// Restart event stops with signal 0 (like strace does), not
					// with the synthetic SIGTRAP nix reports for them.
					self.resume(pid, None);
				},
				Ok(WaitStatus::PtraceSyscall(pid)) => {
					if self.seccomp_mode {
						// Only reached for the statx exit we asked for.
						self.on_syscall_exit(pid);
					} else {
						self.on_syscall_stop(pid);
					}
					self.resume(pid, None);
				},
				Ok(_) => {},
				Err(Errno::ECHILD) => exit(self.main_code.unwrap_or(0)),
				Err(err) => {
					if debug() {
						eprintln!("kernel-compat: waitpid error: {err}");
					}
				},
			}
		}
	}

	/// Handle a `SECCOMP_RET_TRACE` stop. Returns whether the caller must resume
	/// with `PTRACE_SYSCALL` to also catch the syscall exit (statx only).
	fn on_seccomp_stop(&mut self, pid: Pid) -> bool {
		let regs = match ptrace::getregs(pid) {
			Ok(regs) => regs,
			Err(_) => return false,
		};
		if regs.orig_rax == libc::SYS_futex as u64 {
			// A timed WAIT_BITSET reserves scratch; if so it needs its exit
			// stop so on_syscall_exit can restore rsp.
			translate_futex(pid, regs, &mut self.reserved)
		} else if regs.orig_rax == libc::SYS_pipe2 as u64 {
			let mut patched = regs;
			patched.orig_rax = libc::SYS_pipe as u64;
			patched.rax = libc::SYS_pipe as u64;
			let _ = ptrace::setregs(pid, patched);
			if debug() {
				eprintln!("kernel-compat: (seccomp) pipe2 -> pipe (flags {:#x} dropped)", regs.rsi);
			}
			false
		} else if regs.orig_rax == libc::SYS_statx as u64 {
			self.setup_statx(pid, regs);
			true
		} else {
			false
		}
	}

	fn on_syscall_stop(&mut self, pid: Pid) {
		let entering = !*self.in_syscall.get(&pid).unwrap_or(&false);
		self.in_syscall.insert(pid, entering);

		if entering {
			let regs = match ptrace::getregs(pid) {
				Ok(regs) => regs,
				Err(_) => return,
			};
			self.last_syscall.insert(pid, regs.orig_rax);
			if regs.orig_rax == libc::SYS_futex as u64 {
				translate_futex(pid, regs, &mut self.reserved);
			} else if regs.orig_rax == libc::SYS_pipe2 as u64 {
				// pipe2 (2.6.27) -> pipe (ancient). The flags argument is lost
				// entirely: neither O_NONBLOCK nor O_CLOEXEC is applied, and we
				// cannot fix that from here. Callers that relied on pipe2 to
				// set those flags will see a blocking, inheritable pipe.
				let mut patched = regs;
				patched.orig_rax = libc::SYS_pipe as u64;
				patched.rax = libc::SYS_pipe as u64;
				let _ = ptrace::setregs(pid, patched);
				if debug() {
					eprintln!("kernel-compat: pipe2 -> pipe (flags {:#x} dropped)", regs.rsi);
				}
			} else if regs.orig_rax == libc::SYS_statx as u64 {
				self.setup_statx(pid, regs);
			}
		} else {
			self.on_syscall_exit(pid);
		}
	}

	/// Syscall-exit handling shared by both tracing modes: convert the stashed
	/// statx result and restore any scratch stack reservation.
	fn on_syscall_exit(&mut self, pid: Pid) {
		let mut regs = match ptrace::getregs(pid) {
			Ok(regs) => regs,
			Err(_) => return,
		};
		let mut dirty = false;
		if let Some(state) = self.statx.remove(&pid) {
			if regs.rax == 0 {
				let ok = read_struct(pid, state.scratch, 144)
					.map(|stat| build_statx(&stat))
					.map(|stx| write_struct(pid, state.statxbuf, &stx))
					.unwrap_or(false);
				if ok {
					if debug() {
						eprintln!("kernel-compat: statx ok");
					}
				} else {
					regs.rax = (-(libc::EFAULT as i64)) as u64;
					dirty = true;
				}
			} else if debug() {
				eprintln!(
					"kernel-compat: statx -> fallback ret={} (errno {})",
					regs.rax as i64,
					-(regs.rax as i64)
				);
			}
		}
		// Undo any scratch stack reservation made at syscall entry.
		if let Some(saved_rsp) = self.reserved.remove(&pid) {
			regs.rsp = saved_rsp;
			dirty = true;
		}
		if dirty {
			let _ = ptrace::setregs(pid, regs);
		}
		if debug() && regs.rax == (-(libc::ENOSYS as i64)) as u64 {
			let nr = self.last_syscall.get(&pid).copied().unwrap_or(0);
			eprintln!("kernel-compat: pid {pid} syscall {nr} -> ENOSYS");
		}
	}

	/// statx (4.11) -> newfstatat (ancient), translating `struct stat` to
	/// `struct statx` on the way back. Qt6 (and others) rely on statx() and
	/// have no fallback when it returns ENOSYS.
	fn setup_statx(&mut self, pid: Pid, mut regs: libc::user_regs_struct) {
		let statxbuf = regs.r8;
		if statxbuf == 0 {
			return
		}
		if debug() {
			eprintln!(
				"kernel-compat: statx path='{}' flags={:#x}",
				read_cstr(pid, regs.rsi),
				regs.rdx
			);
		}
		let saved_rsp = regs.rsp;
		// 512 bytes clears the red zone (the struct itself needs 256).
		let scratch = (saved_rsp.wrapping_sub(512)) & !0xf;
		// statx(dirfd(rdi), path(rsi), flags(rdx), mask(r10), statxbuf(r8))
		regs.rsp = scratch;
		if regs.rdx & 0x1000 != 0 {
			// AT_EMPTY_PATH (added in 2.6.39) -> fstat(fd, statbuf)
			regs.rsi = scratch;
			regs.rdx = 0;
			regs.orig_rax = libc::SYS_fstat as u64;
			regs.rax = libc::SYS_fstat as u64;
		} else {
			// -> newfstatat(dirfd, path, statbuf(scratch), flags(r10))
			regs.r10 = regs.rdx & 0x900; // AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT
			regs.rdx = scratch;
			regs.orig_rax = libc::SYS_newfstatat as u64;
			regs.rax = libc::SYS_newfstatat as u64;
		}
		if ptrace::setregs(pid, regs).is_err() {
			return
		}
		self.reserved.insert(pid, saved_rsp);
		self.statx.insert(pid, StatxState { statxbuf, scratch });
		if debug() {
			eprintln!("kernel-compat: statx -> fallback (buf {statxbuf:#x})");
		}
	}
}

/// Rewrite a futex op to a form the kernel understands. Returns true if it
/// carved scratch below `rsp` (a timed `WAIT_BITSET`/CLOCK_REALTIME wait), in
/// which case the caller must let the syscall reach its exit stop so `rsp` can
/// be restored.
fn translate_futex(pid: Pid, mut regs: libc::user_regs_struct, reserved: &mut HashMap<Pid, u64>) -> bool {
	// x86_64: futex(uaddr, op, val, timeout, uaddr2, val3) ->
	// rdi, rsi, rdx, r10, r8, r9
	let op = regs.rsi as u32;
	let cmd = op & FUTEX_CMD_MASK;
	let realtime = op & FUTEX_CLOCK_REALTIME != 0;
	if debug() {
		eprintln!("kernel-compat: futex entry op={op:#x} cmd={cmd} timeout={:#x}", regs.r10);
	}
	let new_cmd = match cmd {
		FUTEX_WAIT_BITSET => FUTEX_WAIT,
		FUTEX_WAKE_BITSET => FUTEX_WAKE,
		other => other,
	};
	// Old kernels predate FUTEX_PRIVATE_FLAG / FUTEX_CLOCK_REALTIME and the
	// bitset ops, so hand the kernel a bare command with no flag bits.
	if new_cmd == op {
		return false;
	}
	let mut did_reserve = false;
	if new_cmd == FUTEX_WAIT && (cmd == FUTEX_WAIT_BITSET || realtime) {
		// FUTEX_WAIT_BITSET (and CLOCK_REALTIME waits) use an absolute timeout;
		// FUTEX_WAIT wants a relative one. Compute it in the tracer and point
		// r10 at scratch memory -- never rewrite the caller's timespec.
		let saved_rsp = regs.rsp;
		match reserve_relative_timeout(pid, regs.r10, realtime, saved_rsp) {
			// No timeout at all: nothing to convert, proceed with the rewrite.
			Ok(None) => {},
			Ok(Some(scratch)) => {
				regs.rsp = scratch;
				regs.r10 = scratch;
				reserved.insert(pid, saved_rsp);
				did_reserve = true;
			},
			// Could not convert: leave WAIT_BITSET in place so the kernel
			// returns ENOSYS, rather than handing it the absolute deadline as
			// a relative wait that would effectively never expire.
			Err(()) => {
				if debug() {
					eprintln!("kernel-compat: futex timeout conversion failed, op left as-is");
				}
				return false;
			},
		}
	}
	regs.rsi = new_cmd as u64;
	if let Err(err) = ptrace::setregs(pid, regs) {
		if debug() {
			eprintln!("kernel-compat: futex setregs failed: {err}");
		}
		return did_reserve;
	}
	if debug() {
		eprintln!("kernel-compat: futex op {op:#x} -> {new_cmd:#x}");
	}
	did_reserve
}

/// Read the absolute timespec at `timeout_ptr`, convert it to a relative one,
/// write it to scratch space below `saved_rsp`, and return the scratch address.
/// `Ok(None)` when there is no timeout to convert, `Ok(Some(scratch))` when it
/// converted and reserved scratch below `saved_rsp`, `Err(())` when it could
/// not (read/clock/poke failure).
fn reserve_relative_timeout(pid: Pid, timeout_ptr: u64, realtime: bool, saved_rsp: u64) -> Result<Option<u64>, ()> {
	if timeout_ptr == 0 {
		return Ok(None)
	}
	let raw = read_struct(pid, timeout_ptr, 16).ok_or(())?;
	let abs_sec = i64::from_le_bytes(raw[0..8].try_into().map_err(|_| ())?);
	let abs_nsec = i64::from_le_bytes(raw[8..16].try_into().map_err(|_| ())?);
	let clock = if realtime {
		libc::CLOCK_REALTIME
	} else {
		libc::CLOCK_MONOTONIC
	};
	let mut now: libc::timespec = unsafe { std::mem::zeroed() };
	if unsafe { libc::clock_gettime(clock, &mut now) } != 0 {
		return Err(())
	}
	let mut sec = abs_sec - now.tv_sec;
	let mut nsec = abs_nsec - now.tv_nsec;
	if nsec < 0 {
		sec -= 1;
		nsec += 1_000_000_000;
	}
	if sec < 0 {
		sec = 0;
		nsec = 0;
	}
	let scratch = (saved_rsp.wrapping_sub(512)) & !0xf;
	let mut buf = [0u8; 16];
	buf[0..8].copy_from_slice(&sec.to_le_bytes());
	buf[8..16].copy_from_slice(&nsec.to_le_bytes());
	if !write_struct(pid, scratch, &buf) {
		return Err(())
	}
	if debug() {
		eprintln!(
			"kernel-compat: futex timeout {abs_sec}.{abs_nsec} -> {sec}.{nsec} rel (scratch {scratch:#x})"
		);
	}
	Ok(Some(scratch))
}

fn peek_word(pid: Pid, addr: u64) -> Option<u64> {
	ptrace::read(pid, addr as AddressType).ok().map(|w| w as u64)
}

fn read_cstr(pid: Pid, addr: u64) -> String {
	if addr == 0 {
		return String::new()
	}
	let mut out = Vec::new();
	let mut off = 0u64;
	'outer: while out.len() < 256 {
		let Some(word) = peek_word(pid, addr + off) else { break };
		for i in 0..8 {
			let b = ((word >> (8 * i)) & 0xff) as u8;
			if b == 0 {
				break 'outer
			}
			out.push(b);
		}
		off += 8;
	}
	String::from_utf8_lossy(&out).into_owned()
}

#[allow(deprecated)]
fn poke_word(pid: Pid, addr: u64, val: u64) -> bool {
	ptrace::write(pid, addr as AddressType, val as i64).is_ok()
}

fn read_struct(pid: Pid, addr: u64, len: usize) -> Option<Vec<u8>> {
	let mut out = Vec::with_capacity(len + 8);
	let mut off = 0u64;
	while out.len() < len {
		let word = peek_word(pid, addr + off)?;
		out.extend_from_slice(&word.to_le_bytes());
		off += 8;
	}
	out.truncate(len);
	Some(out)
}

fn write_struct(pid: Pid, addr: u64, bytes: &[u8]) -> bool {
	let mut off = 0usize;
	while off < bytes.len() {
		let mut chunk = [0u8; 8];
		let n = (bytes.len() - off).min(8);
		chunk[..n].copy_from_slice(&bytes[off..off + n]);
		if !poke_word(pid, addr + off as u64, u64::from_le_bytes(chunk)) {
			return false
		}
		off += 8;
	}
	true
}

fn rd_u32(b: &[u8], o: usize) -> u32 {
	u32::from_le_bytes(b[o..o + 4].try_into().unwrap_or_default())
}

fn rd_u64(b: &[u8], o: usize) -> u64 {
	u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or_default())
}

fn wr_u32(b: &mut [u8], o: usize, v: u32) {
	b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

fn wr_u64(b: &mut [u8], o: usize, v: u64) {
	b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

fn dev_major(dev: u64) -> u32 {
	(((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfffu64)) as u32
}

fn dev_minor(dev: u64) -> u32 {
	((dev & 0xff) | ((dev >> 12) & !0xffu64)) as u32
}

/// `struct stat` (x86_64) -> `struct statx`.
fn build_statx(stat: &[u8]) -> Vec<u8> {
	const STATX_BASIC_STATS: u32 = 0x7ff;
	let mut s = vec![0u8; 256];
	let st_dev = rd_u64(stat, 0);
	let st_ino = rd_u64(stat, 8);
	let st_nlink = rd_u64(stat, 16);
	let st_mode = rd_u32(stat, 24);
	let st_uid = rd_u32(stat, 28);
	let st_gid = rd_u32(stat, 32);
	let st_rdev = rd_u64(stat, 40);
	let st_size = rd_u64(stat, 48);
	let st_blksize = rd_u64(stat, 56);
	let st_blocks = rd_u64(stat, 64);
	let atime_s = rd_u64(stat, 72);
	let atime_ns = rd_u64(stat, 80);
	let mtime_s = rd_u64(stat, 88);
	let mtime_ns = rd_u64(stat, 96);
	let ctime_s = rd_u64(stat, 104);
	let ctime_ns = rd_u64(stat, 112);

	wr_u32(&mut s, 0, STATX_BASIC_STATS);
	wr_u32(&mut s, 4, st_blksize as u32);
	wr_u32(&mut s, 16, st_nlink as u32);
	wr_u32(&mut s, 20, st_uid);
	wr_u32(&mut s, 24, st_gid);
	s[28..30].copy_from_slice(&(st_mode as u16).to_le_bytes());
	wr_u64(&mut s, 32, st_ino);
	wr_u64(&mut s, 40, st_size);
	wr_u64(&mut s, 48, st_blocks);
	wr_u64(&mut s, 64, atime_s);
	wr_u32(&mut s, 72, atime_ns as u32);
	wr_u64(&mut s, 96, ctime_s);
	wr_u32(&mut s, 104, ctime_ns as u32);
	wr_u64(&mut s, 112, mtime_s);
	wr_u32(&mut s, 120, mtime_ns as u32);
	wr_u32(&mut s, 128, dev_major(st_rdev));
	wr_u32(&mut s, 132, dev_minor(st_rdev));
	wr_u32(&mut s, 136, dev_major(st_dev));
	wr_u32(&mut s, 140, dev_minor(st_dev));
	s
}

fn supervise(child: Pid, use_seccomp: bool) -> ! {
	// Consume the child's initial SIGSTOP. If it already exited instead (e.g.
	// TRACEME failed after the preflight, so it ran untraced), propagate that
	// status rather than losing it.
	match waitpid(child, None) {
		Ok(WaitStatus::Stopped(_, _)) => {},
		Ok(WaitStatus::Exited(_, code)) => exit(code),
		Ok(WaitStatus::Signaled(_, sig, _)) => exit(128 + sig as i32),
		_ => {},
	}
	let options = install_options(child, &tracer_options(use_seccomp));
	// Every-syscall tracing is only the fallback; with seccomp only the
	// filtered syscalls stop us.
	let seccomp_mode = use_seccomp && options.contains(Options::PTRACE_O_TRACESECCOMP);
	let syscall_mode = !seccomp_mode && options.contains(Options::PTRACE_O_TRACESYSGOOD);
	if debug() {
		eprintln!("kernel-compat: active options: {options:?}");
	}
	let mut tracer = Tracer {
		child,
		configured: HashSet::from([child]),
		in_syscall: HashMap::new(),
		last_syscall: HashMap::new(),
		statx: HashMap::new(),
		reserved: HashMap::new(),
		syscall_mode,
		seccomp_mode,
		main_code: None,
	};
	tracer.supervise()
}

#[cfg(target_arch = "x86_64")]
fn module_for(pid: Pid, addr: u64) -> String {
	let maps = match std::fs::read_to_string(format!("/proc/{pid}/maps")) {
		Ok(maps) => maps,
		Err(_) => return "<no maps>".into(),
	};
	for line in maps.lines() {
		let mut cols = line.split_whitespace();
		let range = cols.next().unwrap_or_default();
		let perms = cols.next().unwrap_or_default();
		let _offset = cols.next();
		let _dev = cols.next();
		let _inode = cols.next();
		let path = cols.next().unwrap_or_default();
		let Some((start, end)) = range.split_once('-') else { continue };
		let (Ok(start), Ok(end)) =
			(u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
		else {
			continue
		};
		if addr >= start && addr < end {
			return format!("{path} [{perms}]");
		}
	}
	"<unknown>".into()
}

#[cfg(target_arch = "x86_64")]
fn emulate_sigill(pid: Pid) -> bool {
	let regs = match ptrace::getregs(pid) {
		Ok(regs) => regs,
		Err(err) => {
			if debug() {
				eprintln!("kernel-compat: getregs failed: {err}");
			}
			return false
		},
	};
	let word = match ptrace::read(pid, regs.rip as AddressType) {
		Ok(word) => word as u64,
		Err(err) => {
			if debug() {
				eprintln!("kernel-compat: peek at 0x{:x} failed: {err}", regs.rip);
			}
			return false
		},
	};
	let opcode = [
		(word & 0xff) as u8,
		((word >> 8) & 0xff) as u8,
		((word >> 16) & 0xff) as u8,
	];
	if debug() {
		eprintln!(
			"kernel-compat: SIGILL at 0x{:x} in {} opcode {:02x} {:02x} {:02x} {:02x} {:02x}",
			regs.rip,
			module_for(pid, regs.rip),
			(word & 0xff) as u8,
			((word >> 8) & 0xff) as u8,
			((word >> 16) & 0xff) as u8,
			((word >> 24) & 0xff) as u8,
			((word >> 32) & 0xff) as u8,
		);
	}
	// XGETBV: 0F 01 D0
	if opcode != [0x0f, 0x01, 0xd0] {
		return false
	}
	// Emulate XGETBV with XCR0 = 0 (no XSAVE state enabled), then skip it.
	let mut patched = regs;
	patched.rax = 0;
	patched.rdx = 0;
	patched.rip = patched.rip.wrapping_add(3);
	if let Err(err) = ptrace::setregs(pid, patched) {
		if debug() {
			eprintln!("kernel-compat: setregs failed: {err}");
		}
		return false
	}
	if debug() {
		eprintln!("kernel-compat: emulated XGETBV (XCR0=0) at 0x{:x}", regs.rip);
	}
	true
}

#[cfg(not(target_arch = "x86_64"))]
fn emulate_sigill(_pid: Pid) -> bool {
	false
}
