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
		wait::{waitpid, WaitStatus},
	},
	unistd::{fork, ForkResult, Pid},
	libc,
};

const ENV_ENABLE: &str = "SHARUN_OLD_KERNEL_COMPAT";
const ENV_DEBUG: &str = "SHARUN_OLD_KERNEL_COMPAT_DEBUG";
const ENV_DEBUG_ALL: &str = "SHARUN_OLD_KERNEL_COMPAT_DEBUG_ALL";

// futex op encoding
const FUTEX_CMD_MASK: u32 = 0x7f;
const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;
const FUTEX_WAIT_BITSET: u32 = 9;
const FUTEX_WAKE_BITSET: u32 = 10;
const FUTEX_CLOCK_REALTIME: u32 = 256;

// The termios2 ioctls (2.6.20) and the 2.6.17-era requests that answer them.
// x86_64 values; the whole module already assumes that ABI.
const TCGETS2: u64 = 0x802c_542a;
const TCSETS2: u64 = 0x402c_542b;
const TCSETSW2: u64 = 0x402c_542c;
const TCSETSF2: u64 = 0x402c_542d;
const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCSETSW: u64 = 0x5403;
const TCSETSF: u64 = 0x5404;
/// Byte offset of `c_ispeed` in `struct termios2` (4 tcflag_t, c_line, 19 cc).
/// Everything before it has the same layout as the `struct termios` the older
/// kernel fills in, which is what makes the translation a pure suffix.
const TERMIOS2_ISPEED: u64 = 36;

pub(crate) fn debug() -> bool {
	matches!(env::var(ENV_DEBUG), Ok(v) if v == "1")
}

/// Even noisier than [`debug`]: the per-syscall trace of every call. Kept
/// separate because it produces tens of megabytes in seconds and slows the
/// tracee down enough to change its behaviour.
pub(crate) fn debug_all() -> bool {
	matches!(env::var(ENV_DEBUG_ALL), Ok(v) if v == "1")
}

/// True when a raw syscall return means "not implemented": -1/ENOSYS, or the
/// syscall number itself (seen on some old kernels, where it would otherwise
/// look like success).
pub(crate) fn not_implemented(nr: libc::c_long, rc: libc::c_long) -> bool {
	rc == nr
		|| (rc == -1
			&& std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS))
}

/// Probe once whether the kernel implements ppoll(2). A zero timeout is used so
/// the probe can never block: a working `ppoll(NULL, 0, {0,0}, NULL, 0)` returns
/// 0 immediately.
fn ppoll_missing() -> bool {
	static MISSING: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
	*MISSING.get_or_init(|| {
		let ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
		let rc = unsafe {
			libc::syscall(
				libc::SYS_ppoll,
				std::ptr::null::<libc::pollfd>(),
				0usize,
				&ts as *const libc::timespec,
				std::ptr::null::<libc::sigset_t>(),
				0usize,
			)
		};
		not_implemented(libc::SYS_ppoll, rc)
	})
}

/// Whether the kernel has the termios2 ioctls, which arrived in 2.6.20 together
/// with the two speed fields they carry and are rejected with ENOIOCTLCMD by
/// anything older. A version check rather than a probe: there is no tty the
/// tracer owns to probe against, and the translation below is exact for
/// everything except those speed fields, which an older kernel cannot report
/// anyway. Confirmed against the sources (absent in v2.6.17 and v2.6.19,
/// present in v2.6.20) and in a 2.6.17 guest, where TCGETS succeeds on a tty
/// while TCGETS2 fails.
fn termios2_missing() -> bool {
	static MISSING: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
	*MISSING.get_or_init(|| kernel_lt(2, 6, 20))
}

/// The request an older kernel understands in place of a termios2 one. The
/// struct is a prefix of `struct termios2` up to the two speed fields, so only
/// that suffix has to be dealt with separately.
fn legacy_termios_request(request: u64) -> Option<u64> {
	match request {
		TCGETS2 => Some(TCGETS),
		TCSETS2 => Some(TCSETS),
		TCSETSW2 => Some(TCSETSW),
		TCSETSF2 => Some(TCSETSF),
		_ => None,
	}
}

/// Line speed for a `Bxxxx` code in `c_cflag`. An older kernel keeps the speed
/// there and nowhere else, so it has to be decoded to fill in termios2's own
/// speed fields; `B0` (hang up) and the codes those kernels cannot produce
/// report no speed.
fn baud_from_cflag(cflag: u32) -> u32 {
	match cflag & 0x100f {
		0x0001 => 50,
		0x0002 => 75,
		0x0003 => 110,
		0x0004 => 134,
		0x0005 => 150,
		0x0006 => 200,
		0x0007 => 300,
		0x0008 => 600,
		0x0009 => 1200,
		0x000a => 1800,
		0x000b => 2400,
		0x000c => 4800,
		0x000d => 9600,
		0x000e => 19200,
		0x000f => 38400,
		0x1001 => 57600,
		0x1002 => 115200,
		0x1003 => 230400,
		0x1004 => 460800,
		0x1005 => 500000,
		0x1006 => 576000,
		0x1007 => 921600,
		0x1008 => 1_000_000,
		0x1009 => 1_152_000,
		0x100a => 1_500_000,
		0x100b => 2_000_000,
		0x100c => 2_500_000,
		0x100d => 3_000_000,
		0x100e => 3_500_000,
		0x100f => 4_000_000,
		_ => 0,
	}
}

/// Probe once whether the kernel implements epoll_create1(2) (added in 2.6.27).
/// Only then is it rewritten to epoll_create, which loses EPOLL_CLOEXEC.
fn epoll_create1_missing() -> bool {
	static MISSING: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
	*MISSING.get_or_init(|| {
		let rc = unsafe { libc::syscall(libc::SYS_epoll_create1, 0) };
		let missing = not_implemented(libc::SYS_epoll_create1, rc);
		if !missing && rc >= 0 {
			unsafe { libc::close(rc as libc::c_int) };
		}
		missing
	})
}

/// Probe once whether the kernel implements prlimit64(2) (added in 2.6.36). Only
/// then is it rewritten to getrlimit/setrlimit: modern glibc only has the 64-bit
/// form, so on an older kernel `getrlimit`, `setrlimit` and everything built on
/// them (thread stack sizing, fd limit lookups) fail outright.
fn prlimit64_missing() -> bool {
	static MISSING: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
	*MISSING.get_or_init(|| {
		let mut limit: libc::rlimit64 = unsafe { std::mem::zeroed() };
		let rc = unsafe {
			libc::syscall(
				libc::SYS_prlimit64,
				0u32,
				libc::RLIMIT_NOFILE,
				std::ptr::null::<libc::rlimit64>(),
				&mut limit,
			)
		};
		not_implemented(libc::SYS_prlimit64, rc)
	})
}

/// Probe once whether the kernel implements pipe2(2) (added in 2.6.27). Only
/// then is pipe2 rewritten to pipe, which loses O_CLOEXEC and O_NONBLOCK.
fn pipe2_missing() -> bool {
	static MISSING: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
	*MISSING.get_or_init(|| {
		let mut fds = [0i32; 2];
		let rc = unsafe { libc::syscall(libc::SYS_pipe2, fds.as_mut_ptr(), 0) };
		let missing = not_implemented(libc::SYS_pipe2, rc);
		if !missing && rc == 0 {
			// Close the two fds the probe created.
			unsafe {
				libc::close(fds[0]);
				libc::close(fds[1]);
			}
		}
		missing
	})
}

/// Probe once whether the kernel implements getrandom(2) (added in 3.17). Only
/// then is it emulated from /dev/urandom.
fn getrandom_missing() -> bool {
	static MISSING: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
	*MISSING.get_or_init(|| {
		// GRND_NONBLOCK (since 3.17) so a kernel that has getrandom is not
		// mistaken for one that lacks it just because the CRNG is not ready
		// yet; EAGAIN then simply means "present".
		const GRND_NONBLOCK: libc::c_long = 0x0001;
		let mut buf = [0u8; 16];
		let rc = unsafe {
			libc::syscall(libc::SYS_getrandom, buf.as_mut_ptr(), buf.len(), GRND_NONBLOCK)
		};
		not_implemented(libc::SYS_getrandom, rc)
	})
}

/// Clock ids to substitute, indexed by clock id; an id maps to itself when the
/// kernel answers it. `CLOCK_MONOTONIC_RAW` arrived in 2.6.28, the two
/// `*_COARSE` clocks in 2.6.32 and `CLOCK_BOOTTIME` in 2.6.39. `clock_gettime`
/// itself is ancient, so a missing id comes back as `EINVAL` rather than
/// `ENOSYS` and callers cannot tell "this kernel has no such clock" from a real
/// failure -- in the zeroed timespec it leaves behind, WTF's `ApproximateTime`
/// aborts. Ask the kernel once which ids it answers, then hand it one it knows:
/// a coarse clock is the same clock at lower resolution, only more precise.
pub(crate) fn clockid_replacements() -> &'static [u64; 8] {
	static REPLACEMENTS: std::sync::OnceLock<[u64; 8]> = std::sync::OnceLock::new();
	REPLACEMENTS.get_or_init(|| {
		let mut map = [0, 1, 2, 3, 4, 5, 6, 7];
		// CLOCK_MONOTONIC_RAW -> CLOCK_MONOTONIC, CLOCK_REALTIME_COARSE ->
		// CLOCK_REALTIME, CLOCK_MONOTONIC_COARSE -> CLOCK_MONOTONIC,
		// CLOCK_BOOTTIME -> CLOCK_MONOTONIC. The seccomp path needs none of
		// this: it only exists from 3.5, where every id above is supported.
		for (id, fallback) in [(4u64, 1u64), (5, 0), (6, 1), (7, 1)] {
			let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
			if unsafe { libc::clock_gettime(id as libc::clockid_t, &mut ts) } != 0 {
				map[id as usize] = fallback;
			}
		}
		map
	})
}

/// Probe once whether the kernel implements statx(2) (added in 4.11). Only then
/// is it translated to newfstatat.
fn statx_missing() -> bool {
	static MISSING: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
	*MISSING.get_or_init(|| {
		let mut stx = [0u8; 256];
		let path = b"/\0";
		let rc = unsafe {
			libc::syscall(
				libc::SYS_statx,
				libc::AT_FDCWD,
				path.as_ptr(),
				0i32,
				0u32,
				stx.as_mut_ptr() as *mut libc::c_void,
			)
		};
		not_implemented(libc::SYS_statx, rc)
	})
}

/// Probe once whether `PR_SET_NO_NEW_PRIVS` breaks `execve` on this kernel.
///
/// Some kernels (observed on 3.8.0-19 from Ubuntu 13.04) return EPERM from
/// `execve` once no_new_privs is set. Installing a seccomp filter requires
/// no_new_privs, so on such a kernel the AppRun re-exec fails and the app never
/// starts. Detect it and fall back to tracing every syscall instead.
///
/// `/proc/self/exe` is used so that no external binary (like `/bin/true`) is
/// needed, which also works on systems such as NixOS. The re-exec'd sharun
/// exits at once thanks to the `SHARUN_NNP_PROBE` sentinel.
fn nnp_exec_broken() -> bool {
	static BROKEN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
	*BROKEN.get_or_init(|| {
		use std::os::unix::process::CommandExt;
		let mut cmd = std::process::Command::new("/proc/self/exe");
		// Reuse this process's argv[0] so the re-exec lands in the same mode
		// (AppRun) as the current one, where the sentinel flag is honored.
		if let Some(arg0) = std::env::args_os().next() {
			cmd.arg0(arg0);
		}
		cmd.arg(crate::SHARUN_NNP_PROBE_FLAG);
		unsafe {
			cmd.pre_exec(|| {
				libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
				Ok(())
			});
		}
		match cmd.status() {
			Ok(status) => !status.success(),
			Err(err) => err.raw_os_error() == Some(libc::EPERM),
		}
	})
}

pub(crate) fn kernel_lt(want_major: u64, want_minor: u64, want_patch: u64) -> bool {
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

/// Whether this kernel can answer an out-of-range syscall with its own number.
/// x86_64 before 2.6.19 does, whenever the caller is being traced: the
/// `tracesys` path jumps into the store that writes the result while `%rax`
/// still holds the number, so `getrandom` surfaces as `318`, `copy_file_range`
/// as `326` and so on, instead of `-ENOSYS` (fixed in 2.6.19, "x86-64: Fix
/// ENOSYS in system call tracing"). Only numbers above the kernel's syscall
/// table are affected; every entry up to `__NR_syscall_max` is a real function
/// or `sys_ni_syscall`. Tracing the caller is what this layer does, so it has
/// to undo the consequences.
fn kernel_echoes_number() -> bool {
	static ECHOES: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
	*ECHOES.get_or_init(|| kernel_lt(2, 6, 19))
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
	statx_missing()
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

	// Prime the no_new_privs/execve probe in this (untraced) parent, so the
	// traced child does not have to fork while it is being ptraced.
	let _ = nnp_exec_broken();

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
	// no_new_privs is required to install the filter, but on some kernels it
	// makes execve fail (see nnp_exec_broken), which would break the AppRun
	// re-exec. Fall back to tracing every syscall in that case.
	if nnp_exec_broken() {
		if debug() {
			eprintln!("kernel-compat: seccomp unusable (no_new_privs breaks execve)");
		}
		return false
	}
	const BPF_LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
	const BPF_JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
	const BPF_RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
	// ELF machine for x86_64 (libc does not export AUDIT_ARCH_X86_64 here).
	const AUDIT_ARCH_X86_64: u32 = 0xc000003e;
	let stmt = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
	let jump = |k: u32, jt: u8, jf: u8| libc::sock_filter { code: BPF_JEQ_K, jt, jf, k };
	// Only trap syscalls this kernel actually lacks (or, for futex, that
	// predate the bitset ops). On anything newer the rewrites are wrong or
	// pointless, and stopping on them just costs a signal per call.
	let mut wanted: Vec<u32> = Vec::new();
	if kernel_lt(2, 6, 29) {
		wanted.push(libc::SYS_futex as u32);
	}
	if pipe2_missing() {
		wanted.push(libc::SYS_pipe2 as u32);
	}
	if statx_missing() {
		wanted.push(libc::SYS_statx as u32);
	}
	if getrandom_missing() {
		wanted.push(libc::SYS_getrandom as u32);
	}
	let n = wanted.len();
	let mut filter: Vec<libc::sock_filter> = Vec::with_capacity(6 + n);
	filter.push(stmt(BPF_LD_W_ABS, 4)); // seccomp_data.arch
	filter.push(jump(AUDIT_ARCH_X86_64, 1, 0));
	filter.push(stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW));
	filter.push(stmt(BPF_LD_W_ABS, 0)); // seccomp_data.nr
	for (i, nr) in wanted.iter().enumerate() {
		// On a match, skip the remaining comparisons to reach RET_TRACE.
		filter.push(jump(*nr, (n - i) as u8, 0));
	}
	filter.push(stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW));
	if n > 0 {
		filter.push(stmt(BPF_RET_K, libc::SECCOMP_RET_TRACE));
	}
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

/// Minimal wait result. Unlike nix's `WaitStatus`, this tolerates stop signals
/// that nix's `Signal` enum cannot represent (e.g. real-time signals): decoding
/// those makes `WaitStatus::from_raw` return `EINVAL`, which otherwise leaves
/// the tracee stopped forever.
enum Wait {
	Exited(Pid, i32),
	Signaled(Pid, i32),
	/// Stopped by the raw signal number.
	Stopped(Pid, i32),
	/// A ptrace event (SIGTRAP + event code).
	Event(Pid, u32),
	/// A syscall stop (PTRACE_O_TRACESYSGOOD).
	Syscall(Pid),
}

/// Diagnostics for a syscall-entry stop. Pure logging, and deliberately not
/// part of the rewrite chain in `on_syscall_stop`: a logging branch in that
/// chain shadows every branch after it, which is how a `regs.rdi <= 2` test
/// once stopped `fcntl(1, F_DUPFD_CLOEXEC)` from being emulated whenever the
/// trace was on, leaving the application to abort on its own stdout.
fn log_entry(pid: Pid, regs: &libc::user_regs_struct) {
	let nr = regs.orig_rax;
	if nr == libc::SYS_prctl as u64 {
		eprintln!(
			"kernel-compat: [t{pid}] prctl({}, {:#x}, {:#x}, {:#x}, {:#x})",
			regs.rdi as i64, regs.rsi, regs.rdx, regs.r10, regs.r8
		);
	} else if nr == libc::SYS_tgkill as u64 {
		eprintln!(
			"kernel-compat: [t{pid}] tgkill(tgid {}, tid {}, sig {})",
			regs.rdi as i64, regs.rsi as i64, regs.rdx as i64
		);
	} else if nr == libc::SYS_kill as u64 {
		eprintln!(
			"kernel-compat: [t{pid}] kill(pid {}, sig {})",
			regs.rdi as i64, regs.rsi as i64
		);
	} else if nr == libc::SYS_tkill as u64 {
		eprintln!(
			"kernel-compat: [t{pid}] tkill(tid {}, sig {})",
			regs.rdi as i64, regs.rsi as i64
		);
	} else if nr == libc::SYS_rt_sigqueueinfo as u64 {
		eprintln!(
			"kernel-compat: [t{pid}] rt_sigqueueinfo(pid {}, sig {})",
			regs.rdi as i64, regs.rsi as i64
		);
	} else if nr == libc::SYS_rt_tgsigqueueinfo as u64 {
		eprintln!(
			"kernel-compat: [t{pid}] rt_tgsigqueueinfo(tgid {}, tid {}, sig {})",
			regs.rdi as i64, regs.rsi as i64, regs.rdx as i64
		);
	} else if nr == libc::SYS_fcntl as u64 {
		eprintln!(
			"kernel-compat: [t{pid}] fcntl(fd {}, cmd {}, arg {:#x})",
			regs.rdi as i64, regs.rsi as i64, regs.rdx
		);
	}
}

fn wait_any() -> Result<Wait, Errno> {
	let mut status: libc::c_int = 0;
	let rc = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
	if rc < 0 {
		return Err(Errno::last())
	}
	let pid = Pid::from_raw(rc);
	let s = status;
	if s & 0x7f == 0 {
		Ok(Wait::Exited(pid, (s >> 8) & 0xff))
	} else if s & 0xff == 0x7f {
		let sig = (s >> 8) & 0xff;
		if sig & 0x80 != 0 {
			Ok(Wait::Syscall(pid))
		} else {
			let event = (s >> 16) as u32;
			if event != 0 {
				Ok(Wait::Event(pid, event))
			} else {
				Ok(Wait::Stopped(pid, sig))
			}
		}
	} else {
		// Continued stops (0xffff) cannot appear here since `WCONTINUED` is not
		// requested, so anything left is a signal death.
		Ok(Wait::Signaled(pid, s & 0x7f))
	}
}

fn ptrace_resume(request: libc::c_uint, pid: Pid, sig: Option<i32>) -> Result<(), ()> {
	let rc = unsafe {
		libc::ptrace(
			request as _,
			pid.as_raw() as libc::pid_t,
			std::ptr::null_mut::<libc::c_void>(),
			sig.unwrap_or(0) as *mut libc::c_void,
		)
	};
	if rc == -1 { Err(()) } else { Ok(()) }
}

struct Tracer {
	child: Pid,
	configured: HashSet<Pid>,
	in_syscall: HashMap<Pid, bool>,
	last_syscall: HashMap<Pid, u64>,
	statx: HashMap<Pid, StatxState>,
	/// Argument of a termios2 TCGETS2 rewritten to TCGETS, whose two speed
	/// fields still have to be filled in once the kernel has answered.
	termios2_get: HashMap<Pid, u64>,
	/// Syscalls emulated with real calls inside the tracee, for the ones that
	/// cannot be answered by rewriting the call itself (`eventfd`).
	emulated: crate::emulated_syscalls::Emulations,
	/// rsp to restore at syscall-exit for tracees whose translated syscall
	/// needed scratch space carved below the stack pointer.
	reserved: HashMap<Pid, u64>,
	/// A signal that arrived while the tracee was inside an emulation, held back
	/// until the sequence finishes. See the `Wait::Stopped` arm: the tracee must
	/// not enter a signal handler between the emulation's injected calls. One
	/// slot per pid, so a second signal arriving during the same sequence
	/// replaces the first rather than queueing behind it; a sequence lasts a
	/// handful of syscalls, and the alternative is a queue that has no reliable
	/// stop left to drain on.
	stashed_signal: HashMap<Pid, i32>,
	/// Pids resumed from a seccomp stop with PTRACE_SYSCALL for which the
	/// spurious syscall-entry stop has not been consumed yet. The entry stop
	/// must be skipped; the stop after it carries the syscall result.
	expect_entry: HashSet<Pid>,
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
	fn resume(&self, pid: Pid, sig: Option<i32>) {
		let request = if self.syscall_mode {
			libc::PTRACE_SYSCALL as libc::c_uint
		} else {
			libc::PTRACE_CONT as libc::c_uint
		};
		let _ = ptrace_resume(request, pid, sig);
	}

	fn resume_syscall(&self, pid: Pid, sig: Option<i32>) {
		let _ = ptrace_resume(libc::PTRACE_SYSCALL as libc::c_uint, pid, sig);
	}

	/// Drop all per-pid state once a tracee is gone, so a recycled pid cannot
	/// inherit stale state (e.g. a `reserved` rsp applied to a later stop).
	fn forget(&mut self, pid: Pid) {
		self.configured.remove(&pid);
		self.in_syscall.remove(&pid);
		self.last_syscall.remove(&pid);
		self.statx.remove(&pid);
		self.termios2_get.remove(&pid);
		self.emulated.forget(pid);
		self.reserved.remove(&pid);
		self.stashed_signal.remove(&pid);
		self.expect_entry.remove(&pid);
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
			// Serve emulated deadlines, including the ones that interrupted the
			// wait below: `SIGALRM` makes waitpid return, and this is where the
			// expiration is handed to the tracee.
			self.emulated.tick();
			match wait_any() {
				Ok(Wait::Exited(pid, code)) => {
					if debug() {
						eprintln!("kernel-compat: pid {pid} exited {code}");
					}
					self.forget(pid);
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
				Ok(Wait::Signaled(pid, sig)) => {
					if debug() {
						eprintln!("kernel-compat: pid {pid} killed by {sig:?}");
					}
					self.forget(pid);
					if pid == self.child {
						if self.seccomp_mode {
							self.main_code = Some(128 + sig);
						} else {
							exit(128 + sig)
						}
					}
				},
				Ok(Wait::Stopped(pid, sig)) => {
					if debug() {
						eprintln!("kernel-compat: pid {pid} stopped: {sig:?}");
						if sig == libc::SIGTRAP
							|| sig == libc::SIGABRT
							|| sig == libc::SIGSEGV
							|| sig == libc::SIGBUS
							|| sig == libc::SIGILL
						{
							if let Ok(r) = ptrace::getregs(pid) {
								eprintln!(
									"kernel-compat: signal {} at {:#x} in {} rsp={:#x} rax={:#x} rdi={:#x} r11={:#x}",
									sig as i32, r.rip, module_for(pid, r.rip), r.rsp, r.rax, r.rdi, r.r11
								);
								// Poor man's unwinder: every stack word that points into
								// an executable mapping is a candidate return address, so
								// the caller chain can be read off without gdb.
								let ranges = executable_ranges(pid);
								let mut hits = Vec::new();
								for i in 0..1024u64 {
									let Ok(word) = ptrace::read(pid, (r.rsp + 8 * i) as AddressType)
									else {
										break;
									};
									let word = word as u64;
									if word != 0
										&& ranges.iter().any(|(lo, hi)| word >= *lo && word < *hi)
									{
										hits.push(word);
									}
								}
								let shown: Vec<String> = hits
									.iter()
									.take(24)
									.map(|a| format!("{a:#x} in {}", module_for(pid, *a)))
									.collect();
								eprintln!("kernel-compat: {} stack code pointers: {}", hits.len(), shown.join(" | "));
							}
						}
					}
					// A newly traced child stops once so we can configure it.
					if pid != self.child && !self.configured.contains(&pid) {
						install_options(pid, &tracer_options(self.seccomp_mode));
						self.configured.insert(pid);
						if sig == libc::SIGSTOP {
							self.resume(pid, None);
							continue;
						}
					}
					// The tracee must not run application code in the middle of an
					// emulation: a handler entered between two injected calls would
					// have its own syscalls collected as the emulation's, and the
					// register write-back that ends the sequence would then pull the
					// tracee out of the handler. This is not a rare interleaving --
					// the call being emulated is interrupted *because* this signal
					// arrived. Hold it back and deliver it once the sequence is
					// done, which is where the kernel would have delivered it.
					if self.emulated.busy(pid)
						&& sig != 0
						&& sig != libc::SIGSTOP
						&& sig != libc::SIGTRAP
					{
						if debug() {
							eprintln!(
								"kernel-compat: holding signal {sig} for pid {pid} until the emulation finishes"
							);
						}
						self.stashed_signal.insert(pid, sig);
						self.resume(pid, None);
						continue;
					}
					// In seccomp mode a signal delivered while a translated
					// syscall's exit stop is pending must not be resumed with
					// PTRACE_CONT: that clears the syscall-trace flag and the
					// exit stop (which restores rsp) would never fire.
					let pending = self.seccomp_mode
						&& (self.reserved.contains_key(&pid)
							|| self.expect_entry.contains(&pid)
							|| self.statx.contains_key(&pid)
							|| self.last_syscall.contains_key(&pid));
					let suppress = sig == libc::SIGILL && emulate_sigill(pid);
					if pending {
						self.resume_syscall(pid, if suppress { None } else { Some(sig) });
					} else if suppress {
						self.resume(pid, None);
					} else {
						self.resume(pid, Some(sig));
					}
				},
				Ok(Wait::Event(pid, event)) if event == libc::PTRACE_EVENT_SECCOMP as u32 => {
					// A filtered syscall: translate it, then continue. statx,
					// getrandom and the timed futex also need the exit stop to
					// convert the result, fill the buffer or restore rsp.
					if self.on_seccomp_stop(pid) {
						// PTRACE_SYSCALL from a seccomp stop also trips the
						// syscall-entry trace, so the next stop is the entry,
						// not the exit. Remember we owe an exit.
						self.expect_entry.insert(pid);
						self.resume_syscall(pid, None);
					} else {
						self.resume(pid, None);
					}
				},
				Ok(Wait::Event(pid, event)) => {
					// Restart event stops with signal 0 (like strace does), not
					// with the synthetic SIGTRAP nix reports for them.
					if debug() {
						eprintln!("kernel-compat: pid {pid} event {event}");
					}
					self.resume(pid, None);
				},
				Ok(Wait::Syscall(pid)) => {
					if self.seccomp_mode {
						if self.expect_entry.remove(&pid) {
							// The syscall-entry stop generated right after the
							// seccomp stop; skip it and ask for the exit stop
							// that follows.
							self.resume_syscall(pid, None);
						} else {
							self.on_syscall_exit(pid);
							self.resume(pid, None);
						}
					} else {
						if self.emulated.busy(pid) {
							// Inside an emulation every stop belongs to it: the
							// tracee is running our calls, not the application's.
							self.emulated.step(pid);
							if !self.emulated.busy(pid) {
								// The sequence is over, so a signal that arrived
								// while it ran can be delivered now: the tracee's
								// registers are the application's again.
								if let Some(sig) = self.stashed_signal.remove(&pid) {
									if debug() {
										eprintln!(
											"kernel-compat: delivering held signal {sig} to pid {pid}"
										);
									}
									self.resume(pid, Some(sig));
									continue;
								}
							}
						} else if !self.emulated.begin(
							pid,
							!*self.in_syscall.get(&pid).unwrap_or(&false),
						) {
							self.on_syscall_stop(pid);
						}
						self.resume(pid, None);
					}
				},
				Err(Errno::ECHILD) => exit(self.main_code.unwrap_or(0)),
				Err(err) => {
					if debug() {
						eprintln!("kernel-compat: waitpid error: {err}");
					}
				},
			}
		}
	}

	/// Rewrites shared by both tracing modes. In seccomp mode only the syscalls
	/// in the filter reach here, but every branch is gated on its own probe so the
	/// ptrace path can call this for any syscall.
	///
	/// `Some(needs_exit)` when the call is one of the shared ones: `true` means the
	/// caller must arrange a syscall-exit stop (statx has a buffer to fill, a
	/// relative futex timeout carved scratch below rsp), `false` means the call is
	/// complete. `None` leaves the syscall to the caller.
	fn translate_common(
		&mut self,
		pid: Pid,
		regs: libc::user_regs_struct,
	) -> Option<bool> {
		if regs.orig_rax == libc::SYS_futex as u64 {
			// A timed WAIT_BITSET reserves scratch; if so it needs its exit
			// stop so on_syscall_exit can restore rsp.
			return Some(translate_futex(pid, regs, &mut self.reserved));
		}
		if regs.orig_rax == libc::SYS_pipe2 as u64 && pipe2_missing() {
			// pipe2 (2.6.27) -> pipe (ancient). The flags argument is lost
			// entirely: neither O_NONBLOCK nor O_CLOEXEC is applied, and we
			// cannot fix that from here. Callers that relied on pipe2 to set
			// those flags will see a blocking, inheritable pipe.
			let mut patched = regs;
			patched.orig_rax = libc::SYS_pipe as u64;
			patched.rax = libc::SYS_pipe as u64;
			let _ = ptrace::setregs(pid, patched);
			if debug() {
				eprintln!("kernel-compat: pipe2 -> pipe (flags {:#x} dropped)", regs.rsi);
			}
			return Some(false);
		}
		if regs.orig_rax == libc::SYS_statx as u64 && statx_missing() {
			self.setup_statx(pid, regs);
			return Some(true);
		}
		None
	}

	/// Handle a `SECCOMP_RET_TRACE` stop. Returns whether the caller must resume
	/// with `PTRACE_SYSCALL` to also catch the syscall exit.
	fn on_seccomp_stop(&mut self, pid: Pid) -> bool {
		let regs = match ptrace::getregs(pid) {
			Ok(regs) => regs,
			Err(_) => return false,
		};
		if let Some(needs_exit) = self.translate_common(pid, regs) {
			return needs_exit;
		}
		if regs.orig_rax == libc::SYS_getrandom as u64 && getrandom_missing() {
			// Need the exit stop to fill the buffer when the kernel lacks
			// getrandom (3.17).
			self.last_syscall.insert(pid, regs.orig_rax);
			return true;
		}
		false
	}

	fn on_syscall_stop(&mut self, pid: Pid) {
		let entering = !*self.in_syscall.get(&pid).unwrap_or(&false);
		self.in_syscall.insert(pid, entering);

		if entering {
			let regs = match ptrace::getregs(pid) {
				Ok(regs) => regs,
				Err(_) => return,
			};
			if debug() {
				log_entry(pid, &regs);
			}
			// This layer is x86_64 only: the numbers, the argument registers and
			// the ioctl requests below all mean something else to an i386
			// tracee, so a 32-bit process (a child of the application, or a
			// binary the application picks at runtime) is never translated. It
			// is only traced, and its signals passed through. This is the only
			// place that decides, so it does not matter whether the process
			// came from a binary the AppDir ships or one it picked up
			// elsewhere.
			if regs.cs != 0x33 {
				return
			}
			self.last_syscall.insert(pid, regs.orig_rax);
			if self.translate_common(pid, regs).is_some() {
				// futex, pipe2 and statx are done; no syscall number below can
				// also match, so there is nothing left to try.
				return
			}
			if regs.orig_rax == libc::SYS_epoll_create1 as u64 && epoll_create1_missing() {
				// epoll_create1 (2.6.27) -> epoll_create (2.6). The size argument
				// is ignored by every kernel that has the old call, but
				// EPOLL_CLOEXEC is lost, so the fd is inheritable. It has to work
				// rather than fail cleanly: uSockets does not look at the result
				// and carries on with an epoll fd of -1, which turns every later
				// epoll_ctl into EBADF.
				let mut patched = regs;
				patched.orig_rax = libc::SYS_epoll_create as u64;
				patched.rax = libc::SYS_epoll_create as u64;
				patched.rdi = 1;
				let _ = ptrace::setregs(pid, patched);
				if debug() {
					eprintln!(
						"kernel-compat: epoll_create1 -> epoll_create (flags {:#x} dropped)",
						regs.rdi
					);
				}
			} else if regs.orig_rax == libc::SYS_prlimit64 as u64 && prlimit64_missing() {
				// prlimit64(pid, resource, new, old) -> getrlimit/setrlimit.
				// `struct rlimit` and `struct rlimit64` are the same two u64s on
				// x86_64, so only the number and the argument order change. A
				// caller that passes both a new and an old limit keeps the new
				// one and gets nothing back in the old one. Only pid 0 (self) is
				// translated; anything else is left to fail as before.
				if regs.rdi == 0 {
					let setting = regs.rdx != 0;
					let number = if setting { libc::SYS_setrlimit } else { libc::SYS_getrlimit } as u64;
					let mut patched = regs;
					patched.orig_rax = number;
					patched.rax = number;
					patched.rdi = regs.rsi;
					patched.rsi = if setting { regs.rdx } else { regs.r10 };
					let _ = ptrace::setregs(pid, patched);
					if debug() {
						eprintln!(
							"kernel-compat: prlimit64 -> {} (resource {})",
							if setting { "setrlimit" } else { "getrlimit" },
							regs.rsi
						);
					}
				}
			} else if regs.orig_rax == libc::SYS_ioctl as u64 && termios2_missing() {
				self.setup_termios2(pid, regs);
			} else if regs.orig_rax == libc::SYS_clock_gettime as u64
				|| regs.orig_rax == libc::SYS_clock_getres as u64
				|| regs.orig_rax == libc::SYS_clock_nanosleep as u64 {
				// All three take the clock id as their first argument.
				let replacements = clockid_replacements();
				let use_instead = replacements
					.get(regs.rdi as usize)
					.copied()
					.unwrap_or(regs.rdi);
				if use_instead != regs.rdi {
					let mut patched = regs;
					patched.rdi = use_instead;
					let _ = ptrace::setregs(pid, patched);
					if debug_all() {
						eprintln!("kernel-compat: clock id {} -> {}", regs.rdi, use_instead);
					}
				}
			} else if regs.orig_rax == libc::SYS_ppoll as u64 && ppoll_missing() {
				// ppoll -> poll, dropping the signal mask. Kernels that lack
				// ppoll make GLib's main loop spin on the ENOSYS.
				let ts = regs.rdx;
				let ms: i32 = if ts == 0 {
					-1
				} else {
					match read_struct(pid, ts, 16) {
						Some(b) => {
							let sec = i64::from_le_bytes(b[0..8].try_into().unwrap_or_default());
							let nsec = i64::from_le_bytes(b[8..16].try_into().unwrap_or_default());
							sec.saturating_mul(1000)
								.saturating_add(nsec / 1_000_000)
								.clamp(-1, i32::MAX as i64) as i32
						},
						None => -1,
					}
				};
				let mut patched = regs;
				patched.rdx = ms as i64 as u64;
				patched.orig_rax = libc::SYS_poll as u64;
				patched.rax = libc::SYS_poll as u64;
				let _ = ptrace::setregs(pid, patched);
				if debug() {
					eprintln!("kernel-compat: ppoll -> poll (timeout {ms}ms)");
				}
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
			Err(_) => {
				// Nothing can be completed for a tracee we cannot read; drop the
				// pending state rather than let a later stop collect it.
				self.termios2_get.remove(&pid);
				self.statx.remove(&pid);
				self.last_syscall.remove(&pid);
				self.reserved.remove(&pid);
				return
			},
		};
		// Same rule as on the way in: nothing here applies to a 32-bit tracee,
		// whose numbers match these constants only by accident.
		if regs.cs != 0x33 {
			return
		}
		if debug_all() {
			eprintln!(
				"kernel-compat: [t{pid}] syscall {} -> {}",
				self.last_syscall.get(&pid).copied().unwrap_or(0),
				regs.rax as i64
			);
		}
		if debug_all() && self.last_syscall.get(&pid).copied() == Some(libc::SYS_futex as u64) {
			eprintln!("kernel-compat: [t{pid}] futex ret {}", regs.rax as i64);
		}
		let mut dirty = false;
		if self.finish_termios2(pid, &mut regs) {
			dirty = true;
		}
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
		// getrandom (3.17): always fill the buffer ourselves. Rust std (and thus
		// any HashMap/HashSet) does not cope with what old kernels return here
		// and panics with "range start index 318 out of range for slice of
		// length 16", so we synthesize it regardless of the syscall's result.
		let getrandom_nr = libc::SYS_getrandom as u64;
		let mut synthesized = false;
		if self.last_syscall.get(&pid).copied() == Some(getrandom_nr) && getrandom_missing() {
			if emulate_getrandom(pid, regs.rdi, regs.rsi as usize) {
				if debug() {
					eprintln!(
						"kernel-compat: getrandom emulated ({} bytes at {:#x})",
						regs.rsi,
						regs.rdi
					);
				}
				regs.rax = regs.rsi;
				synthesized = true;
				dirty = true;
			} else if regs.rax == getrandom_nr {
				// Emulation failed and the kernel answered with its own number:
				// report ENOSYS so callers fall back to /dev/urandom instead of
				// treating the syscall number as a success.
				regs.rax = (-(libc::ENOSYS as i64)) as u64;
				dirty = true;
			}
		}
		// Syscalls newer than these kernels must fail with ENOSYS so callers take
		// their fallback path. A pre-2.6.19 x86_64 kernel does not answer an
		// unknown number with -ENOSYS but with the number itself (clone3 -> 435),
		// which makes glibc think it succeeded; normalize that back to ENOSYS.
		//
		// This must test the *number*, not a list of numbers: the kernels that
		// echo at all echo for every entry they do not have (which is what burnt
		// us on `copy_file_range`, 326), and 2.6.17 tops out at 278 while 2.6.18
		// tops out at 279, so anything above that is a syscall they simply do not
		// have to begin with. Testing a list instead would turn a legitimate
		// result that happens to equal the call's number -- `epoll_create1` 291
		// returning fd 291, `openat2` 437 returning fd 437 -- into ENOSYS on
		// every kernel that implements those calls.
		if let Some(nr) = self.last_syscall.get(&pid).copied() {
			const ABOVE_TABLE: u64 = 279;
			// Only an *untranslated* call can be echoing: a number the kernel
			// really does not have is passed through untouched, whereas a
			// rewritten one executes a different syscall whose result is its own
			// (`epoll_create` handing back fd 291 for the rewritten
			// `epoll_create1`, or an emulated getrandom filling a 318-byte
			// buffer). 64-bit tracees only: the i386 entry path returns a real
			// -ENOSYS, and numbers this high are ordinary syscalls there.
			let echoed = regs.cs == 0x33
				&& nr > ABOVE_TABLE
				&& kernel_echoes_number()
				&& regs.orig_rax == nr;
			// `synthesized` is the count this layer just wrote into rax: a request
			// for exactly 318 bytes would otherwise match its own syscall number
			// and be turned back into ENOSYS.
			if !synthesized && echoed && regs.rax == nr {
				if debug() {
					eprintln!(
						"kernel-compat: syscall {nr} returned its own number; forcing ENOSYS"
					);
				}
				regs.rax = (-(libc::ENOSYS as i64)) as u64;
				dirty = true;
			}
		}
		if dirty {
			let _ = ptrace::setregs(pid, regs);
		}
		if debug() && regs.rax == (-(libc::ENOSYS as i64)) as u64 {
			let nr = self.last_syscall.get(&pid).copied().unwrap_or(0);
			eprintln!("kernel-compat: pid {pid} syscall {nr} -> ENOSYS");
		}
		// The entry was consumed. Without this, a later exit stop that reuses
		// the slot (e.g. a statx exit after a getrandom exit) could re-enter
		// the getrandom branch with the wrong registers.
		self.last_syscall.remove(&pid);
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
			// Only AT_SYMLINK_NOFOLLOW: older kernels reject AT_NO_AUTOMOUNT
			// (0x800) with EINVAL (reproduced on 2.6.17; 2.6.20 accepts it).
			regs.r10 = regs.rdx & 0x100;
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

	/// The termios2 requests (2.6.20) -> the requests of the era. Everything the
	/// kernel writes or reads back sits in the first 36 bytes, which
	/// `struct termios2` shares with the `struct termios` of those kernels, so
	/// the request number carries the whole translation for the TCSETS2 family.
	/// What it cannot carry are the two speed fields the caller put after those
	/// 36 bytes: an older kernel has no way to express a rate that is not a
	/// `Bxxxx` code, so `c_cflag` decides the line speed there. Calls that are
	/// not 64-bit are left alone: the request would be in a different register,
	/// and a misread one could only do damage.
	fn setup_termios2(&mut self, pid: Pid, mut regs: libc::user_regs_struct) {
		if regs.cs != 0x33 {
			return
		}
		let request = regs.rsi;
		let Some(legacy) = legacy_termios_request(request) else { return };
		let arg = regs.rdx;
		regs.rsi = legacy;
		if ptrace::setregs(pid, regs).is_err() {
			return
		}
		if legacy == TCGETS {
			self.termios2_get.insert(pid, arg);
		}
		if debug() {
			eprintln!(
				"kernel-compat: ioctl({request:#x}) -> {legacy:#x} (fd {})",
				regs.rdi as i64
			);
		}
	}

	/// Fill in the speed fields of a translated TCGETS2 result: `struct termios2`
	/// puts `c_ispeed`/`c_ospeed` after the `struct termios` the old kernel
	/// filled in, and such a kernel only knows the line speed as a `Bxxxx` code
	/// in c_cflag. Returns true if `rax` had to be replaced, which happens when
	/// the caller's buffer cannot be written.
	///
	/// This assumes the call is not restarted after a signal: a restart would
	/// re-execute the rewritten `TCGETS`, arrive here with no pending entry (the
	/// request no longer looks like a termios2 one) and leave the speed fields
	/// as the caller had them. The 2.6.17 `TCGETS` path only copies to user
	/// space, so it cannot come back `-ERESTARTSYS`.
	fn finish_termios2(&mut self, pid: Pid, regs: &mut libc::user_regs_struct) -> bool {
		let Some(termios2) = self.termios2_get.remove(&pid) else { return false };
		if regs.rax != 0 {
			// The kernel refused; there is no result to complete.
			return false
		}
		let speed = read_struct(pid, termios2, TERMIOS2_ISPEED as usize)
			.map(|termios| {
				let cflag = u32::from_le_bytes(termios[8..12].try_into().unwrap_or_default());
				baud_from_cflag(cflag)
			})
			.unwrap_or(0);
		let mut speeds = [0u8; 8];
		speeds[0..4].copy_from_slice(&speed.to_le_bytes());
		speeds[4..8].copy_from_slice(&speed.to_le_bytes());
		if write_struct(pid, termios2 + TERMIOS2_ISPEED, &speeds) {
			if debug() {
				eprintln!("kernel-compat: termios2 speeds filled in as {speed}");
			}
			return false
		}
		regs.rax = (-(libc::EFAULT as i64)) as u64;
		true
	}
}

/// Rewrite a futex op to a form the kernel understands. Returns true if it
/// carved scratch below `rsp` (a timed `WAIT_BITSET`/CLOCK_REALTIME wait), in
/// which case the caller must let the syscall reach its exit stop so `rsp` can
/// be restored.
fn translate_futex(pid: Pid, mut regs: libc::user_regs_struct, reserved: &mut HashMap<Pid, u64>) -> bool {
	// The bitset ops only exist from 2.6.25, and FUTEX_CLOCK_REALTIME from
	// 2.6.29: on 2.6.25-2.6.28 the bitset ops are there but a realtime wait is
	// rejected with EINVAL, which glibc answers with futex_fatal_error()
	// instead of falling back. On anything newer (e.g. 3.x, where the layer
	// still auto-enables for statx/getrandom) leave futex alone: stripping
	// FUTEX_PRIVATE_FLAG changes glibc's locking behaviour and can stall the
	// application.
	if !kernel_lt(2, 6, 29) {
		return false;
	}
	// x86_64: futex(uaddr, op, val, timeout, uaddr2, val3) ->
	// rdi, rsi, rdx, r10, r8, r9
	let op = regs.rsi as u32;
	let cmd = op & FUTEX_CMD_MASK;
	let realtime = op & FUTEX_CLOCK_REALTIME != 0;
	if debug_all() {
		eprintln!(
			"kernel-compat: [t{pid}] futex entry op={op:#x} cmd={cmd} uaddr={:#x} val={} timeout={:#x}",
			regs.rdi, regs.rdx as i64, regs.r10
		);
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

pub(crate) fn peek_word(pid: Pid, addr: u64) -> Option<u64> {
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

pub(crate) fn read_struct(pid: Pid, addr: u64, len: usize) -> Option<Vec<u8>> {
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

pub(crate) fn write_struct(pid: Pid, addr: u64, bytes: &[u8]) -> bool {
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

/// Emulate getrandom(2) on kernels that lack it by filling the tracee's buffer
/// from /dev/urandom.
fn emulate_getrandom(pid: Pid, buf: u64, count: usize) -> bool {
	if count == 0 {
		return true
	}
	if buf == 0 {
		return false
	}
	use std::io::Read;
	let mut file = match std::fs::File::open("/dev/urandom") {
		Ok(file) => file,
		Err(_) => return false,
	};
	// Fill the entire requested range in bounded chunks: read_exact can return
	// short reads and callers may ask for more than one chunk. Only report
	// success once every byte has been written to the tracee.
	const CHUNK: usize = 64 * 1024;
	let mut chunk = vec![0u8; count.min(CHUNK)];
	let mut off = 0usize;
	while off < count {
		let want = (count - off).min(CHUNK);
		let dst = &mut chunk[..want];
		if file.read_exact(dst).is_err() {
			return false
		}
		if !write_struct(pid, buf + off as u64, dst) {
			return false
		}
		off += want;
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
		termios2_get: HashMap::new(),
		emulated: crate::emulated_syscalls::Emulations::new(),
		reserved: HashMap::new(),
		stashed_signal: HashMap::new(),
		expect_entry: HashSet::new(),
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

/// Executable mappings of a tracee, for spotting return addresses on its stack.
#[cfg(target_arch = "x86_64")]
fn executable_ranges(pid: Pid) -> Vec<(u64, u64)> {
	let mut out = Vec::new();
	let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else { return out };
	for line in maps.lines() {
		let mut cols = line.split_whitespace();
		let (Some(range), Some(perms)) = (cols.next(), cols.next()) else { continue };
		if !perms.starts_with('r') || !perms.contains('x') {
			continue;
		}
		let Some((start, end)) = range.split_once('-') else { continue };
		let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16)) else {
			continue
		};
		out.push((start, end));
	}
	out
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
