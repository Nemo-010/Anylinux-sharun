//! Syscalls a modern binary calls unconditionally that an old kernel does not
//! have *at all*, and that cannot be answered by retargeting the call: the
//! object it creates has to exist inside the tracee, with the semantics the
//! caller expects. The tracer makes the calls itself, in the tracee, and hands
//! back the result.
//!
//! Two of those so far:
//!
//! * `eventfd`/`eventfd2` (2.6.22/2.6.27). Bun's loop treats a failure as fatal
//!   ("eventfd() failed during loop init"), so `ENOSYS` is not enough. An
//!   `AF_UNIX` datagram socket *connected to its own abstract address* is a
//!   single fd with much of the same shape: a write makes it readable,
//!   `poll`/`epoll` report `EPOLLIN`, reading an empty non-blocking fd gives
//!   `EAGAIN`, and closing either end wakes the other.
//!
//!   It is not a counter, though, and that is the one place the substitution is
//!   visible: two `write(fd, &1, 8)` followed by a `read` return `1` and leave
//!   the second datagram queued, where a real eventfd returns `2` and drains.
//!   `POLLOUT` is always ready rather than ready below `UINT64_MAX - 1`, and a
//!   blocking write blocks when the socket buffer fills (about 200 KB) instead
//!   of at the counter's limit. An application that only uses an eventfd as a
//!   wakeup -- write one end, wait for the other, drain it -- cannot tell the
//!   difference, which is what this is for.
//! * `timerfd_create`/`settime`/`gettime` (2.6.25). uSockets' epoll backend
//!   returns NULL when the create fails, which Bun turns into a panic. Here the
//!   read that has to become readable on a deadline belongs to the application
//!   but the write that makes it readable belongs to us, so the fd is a pipe:
//!   the application keeps the read end, the tracer holds the write end
//!   (reopened through `/proc/<pid>/fd`, which works for pipes and not for
//!   sockets -- hence the two different shapes). The tracer arms an
//!   `ITIMER_REAL` for the nearest deadline, these kernels having no `timerfd`
//!   for the tracer either, and writes the expiration count when it lands.
//!   Unlike the eventfd shape, this one needs `/proc` mounted for the tracee:
//!   without it the write end cannot be reopened and the emulation fails, so a
//!   container that hides `/proc` keeps any application that creates a timerfd
//!   from starting.
//!
//! Everything runs through the tracee's own syscalls. At the entry stop of the
//! emulated call we rewrite it into the first call of the sequence; the calls
//! after that are entered by resuming at the `syscall` instruction the tracee
//! just executed, so it never runs application code in between and the stack is
//! left alone. `timerfd_settime`/`gettime` need no sequence at all: the tracer
//! does the bookkeeping and the syscall is replaced with a harmless one whose
//! result is then overwritten.
//!
//! Only the ptrace mode can carry a sequence (seccomp mode resumes with
//! `PTRACE_CONT` and never sees the stops), which is fine: the filter needs
//! seccomp-bpf (3.5), and every kernel with that also has eventfd and timerfd.

use std::{
	collections::{HashMap, VecDeque},
	os::fd::{AsRawFd, OwnedFd},
	os::unix::fs::OpenOptionsExt,
	sync::{
		atomic::{AtomicBool, Ordering},
		Once,
	},
};

use nix::{errno::Errno, libc, sys::ptrace, unistd::Pid};

use crate::kernel_compat::{
	clockid_replacements, debug, debug_all, kernel_lt, not_implemented, peek_word, read_struct,
	write_struct,
};

/// `EFD_CLOEXEC`/`TFD_CLOEXEC` and `EFD_SEMAPHORE` are deliberately not
/// honoured: nothing on this path execs, and semaphore mode only changes what a
/// reader of a *counted* eventfd sees, which is already the one difference the
/// eventfd shape accepts. Honouring them would cost an extra `fcntl` per fd.
const EFD_NONBLOCK: u64 = 0x800;
const TFD_NONBLOCK: u64 = 0x800;
const TFD_TIMER_ABSTIME: u64 = 0x1;

/// Byte patterns that enter the kernel, so an injected call can be made from a
/// known-good instruction instead of a stack stub.
const SYSCALL64: u64 = 0x050f;
const SYSCALL32: u64 = 0x80cd;

/// A point in time, or a duration, in (seconds, nanoseconds).
type Time = (i64, i64);

/// Set by the `SIGALRM` handler and consumed by `tick`.
static ALARM: AtomicBool = AtomicBool::new(false);

extern "C" fn on_alarm(_: libc::c_int) {
	ALARM.store(true, Ordering::Relaxed);
}

/// The tracer is about to write into pipes whose reader may be gone, and needs
/// `waitpid` to come back with `EINTR` so that it can serve deadlines.
fn install_handlers() {
	static ONCE: Once = Once::new();
	ONCE.call_once(|| unsafe {
		let mut action: libc::sigaction = std::mem::zeroed();
		let handler: extern "C" fn(libc::c_int) = on_alarm;
		action.sa_sigaction = handler as usize;
		// No SA_RESTART on purpose: waitpid has to return so timers get served.
		action.sa_flags = 0;
		libc::sigemptyset(&mut action.sa_mask);
		libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut());
		libc::signal(libc::SIGPIPE, libc::SIG_IGN);
	});
}

/// Which fd of the emulation a call refers to, for the steps that need one that
/// an earlier call produced.
#[derive(Clone, Copy)]
enum Which {
	/// The emulated fd itself: eventfd's socket, timerfd's read end.
	Result,
	ReadEnd,
	WriteEnd,
}

/// One call of a sequence. Steps that need an fd from an earlier call name it
/// rather than carrying a value.
enum Step {
	Socket,
	Pipe { buffer: u64 },
	Attach { fd: Which, addr: u64, length: u64, connect: bool },
	Nonblock { fd: Which },
	WriteInitial { fd: Which, buffer: u64 },
	Close { fd: Which },
	/// fcntl(fd, F_DUPFD, minimum): the tracee's own fd, so the value is a
	/// literal, plus the lowest fd the caller will accept.
	FcntlDupfd { fd: u64, minimum: u64 },
	/// fcntl(fd, F_SETFD, FD_CLOEXEC) on the fd an earlier call returned.
	FcntlCloexec { fd: Which },
	/// lseek(fd, offset, SEEK_SET): the offset half of a pwritev/preadv.
	Lseek { fd: u64, offset: i64 },
	/// writev/readv(fd, iov, iovcnt): the data half.
	VectorIo { write: bool, fd: u64, iov: u64, count: u64 },
	/// rt_sigprocmask(SIG_SETMASK, mask, saved, 8): the mask half of an
	/// epoll_pwait, run once before the wait and once after it. The trailing
	/// one is marked `always` so that a failed wait (an interrupted epoll_wait
	/// returns EINTR, which the application expects) cannot leave the caller
	/// with the mask the wait installed.
	Sigprocmask { mask: u64, saved: u64, always: bool },
	/// epoll_wait(epfd, events, maxevents, timeout).
	EpollWait { epfd: u64, events: u64, maxevents: u64, timeout: u64 },
}

/// Which of the completed calls answers the emulated syscall.
enum Outcome {
	/// The value that call returned -- the created fd, for eventfd.
	Call(usize),
	/// The fd the emulation adopted -- the pipe's read end, for timerfd.
	Adopted,
}

enum Active {
	Sequence {
		/// Registers as they were at the entry stop of the emulated call, so the
		/// tracee resumes where it left off with only the result replaced.
		saved: libc::user_regs_struct,
		/// A `syscall` instruction to re-enter the kernel with: the one the
		/// tracee just executed, so it is mapped and executable by definition.
		gadget: u64,
		/// Calls still to make.
		queue: VecDeque<Step>,
		/// The call in flight, whose result the next exit stop collects.
		running: Option<Step>,
		/// True while the stop in hand is that call's entry.
		at_entry: bool,
		results: Vec<i64>,
		outcome: Outcome,
		fd: i64,
		read_end: i64,
		write_end: i64,
		/// Clock the timerfd being created counts in.
		clockid: i32,
	},
	/// The syscall was replaced with one that always succeeds; leave this in rax
	/// when it returns. For the calls that need bookkeeping only.
	Fixup(i64),
}

/// An emulated timerfd.
struct Timer {
	clockid: i32,
	/// Absolute deadline in that clock's timebase, `None` when disarmed.
	deadline: Option<Time>,
	/// `(0, 0)` makes it one-shot.
	interval: Time,
}

pub struct Emulations {
	active: HashMap<Pid, Active>,
	/// Keeps the abstract addresses of successive eventfds apart.
	sequence: u64,
	/// Emulated timerfds, by the fd the application sees.
	timers: HashMap<i64, Timer>,
	/// The write end of each emulated timerfd's pipe, held here so the tracer can
	/// make the read end readable when a deadline passes.
	write_ends: HashMap<i64, OwnedFd>,
}

impl Emulations {
	pub fn new() -> Self {
		Self {
			active: HashMap::new(),
			sequence: 0,
			timers: HashMap::new(),
			write_ends: HashMap::new(),
		}
	}

	/// True while an emulation is in progress, in which case every stop belongs
	/// to `step` until it hands the result back.
	pub fn busy(&self, pid: Pid) -> bool {
		self.active.contains_key(&pid)
	}

	/// Forget the tracee's in-flight emulation. The emulated fds themselves stay:
	/// another process may have inherited them, and a stale one is dropped as
	/// soon as a write finds nobody reading.
	pub fn forget(&mut self, pid: Pid) {
		self.active.remove(&pid);
	}

	/// Take over the entry stop if this is a syscall we emulate and the kernel
	/// lacks it. `entering` is the caller's record of which way round this stop
	/// is; `true` means the caller must skip its own entry handling.
	pub fn begin(&mut self, pid: Pid, entering: bool) -> bool {
		// Only an entry stop has a call to take over: the exit stop of a call
		// that already ran must not be rewritten, or the application would lose
		// the result and the call would be executed a second time.
		if !entering {
			return false
		}
		let Ok(regs) = ptrace::getregs(pid) else { return false };
		// x86_64 only. An i386 tracee uses the same numbers for unrelated
		// syscalls (`waitid` 284 is `eventfd`, `kexec_load` 283 is
		// `timerfd_create`, ...) and keeps its arguments in different registers,
		// so matching here would hand it an emulated object it never asked for.
		if regs.cs != 0x33 {
			return false
		}
		match regs.orig_rax {
			nr if nr == libc::SYS_close as u64 => {
				// Stop tracking an emulated fd the application is done with.
				let fd = regs.rdi as i64;
				self.timers.remove(&fd);
				self.write_ends.remove(&fd);
				false
			},
			nr if nr == libc::SYS_eventfd as u64 => self.eventfd(pid, regs),
			nr if nr == libc::SYS_eventfd2 as u64 => self.eventfd(pid, regs),
			nr if nr == libc::SYS_timerfd_create as u64 => self.timerfd_create(pid, regs),
			nr if nr == libc::SYS_timerfd_settime as u64 => self.timerfd_settime(pid, regs),
			nr if nr == libc::SYS_timerfd_gettime as u64 => self.timerfd_gettime(pid, regs),
			nr if nr == libc::SYS_fcntl as u64 => self.dupfd_cloexec(pid, regs),
			nr if nr == libc::SYS_pwritev as u64 => self.vector_io(pid, regs, true),
			nr if nr == libc::SYS_preadv as u64 => self.vector_io(pid, regs, false),
			nr if nr == libc::SYS_epoll_pwait as u64 => self.epoll_pwait(pid, regs),
			_ => false,
		}
	}

	/// epoll_pwait (2.6.19) -> rt_sigprocmask + epoll_wait + rt_sigprocmask.
	/// Deliberately not epoll_wait alone: the caller's mask is real (Bun's loop
	/// passes one on every call), and dropping it lets signals in during the
	/// wait, so the wakeups the mask was there to gate go missing. The result is
	/// the epoll_wait's. A null mask is fine: rt_sigprocmask then only reads the
	/// current one into scratch, and the restore is a no-op.
	fn epoll_pwait(&mut self, pid: Pid, regs: libc::user_regs_struct) -> bool {
		if !kernel_lt(2, 6, 19) {
			return false;
		}
		let Some(gadget) = gadget_for(pid, regs) else { return false };
		let scratch = regs.rsp.wrapping_sub(512) & !0xf;
		let queue = VecDeque::from([
			Step::Sigprocmask { mask: regs.r8, saved: scratch, always: false },
			Step::EpollWait {
				epfd: regs.rdi,
				events: regs.rsi,
				maxevents: regs.rdx,
				timeout: regs.r10,
			},
			Step::Sigprocmask { mask: scratch, saved: 0, always: true },
		]);
		if debug_all() {
			eprintln!("kernel-compat: epoll_pwait emulated as sigprocmask + epoll_wait + sigprocmask");
		}
		self.start_sequence(pid, regs, gadget, queue, Outcome::Call(1), 0)
	}

	/// pwritev(fd, iov, iovcnt, offset) (2.6.30) -> lseek + writev; preadv is the
	/// same split with readv. The data goes to the same place, but the pair is
	/// not what the caller asked for in three ways: the file offset moves, the
	/// lseek and the transfer are not atomic against another writer, and on an
	/// `O_APPEND` file the write lands at the end rather than at the offset. A
	/// caller that does its own position tracking -- which is what this exists
	/// for, Bun writing its buffered output through the offset form -- notices
	/// none of that: without it the bytes stay in the buffer forever, so the
	/// application runs, prints nothing and no terminal UI ever appears.
	fn vector_io(&mut self, pid: Pid, regs: libc::user_regs_struct, write: bool) -> bool {
		if !kernel_lt(2, 6, 30) {
			return false;
		}
		let Some(gadget) = gadget_for(pid, regs) else { return false };
		let queue = VecDeque::from([
			Step::Lseek { fd: regs.rdi, offset: regs.r10 as i64 },
			Step::VectorIo { write, fd: regs.rdi, iov: regs.rsi, count: regs.rdx },
		]);
		if debug() {
			eprintln!(
				"kernel-compat: {} emulated as lseek + {} (fd {}, offset {})",
				if write { "pwritev" } else { "preadv" },
				if write { "writev" } else { "readv" },
				regs.rdi as i64,
				regs.r10 as i64
			);
		}
		// The result is the transfer count, not the lseek offset.
		self.start_sequence(pid, regs, gadget, queue, Outcome::Call(1), 0)
	}

	/// fcntl(fd, F_DUPFD_CLOEXEC) (2.6.24) -> F_DUPFD, then FD_CLOEXEC on the
	/// result. Bun builds its lazy `process.stdout`/`process.stderr` getters by
	/// running the fd through a WriteStream, which dups it this way; when the
	/// dup fails the getter throws and the properties stay undefined, so the
	/// application dies on its first `process.stderr.isTTY` -- before it has
	/// printed anything at all.
	fn dupfd_cloexec(&mut self, pid: Pid, regs: libc::user_regs_struct) -> bool {
		// Deliberately a version check rather than a probe. The rewrite is
		// equivalent to the original call -- two syscalls where there was one --
		// so guessing wrong on a hypothetical backport costs nothing, while a
		// probe that answers "supported" silently disables the emulation and
		// leaves the application undefined. This is what broke Bun on 2.6.17:
		// `process.stdout`/`stderr` stay undefined and the app dies on its first
		// `process.stderr.isTTY`. F_DUPFD_CLOEXEC arrived in 2.6.24.
		if regs.rsi != libc::F_DUPFD_CLOEXEC as u64 || !kernel_lt(2, 6, 24) {
			return false;
		}
		let Some(gadget) = gadget_for(pid, regs) else { return false };
		let queue = VecDeque::from([
			Step::FcntlDupfd { fd: regs.rdi, minimum: regs.rdx },
			Step::FcntlCloexec { fd: Which::Result },
		]);
		if debug() {
			eprintln!(
				"kernel-compat: fcntl(F_DUPFD_CLOEXEC) emulated as F_DUPFD + FD_CLOEXEC (fd {})",
				regs.rdi
			);
		}
		self.start_sequence(pid, regs, gadget, queue, Outcome::Call(0), 0)
	}

	/// eventfd/eventfd2(initial, flags) becomes a socket connected to itself.
	fn eventfd(&mut self, pid: Pid, regs: libc::user_regs_struct) -> bool {
		if !eventfd_missing() {
			return false;
		}
		let initial = regs.rdi;
		let flags = regs.rsi;
		if initial > u32::MAX as u64 {
			return false;
		}
		let Some(gadget) = gadget_for(pid, regs) else { return false };
		// Scratch below the caller's stack pointer, the way the statx and futex
		// translations do it: an abstract `sockaddr_un` and the initial value.
		let scratch = regs.rsp.wrapping_sub(512) & !0xf;
		let name = format!("sharun-efd-{}-{}", pid.as_raw(), self.sequence);
		self.sequence += 1;
		let mut address = vec![0u8; 3 + name.len()];
		address[0..2].copy_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
		address[2] = 0; // abstract: a leading NUL, then the name
		address[3..].copy_from_slice(name.as_bytes());
		let length = address.len() as u64;
		if !write_struct(pid, scratch, &address) {
			return false;
		}
		let mut queue = VecDeque::from([
			Step::Socket,
			Step::Attach { fd: Which::Result, addr: scratch, length, connect: false },
			Step::Attach { fd: Which::Result, addr: scratch, length, connect: true },
		]);
		if flags & EFD_NONBLOCK != 0 {
			queue.push_back(Step::Nonblock { fd: Which::Result });
		}
		if initial != 0 {
			let buffer = scratch + 256;
			if !write_struct(pid, buffer, &initial.to_ne_bytes()) {
				return false;
			}
			queue.push_back(Step::WriteInitial { fd: Which::Result, buffer });
		}
		if debug() {
			eprintln!(
				"kernel-compat: eventfd({initial}) emulated with a self-connected socket (flags {flags:#x})"
			);
		}
		self.start_sequence(pid, regs, gadget, queue, Outcome::Call(0), 0)
	}

	/// timerfd_create(clock, flags) becomes a pipe whose write end we keep.
	fn timerfd_create(&mut self, pid: Pid, regs: libc::user_regs_struct) -> bool {
		if !timerfd_missing() {
			return false;
		}
		let flags = regs.rsi;
		// A clock this kernel does not have is replaced by one it does; the timer
		// then counts in the substitute, which is the same clock at another
		// resolution.
		let clockid = clockid_replacements()
			.get(regs.rdi as usize)
			.copied()
			.unwrap_or(regs.rdi) as i32;
		let Some(gadget) = gadget_for(pid, regs) else { return false };
		let scratch = regs.rsp.wrapping_sub(512) & !0xf;
		let mut queue = VecDeque::from([
			Step::Pipe { buffer: scratch },
			Step::Close { fd: Which::WriteEnd },
		]);
		if flags & TFD_NONBLOCK != 0 {
			queue.push_back(Step::Nonblock { fd: Which::ReadEnd });
		}
		if debug() {
			eprintln!("kernel-compat: timerfd_create({clockid}, {flags:#x}) emulated with a pipe");
		}
		self.start_sequence(pid, regs, gadget, queue, Outcome::Adopted, clockid)
	}

	/// timerfd_settime(fd, flags, new, old) is bookkeeping only: the tracer keeps
	/// the deadline and makes the pipe readable when it lands.
	fn timerfd_settime(&mut self, pid: Pid, regs: libc::user_regs_struct) -> bool {
		let fd = regs.rdi as i64;
		let Some(timer) = self.timers.get(&fd) else { return false };
		let clockid = timer.clockid;
		let previous = (timer.interval, timer.deadline);
		let Some(requested) = read_struct(pid, regs.rdx, 32) else { return false };
		let interval = (rd64(&requested, 0), rd64(&requested, 8));
		let value = (rd64(&requested, 16), rd64(&requested, 24));
		if debug_all() {
			eprintln!(
				"kernel-compat: timerfd_settime(fd {fd}, flags {:#x}, value {}.{}, interval {}.{})",
				regs.rsi, value.0, value.1, interval.0, interval.1
			);
		}
		// The caller may ask what it is replacing.
		if regs.r10 != 0 {
			let now = clock_now(clockid).unwrap_or((0, 0));
			let remaining = previous.1.map_or((0, 0), |deadline| sub(deadline, now));
			let mut old = Vec::with_capacity(32);
			push_time(&mut old, previous.0);
			push_time(&mut old, remaining);
			if !write_struct(pid, regs.r10, &old) {
				return false;
			}
		}
		let deadline = if value == (0, 0) {
			None
		} else if regs.rsi & TFD_TIMER_ABSTIME != 0 {
			Some(value)
		} else {
			match clock_now(clockid) {
				Some(now) => Some(add(now, value)),
				None => return false,
			}
		};
		if let Some(timer) = self.timers.get_mut(&fd) {
			timer.interval = interval;
			timer.deadline = deadline;
		}
		self.arm();
		self.stand_in(pid, regs, 0)
	}

	/// timerfd_gettime(fd, current) reports what is left of the deadline.
	fn timerfd_gettime(&mut self, pid: Pid, regs: libc::user_regs_struct) -> bool {
		let fd = regs.rdi as i64;
		let Some(timer) = self.timers.get(&fd) else { return false };
		let now = clock_now(timer.clockid).unwrap_or((0, 0));
		let remaining = timer.deadline.map_or((0, 0), |deadline| sub(deadline, now));
		if debug() {
			eprintln!("kernel-compat: timerfd_gettime(fd {fd}) -> {}.{} left, interval {}.{}", remaining.0, remaining.1, timer.interval.0, timer.interval.1);
		}
		let mut current = Vec::with_capacity(32);
		push_time(&mut current, timer.interval);
		push_time(&mut current, remaining);
		if !write_struct(pid, regs.rsi, &current) {
			return false;
		}
		self.stand_in(pid, regs, 0)
	}

	/// Replace the syscall with one that always succeeds, and overwrite its
	/// result when it returns.
	fn stand_in(&mut self, pid: Pid, regs: libc::user_regs_struct, result: i64) -> bool {
		let mut patched = regs;
		patched.orig_rax = libc::SYS_getpid as u64;
		patched.rax = libc::SYS_getpid as u64;
		if ptrace::setregs(pid, patched).is_err() {
			return false;
		}
		self.active.insert(pid, Active::Fixup(result));
		true
	}

	/// Rewrite the emulated call into the first one of the sequence. The entry
	/// stop is consumed here, so the next stop is that call's exit.
	fn start_sequence(
		&mut self,
		pid: Pid,
		regs: libc::user_regs_struct,
		gadget: u64,
		mut queue: VecDeque<Step>,
		outcome: Outcome,
		clockid: i32,
	) -> bool {
		let Some(first) = queue.pop_front() else { return false };
		let mut active = Active::Sequence {
			saved: regs,
			gadget,
			queue,
			running: None,
			at_entry: false,
			results: Vec::new(),
			outcome,
			fd: -1,
			read_end: -1,
			write_end: -1,
			clockid,
		};
		let (call_nr, args) = build(&first, &active);
		if let Active::Sequence { running, .. } = &mut active {
			*running = Some(first);
		}
		let mut patched = regs;
		patched.orig_rax = call_nr;
		patched.rax = call_nr;
		patched.rdi = args[0];
		patched.rsi = args[1];
		patched.rdx = args[2];
		patched.r10 = args[3];
		patched.r8 = args[4];
		patched.r9 = args[5];
		if ptrace::setregs(pid, patched).is_err() {
			return false;
		}
		self.active.insert(pid, active);
		true
	}

	/// Advance an emulation by one stop. The caller resumes the tracee with
	/// `PTRACE_SYSCALL` afterwards, which is what makes the injected calls stop
	/// here in the first place.
	pub fn step(&mut self, pid: Pid) {
		let Some(mut active) = self.active.remove(&pid) else { return };

		if let Active::Fixup(result) = active {
			if let Ok(mut regs) = ptrace::getregs(pid) {
				regs.rax = result as u64;
				let _ = ptrace::setregs(pid, regs);
			}
			return;
		}

		// Entry stop of the call we set up: nothing to collect yet.
		if matches!(&active, Active::Sequence { at_entry: true, .. }) {
			if let Active::Sequence { at_entry, .. } = &mut active {
				*at_entry = false;
			}
			self.active.insert(pid, active);
			return;
		}

		let Ok(regs) = ptrace::getregs(pid) else { return };

		// What the call that just finished returned. The first one is the fd the
		// whole emulation is built on -- but only when the call is one that
		// returns an fd: the pipe half of the timerfd emulation returns a status
		// (0 on success), and its read end is picked up in the `Pipe` arm below.
		let completed = match &mut active {
			Active::Sequence { running, results, fd, .. } => {
				results.push(regs.rax as i64);
				let step = running.take();
				if results.len() == 1
					&& matches!(step, Some(Step::Socket) | Some(Step::FcntlDupfd { .. }))
				{
					*fd = regs.rax as i64;
				}
				step
			},
			_ => None,
		};

		// The pipe needs the tracer to take a handle on it before the tracee
		// closes its end; every other call is finished with on its own.
		if let Some(Step::Pipe { buffer }) = completed {
			let clockid = match &active {
				Active::Sequence { clockid, .. } => *clockid,
				_ => 0,
			};
			match capture_pipe(&mut self.timers, &mut self.write_ends, pid, buffer, clockid) {
				Some((read_end, write_end)) => {
					if let Active::Sequence {
						read_end: read, write_end: write, fd, ..
					} = &mut active
					{
						*read = read_end;
						*write = write_end;
						*fd = read_end;
					}
				},
				// A half-built object is worse than an error, so record one: the
				// fd slot was never seeded from the pipe's status, and without
				// this the sequence would complete with `Outcome::Adopted` and
				// hand the application whatever that slot holds.
				None => {
					if let Active::Sequence { results, .. } = &mut active {
						results.push(-(libc::EIO as i64));
					}
				},
			}
		}

		let failure = match &active {
			Active::Sequence { results, .. } => {
				results.iter().copied().find(|rc| (-4095..0).contains(rc))
			},
			_ => None,
		};

		let next = match &mut active {
			Active::Sequence { queue, results, .. } => {
				if failure.is_none() {
					queue.pop_front()
				} else {
					// Once a call has failed the rest of the sequence is
					// pointless -- it would work on objects that were never
					// created -- but a step marked `always` still has to run, or
					// the caller is left with state the emulation installed and
					// never took back. Only when everything before the failure
					// succeeded, though: a sequence whose *first* call failed
					// installed nothing, and running the cleanup anyway would
					// take back something that never happened -- for a mask that
					// means installing whichever bits the saved-mask scratch
					// happens to hold.
					let took_effect = results.len() > 1
						&& results[..results.len() - 1].iter().all(|rc| *rc >= 0);
					let mut cleanup = None;
					if took_effect {
						while let Some(step) = queue.pop_front() {
							if matches!(step, Step::Sigprocmask { always: true, .. }) {
								cleanup = Some(step);
								break
							}
						}
					}
					cleanup
				}
			},
			_ => None,
		};

		if let Some(step) = next {
			let (call_nr, args) = build(&step, &active);
			let mut patched = regs;
			patched.orig_rax = call_nr;
			patched.rax = call_nr;
			patched.rdi = args[0];
			patched.rsi = args[1];
			patched.rdx = args[2];
			patched.r10 = args[3];
			patched.r8 = args[4];
			patched.r9 = args[5];
			if let Active::Sequence { gadget, running, at_entry, .. } = &mut active {
				patched.rip = *gadget;
				*running = Some(step);
				*at_entry = true;
			}
			let _ = ptrace::setregs(pid, patched);
			self.active.insert(pid, active);
			return;
		}

		// Done: hand the application the emulated result, or the error.
		if let Active::Sequence { saved, results, outcome, fd, .. } = &active {
			let value = match outcome {
				Outcome::Call(i) => results.get(*i).copied().unwrap_or(-libc::EINVAL as i64),
				Outcome::Adopted => *fd,
			};
			// The answer is what the call the emulation is *for* returned. A
			// trailing step failing -- a signal-mask restore, an FD_CLOEXEC that
			// could not be set -- is a loss, but not a reason to replace that
			// answer with the cleanup's error and, in the dup case, throw away
			// the fd it produced. Only when the outcome itself did not happen is
			// the first error the honest answer.
			let outcome_happened = value >= 0;
			let result = if outcome_happened { value } else { failure.unwrap_or(value) };
			if debug() {
				if let Some(err) = failure {
					if outcome_happened && err != result {
						eprintln!(
							"kernel-compat: emulation done with result {result}, a later step failed with {}",
							-err
						);
					}
				}
			}
			let mut done = *saved;
			done.rax = result as u64;
			let _ = ptrace::setregs(pid, done);
		}
	}

	/// Serve deadlines that have come due: `SIGALRM` says at least one has, the
	/// loop calls this whenever it comes back.
	pub fn tick(&mut self) {
		if !ALARM.swap(false, Ordering::Relaxed) {
			return;
		}
		let mut due = Vec::new();
		for (fd, timer) in self.timers.iter() {
			let Some(deadline) = timer.deadline else { continue };
			let Some(now) = clock_now(timer.clockid) else { continue };
			if now < deadline {
				continue;
			}
			// An interval timer may have missed several periods while the tracer
			// was busy; report them together, the way the real counter does. The
			// new deadline is worked out here but only applied once the
			// expiration has actually been handed over, below.
			let mut count = 1u64;
			let mut next = None;
			if timer.interval != (0, 0) {
				let mut following = add(deadline, timer.interval);
				while now >= following && count < u32::MAX as u64 {
					following = add(following, timer.interval);
					count += 1;
				}
				next = Some(following);
			}
			due.push((*fd, count, next));
		}
		for (fd, count, next) in due {
			let Some(handle) = self.write_ends.get(&fd) else {
				self.timers.remove(&fd);
				continue;
			};
			let buffer = count.to_ne_bytes();
			if debug_all() {
				eprintln!("kernel-compat: timerfd {fd} expired, reporting {count}");
			}
			let written = unsafe {
				libc::write(handle.as_raw_fd(), buffer.as_ptr() as *const libc::c_void, 8)
			};
			if written == 8 {
				// The expiration is on its way to the application, so the timer
				// can move on: to the next period, or to nothing at all for a
				// one-shot. Advancing it before the write is what lost a
				// one-shot's only expiration when the write came back EINTR.
				if let Some(timer) = self.timers.get_mut(&fd) {
					timer.deadline = next;
				}
				continue
			}
			match Errno::last() {
				// The reader is alive, so the timer stays theirs to read. An
				// interval timer moves to its next period rather than keeping an
				// overdue deadline, which would have the tracer retrying on a
				// microsecond loop for as long as the pipe stays full; a one-shot
				// keeps its deadline, since only EINTR can fail its single write
				// and that retry succeeds straight away.
				Errno::EAGAIN | Errno::EINTR => {
					if let (Some(timer), Some(next)) = (self.timers.get_mut(&fd), next) {
						timer.deadline = Some(next);
					}
				},
				// The read end is gone: the application closed its timerfd.
				_ => {
					self.write_ends.remove(&fd);
					self.timers.remove(&fd);
				},
			}
		}
		self.arm();
	}

	/// Arm the tracer's interval timer for the nearest deadline. A zero delta
	/// would turn it off, so an overdue deadline is given a microsecond.
	fn arm(&self) {
		let mut soonest: Option<Time> = None;
		for timer in self.timers.values() {
			let Some(deadline) = timer.deadline else { continue };
			let Some(now) = clock_now(timer.clockid) else { continue };
			let left = sub(deadline, now);
			if soonest.is_none_or(|current| left < current) {
				soonest = Some(left);
			}
		}
		unsafe {
			let mut itimer: libc::itimerval = std::mem::zeroed();
			if let Some((seconds, nanoseconds)) = soonest {
				itimer.it_value.tv_sec = seconds;
				itimer.it_value.tv_usec = nanoseconds / 1000;
				if seconds == 0 && itimer.it_value.tv_usec == 0 {
					itimer.it_value.tv_usec = 1;
				}
			}
			libc::setitimer(libc::ITIMER_REAL, &itimer, std::ptr::null_mut());
		}
	}
}

/// Build the syscall a step asks for, with the fd it names filled in.
fn build(step: &Step, active: &Active) -> (u64, [u64; 6]) {
	let (fd, read_end, write_end) = match active {
		Active::Sequence { fd, read_end, write_end, .. } => (*fd, *read_end, *write_end),
		Active::Fixup(_) => (-1, -1, -1),
	};
	let fd_of = |which: Which| match which {
		Which::Result => fd as u64,
		Which::ReadEnd => read_end as u64,
		Which::WriteEnd => write_end as u64,
	};
	match *step {
		Step::Socket => (
			libc::SYS_socket as u64,
			[libc::AF_UNIX as u64, libc::SOCK_DGRAM as u64, 0, 0, 0, 0],
		),
		Step::Pipe { buffer } => (libc::SYS_pipe as u64, [buffer, 0, 0, 0, 0, 0]),
		Step::Attach { fd: which, addr, length, connect } => (
			if connect { libc::SYS_connect as u64 } else { libc::SYS_bind as u64 },
			[fd_of(which), addr, length, 0, 0, 0],
		),
		Step::Nonblock { fd: which } => (
			libc::SYS_fcntl as u64,
			[fd_of(which), libc::F_SETFL as u64, libc::O_NONBLOCK as u64, 0, 0, 0],
		),
		Step::WriteInitial { fd: which, buffer } => {
			(libc::SYS_write as u64, [fd_of(which), buffer, 8, 0, 0, 0])
		},
		Step::Close { fd: which } => (libc::SYS_close as u64, [fd_of(which), 0, 0, 0, 0, 0]),
		Step::FcntlDupfd { fd, minimum } => (
			libc::SYS_fcntl as u64,
			[fd, libc::F_DUPFD as u64, minimum, 0, 0, 0],
		),
		Step::FcntlCloexec { fd: which } => (
			libc::SYS_fcntl as u64,
			[fd_of(which), libc::F_SETFD as u64, libc::FD_CLOEXEC as u64, 0, 0, 0],
		),
		Step::Lseek { fd, offset } => (
			libc::SYS_lseek as u64,
			[fd, offset as u64, libc::SEEK_SET as u64, 0, 0, 0],
		),
		Step::VectorIo { write, fd, iov, count } => (
			if write { libc::SYS_writev as u64 } else { libc::SYS_readv as u64 },
			[fd, iov, count, 0, 0, 0],
		),
		Step::Sigprocmask { mask, saved, .. } => (
			libc::SYS_rt_sigprocmask as u64,
			[libc::SIG_SETMASK as u64, mask, saved, 8, 0, 0],
		),
		Step::EpollWait { epfd, events, maxevents, timeout } => (
			libc::SYS_epoll_wait as u64,
			[epfd, events, maxevents, timeout, 0, 0],
		),
	}
}

/// Take a write handle on the pipe the tracee just created, so a deadline can be
/// served without going near the tracee, and adopt its read end. A socket
/// cannot be reopened this way, which is why eventfd uses a self-connected one
/// instead of a pipe.
fn capture_pipe(
	timers: &mut HashMap<i64, Timer>,
	write_ends: &mut HashMap<i64, OwnedFd>,
	pid: Pid,
	buffer: u64,
	clockid: i32,
) -> Option<(i64, i64)> {
	let raw = read_struct(pid, buffer, 8)?;
	let read_end = i32::from_ne_bytes(raw[0..4].try_into().ok()?) as i64;
	let write_end = i32::from_ne_bytes(raw[4..8].try_into().ok()?) as i64;
	let handle = match std::fs::OpenOptions::new()
		.write(true)
		.custom_flags(libc::O_NONBLOCK)
		.open(format!("/proc/{pid}/fd/{write_end}"))
	{
		Ok(handle) => handle,
		Err(err) => {
			if debug() {
				eprintln!("kernel-compat: cannot hold the timerfd pipe open: {err}");
			}
			return None;
		},
	};
	timers.insert(read_end, Timer { clockid, deadline: None, interval: (0, 0) });
	write_ends.insert(read_end, handle.into());
	install_handlers();
	Some((read_end, write_end))
}

/// Probe once whether the kernel implements eventfd(2) (added in 2.6.22, with
/// the flags-taking eventfd2 in 2.6.27). Only then is it emulated.
fn eventfd_missing() -> bool {
	static MISSING: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
	*MISSING.get_or_init(|| {
		let rc = unsafe { libc::syscall(libc::SYS_eventfd2, 0u32, 0u32) };
		let missing = not_implemented(libc::SYS_eventfd2, rc);
		if !missing && rc >= 0 {
			unsafe { libc::close(rc as libc::c_int) };
		}
		missing
	})
}

/// Probe once whether the kernel implements timerfd_create(2) (added in 2.6.25).
fn timerfd_missing() -> bool {
	static MISSING: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
	*MISSING.get_or_init(|| {
		let rc = unsafe { libc::syscall(libc::SYS_timerfd_create, libc::CLOCK_MONOTONIC, 0u32) };
		let missing = not_implemented(libc::SYS_timerfd_create, rc);
		if !missing && rc >= 0 {
			unsafe { libc::close(rc as libc::c_int) };
		}
		missing
	})
}

/// The instruction the tracee just executed, which is the `syscall` of its
/// wrapper, so the tracee can be sent back into the kernel from there.
fn gadget_for(pid: Pid, regs: libc::user_regs_struct) -> Option<u64> {
	let address = regs.rip.wrapping_sub(2);
	let word = peek_word(pid, address)? & 0xffff;
	if matches!(word, SYSCALL64 | SYSCALL32) {
		return Some(address);
	}
	if debug() {
		eprintln!("kernel-compat: no syscall instruction behind {:#x}, not emulating", regs.rip);
	}
	None
}

fn rd64(bytes: &[u8], offset: usize) -> i64 {
	i64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap_or_default())
}

fn push_time(out: &mut Vec<u8>, value: Time) {
	out.extend_from_slice(&value.0.to_ne_bytes());
	out.extend_from_slice(&value.1.to_ne_bytes());
}

fn clock_now(clockid: i32) -> Option<Time> {
	let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
	(unsafe { libc::clock_gettime(clockid, &mut ts) } == 0)
		.then_some((ts.tv_sec as i64, ts.tv_nsec as i64))
}

fn add(a: Time, b: Time) -> Time {
	let mut seconds = a.0 + b.0;
	let mut nanoseconds = a.1 + b.1;
	if nanoseconds >= 1_000_000_000 {
		nanoseconds -= 1_000_000_000;
		seconds += 1;
	}
	(seconds, nanoseconds)
}

/// `a - b`, clamped at zero: a deadline that has passed has nothing left.
fn sub(a: Time, b: Time) -> Time {
	let mut seconds = a.0 - b.0;
	let mut nanoseconds = a.1 - b.1;
	if nanoseconds < 0 {
		nanoseconds += 1_000_000_000;
		seconds -= 1;
	}
	if seconds < 0 {
		return (0, 0);
	}
	(seconds, nanoseconds)
}
