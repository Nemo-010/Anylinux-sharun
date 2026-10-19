//! The shell that runs AppRun.sh. It is a static dash, built by
//! tools/build-dash.sh and embedded into sharun, so AppImages do not depend
//! on a host /bin/sh.

use std::{
	ffi::CString,
	fs::{File, OpenOptions, Permissions, remove_file},
	io::{Error, ErrorKind, Write},
	os::unix::{
		fs::{OpenOptionsExt, PermissionsExt},
		io::{AsRawFd, FromRawFd},
	},
	path::Path,
};

extern "C" {
	static environ: *const *const nix::libc::c_char;
}

static SHELL: &[u8] = include_bytes!("../shell/dash");

const MFD_CLOEXEC: nix::libc::c_uint = 0x1;
/// Linux 6.3. With vm.memfd_noexec=1 a memfd made without it is not executable.
/// Older kernels reject the unknown flag with EINVAL.
const MFD_EXEC: nix::libc::c_uint = 0x10;

/// Anonymous in-memory file, needs Linux 3.17.
///
/// `cloexec` is not cosmetic. When the executed file cannot be run directly,
/// the kernel has to hand its *path* to an interpreter, and it marks the exec
/// BINPRM_FLAGS_PATH_INACCESSIBLE when the fd is close-on-exec:
///
///     fs/exec.c:  if (get_close_on_exec(fd))
///                     bprm->interp_flags |= BINPRM_FLAGS_PATH_INACCESSIBLE;
///
/// Every binfmt then gives up with ENOENT before the interpreter starts:
///
///     fs/binfmt_misc.c, fs/binfmt_script.c:
///                 if (bprm->interp_flags & BINPRM_FLAGS_PATH_INACCESSIBLE)
///                         return -ENOENT;
///
/// The shell needs an interpreter only when it is not a native ELF, which is
/// the case under qemu user emulation: the embedded dash is a foreign-arch
/// ELF, so binfmt_misc has to run it. A memfd is reachable by path only
/// through /dev/fd/N, so there the fd has to survive the exec. Keeping it
/// alive leaks it into the shell and everything the shell starts, so it is
/// only done after the close-on-exec attempt has failed.
fn memfd_with_shell(cloexec: bool) -> Result<File, Error> {
	let flags = if cloexec { MFD_CLOEXEC | MFD_EXEC } else { MFD_EXEC };
	let mut fd = unsafe { nix::libc::memfd_create(c"sharun-sh".as_ptr(), flags) };
	if fd < 0 && Error::last_os_error().raw_os_error() == Some(nix::libc::EINVAL) {
		// pre-6.3 kernel, MFD_EXEC is unknown there
		let fallback = if cloexec { MFD_CLOEXEC } else { 0 };
		fd = unsafe { nix::libc::memfd_create(c"sharun-sh".as_ptr(), fallback) };
	}
	if fd < 0 {
		return Err(Error::last_os_error())
	}
	let mut file = unsafe { File::from_raw_fd(fd) };
	file.write_all(SHELL)?;
	Ok(file)
}

/// Drops FD_CLOEXEC from `file`.
///
/// std's `OpenOptions::open` always passes O_CLOEXEC to open(2), so
/// `custom_flags` cannot clear it: the flag is OR'ed in unconditionally
/// (`libc::O_CLOEXEC | ... | opts.custom_flags`). It has to be cleared with
/// fcntl(2) after the fact.
fn clear_close_on_exec(file: &File) -> Result<(), Error> {
	let flags = unsafe { nix::libc::fcntl(file.as_raw_fd(), nix::libc::F_GETFD) };
	if flags < 0 {
		return Err(Error::last_os_error())
	}
	if unsafe { nix::libc::fcntl(file.as_raw_fd(), nix::libc::F_SETFD, flags & !nix::libc::FD_CLOEXEC) } < 0 {
		return Err(Error::last_os_error())
	}
	Ok(())
}

/// Fallback for when the memfd cannot be created or executed. The file is
/// removed right after it is reopened read-only, so nothing is left behind.
/// Reopening is needed because executing a file that is open for writing fails
/// with ETXTBSY.
///
/// Unlinking does not hurt an interpreter: the fd keeps the inode alive and
/// /dev/fd/N still resolves through it. `cloexec` has the meaning described in
/// `memfd_with_shell`.
fn tmpfile_with_shell(cloexec: bool) -> Result<File, Error> {
	let mut dirs: Vec<String> = Vec::new();
	if let Ok(dir) = std::env::var("TMPDIR") {
		if !dir.is_empty() {
			dirs.push(dir)
		}
	}
	dirs.push("/tmp".into());
	dirs.push("/dev/shm".into());

	let mut last_err = Error::new(ErrorKind::NotFound, "no temporary directory");
	for dir in dirs {
		let path = format!("{dir}/.sharun-sh-{}", std::process::id());
		let write_result = create_executable(&path).and_then(|mut file| {
			file.write_all(SHELL)?;
			// the mode given to open() is masked by the umask
			file.set_permissions(Permissions::from_mode(0o700))
		});
		if let Err(err) = write_result {
			let _ = remove_file(&path);
			last_err = err;
			continue
		}
		let reopened = OpenOptions::new().read(true).open(&path);
		let _ = remove_file(&path);
		match reopened {
			Ok(file) => {
				if !cloexec {
					clear_close_on_exec(&file)?;
				}
				return Ok(file)
			}
			Err(err) => last_err = err,
		}
	}
	Err(last_err)
}

/// A file left by a killed run whose pid was recycled is removed and replaced.
/// The fd it returns is only used for writing and is dropped before the file
/// is reopened for exec'ing, so its close-on-exec flag does not matter.
fn create_executable(path: &str) -> Result<File, Error> {
	let create = || {
		OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o700)
			.open(path)
	};
	match create() {
		Err(err) if err.kind() == ErrorKind::AlreadyExists => {
			remove_file(path)?;
			create()
		}
		result => result,
	}
}

/// Runs one way of getting the shell executed: with a close-on-exec fd
/// first, and again without it when the kernel says ENOENT.
///
/// ENOENT is the kernel refusing to hand a close-on-exec fd to an
/// interpreter (see `memfd_with_shell`), so the fd flag is worth retrying
/// without. Any other errno is not about the flag, so there is nothing to
/// gain from a second attempt and the caller moves on to the next strategy.
/// Returns the last error, or `None` if the list of strategies was empty.
fn run_strategy<O, R>(
	label: &str,
	open: O,
	run: &R,
	errors: &mut Vec<String>,
) -> Option<Error>
where
	O: Fn(bool) -> Result<File, Error>,
	R: Fn(&File) -> Error,
{
	let mut last: Option<Error> = None;
	for cloexec in [true, false] {
		let err = match open(cloexec) {
			Ok(file) => run(&file),
			Err(err) => err,
		};
		errors.push(format!("{label}, cloexec={cloexec}: {err}"));
		let retry = err.kind() == ErrorKind::NotFound;
		last = Some(err);
		if !retry {
			break
		}
	}
	last
}

/// Runs every way of getting the shell executed, in order, and returns the
/// last error together with a record of everything that was tried.
///
/// Both strategies are always attempted. A memfd that exists but cannot be
/// executed (EACCES from a policy that refuses to execute memfds, for
/// example) has to fall through to the temporary file, so a non-ENOENT error
/// only ends that one strategy, never the whole thing. The close-on-exec
/// retry within a strategy is `run_strategy`.
fn run_all_strategies<M, T, R>(memfd: M, tmpfile: T, run: &R) -> (Error, Vec<String>)
where
	M: Fn(bool) -> Result<File, Error>,
	T: Fn(bool) -> Result<File, Error>,
	R: Fn(&File) -> Error,
{
	let mut errors: Vec<String> = Vec::new();
	let mut last_err = Error::new(ErrorKind::NotFound, "no way to run the embedded shell");
	let mut keep = |err: Option<Error>| {
		if let Some(err) = err {
			last_err = err;
		}
	};
	keep(run_strategy("memfd", memfd, run, &mut errors));
	keep(run_strategy("temporary file", tmpfile, run, &mut errors));
	(last_err, errors)
}

/// Replaces this process with the embedded shell running `script` with `args`.
/// Only returns on failure, with the error.
pub fn exec_script(script: &Path, args: &[String]) -> Error {
	let mut argv: Vec<CString> = vec![CString::new("sh").unwrap()];
	match CString::new(script.as_os_str().as_encoded_bytes()) {
		Ok(script) => argv.push(script),
		Err(err) => return err.into(),
	}
	for arg in args {
		match CString::new(arg.as_bytes()) {
			Ok(arg) => argv.push(arg),
			Err(err) => return err.into(),
		}
	}
	let mut argv_ptrs: Vec<*const nix::libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
	argv_ptrs.push(std::ptr::null());

	let run = |file: &File| -> Error {
		unsafe { nix::libc::fexecve(file.as_raw_fd(), argv_ptrs.as_ptr(), environ) };
		Error::last_os_error()
	};
	let (last_err, errors) = run_all_strategies(memfd_with_shell, tmpfile_with_shell, &run);

	Error::new(
		last_err.kind(),
		format!(
			"cannot execute the embedded shell ({}), a noexec TMPDIR, /tmp and /dev/shm would cause this",
			errors.join(", ")
		),
	)
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::io::{Read, Seek, SeekFrom};

	fn is_close_on_exec(file: &File) -> bool {
		let flags = unsafe { nix::libc::fcntl(file.as_raw_fd(), nix::libc::F_GETFD) };
		assert!(flags >= 0, "F_GETFD failed");
		flags & nix::libc::FD_CLOEXEC != 0
	}

	/// Some sandboxes deny memfd_create. Skipping is reported instead of
	/// failing: a test that cannot run here is not a broken build.
	fn memfd_or_skip(cloexec: bool) -> Option<File> {
		match memfd_with_shell(cloexec) {
			Ok(file) => Some(file),
			Err(err) => {
				eprintln!("skipping: memfd_create is not available here: {err}");
				None
			}
		}
	}

	/// A noexec TMPDIR fails here for a reason that is not this code's
	/// business either.
	fn tmpfile_or_skip(cloexec: bool) -> Option<File> {
		match tmpfile_with_shell(cloexec) {
			Ok(file) => Some(file),
			Err(err) => {
				eprintln!("skipping: no usable temporary directory here: {err}");
				None
			}
		}
	}

	// The shell is normally run with the fd close-on-exec so it does not leak
	// into the shell and everything the shell starts.
	#[test]
	fn memfd_is_close_on_exec_when_asked() {
		let Some(file) = memfd_or_skip(true) else { return };
		assert!(is_close_on_exec(&file));
	}

	// Under qemu user emulation the embedded dash is a foreign-arch ELF, so
	// binfmt_misc has to run it, and the kernel refuses that for a
	// close-on-exec fd (BINPRM_FLAGS_PATH_INACCESSIBLE -> ENOENT). The fd has
	// to survive the exec, or the AppImage cannot start at all.
	#[test]
	fn memfd_keeps_the_fd_open_across_exec_when_asked() {
		let Some(file) = memfd_or_skip(false) else { return };
		assert!(!is_close_on_exec(&file));
	}

	#[test]
	fn tmpfile_is_close_on_exec_when_asked() {
		let Some(file) = tmpfile_or_skip(true) else { return };
		assert!(is_close_on_exec(&file));
	}

	#[test]
	fn tmpfile_keeps_the_fd_open_across_exec_when_asked() {
		let Some(file) = tmpfile_or_skip(false) else { return };
		assert!(!is_close_on_exec(&file));
	}

	// The shell that gets written is the embedded one, both ways round. The
	// fd is read from position 0 because writing left it at the end.
	#[test]
	fn both_paths_hold_the_embedded_shell() {
		for cloexec in [true, false] {
			let mut files: Vec<File> = Vec::new();
			files.extend(memfd_or_skip(cloexec));
			files.extend(tmpfile_or_skip(cloexec));
			for file in files {
				let mut f = &file;
				f.seek(SeekFrom::Start(0)).unwrap();
				let mut buf = Vec::new();
				f.read_to_end(&mut buf).unwrap();
				assert_eq!(buf, SHELL, "cloexec={cloexec}");
			}
		}
	}

	// A close-on-exec fd that needs an interpreter is refused with ENOENT, so
	// the strategy has to be tried a second time without the flag. This is the
	// qemu-user case, expressed as a plain error sequence.
	#[test]
	fn enoent_retries_without_cloexec() {
		let mut errors = Vec::new();
		let last = run_strategy(
			"memfd",
			|_| Ok(File::open("/dev/null").unwrap()),
			&|_| Error::from_raw_os_error(nix::libc::ENOENT),
			&mut errors,
		);
		assert_eq!(last.unwrap().kind(), ErrorKind::NotFound);
		assert_eq!(errors.len(), 2, "both attempts have to be recorded");
		assert!(errors[0].contains("cloexec=true"), "{}", errors[0]);
		assert!(errors[1].contains("cloexec=false"), "{}", errors[1]);
	}

	// Any other errno is not about the fd flag, so the second attempt would
	// only repeat it: one attempt, and the caller moves on to the temporary
	// file instead of giving up.
	#[test]
	fn other_errors_do_not_retry() {
		let mut errors = Vec::new();
		let last = run_strategy(
			"memfd",
			|_| Ok(File::open("/dev/null").unwrap()),
			&|_| Error::from_raw_os_error(nix::libc::EACCES),
			&mut errors,
		);
		assert_eq!(last.unwrap().kind(), ErrorKind::PermissionDenied);
		assert_eq!(errors.len(), 1, "a non-ENOENT errno is not retried");
	}

	// The two strategies are independent: a memfd that exists but cannot be
	// executed (EACCES, e.g. a policy that refuses to execute memfds) has to
	// let the temporary file have its turn. This is the regression the
	// close-on-exec retry could introduce, so it is pinned here.
	#[test]
	fn a_failed_memfd_still_lets_the_temporary_file_run() {
		let tried = std::cell::RefCell::new(Vec::new());
		let (_last, errors) = run_all_strategies(
			|_| Ok(File::open("/dev/null").unwrap()),
			|_| Ok(File::open("/dev/null").unwrap()),
			&|_| {
				tried.borrow_mut().push("exec");
				Error::from_raw_os_error(nix::libc::EACCES)
			},
		);
		// one attempt per strategy: EACCES is not retried within a strategy
		assert_eq!(tried.borrow().len(), 2, "both strategies have to run");
		assert_eq!(errors.len(), 2, "{errors:?}");
		assert!(errors[0].starts_with("memfd, "), "{}", errors[0]);
		assert!(errors[1].starts_with("temporary file, "), "{}", errors[1]);
	}

	// The same with the two strategies failing differently, to show that the
	// last error is what gets reported and the earlier one is not lost.
	#[test]
	fn the_message_lists_every_attempt() {
		let (_last, errors) = run_all_strategies(
			|_| Err(Error::from_raw_os_error(nix::libc::EPERM)),
			|_| Err(Error::from_raw_os_error(nix::libc::EACCES)),
			&|_| unreachable!("no fd was produced"),
		);
		assert_eq!(errors.len(), 2, "{errors:?}");
		assert!(errors[0].starts_with("memfd, cloexec=true: "), "{}", errors[0]);
		assert!(
			errors[1].starts_with("temporary file, cloexec=true: "),
			"{}",
			errors[1]
		);
	}

	// A strategy that cannot even produce an fd still records why, so the
	// final message says what was tried.
	#[test]
	fn a_failed_open_is_recorded() {
		let mut errors = Vec::new();
		let last = run_strategy(
			"memfd",
			|_| Err(Error::from_raw_os_error(nix::libc::EPERM)),
			&|_| unreachable!("nothing to run"),
			&mut errors,
		);
		assert_eq!(last.unwrap().kind(), ErrorKind::PermissionDenied);
		assert_eq!(errors.len(), 1);
		assert!(errors[0].starts_with("memfd, cloexec=true: "), "{}", errors[0]);
	}
}
