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

	let mut errors: Vec<String> = Vec::new();
	let mut last_err = Error::new(ErrorKind::NotFound, "no way to run the embedded shell");

	// CLOEXEC first: when the shell is a native ELF the exec succeeds right
	// away and no fd leaks. ENOENT means the kernel needed an interpreter and
	// refused because of the close-on-exec fd, so try again without it.
	for cloexec in [true, false] {
		match memfd_with_shell(cloexec) {
			Ok(file) => {
				unsafe { nix::libc::fexecve(file.as_raw_fd(), argv_ptrs.as_ptr(), environ) };
				let err = Error::last_os_error();
				if err.kind() != ErrorKind::NotFound {
					return err
				}
				errors.push(format!("memfd, cloexec={cloexec}: {err}"));
				last_err = err;
			}
			Err(err) => {
				errors.push(format!("memfd, cloexec={cloexec}: {err}"));
				last_err = err;
			}
		}
	}

	for cloexec in [true, false] {
		match tmpfile_with_shell(cloexec) {
			Ok(file) => {
				unsafe { nix::libc::fexecve(file.as_raw_fd(), argv_ptrs.as_ptr(), environ) };
				let err = Error::last_os_error();
				if err.kind() != ErrorKind::NotFound {
					return err
				}
				errors.push(format!("temporary file, cloexec={cloexec}: {err}"));
				last_err = err;
			}
			Err(err) => {
				errors.push(format!("temporary file, cloexec={cloexec}: {err}"));
				last_err = err;
			}
		}
	}

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

	fn is_close_on_exec(file: &File) -> bool {
		let flags = unsafe { nix::libc::fcntl(file.as_raw_fd(), nix::libc::F_GETFD) };
		assert!(flags >= 0, "F_GETFD failed");
		flags & nix::libc::FD_CLOEXEC != 0
	}

	// The shell is normally run with the fd close-on-exec so it does not leak
	// into the shell and everything the shell starts.
	#[test]
	fn memfd_is_close_on_exec_when_asked() {
		let file = memfd_with_shell(true).unwrap();
		assert!(is_close_on_exec(&file));
	}

	// Under qemu user emulation the embedded dash is a foreign-arch ELF, so
	// binfmt_misc has to run it, and the kernel refuses that for a
	// close-on-exec fd (BINPRM_FLAGS_PATH_INACCESSIBLE -> ENOENT). The fd has
	// to survive the exec, or the AppImage cannot start at all.
	#[test]
	fn memfd_keeps_the_fd_open_across_exec_when_asked() {
		let file = memfd_with_shell(false).unwrap();
		assert!(!is_close_on_exec(&file));
	}

	#[test]
	fn tmpfile_is_close_on_exec_when_asked() {
		let file = tmpfile_with_shell(true).unwrap();
		assert!(is_close_on_exec(&file));
	}

	#[test]
	fn tmpfile_keeps_the_fd_open_across_exec_when_asked() {
		let file = tmpfile_with_shell(false).unwrap();
		assert!(!is_close_on_exec(&file));
	}

	// The shell that gets written is the embedded one, both ways round. The
	// fd is read from position 0 because writing left it at the end.
	#[test]
	fn both_paths_hold_the_embedded_shell() {
		use std::io::{Read, Seek, SeekFrom};

		for cloexec in [true, false] {
			for file in [
				memfd_with_shell(cloexec).unwrap(),
				tmpfile_with_shell(cloexec).unwrap(),
			] {
				let mut f = &file;
				f.seek(SeekFrom::Start(0)).unwrap();
				let mut buf = Vec::new();
				f.read_to_end(&mut buf).unwrap();
				assert_eq!(buf, SHELL, "cloexec={cloexec}");
			}
		}
	}
}
