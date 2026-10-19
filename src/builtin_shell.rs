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
fn memfd_with_shell() -> Result<File, Error> {
	let mut fd = unsafe { nix::libc::memfd_create(c"sharun-sh".as_ptr(), MFD_CLOEXEC | MFD_EXEC) };
	if fd < 0 && Error::last_os_error().raw_os_error() == Some(nix::libc::EINVAL) {
		fd = unsafe { nix::libc::memfd_create(c"sharun-sh".as_ptr(), MFD_CLOEXEC) };
	}
	if fd < 0 {
		return Err(Error::last_os_error())
	}
	let mut file = unsafe { File::from_raw_fd(fd) };
	file.write_all(SHELL)?;
	Ok(file)
}

/// Fallback for when the memfd cannot be created or executed. The file is
/// removed right after it is reopened read-only, so nothing is left behind.
/// Reopening is needed because executing a file that is open for writing fails
/// with ETXTBSY.
fn tmpfile_with_shell() -> Result<File, Error> {
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
		let reopened = OpenOptions::new()
			.read(true)
			.custom_flags(nix::libc::O_CLOEXEC)
			.open(&path);
		let _ = remove_file(&path);
		match reopened {
			Ok(file) => return Ok(file),
			Err(err) => last_err = err,
		}
	}
	Err(last_err)
}

/// A file left by a killed run whose pid was recycled is removed and replaced.
fn create_executable(path: &str) -> Result<File, Error> {
	let create = || {
		OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o700)
			.custom_flags(nix::libc::O_CLOEXEC)
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

	let memfd_err = match memfd_with_shell() {
		Ok(file) => {
			unsafe { nix::libc::fexecve(file.as_raw_fd(), argv_ptrs.as_ptr(), environ) };
			// the memfd exists but cannot be executed (vm.memfd_noexec, seccomp)
			Error::last_os_error()
		}
		Err(err) => err,
	};

	let file = match tmpfile_with_shell() {
		Ok(file) => file,
		Err(tmp_err) => {
			return Error::new(
				tmp_err.kind(),
				format!("memfd failed ({memfd_err}), temporary file failed ({tmp_err})"),
			)
		}
	};
	unsafe { nix::libc::fexecve(file.as_raw_fd(), argv_ptrs.as_ptr(), environ) };
	let err = Error::last_os_error();
	Error::new(err.kind(), format!("cannot execute the embedded shell: {err} (memfd: {memfd_err}), a noexec TMPDIR, /tmp and /dev/shm would cause this"))
}
