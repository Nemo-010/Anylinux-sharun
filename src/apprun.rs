use std::{
	env,
	ffi::CStr,
	path::Path,
	process::{Command, exit},
	fs::read_to_string,
	os::unix::process::CommandExt,
};

use crate::utils::{find_shell, is_file, basename, add_to_env, get_env_var};

extern "C" {
	fn getuid() -> u32;
}

/// The running kernel version as `major.minor.patch` (e.g. `2.6.17`), taken from
/// `uname(2)`'s release and stripped of any `-extra` suffix.
fn host_kernel_version() -> String {
	let mut uts: nix::libc::utsname = unsafe { std::mem::zeroed() };
	if unsafe { nix::libc::uname(&mut uts) } != 0 {
		return String::new()
	}
	let release = unsafe { CStr::from_ptr(uts.release.as_ptr()) }.to_string_lossy();
	let mut parts = release.split(|c: char| !c.is_ascii_digit());
	let a = parts.next().unwrap_or("0");
	let b = parts.next().unwrap_or("0");
	let c = parts.next().unwrap_or("0");
	format!("{a}.{b}.{c}")
}

fn env_or(keys: &[&str], fallback: &str) -> String {
	for key in keys {
		let val = get_env_var(key);
		if !val.is_empty() {
			return val
		}
	}
	fallback.to_string()
}


pub fn run_as_apprun(
	sharun_dir: &str,
	bin_dir: &str,
	exec_args: &[String],
) -> ! {
	let host_home = env_or(&["REAL_HOME", "HOME"], "");

	env::set_var("HOST_HOME", &host_home);
	env::set_var("HOST_XDG_CONFIG_HOME", env_or(&["REAL_XDG_CONFIG_HOME", "XDG_CONFIG_HOME"], &format!("{host_home}/.config")));
	env::set_var("HOST_XDG_DATA_HOME", env_or(&["REAL_XDG_DATA_HOME", "XDG_DATA_HOME"], &format!("{host_home}/.local/share")));
	env::set_var("HOST_XDG_CACHE_HOME", env_or(&["REAL_XDG_CACHE_HOME", "XDG_CACHE_HOME"], &format!("{host_home}/.cache")));
	env::set_var("HOST_XDG_STATE_HOME", env_or(&["REAL_XDG_STATE_HOME", "XDG_STATE_HOME"], &format!("{host_home}/.local/state")));
	env::set_var("HOST_KERNEL_VERSION", host_kernel_version());

	env::set_var("APPIMAGE_ARCH", std::env::consts::ARCH);
	env::set_var("APPIMAGE_UID", unsafe { getuid() }.to_string());
	env::set_var("HOSTPATH", get_env_var("PATH"));
	add_to_env("PATH", bin_dir);
	env::set_var("APPDIR", sharun_dir);
	env::set_var("SHARUN_DIR", sharun_dir);

	let apprun_wrapped = Path::new(sharun_dir).join("AppRun.sh");
	if apprun_wrapped.exists() {
		let shell = find_shell().unwrap_or_else(|| {
			eprintln!(
				"Failed to find a shell for {}",
				apprun_wrapped.display()
			);
			exit(1)
		});

		let err = Command::new(shell)
			.arg(apprun_wrapped)
			.args(exec_args)
			.exec();
		eprintln!("Failed to run AppRun.sh: {err}");
		exit(1);
	}
	let mut appname: String = "".into();
	if let Ok(dir) = Path::new(sharun_dir).read_dir() {
		for entry in dir.flatten() {
			let path = entry.path();
			if is_file(&path) {
				let name = entry.file_name();
				let name = name.to_str().unwrap_or_default();
				if name.ends_with(".desktop") {
					let data = read_to_string(path).unwrap_or_else(|err|{
						eprintln!("Failed to read desktop file: {name}: {err}");
						exit(1)
					});
					appname = data.split("\n").filter_map(|string| {
						if string.starts_with("Exec=") {
							Some(string.replace("Exec=", "").split_whitespace().next().unwrap_or("").into())
						} else {None}
					}).next().unwrap_or_else(||"".into())
				}
			}
		}
	}

	if let Some(name) = appname.trim().split("\n").next() {
		appname = basename(name)
		.replace("'", "").replace("\"", "")
	} else {
		eprintln!("Failed to get app name from .desktop file");
		exit(1)
	}
	let app = &format!("{bin_dir}/{appname}");

	let err = Command::new(app)
		.args(exec_args)
		.exec();
	eprintln!("Failed to run App: {app}: {err}");
	exit(1)
}
