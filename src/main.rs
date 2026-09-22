use std::{
	env,
	str::FromStr,
	path::{Path, PathBuf},
	ffi::CString,
	process::{Command, exit},
	os::unix::{fs::PermissionsExt, process::CommandExt},
};

mod utils;
mod abi_note;
mod apprun;
mod gio_launch_desktop;
mod bwrap_wrapper;
mod set_appdir_env;
#[cfg(target_arch = "x86_64")]
mod kernel_compat;
use utils::*;


const SHARUN_NAME: &str = env!("CARGO_PKG_NAME");

/// Internal-only flag used by the kernel-compat no_new_privs/execve probe. It
/// is intentionally long so it cannot collide with an application argument.
pub(crate) const SHARUN_NNP_PROBE_FLAG: &str =
	"--sharun-internal-probe-execve-after-no-new-privs";


fn print_usage() {
	println!("[ {} ]

[ Usage ]: {SHARUN_NAME} [OPTIONS] [EXEC ARGS]...",
	env!("CARGO_PKG_DESCRIPTION"));
	println!("
[ Arguments ]:
	[EXEC ARGS]...              Command line arguments for execution

[ Options ]:");
	println!("    -g,  --gen-lib-path         Generate a lib.path file
	-v,  --version              Print version
	-h,  --help                 Print help

[ Environments ]:
	SHARUN_WORKING_DIR=/path       Specifies the path to the working directory
	SHARUN_ALLOW_SYS_VKICD=1       Enables breaking system vulkan/icd.d for vulkan loader
	                               Set to 0 to only use the bundled vulkan icds
	SHARUN_ALLOW_LD_PRELOAD=1      Enables breaking LD_PRELOAD env variable
	SHARUN_ALLOW_QT_PLUGIN_PATH=1  Enables breaking QT_PLUGIN_PATH env variable
	SHARUN_NO_NVIDIA_EGL_PRIME=1   Disables NVIDIA EGL prime logic
	SHARUN_PRINTENV=1              Print environment variables to stderr
	SHARUN_LDNAME=ld.so            Specifies the name of the interpreter
	SHARUN_OLD_KERNEL_COMPAT=1     Enable compatibility layer that allows
	                                applications to run on ancient kernels;
	                                set to 0 to disable, default is automatic
	                                on kernels older than 4.0 or when statx is missing
	                                (on kernels without seccomp-bpf, < 3.5, every
	                                syscall is traced, which is slow; seccomp mode
	                                sets no_new_privs, so setuid helpers cannot
	                                gain privileges)
	SHARUN_EXTRA_LIBRARY_PATH      Extra library directories with highest priority
	SHARUN_FALLBACK_LIBRARY_PATH   Fallback library directories with lowest priority
	SHARUN_MESA_PATH=/path         External mesa install dir (with lib/ and share/)
	                                to source graphics env vars and libraries from
	                                DO NOT SET THIS VARIABLE TO '/usr'!
	                                It needs to be set a directory that contains
	                                a mesa installation only, no other libraries!
	SHARUN_DIR                     Sharun directory");
}

fn main() {
	let sharun = env::current_exe().unwrap_or_else(|err|{
		eprintln!("Failed to get sharun path: {err}");
		exit(1)
	});

	let mut exec_args: Vec<String> = env::args().collect();

	let mut sharun_dir = realpath(&get_env_var("SHARUN_DIR"));
	if sharun_dir.is_empty() ||
		!(is_dir(&sharun_dir) && {
			let sharun_dir_path = Path::new(&sharun_dir);
			let sharun_path = sharun_dir_path.join(SHARUN_NAME);
			sharun_dir_path.join("shared").is_dir() && is_exe(&sharun_path) &&
			is_same_rootdir(sharun_dir_path, &sharun, &sharun_path)
		})
	{
		sharun_dir = sharun.parent().unwrap_or_else(||{
			eprintln!("Failed to get sharun parrent dir!");
			exit(1)
		}).to_str().unwrap_or_default().to_string();
		let lower_dir = &format!("{sharun_dir}/../");
		if basename(&sharun_dir) == "bin" &&
			is_dir(&format!("{lower_dir}shared")) {
			sharun_dir = realpath(lower_dir)
		}
		env::set_var("SHARUN_DIR", &sharun_dir)
	}

	let bin_dir = &format!("{sharun_dir}/bin");
	let shared_dir = &format!("{sharun_dir}/shared");
	let shared_bin = &format!("{shared_dir}/bin");
	let lib = format!("{sharun_dir}/lib");
	let lib32 = format!("{sharun_dir}/lib32");

	let arg0 = PathBuf::from(exec_args.remove(0));
	let arg0_name = arg0.file_name().unwrap_or_default().to_str().unwrap_or_default();
	let arg0_dir = PathBuf::from(dirname(arg0.to_str().unwrap_or_default())).canonicalize()
		.unwrap_or_else(|_|{
			if let Some(which_arg0) = which(arg0_name) {
				which_arg0.parent().unwrap_or_else(||{
					eprintln!("Failed to get ARG0 parrent dir!");
					exit(1)
				}).to_path_buf()
			} else {
				eprintln!("Failed to find ARG0 dir!");
				exit(1)
			}
	});

	let mut arg0_path = arg0_dir.join(arg0_name);
	let arg0_full_path = arg0_path.canonicalize().unwrap_or_default();
	let arg0_full_path_name = arg0_full_path.file_name().unwrap_or_default().to_string_lossy().to_string();
	let mut bin_name = if arg0_path.is_symlink() &&
		arg0_full_path == Path::new(&sharun_dir).join(SHARUN_NAME) {
		arg0_name.into()
	} else if arg0_path.is_symlink() && Path::new(&shared_bin).join(&arg0_full_path_name).exists() {
		arg0_full_path_name
	} else {
		sharun.file_name().unwrap_or_default().to_string_lossy().to_string()
	};
	drop(arg0_dir);
	drop(arg0_full_path);

	if bin_name == SHARUN_NAME {
		if !exec_args.is_empty() {
			match exec_args[0].as_str() {
				"-v" | "--version" => {
					println!("Anylinux-sharun {}", env!("CARGO_PKG_VERSION"));
					return
				}
				"-h" | "--help" => {
					print_usage();
					return
				}
				"-g" | "--gen-lib-path" => {
					for library_path in [lib, lib32] {
						if Path::new(&library_path).exists() {
							let lib_path_file = &format!("{library_path}/lib.path");
							gen_library_path(&library_path, lib_path_file)
						}
					}
					return
				}
				_ => {
					bin_name = exec_args.remove(0);
					let bin_path = PathBuf::from(bin_dir).join(&bin_name);
					if let Ok(bin_full_path) = bin_path.canonicalize() {
						let bin_full_path_name = bin_full_path.file_name().unwrap_or_default().to_string_lossy().to_string();
						if bin_path.is_symlink() && Path::new(&shared_bin).join(&bin_full_path_name).exists() {
							bin_name = bin_full_path_name
						}
						if is_exe(&bin_full_path) {
							add_to_env("PATH", bin_dir);
							match is_script(&bin_path) {
								Ok(true) => {
									if let Err(err) = exec_script(&bin_path, &exec_args) {
										eprintln!("Error executing script: {err}");
										exit(1);
									}
								}
								Ok(false) if is_hardlink(&sharun, &bin_full_path) => {
									let err = Command::new(&bin_path)
										.args(exec_args)
										.exec();
									eprintln!("Error executing file {:?}: {err}", &bin_path);
									exit(1)
								}
								Ok(false) => {
									bin_name = bin_full_path.to_string_lossy().to_string();
									arg0_path = bin_full_path.clone()
								}
								Err(err) => {
									eprintln!("Error reading file {:?}: {err}", &bin_path);
									exit(1)
								}
							}
						}
					}
				}
			}
		} else {
			eprintln!("Specify the executable from: '{bin_dir}'");
			if let Ok(dir) = Path::new(bin_dir).read_dir() {
				for bin in dir.flatten() {
					if is_exe(&bin.path()) {
						println!("{}", bin.file_name().to_str().unwrap_or_default())
					}
				}
			}
			exit(1)
		}
	} else if bin_name == "AppRun" {
		// Sentinel for the kernel-compat probe: a re-exec of this binary with
		// no_new_privs set only checks whether execve works on this kernel, so
		// exit immediately instead of recursing into the AppRun logic.
		if exec_args.iter().any(|arg| arg.as_str() == SHARUN_NNP_PROBE_FLAG) {
			exit(0)
		}
		#[cfg(target_arch = "x86_64")]
		if kernel_compat::enabled() {
			kernel_compat::run_apprun_traced(&sharun_dir, bin_dir, &exec_args);
		}
		apprun::run_as_apprun(&sharun_dir, bin_dir, &exec_args);
	} else if bin_name == "gio-launch-desktop" {
		gio_launch_desktop::run(&exec_args);
	}
	let mut bin = if Path::new(&bin_name).is_absolute() {
		bin_name.clone()
	} else {
		format!("{shared_bin}/{bin_name}")
	};

	if !Path::new(&bin).exists() && !Path::new(&bin_name).is_absolute() {
		if let Ok(true) = is_script(&PathBuf::from(&bin_name)) {
			let err = Command::new(&bin_name).args(exec_args).exec();
			eprintln!("Failed to exec script {bin_name}: {err}");
			exit(1)
		}
		if let Some(path) = which(&bin_name) {
			bin = path.to_string_lossy().to_string()
		} else {
			eprintln!("Failed to find '{bin_name}' in PATH or '{shared_bin}'");
			exit(1)
		}
	}

	let is_elf32_bin = is_elf32(&bin).unwrap_or_else(|err|{
		eprintln!("Failed to check ELF class: {bin}: {err}");
		exit(1)
	});

	let elf_bytes = get_elf(&bin, is_elf32_bin).unwrap_or_else(|err|{
		eprintln!("Failed to read ELF: {}: {err}", &bin);
		exit(1)
	});

	let is_static_bin = is_static_elf(&elf_bytes).unwrap_or(false);

	let mut library_path = if is_elf32_bin {
		lib32
	} else {
		lib
	};

	let unset_envs = read_dotenv(&sharun_dir);

	if get_env_var("SHARUN_ALLOW_LD_PRELOAD") != "1" {
		env::remove_var("LD_PRELOAD")
	}
	env::remove_var("SHARUN_ALLOW_LD_PRELOAD");

	if get_env_var("SHARUN_ALLOW_QT_PLUGIN_PATH") != "1" {
		env::remove_var("QT_PLUGIN_PATH")
	}
	env::remove_var("SHARUN_ALLOW_QT_PLUGIN_PATH");

	let interpreter = if is_static_bin {
		PathBuf::new()
	} else {
		get_interpreter(&library_path).unwrap_or_else(|_|{
			eprintln!("Interpreter not found!");
			exit(1)
		})
	};

	let working_dir = &get_env_var("SHARUN_WORKING_DIR");
	if !working_dir.is_empty() {
		env::set_current_dir(working_dir).unwrap_or_else(|err|{
			eprintln!("Failed to change working directory: {working_dir}: {err}");
			exit(1)
		});
		env::remove_var("SHARUN_WORKING_DIR")
	}

	let mesa_path = get_env_var("SHARUN_MESA_PATH");
	let (mesa_share, mesa_lib): (Option<String>, Option<String>) = if !mesa_path.is_empty() {
		if Path::new(&mesa_path).is_dir() {
			let share = format!("{mesa_path}/share");
			let lib = format!("{mesa_path}/lib");
			env::remove_var("SHARUN_MESA_PATH");
			(Some(share), Some(lib))
		} else {
			eprintln!("WARNING: SHARUN_MESA_PATH points to an invalid location: '{mesa_path}'");
			(None, None)
		}
	} else {
		(None, None)
	};

	let mut lib_path_data = set_appdir_env::setup(bin_dir, &library_path, &sharun_dir, mesa_share.as_deref(), mesa_lib.as_deref());

	if !lib_path_data.is_empty() {
		lib_path_data = lib_path_data.trim().into();
		library_path = lib_path_data
			.replace("\n", ":")
			.replace("+", &library_path)
	}

	drop(lib_path_data);

	// the sharun-preload dir is part of the search path so the --preload
	// flag and the .preload file can use bare names instead of full paths
	let lib_dir = if is_elf32_bin { "lib32" } else { "lib" };
	let preload_dir = &format!("{sharun_dir}/{lib_dir}/sharun-preload");
	if Path::new(preload_dir).is_dir() {
		library_path += &format!(":{preload_dir}");
	}

	let ld_library_path_env = &get_env_var("LD_LIBRARY_PATH");
	if !ld_library_path_env.is_empty() {
		library_path += &format!(":{ld_library_path_env}")
	}

	if let Some(ml) = &mesa_lib {
		if Path::new(ml).is_dir() {
			library_path = format!("{}:{}", ml, library_path);
		}
	}

	let extra_library_path = get_env_var("SHARUN_EXTRA_LIBRARY_PATH");
	if !extra_library_path.is_empty() {
		library_path = format!("{}:{}", extra_library_path, library_path);
		env::remove_var("SHARUN_EXTRA_LIBRARY_PATH");
	}

	if Path::new("/etc/libnvidiacurrent").is_dir() {
		library_path += ":/etc/libnvidiacurrent";
	}

	library_path += ":/usr/local/lib:/usr/lib:/lib";
	if is_elf32_bin {
		library_path += ":/usr/local/lib32:/usr/lib32:/lib32";
		#[cfg(target_arch = "x86_64")]
		{ library_path += ":/usr/lib/i386-linux-gnu" }
	} else {
		library_path += ":/usr/local/lib64:/usr/lib64:/lib64";
		#[cfg(target_arch = "x86_64")]
		{ library_path += ":/usr/lib/x86_64-linux-gnu" }
		#[cfg(target_arch = "aarch64")]
		{ library_path += ":/usr/lib/aarch64-linux-gnu" }
		#[cfg(target_arch = "riscv64")]
		{ library_path += ":/usr/lib/riscv64-linux-gnu" }
		#[cfg(target_arch = "loongarch64")]
		{ library_path += ":/usr/lib/loongarch64-linux-gnu" }
		#[cfg(all(target_arch = "powerpc64", target_endian = "big"))]
		{ library_path += ":/usr/lib/powerpc64-linux-gnu" }
		#[cfg(all(target_arch = "powerpc64", target_endian = "little"))]
		{ library_path += ":/usr/lib/powerpc64le-linux-gnu" }
	}

	let cache_library_path = get_ld_cache_dirs("/etc/ld.so.cache");
	if !cache_library_path.is_empty() {
		library_path += &format!(":{cache_library_path}");
	}

	library_path += ":/run/opengl-driver/lib:/run/current-system/sw/lib";

	let fallback_library_path = get_env_var("SHARUN_FALLBACK_LIBRARY_PATH");
	if !fallback_library_path.is_empty() {
		library_path = format!("{}:{}", library_path, fallback_library_path);
		env::remove_var("SHARUN_FALLBACK_LIBRARY_PATH");
	}

	for var_name in unset_envs {
		env::remove_var(var_name)
	}

	if get_env_var("SHARUN_PRINTENV") == "1" {
		env::remove_var("SHARUN_PRINTENV");
		for (key, value) in env::vars_os() {
			eprintln!("{}={}", key.to_string_lossy(), value.to_string_lossy())
		}
	}

	let _bwrap_keep_fd: Option<std::ffi::c_int> = if bin_name == "bwrap" {
		let path_val = get_env_var("PATH");
		let (new_args, keep_fd) = bwrap_wrapper::process_bwrap_args(
			exec_args, &sharun_dir, &sharun_dir, &path_val
		);
		exec_args = new_args;
		keep_fd
	} else {
		None
	};

	if bin_name == "bwrap" && !Path::new(&format!("{shared_bin}/bwrap")).exists() {
		let hostpath = get_env_var("HOSTPATH");
		let search_path = if !hostpath.is_empty() { hostpath } else { get_env_var("PATH") };
		match bwrap_wrapper::find_system_bwrap(&search_path, &sharun) {
			Some(bwrap_path) => {
				eprintln!("bwrap-wrapper: shared/bin/bwrap not found, using system bwrap: {bwrap_path}");
				let err = Command::new(&bwrap_path).args(&exec_args).exec();
				eprintln!("bwrap-wrapper: failed to exec system bwrap '{bwrap_path}': {err}");
				exit(1);
			}
			None => {
				eprintln!("bwrap-wrapper: bwrap not found in shared/bin or system PATH");
				exit(1);
			}
		}
	}

	let is_patched_bin = is_patched_elf(&bin, &elf_bytes);

	let mut interpreter_args: Vec<CString> = Vec::new();
	if !is_static_bin && !is_patched_bin {
		interpreter_args.append(&mut vec![
			CString::from_str(&interpreter.to_string_lossy()).unwrap_or_default(),
			CString::new("--library-path").unwrap_or_default(),
			CString::new(&*library_path).unwrap_or_default(),
			CString::new("--argv0").unwrap_or_default()
		]);

		if is_elf32_bin {
			interpreter_args.push(CString::new(&*bin).unwrap_or_default())
		} else {
			interpreter_args.push(CString::new(arg0_path.to_str().unwrap_or_default()).unwrap_or_default())
		}

		let preload = read_preload(&sharun_dir, is_elf32_bin);
		if !preload.is_empty() {
			interpreter_args.append(&mut vec![
				CString::new("--preload").unwrap_or_default(),
				CString::new(preload.join(" ")).unwrap_or_default()
			])
		}

		interpreter_args.push(CString::new(&*bin).unwrap_or_default());
		for arg in &exec_args {
			interpreter_args.push(CString::from_str(arg).unwrap_or_default())
		}
	}

	if is_static_bin {
		drop(elf_bytes);
		let err = Command::new(&bin).args(exec_args).exec();
		eprint!("Failed to exec: {bin}: {err}");
		exit(1)
	} else if is_patched_bin || is_elf32_bin {
		let err = if is_patched_bin {
			drop(elf_bytes);
			let temp_ld = "/tmp/.ld-sharun.so.67";
			let tmp_ld = format!("{temp_ld}.{}", std::process::id());
			std::fs::copy(&interpreter, &tmp_ld).unwrap_or_else(|err|{
				eprintln!("Failed to copy interpreter to {tmp_ld}: {err}");
				exit(1)
			});
			let _ = std::fs::set_permissions(&tmp_ld, std::fs::Permissions::from_mode(0o777));
			std::fs::rename(&tmp_ld, &temp_ld).unwrap_or_else(|err|{
				eprintln!("Failed to install interpreter to {temp_ld}: {err}");
				exit(1)
			});
			env::set_var("LD_LIBRARY_PATH", &library_path);
			let preload = read_preload(&sharun_dir, is_elf32_bin);
			if !preload.is_empty() {
				env::set_var("LD_PRELOAD", preload.join(" "));
			}
			Command::new(&bin)
				.args(exec_args)
				.exec()
		} else {
			drop(elf_bytes);
			let interpreter_args: Vec<String> = interpreter_args.iter()
				.map(|s| s.clone().into_string().unwrap_or_default()).skip(1).collect();
			Command::new(interpreter)
				.args(interpreter_args)
				.exec()
		};
		eprint!("Failed to exec: {bin}: {err}");
		exit(1)
	} else {
		drop(elf_bytes);
		let envs: Vec<CString> = env::vars_os()
			.map(|(key, value)| CString::new(
				format!("{}={}", key.to_string_lossy(), value.to_string_lossy())
		).unwrap_or_default()).collect();

		userland_execve::exec(
			interpreter.as_path(),
			&interpreter_args,
			&envs,
		)
	}
}
