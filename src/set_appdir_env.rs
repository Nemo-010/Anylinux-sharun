use std::{
	env,
	path::{Path, PathBuf},
	fs::read_to_string,
};

use walkdir::WalkDir;

use crate::utils::*;

pub fn setup(
	bin_dir: &str,
	library_path: &str,
	sharun_dir: &str,
	mesa_share: Option<&str>,
	mesa_lib: Option<&str>,
) -> String {
	let lib_path_data = set_lib_env(bin_dir, library_path, sharun_dir);
	set_mesa_lib_env(mesa_lib);
	set_share_env(sharun_dir, library_path, mesa_share);
	set_etc_env(sharun_dir);
	lib_path_data
}

// When an external mesa install is in use, point the lib-derived graphics driver
// paths (dir/gbm/vaapi) at it instead. Runs only when SHARUN_MESA_PATH is set
fn set_mesa_lib_env(mesa_lib: Option<&str>) {
	let mesa_lib = match mesa_lib { Some(m) => m, None => return };
	let mesa_dri = format!("{mesa_lib}/dri");
	if Path::new(&mesa_dri).is_dir() {
		env::set_var("LIBGL_DRIVERS_PATH", &mesa_dri);
		add_to_env("LIBVA_DRIVERS_PATH", &mesa_dri);
	}
	let mesa_gbm = format!("{mesa_lib}/gbm");
	if Path::new(&mesa_gbm).is_dir() {
		add_to_env("GBM_BACKENDS_PATH", &mesa_gbm);
	}
}

fn set_lib_env(
	bin_dir: &str,
	library_path: &str,
	sharun_dir: &str,
) -> String {
	let gio_launch_desktop = PathBuf::from(bin_dir).join("gio-launch-desktop");
	if is_exe(&gio_launch_desktop) {
		env::set_var("GIO_LAUNCH_DESKTOP", gio_launch_desktop)
	}
	if let Ok(dir) = PathBuf::from(library_path).read_dir() {
		for entry in dir.flatten() {
			let entry_path = entry.path();
			if entry_path.is_dir() {
				let name = entry.file_name();
				if let Some(name) = name.to_str() {
					if name.starts_with("girepository-") {
						env::set_var("GI_TYPELIB_PATH", entry_path)
					}
				}
			}
		}
	}

	let python_bin = PathBuf::from(bin_dir).join("python");
	let python3_bin = PathBuf::from(bin_dir).join("python3");
	if is_exe(&python_bin) || is_exe(&python3_bin) {
		if get_env_var("PYTHONNOUSERSITE").is_empty() {
			env::set_var("PYTHONNOUSERSITE", "1");
		}
	}

	if let Ok(dir) = Path::new(bin_dir).read_dir() {
		for entry in dir.flatten() {
			if entry.file_name().to_string_lossy().starts_with("WebKit") &&
				is_exe(&entry.path()) {
				env::set_var("WEBKIT_EXEC_PATH", bin_dir);
				break
			}
		}
	}

	let lib_path_file = &format!("{library_path}/lib.path");
	if !Path::new(lib_path_file).exists() && is_writable(library_path) {
		gen_library_path(library_path, lib_path_file)
	}

	add_to_env("PATH", bin_dir);

	let lib_path_data = read_to_string(lib_path_file).unwrap_or_default();

	if !lib_path_data.is_empty() {
		let dirs: std::collections::HashSet<&str> = lib_path_data.split("\n").map(|string|{
			string.split("/").nth(1).unwrap_or("")
		}).collect();
		for dir in dirs {
			let dir_path = &format!("{library_path}/{dir}");
			if dir.starts_with("python") && !is_writable(sharun_dir) {
				env::set_var("PYTHONDONTWRITEBYTECODE", "1")
			}
			if dir.starts_with("perl") {
				add_to_env("PERLLIB", dir_path)
			}
			if dir == "gconv" {
				add_to_env("GCONV_PATH", dir_path)
			}
			if dir == "gio" {
				let modules = &format!("{dir_path}/modules");
				if Path::new(modules).exists() {
					env::set_var("GIO_MODULE_DIR", modules)
				}
			}
			if dir == "dri" {
				env::set_var("LIBGL_DRIVERS_PATH", dir_path);
				if get_env_var("SHARUN_NO_NVIDIA_EGL_PRIME") != "1" &&
					Path::new("/sys/module/nvidia/version").exists() {
						add_to_env("LIBVA_DRIVERS_PATH", "/run/opengl-driver/lib/dri");
						add_to_env("LIBVA_DRIVERS_PATH", "/usr/lib/dri");
						add_to_env("LIBVA_DRIVERS_PATH", "/usr/lib64/dri");
						if let Some(triplet) = multiarch_triplet() {
							add_to_env("LIBVA_DRIVERS_PATH", format!("/usr/lib/{triplet}/dri"))
						}
				}
				add_to_env("LIBVA_DRIVERS_PATH", dir_path)
			}
			if dir == "gbm" {
				add_to_env("GBM_BACKENDS_PATH", "/run/opengl-driver/lib/gbm");
				add_to_env("GBM_BACKENDS_PATH", "/usr/lib/gbm");
				add_to_env("GBM_BACKENDS_PATH", "/usr/lib64/gbm");
				if let Some(triplet) = multiarch_triplet() {
					add_to_env("GBM_BACKENDS_PATH", format!("/usr/lib/{triplet}/gbm"))
				}
				add_to_env("GBM_BACKENDS_PATH", dir_path)
			}
			if dir == "libheif" {
				let plugins = &format!("{dir_path}/plugins");
				if Path::new(plugins).exists() {
					env::set_var("LIBHEIF_PLUGIN_PATH", plugins)
				} else {
					env::set_var("LIBHEIF_PLUGIN_PATH", dir_path)
				}
			}
			if dir == "xtables" {
				env::set_var("XTABLES_LIBDIR", dir_path)
			}
			if dir.starts_with("spa-") {
				env::set_var("SPA_PLUGIN_DIR", dir_path)
			}
			if dir.starts_with("pipewire-") {
				env::set_var("PIPEWIRE_MODULE_DIR", dir_path)
			}
			if dir.starts_with("webkit") {
				for entry in WalkDir::new(dir_path).into_iter().flatten() {
					let path = entry.path();
					if is_file(path) {
						let name = entry.file_name().to_string_lossy();
						if name.starts_with("libwebkit") &&
							name.ends_with("gtkinjectedbundle.so") {
							if let Some(parent) = path.parent() {
								env::set_var("WEBKIT_INJECTED_BUNDLE_PATH", parent);
							}
							break
						}
					}
				}
			}
			if dir.starts_with("gtk-") {
				add_to_env("GTK_PATH", dir_path);
				env::set_var("GTK_EXE_PREFIX", sharun_dir);
				env::set_var("GTK_DATA_PREFIX", sharun_dir);
				for entry in WalkDir::new(dir_path).into_iter().flatten() {
					let path = entry.path();
					if is_file(path) && entry.file_name().to_string_lossy() == "immodules.cache" {
						env::set_var("GTK_IM_MODULE_FILE", path);
						break
					}
				}
			}
			if dir == "folks" {
				for entry in WalkDir::new(dir_path).into_iter().flatten() {
					let path = entry.path();
					if path.is_dir() && entry.file_name().to_string_lossy() == "backends" {
						env::set_var("FOLKS_BACKEND_PATH", path);
						break
					}
				}
			}
			if dir.starts_with("qt") {
				let qt_conf = &format!("{bin_dir}/qt.conf");
				let plugins = &format!("{dir_path}/plugins");
				if Path::new(plugins).exists() && ! Path::new(qt_conf).exists() {
					add_to_env("QT_PLUGIN_PATH", plugins)
				}
			}
			if dir == "imlib2" {
				let loaders = &format!("{dir_path}/loaders");
				let filters = &format!("{dir_path}/filters");
				if Path::new(loaders).exists() {
					env::set_var("IMLIB2_LOADER_PATH", loaders)
				}
				if Path::new(filters).exists() {
					env::set_var("IMLIB2_FILTER_PATH", filters)
				}
			}
			if dir.starts_with("babl-") {
				env::set_var("BABL_PATH", dir_path)
			}
			if dir.starts_with("gegl-") {
				env::set_var("GEGL_PATH", dir_path)
			}
			if dir.starts_with("ImageMagick-") {
				env::set_var("MAGICK_HOME", sharun_dir);
				let mut coders: Option<PathBuf> = None;
				let mut filters: Option<PathBuf> = None;
				for entry in WalkDir::new(dir_path)
					.max_depth(2)
					.into_iter()
					.flatten()
				{
					let path = entry.path();
					if path.is_dir() {
						let name = entry.file_name().to_string_lossy();
						if name == "coders" {
							coders = Some(path.to_path_buf())
						} else if name == "filters" {
							filters = Some(path.to_path_buf())
						}
					}
				}
				if let Some(c) = coders {
					env::set_var("MAGICK_CODER_MODULE_PATH", c)
				}
				if let Some(f) = filters {
					env::set_var("MAGICK_CODER_FILTER_PATH", f)
				}
				let etc_dir = format!("{sharun_dir}/etc");
				if let Ok(entries) = Path::new(&etc_dir).read_dir() {
					for entry in entries.flatten() {
						if entry.file_name().to_string_lossy().starts_with("ImageMagick-") &&
							entry.path().is_dir() {
							env::set_var("MAGICK_CONFIGURE_PATH", entry.path());
							break
						}
					}
				}
			}
			if dir == "libdecor" {
				let plugins = &format!("{dir_path}/plugins-1");
				if Path::new(plugins).exists() {
					env::set_var("LIBDECOR_PLUGIN_DIR", plugins)
				}
			}
			if dir.starts_with("libpeas-") {
				let loaders = &format!("{dir_path}/loaders");
				if Path::new(loaders).exists() {
					env::set_var("PEAS_PLUGIN_LOADERS_DIR", loaders)
				}
			}
			if dir.starts_with("tcl") && Path::new(&format!("{dir_path}/msgs")).exists() {
				add_to_env("TCL_LIBRARY", dir_path);
				let tk = &format!("{library_path}/{}", dir.replace("tcl", "tk"));
				if Path::new(&tk).exists() {
					add_to_env("TK_LIBRARY", tk)
				}
			}
			if dir.starts_with("gstreamer-") {
				add_to_env("GST_PLUGIN_PATH", dir_path);
				add_to_env("GST_PLUGIN_SYSTEM_PATH", dir_path);
				add_to_env("GST_PLUGIN_SYSTEM_PATH_1_0", dir_path);
				let gst_scanner = &format!("{dir_path}/gst-plugin-scanner");
				if Path::new(gst_scanner).exists() {
					env::set_var("GST_PLUGIN_SCANNER", gst_scanner)
				}
			}
			if dir.starts_with("gdk-pixbuf-") {
				let mut is_loaders = false;
				let mut is_loaders_cache = false;
				for entry in WalkDir::new(dir_path).into_iter().flatten() {
					let path = entry.path();
					let name = entry.file_name().to_string_lossy();
					if name == "loaders" && path.is_dir() {
						env::set_var("GDK_PIXBUF_MODULEDIR", path);
						is_loaders = true
					}
					if name == "loaders.cache" && is_file(path) {
						env::set_var("GDK_PIXBUF_MODULE_FILE", path);
						is_loaders_cache = true
					}
					if is_loaders && is_loaders_cache {
						break
					}
				}
			}
			if dir == "ladspa" {
				env::set_var("LADSPA_PATH", dir_path)
			}
			if dir.starts_with("frei0r-") {
				env::set_var("FREI0R_PATH", dir_path)
			}
			if dir.starts_with("mlt-") {
				env::set_var("MLT_REPOSITORY", dir_path)
			}
		}
	}

	lib_path_data
}

// When pipewire is not deployed there is no libasound_module_pcm_pipewire.so
// This means that if the host config defaults to pipewire-alsa
// which is very common on systems that have pipewire, the appimage will try
// to dlopen libasound_module_pcm_pipewire.so and fail.
//
// So we have to fix this issue in these cases:
// * If the host has no /usr/share/alsa/alsa.conf at all, use the bundled
//   alsa config, otherwise libasound has nothing to read and alsa cannot work.
// * If the pipewire alsa plugin is NOT bundled, use the bundled alsa config.
// * If the pipewire alsa plugin IS bundled, use the host alsa config,
//   this way we prevent the reverse issue of alsa using the pipewire plugin
//   on systems that do not have pipewire-alsa at all and would fail to work.
fn is_alsa_plugin_bundled(library_path: &str, plugin: &str) -> bool {
	Path::new(&format!("{library_path}/alsa-lib")).read_dir().is_ok_and(|entries| {
		entries.flatten().any(|entry| {
			entry.file_name().to_string_lossy().contains(plugin)
		})
	})
}

fn set_share_env(sharun_dir: &str, library_path: &str, mesa_share: Option<&str>) {
	let share_dir = PathBuf::from(format!("{sharun_dir}/share"));
	let mesa_share_dir = mesa_share.and_then(|p| {
		if Path::new(p).is_dir() { Some(PathBuf::from(p)) } else { None }
	});
	let using_mesa = mesa_share_dir.is_some();
	let graphics_share = mesa_share_dir.unwrap_or_else(|| share_dir.clone());
	let graphics_share_str = graphics_share.to_string_lossy().to_string();
	let share_exists = share_dir.exists();

	if share_exists || using_mesa {
		add_to_env("XDG_DATA_DIRS", "/etc");
		add_to_env("XDG_DATA_DIRS", "/run/current-system/sw/share");
		add_to_env("XDG_DATA_DIRS", "/run/opengl-driver/share");
		add_to_env("XDG_DATA_DIRS", "/usr/share");
		add_to_env("XDG_DATA_DIRS", "/usr/local/share");
		add_to_env("XDG_DATA_DIRS", format!("{}/.local/share", get_env_var("HOME")));
		if share_exists {
			add_to_env("XDG_DATA_DIRS", &share_dir);
		}
		if using_mesa {
			add_to_env("XDG_DATA_DIRS", &graphics_share_str);
		}
	}
	let xdg_data_dirs = &get_env_var("XDG_DATA_DIRS");

	if share_exists {
		if let Ok(dir) = share_dir.read_dir() {
			for entry in dir.flatten() {
				let entry_path = entry.path();
				if entry_path.is_dir() {
					let name = entry.file_name();
					match name.to_str().unwrap_or_default() {
						"alsa" => {
							let alsa_conf = entry_path.join("alsa.conf");
							if alsa_conf.exists() &&
								!(Path::new("/usr/share/alsa/alsa.conf").exists() &&
								  is_alsa_plugin_bundled(library_path, "pipewire")) {
								env::set_var("ALSA_CONFIG_PATH", alsa_conf)
							}
						}
						"X11" => {
							let xkb = &entry_path.join("xkb");
							if !Path::new("/usr/share/X11/xkb").exists() && xkb.exists() {
								env::set_var("XKB_CONFIG_ROOT", xkb);
								env::set_var("QT_XKB_CONFIG_ROOT", xkb)
							}
							let xlocale = &entry_path.join("locale");
							if !Path::new("/usr/share/X11/locale").exists() && xlocale.exists() {
								env::set_var("XLOCALEDIR", xlocale)
							}
						}
						"libthai" => {
							if entry_path.join("thbrk.tri").exists() {
								env::set_var("LIBTHAI_DICTDIR", entry_path)
							}
						}
						"glib-2.0" => {
							add_to_xdg_data_env(xdg_data_dirs,
								"GSETTINGS_SCHEMA_DIR", "glib-2.0/schemas")
						}
						"terminfo" => {
							env::set_var("TERMINFO", entry_path)
						}
						"locale" => {
							env::set_var("TEXTDOMAINDIR", entry_path)
						}
						"file" => {
							let magic_file = &entry_path.join("misc/magic.mgc");
							if magic_file.exists() {
								env::set_var("MAGIC", magic_file)
							}
						}
						"ghostscript" => {
							let mut gs_base: Option<PathBuf> = None;
							if let Ok(gs_dir) = entry_path.read_dir() {
								for gs_entry in gs_dir.flatten() {
									let gs_init = gs_entry.path().join("Resource").join("Init");
									if gs_init.is_dir() {
										gs_base = Some(gs_entry.path().join("Resource"));
										break
									}
								}
							}
							if gs_base.is_none() {
								let gs_unversioned = entry_path.join("Resource").join("Init");
								if gs_unversioned.is_dir() {
									gs_base = Some(entry_path.join("Resource"))
								}
							}
							if let Some(base) = gs_base {
								env::set_var("GS_LIB", format!("{}:{}",
									base.join("Init").to_string_lossy(),
									base.to_string_lossy()))
							}
						}
						"pipewire" => {
							if !Path::new("/usr/share/pipewire").exists() &&
								env::var_os("PIPEWIRE_CONFIG_DIR").is_none() {
									env::set_var("PIPEWIRE_CONFIG_DIR", entry_path)
							}
						}
						mlt if mlt.starts_with("mlt-") => {
							let profiles = entry_path.join("profiles");
							let presets = entry_path.join("presets");
							if profiles.exists() {
								env::set_var("MLT_PROFILES_PATH", profiles)
							}
							if presets.exists() {
								env::set_var("MLT_PRESETS_PATH", presets)
							}
						}
						_ => {}
					}
				}
			}
		}
	}

	if graphics_share.exists() {
		if let Ok(dir) = graphics_share.read_dir() {
			for entry in dir.flatten() {
				let entry_path = entry.path();
				if entry_path.is_dir() {
					let name = entry.file_name();
					match name.to_str().unwrap_or_default() {
						"glvnd" => {
							if get_env_var("SHARUN_NO_NVIDIA_EGL_PRIME") != "1" &&
							   Path::new("/sys/module/nvidia/version").exists() &&
							   get_env_var("__EGL_VENDOR_LIBRARY_FILENAMES").is_empty() {
							   let mut xdg_json_paths = Vec::new();
							   for xdg_data_dir in xdg_data_dirs.split(":") {
								   let egl_vendor = Path::new(xdg_data_dir).join("glvnd/egl_vendor.d");
								   let mut paths = collect_json_files(&egl_vendor);
								   xdg_json_paths.append(&mut paths)
							   }
							   let nvidia_json = xdg_json_paths.iter()
								   .find(|p| p.file_name().unwrap_or_default().to_string_lossy().contains("nvidia"));
							   if let Some(nvidia_path) = nvidia_json {
								   let mut all_paths = Vec::new();
								   all_paths.push(nvidia_path.clone());
								   for path in xdg_json_paths.iter() {
									   if !path.file_name().unwrap_or_default().to_string_lossy().contains("nvidia") {
										   all_paths.push(path.clone())
									   }
								   }
								   if !all_paths.is_empty() {
									   let paths_str = all_paths.iter()
										   .map(|p| p.to_string_lossy())
										   .collect::<Vec<_>>()
										   .join(":");
									   env::set_var("__EGL_VENDOR_LIBRARY_FILENAMES", &paths_str)
								   }
							   }
						   }
							add_to_xdg_data_env(xdg_data_dirs,
								"__EGL_VENDOR_LIBRARY_DIRS", "glvnd/egl_vendor.d")
						}
						"vulkan" => {
							let vk_dir = "vulkan/icd.d";
							let vk_env = "VK_DRIVER_FILES";
							let sys_vkicd = get_env_var("SHARUN_ALLOW_SYS_VKICD");
							if sys_vkicd == "1" {
								env::remove_var("SHARUN_ALLOW_SYS_VKICD");
								add_to_xdg_data_env(xdg_data_dirs, vk_env, vk_dir)
							} else {
								// host icds are only used as fallback, they are
								// disabled entirely with SHARUN_ALLOW_SYS_VKICD=0.
								// nouveau is not bundled by default, use the host
								// one unless it was bundled explicitly. lavapipe
								// is deliberately not exposed from the host.
								let use_host_icds = sys_vkicd != "0";
								let bundled_icds = collect_json_files(&graphics_share.join(vk_dir));
								let has_nouveau = bundled_icds.iter().any(|p| {
									p.file_name().unwrap_or_default().to_string_lossy().contains("nouveau")
								});
								for xdg_data_dir in xdg_data_dirs.rsplit(":") {
									let vk_icd_dir = Path::new(xdg_data_dir).join(vk_dir);
									if vk_icd_dir.exists() {
										if xdg_data_dir.starts_with(graphics_share_str.as_str()) {
											add_to_env(vk_env, vk_icd_dir);
										} else if let Ok(dir) = vk_icd_dir.read_dir() {
											for entry in dir.flatten() {
												let path = entry.path();
												let name = entry.file_name().to_string_lossy().to_string();
												if use_host_icds && is_file(&path) &&
													(name.contains("nvidia") ||
													(!has_nouveau && name.contains("nouveau"))) {
													add_to_env(vk_env, path)
												}
											}
										}
									}
								}
							}
						}
						"drirc.d" => {
							let sys_drirc_dir = Path::new("/usr/share/drirc.d");
							if !sys_drirc_dir.exists() {
								env::set_var("DRIRC_CONFIGDIR", entry_path)
							}
						}
						"libdrm" => {
							add_to_env("AMDGPU_ASIC_ID_TABLE_PATHS", entry_path);
							add_to_env("AMDGPU_ASIC_ID_TABLE_PATHS", "/usr/share/libdrm");
							add_to_env("AMDGPU_ASIC_ID_TABLE_PATHS", "/usr/local/share/libdrm")
						}
						_ => {}
					}
				}
			}
		}
	}
}

fn set_etc_env(sharun_dir: &str) {
	let etc_dir = PathBuf::from(format!("{sharun_dir}/etc"));
	if etc_dir.exists() {
		if let Ok(dir) = etc_dir.read_dir() {
			for entry in dir.flatten() {
				let entry_path = entry.path();
				if entry_path.is_dir() {
					let name = entry.file_name();
					match name.to_str().unwrap_or_default() {
						"fonts" => {
							let fonts_conf = entry_path.join("fonts.conf");
							if !Path::new("/etc/fonts/fonts.conf").exists() && fonts_conf.exists() {
								env::set_var("FONTCONFIG_FILE", fonts_conf)
							}
						}
						"ssl" => {
							let openssl_conf = entry_path.join("openssl.cnf");
							if openssl_conf.exists() {
								env::set_var("OPENSSL_CONF", openssl_conf)
							}
						}
						_ => {}
					}
				}
			}
		}
	}

	if !Path::new("/etc/ssl/certs/ca-certificates.crt").exists() {
		let possible_certs = [
			"/etc/pki/tls/cert.pem",
			"/etc/pki/tls/cacert.pem",
			"/etc/ssl/cert.pem",
			"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
			"/var/lib/ca-certificates/ca-bundle.pem",
		];

		if let Some(found_cert) = possible_certs.iter().find(|&&path| Path::new(path).exists()) {
			for var_name in ["REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE"].iter() {
				if env::var_os(var_name).is_none() {
					env::set_var(var_name, found_cert);
				}
			}
		} else {
			eprintln!("WARNING: Cannot find CA Certificates in host!");
		}
	}
}
