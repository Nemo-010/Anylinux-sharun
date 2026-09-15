use std::{
	collections::HashSet,
	env,
	path::{Path, PathBuf},
	ffi::OsStr,
	process::{Command, exit},
	fs::{File, write, read_to_string, read, read_dir},
	os::unix::{fs::{MetadataExt, PermissionsExt}, process::CommandExt},
	io::{Read, Result, Error, BufRead, BufReader, ErrorKind::{InvalidData, NotFound}}
};

use walkdir::WalkDir;
use nix::unistd::{access, AccessFlags};
use goblin::elf::Elf;


pub fn get_interpreter(library_path: &str, is_elf32: bool) -> Result<PathBuf> {
	let mut interpreters = Vec::new();
	if let Ok(ldname) = env::var("SHARUN_LDNAME") {
		if !ldname.is_empty() {
			interpreters.push(ldname)
		}
	} else {
		#[cfg(target_arch = "x86_64")]          // target x86_64-unknown-linux-musl
		if is_elf32 {
			interpreters.append(&mut vec!["ld-linux.so.2".into()]);
		} else {
			interpreters.append(&mut vec![
				"ld-linux-x86-64.so.2".into(),
				"ld-musl-x86_64.so.1".into()
			]);
		}
		#[cfg(target_arch = "aarch64")]         // target aarch64-unknown-linux-musl
		interpreters.append(&mut vec![
			"ld-linux-aarch64.so.1".into(),
			"ld-musl-aarch64.so.1".into()
		]);
		#[cfg(target_arch = "riscv64")]         // target riscv64gc-unknown-linux-musl
		interpreters.append(&mut vec![
			"ld-linux-riscv64-lp64d.so.1".into(),
			"ld-musl-riscv64.so.1".into()
		]);
		#[cfg(target_arch = "loongarch64")]     // target loongarch64-unknown-linux-musl
		interpreters.append(&mut vec![
			"ld-linux-loongarch-lp64d.so.1".into(),
			"ld-musl-loongarch64.so.1".into()
		]);
		#[cfg(target_arch = "powerpc64")]       // targets powerpc64{,le}-unknown-linux-musl
		interpreters.append(&mut vec![
			"ld64.so.1".into(),                 // glibc ELFv1 (Debian ppc64, ...)
			"ld64.so.2".into(),                 // glibc ELFv2 (Arch Linux PPC, ppc64le, ...)
			"ld-musl-powerpc64.so.1".into(),
			"ld-musl-powerpc64le.so.1".into()
		]);
	}
	for interpreter in interpreters {
		let interpreter_path = Path::new(library_path).join(interpreter);
		if interpreter_path.exists() {
			return Ok(interpreter_path)
		}
	}
	Err(Error::last_os_error())
}

pub fn realpath(path: &str) -> String {
	Path::new(path).canonicalize().unwrap_or_default().to_str().unwrap_or_default().to_string()
}

pub fn basename(path: &str) -> String {
	let pieces: Vec<&str> = path.rsplit('/').collect();
	pieces.first().unwrap_or(&"").to_string()
}

pub fn dirname(path: &str) -> String {
	let mut pieces: Vec<&str> = path.split('/').collect();
	if pieces.len() == 1 || path.is_empty() {
		// return ".".to_string();
	} else if !path.starts_with('/') &&
		!path.starts_with('.') &&
		!path.starts_with('~') {
			pieces.insert(0, ".");
	} else if pieces.len() == 2 && path.starts_with('/') {
		pieces.insert(0, "");
	};
	pieces.pop();
	pieces.join(&'/'.to_string())
}

pub fn is_hardlink(path1: &Path, path2: &Path) -> bool {
	if let Ok(metadata1) = path1.metadata() {
		if let Ok(metadata2) = path2.metadata() {
			return metadata1.ino() == metadata2.ino()
		}
	}
	false
}

pub fn is_same_rootdir(rootdir: &Path, path1: &Path, path2: &Path) -> bool {
	if let Ok(abs_path1) = path1.canonicalize() {
		if let Ok(abs_path2) = path2.canonicalize() {
			if let Ok(abs_rootdir) = &rootdir.canonicalize() {
				return abs_path1.starts_with(abs_rootdir) && abs_path2.starts_with(abs_rootdir)
			}
		}
	}
	false
}

pub fn is_writable(path: &str) -> bool {
	access(path, AccessFlags::W_OK).is_ok()
}

pub fn is_dir(path: &str) -> bool {
	Path::new(path).is_dir()
}

pub fn is_file(path: &Path) -> bool {
	if let Ok(metadata) = path.metadata() {
		return metadata.is_file()
	}
	false
}

pub fn is_exe(path: &Path) -> bool {
	if let Ok(metadata) = path.metadata() {
		return metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
	}
	false
}

pub fn which(executable: &str) -> Option<PathBuf> {
	if let Ok(path) = env::var("PATH") {
		for dir in path.split(':') {
			let full_path = Path::new(dir).join(executable);
			if is_exe(&full_path) {
				return Some(full_path)
			}
		}
	}
	None
}

pub fn find_shell() -> Option<PathBuf> {
	let candidates = [
		PathBuf::from("/bin/sh"),
		PathBuf::from("/bin/bash"),
		PathBuf::from("/usr/bin/sh"),
		PathBuf::from("/usr/bin/bash"),
	];
	for candidate in candidates {
		if is_exe(&candidate) {
			return Some(candidate);
		}
	}
	for name in ["sh", "bash"] {
		if let Some(path) = which(name) {
			return Some(path);
		}
	}
	None
}

pub fn is_script(path: &PathBuf) -> Result<bool> {
	let mut file = File::open(path)?;
	let mut buffer = [0; 2];
	file.read_exact(&mut buffer)?;
	Ok(&buffer[0..2] == b"#!")
}

pub fn read_first_line(path: &PathBuf) -> Result<String> {
	let file = File::open(path)?;
	let mut reader = BufReader::new(file);
	let mut line = String::new();
	reader.read_line(&mut line)?;
	Ok(line)
}

pub fn exec_script(path: &PathBuf, exec_args: &[String]) -> Result<()> {
	let first_line = read_first_line(path)?;
	if !first_line.starts_with("#!") {
		return Err(Error::new(NotFound, "Script does not have a valid shebang!"))
	}
	let shebang = first_line[2..].trim();
	let parts: Vec<&str> = shebang.split_whitespace().collect();
	if parts.is_empty() {
		return Err(Error::new(NotFound, "Invalid shebang: no interpreter specified!"))
	}
	let interpreter_path = parts[0];
	let mut command = if interpreter_path.ends_with("/env") {
		if parts.len() < 2 {
			return Err(Error::new(NotFound, "No interpreter specified after env!"))
		}
		let interpreter = parts[1];
		let interpreter_path = match which(interpreter) {
			Some(path) => path,
			None => return Err(Error::new(NotFound,
				format!("Interpreter '{interpreter}' not found in PATH"))
			)
		};
		let mut command = Command::new(&interpreter_path);
		for arg in &parts[2..] {
			command.arg(arg);
		}
		command
	} else {
		let interpreter_name = Path::new(interpreter_path)
			.file_name()
			.unwrap_or_default()
			.to_string_lossy()
			.to_string();
		let interpreter_path = match which(&interpreter_name) {
			Some(path) => path,
			None => PathBuf::from(interpreter_path)
		};
		if !interpreter_path.exists() {
			return Err(Error::new(NotFound,
				format!("Interpreter '{}' not found", interpreter_path.display()))
			)
		}
		let mut command = Command::new(&interpreter_path);
		for arg in &parts[1..] {
			command.arg(arg);
		}
		command
	};
	let err = command.arg(path).args(exec_args).exec();
	Err(Error::new(InvalidData, err))
}

pub fn is_elf32(path: &String) -> Result<bool> {
	let mut file = File::open(path)?;
	let mut elf_bytes = [0; 5];
	file.read_exact(&mut elf_bytes)?;
	if &elf_bytes[0..4] != b"\x7fELF" {
		return Ok(false)
	}
	Ok(elf_bytes[4] == 1)
}

pub fn get_elf(path: &String, is_elf32: bool) -> Result<Vec<u8>> {
	let mut file = File::open(path)?;
	if is_elf32 {
		let mut headers_bytes = Vec::new();
		file.read_to_end(&mut headers_bytes)?;
		Ok(headers_bytes)
	} else {
		let mut elf_header_raw = [0; 64];
		file.read_exact(&mut elf_header_raw)?;
		// e_shoff and e_shnum are stored in the file endianness, EI_DATA
		// at byte 5 of e_ident tells which one it is (2 = big endian)
		let (section_table_offset, section_count) = if elf_header_raw[5] == 2 {
			(
				u64::from_be_bytes(elf_header_raw[40..48].try_into().unwrap_or_default()),
				u16::from_be_bytes(elf_header_raw[60..62].try_into().unwrap_or_default()),
			)
		} else {
			(
				u64::from_le_bytes(elf_header_raw[40..48].try_into().unwrap_or_default()),
				u16::from_le_bytes(elf_header_raw[60..62].try_into().unwrap_or_default()),
			)
		}; // e_shoff, e_shnum
		let section_table_size = section_count as u64 * 64;
		let required_bytes = section_table_offset + section_table_size;
		let mut headers_bytes = vec![0; required_bytes as usize];
		std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(0))?;
		file.read_exact(&mut headers_bytes)?;
		Ok(headers_bytes)
	}
}

pub fn is_patched_elf(path: &str, elf_bytes: &[u8]) -> bool {
	use goblin::{elf::{Elf, program_header::{ProgramHeader, PT_INTERP}}, container::Ctx};
	use std::os::unix::fs::FileExt;
	let Some(header) = Elf::parse_header(elf_bytes).ok() else { return false };
	let ctx = Ctx::new(header.container().unwrap_or_default(), header.endianness().unwrap_or_default());
	let Some(phdr) = ProgramHeader::parse(elf_bytes, header.e_phoff as usize, header.e_phnum as usize, ctx)
		.ok().and_then(|phdrs| phdrs.into_iter().find(|ph| ph.p_type == PT_INTERP))
	else { return false };
	// patchelf may append the interpreter string at EOF, so read it from the file
	let mut interp = vec![0; phdr.p_filesz.min(4096) as usize];
	std::fs::File::open(path).ok()
		.and_then(|f| f.read_exact_at(&mut interp, phdr.p_offset).ok())
		.is_some_and(|_| interp.starts_with(b"/tmp/.ld-sharun.so"))
}

pub fn is_static_elf(elf_bytes: &[u8]) -> Result<bool> {
	if let Ok(elf) = Elf::parse(elf_bytes) {
		return Ok(!elf.program_headers.iter()
			.any(|ph| ph.p_type == goblin::elf::program_header::PT_INTERP))
	}
	Ok(false)
}

pub fn get_env_var<K: AsRef<OsStr>>(key: K) -> String {
	env::var(key).unwrap_or_default()
}

pub fn add_to_env<K: AsRef<OsStr>, V: AsRef<OsStr>>(key: K, val: V) {
	let (key, val) = (key.as_ref(), val.as_ref().to_str().unwrap_or_default());
	let old_val = get_env_var(key);
	if old_val.is_empty() {
		env::set_var(key, val)
	} else if old_val != val &&
	  !old_val.starts_with(&format!("{val}:")) &&
	  !old_val.ends_with(&format!(":{val}")) &&
	  !old_val.contains(&format!(":{val}:")) {
		env::set_var(key, format!("{val}:{old_val}"))
	}
}

pub fn expand_vars(val: &str) -> String {
	let mut out = String::new();
	let mut rest = val;
	while let Some(start) = rest.find('$') {
		out.push_str(&rest[..start]);
		rest = &rest[start + 1..];
		if let Some(stripped) = rest.strip_prefix('{') {
			if let Some(end) = stripped.find('}') {
				let name = &stripped[..end];
				out.push_str(&env::var(name).unwrap_or_else(|_| format!("${{{name}}}")));
				rest = &stripped[end + 1..];
				continue
			}
		} else {
			let end = rest.find(|c: char| !c.is_ascii_alphanumeric() && c != '_').unwrap_or(rest.len());
			if end > 0 {
				let name = &rest[..end];
				out.push_str(&env::var(name).unwrap_or_else(|_| format!("${name}")));
				rest = &rest[end..];
				continue
			}
		}
		out.push('$');
	}
	out.push_str(rest);
	out
}

pub fn read_dotenv(dotenv_dir: &str) -> Vec<String> {
	let mut unset_envs = Vec::new();
	let dotenv_path = PathBuf::from(format!("{dotenv_dir}/.env"));
	if dotenv_path.exists() {
		let data = read_to_string(&dotenv_path).unwrap_or_else(|err|{
			eprintln!("Failed to read .env file: {}: {err}", dotenv_path.display());
			exit(1)
		});
		for line in data.lines() {
			let line = line.trim();
			if line.is_empty() || line.starts_with('#') {
				continue
			}
			if line.starts_with("unset ") {
				for var_name in line.split_whitespace().skip(1) {
					unset_envs.push(var_name.into());
				}
				continue
			}
			let line = line.strip_prefix("export ").unwrap_or(line);
			if let Some((key, val)) = line.split_once('=') {
				let key = key.trim();
				let val = val.trim();
				let (val, expand) = if let Some(v) = val.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')) {
					(v.to_string(), false)
				} else if let Some(v) = val.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
					(v.to_string(), true)
				} else {
					(val.to_string(), true)
				};
				let val = if expand { expand_vars(&val) } else { val };
				if !key.is_empty() {
					env::set_var(key, &val);
				}
			}
		}
	}
	unset_envs
}

pub fn read_preload(sharun_dir: &str, is_lib32_bin: bool) -> Vec<String> {
	let mut preload: Vec<String> = Vec::new();

	// the classic .preload file with the names of the libraries to preload
	let preload_path = PathBuf::from(format!("{sharun_dir}/.preload"));
	if preload_path.exists() {
		let data = read_to_string(&preload_path).unwrap_or_else(|err|{
			eprintln!("Failed to read .preload file: {}: {err}", preload_path.display());
			exit(1)
		});
		preload.extend(
			data.trim().split("\n")
				.map(|s| s.trim().into())
				.filter(|s: &String| !s.is_empty())
		);
	}

	// every library found in $SHARUN_DIR/lib{,32}/sharun-preload is
	// preloaded automatically, no need to keep a .preload file with the
	// names. The name is sharun specific on purpose to prevent collisions
	// with apps that have their own 'preload' dir with unrelated content
	let lib_dir = if is_lib32_bin { "lib32" } else { "lib" };
	let preload_dir = PathBuf::from(format!("{sharun_dir}/{lib_dir}/sharun-preload"));
	if preload_dir.is_dir() {
		let mut libs: Vec<String> = read_dir(&preload_dir).unwrap_or_else(|err| {
			eprintln!("Failed to read '{lib_dir}/sharun-preload/' dir: {preload_dir:?}: {err}");
			exit(1)
		})
		.filter_map(|entry| entry.ok())
		.filter(|entry| {
			entry.path().is_file() && {
				let name = entry.file_name().to_owned().into_string().unwrap_or_default();
				name.ends_with(".so") || name.contains(".so.")
			}
		})
		.map(|entry| entry.file_name().to_owned().into_string().unwrap_or_default())
		.collect();
		libs.sort();
		preload.extend(libs);
	}

	// path-mapping.so is shipped together with the other helper libraries
	// but is only useful when PATH_MAPPING is set, keep it out otherwise
	if get_env_var("PATH_MAPPING").is_empty() {
		preload.retain(|lib| basename(lib) != "path-mapping.so");
	}

	preload
}

pub fn add_to_xdg_data_env(xdg_data_dirs: &str, env: &str, path: &str) {
	for xdg_data_dir in xdg_data_dirs.rsplit(":") {
		let env_data_dir = Path::new(xdg_data_dir).join(path);
		if env_data_dir.exists() {
			add_to_env(env, env_data_dir)
		}
	}
}

pub fn gen_library_path(library_path: &str, lib_path_file: &String) {
	let mut new_paths: Vec<String> = Vec::new();
	let skip_dirs = ["lib-dynload".to_string()];
	WalkDir::new(library_path)
		.into_iter()
		.filter_map(|entry| entry.ok())
		.for_each(|entry| {
			let name = entry.file_name().to_string_lossy();
			if name.ends_with(".so") || name.contains(".so.") {
				if let Some(parent) = entry.path().parent() {
					if let Some(parent_str) = parent.to_str() {
						if parent_str != library_path && parent.is_dir() &&
							!new_paths.contains(&parent_str.into()) &&
							!skip_dirs.contains(&basename(parent_str)) {
							new_paths.push(parent_str.into());
						}
					}
				}
			}
		});
	if let Err(err) = write(lib_path_file,
		format!("+:{}", &new_paths.join(":"))
			.replace(":", "\n")
			.replace(library_path, "+")
	) {
		eprintln!("Failed to write lib.path: {lib_path_file}: {err}");
		exit(1)
	} else {
		eprintln!("Write lib.path: {lib_path_file}")
	}
}

pub fn collect_json_files(dir: &Path) -> Vec<PathBuf> {
	let mut json_paths = Vec::new();
	if dir.exists() {
		if let Ok(entries) = dir.read_dir() {
			for entry in entries.flatten() {
				let path = entry.path();
				if path.extension().is_some_and(|ext| ext == "json") &&
				   path.exists() { json_paths.push(path) }
			}
		}
	}
	json_paths
}

pub fn get_ld_cache_dirs(cache_file: &str) -> String {
	let Ok(data) = read(cache_file) else { return String::new() };
	let mut seen: HashSet<&[u8]> = HashSet::new();
	let mut dirs: Vec<&[u8]> = Vec::new();
	let len = data.len();
	let mut i = 0;
	while i < len {
		while i < len && (data[i] < 0x20 || data[i] > 0x7e) { i += 1 }
		let start = i;
		while i < len && !(data[i] < 0x20 || data[i] > 0x7e) { i += 1 }
		if start < len && data[start] == b'/' {
			let chunk = &data[start..i];
			if let Some(pos) = chunk.iter().rposition(|&c| c == b'/') {
				if pos > 0 && seen.insert(&chunk[..pos]) {
					dirs.push(&chunk[..pos]);
				}
			}
		}
	}
	dirs.sort_unstable();
	let mut out = String::new();
	for dir in dirs {
		let Ok(dir) = core::str::from_utf8(dir) else { continue };
		if !Path::new(dir).is_dir() { continue }
		if !out.is_empty() { out.push(':') }
		out.push_str(dir);
	}
	out
}

#[cfg(test)]
mod tests {
	use super::get_elf;

	// minimal ELF64 file, a two entry section table sits at the end and
	// e_shoff/e_shnum are written in the requested endianness, get_elf
	// must read those two fields in the matching byte order
	fn elf64(be: bool) -> Vec<u8> {
		let mut b = vec![0u8; 192];
		b[0..4].copy_from_slice(b"\x7fELF");
		b[4] = 2; // ELFCLASS64
		b[5] = if be { 2 } else { 1 }; // ELFDATA2MSB / ELFDATA2LSB
		b[6] = 1; // EV_CURRENT
		let (shoff, shnum) = (64u64, 2u16);
		let (shoff_be, shnum_be) = (shoff.to_be_bytes(), shnum.to_be_bytes());
		let (shoff_le, shnum_le) = (shoff.to_le_bytes(), shnum.to_le_bytes());
		if be {
			b[40..48].copy_from_slice(&shoff_be);
			b[60..62].copy_from_slice(&shnum_be);
		} else {
			b[40..48].copy_from_slice(&shoff_le);
			b[60..62].copy_from_slice(&shnum_le);
		}
		b
	}

	#[test]
	fn get_elf_little_endian() {
		let path = std::env::temp_dir().join("sharun-test-elf64le");
		std::fs::write(&path, elf64(false)).unwrap();
		let bytes = get_elf(&path.to_string_lossy().to_string(), false).unwrap();
		assert_eq!(bytes.len(), 192);
		std::fs::remove_file(&path).unwrap();
	}

	#[test]
	fn get_elf_big_endian() {
		let path = std::env::temp_dir().join("sharun-test-elf64be");
		std::fs::write(&path, elf64(true)).unwrap();
		let bytes = get_elf(&path.to_string_lossy().to_string(), false).unwrap();
		assert_eq!(bytes.len(), 192);
		std::fs::remove_file(&path).unwrap();
	}
}
