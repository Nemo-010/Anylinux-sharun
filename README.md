# Anylinux-sharun

Fork of [VHSgunzo/sharun](https://github.com/VHSgunzo/sharun). Run dynamically linked ELF binaries everywhere (musl and glibc).

This fork is used by the [Anylinux-AppImages](https://github.com/pkgforge-dev/Anylinux-AppImages) project. It is intended for AppImage deployment only.

## What this fork adds

- **Extra architectures**: Builds for `riscv64`, `loongarch64`, `powerpc64` (big-endian) and `ppc64le` in addition to `x86_64` and `aarch64`. Uses a forked [userland-execve](https://github.com/pkgforge-dev/userland-execve-rust) with support for these architectures.

- **`SHARUN_MESA_PATH`**: Point to an external mesa installation (with `lib/` and `share/` subdirs). **Allows switching mesa versions at runtime.**

- **bwrap-wrapper**: When `sharun` is invoked as `bwrap`, it intercepts `bwrap` arguments to preserve essential paths and env variables (`$APPDIR`, `/tmp`, `/proc`, `$SHARUN_DIR`, `$PATH`). Rewrites hardcoded command paths to their AppDir equivalents. Falls back to system `bwrap` if real bwrap wasn't deployed. This lets applications that sandbox themselves with bwrap (example WebKitGTK) work correctly as AppImage.

- **`gio-launch-desktop` handler**: When `sharun` is hardlinked as `gio-launch-desktop`, it sets `GIO_LAUNCHED_DESKTOP_FILE_PID` and launches the target. Required for AppImages that rely on GIO-based `.desktop` file launching.

- **`AppRun.sh` support**: If an `AppRun.sh` exists in the sharun directory and sharun is hardlink as the `AppRun`, it executes `AppRun.sh` using any `sh`/`bash` found in `PATH` or the AppDir, **removes hard `/bin/sh` dependency from `AppRun`.**

- **Old kernel compatibility layer** (`x86_64` only): Runs AppImages built against a modern glibc on kernels far older than that glibc assumes, down to **Linux 2.6.17** (Ubuntu 6.10). Modern glibc (e.g. the `--enable-kernel=4.4` Arch build) both executes instructions old kernels do not support and calls syscalls that do not exist yet. The layer catches the resulting `SIGILL` and emulates the instruction (`XGETBV` etc.), and handles the offending syscalls at trace time. Most are rewritten to an older equivalent; the ones no single older call can answer are emulated with a short sequence of calls made inside the traced process. Each is gated on a one-time probe, or on the kernel version when there is nothing reliable to probe:

  - `FUTEX_WAIT_BITSET`/`FUTEX_WAKE_BITSET` (2.6.25) to `FUTEX_WAIT`/`FUTEX_WAKE`, and `FUTEX_CLOCK_REALTIME` waits (2.6.29) to plain ones with a relative timeout: on 2.6.25-2.6.28 a realtime wait is rejected with `EINVAL`, which glibc answers with `futex_fatal_error()` instead of falling back.
  - `pipe2` (2.6.27) to `pipe`.
  - `statx` (4.11) to `newfstatat`/`fstat`, translating `struct stat` back to `struct statx` (Qt6 has no fallback when `statx` fails).
  - `getrandom` (3.17) filled from `/dev/urandom` (some kernels answer it with their own syscall number, which makes Rust's std panic).
  - `ppoll` (2.6.19; the x86_64 number was reserved in 2.6.16 but only wired up in 2.6.19) to `poll`.
  - `epoll_pwait` (2.6.19) emulated as `rt_sigprocmask` + `epoll_wait` + `rt_sigprocmask`, so the caller's signal mask is in force during the wait and put back afterwards, including when the wait fails. Dropping the mask instead loses wakeups the application is waiting for.
  - `epoll_create1` (2.6.27) to `epoll_create`.
  - `prlimit64` (2.6.36) to `getrlimit`/`setrlimit` for the calling process (modern glibc has no 32-bit fallback, so the runtime's stack and file-descriptor limit lookups fail outright).
  - `pwritev`/`preadv` (2.6.30) emulated as `lseek` + `writev`/`readv` (Bun writes buffered output through the offset form).
  - `F_DUPFD_CLOEXEC` (2.6.24) to `F_DUPFD` plus `FD_CLOEXEC` (Bun builds its lazy `stdout`/`stderr` getters this way).
  - `eventfd`/`eventfd2` (2.6.22/2.6.27) emulated with a self-connected `AF_UNIX` socket, and `timerfd_create`/`timerfd_settime`/`timerfd_gettime` (2.6.25) with a pipe the tracer writes to when a deadline passes (the timerfd shape needs `/proc` mounted for the traced process, the eventfd one does not).
  - the termios2 ioctls `TCGETS2`/`TCSETS2`/`TCSETSW2`/`TCSETSF2` (2.6.20) to `TCGETS`/`TCSETS*`, decoding the line speed out of `c_cflag` for the read side (Bun probes with `TCGETS2`, and concludes there is no terminal when it fails).
  - clock ids the kernel predates (`CLOCK_MONOTONIC_RAW` 2.6.28, `CLOCK_REALTIME_COARSE`/`CLOCK_MONOTONIC_COARSE` 2.6.32, `CLOCK_BOOTTIME` 2.6.39) to the closest clock it has.
  - `ENOSYS` is forced for newer syscalls a pre-2.6.19 kernel answers with its own syscall number instead of failing (`rseq`, `clone3`, `openat2`, `faccessat2`, `signalfd`/`signalfd4`, `accept4`, `dup3`, `inotify_init1`, and any other number above its syscall table). Calls the layer translated are left alone, since their result is the real one.

  It is enabled automatically on kernels older than 4.0 or when `statx` is missing; set `SHARUN_OLD_KERNEL_COMPAT=1` to force it on and `=0` to disable. It supports no 32-bit application: a 32-bit process is traced but never translated, so an application that runs 32-bit binaries gets nothing from this layer and pays for the tracing. There is no AppDir-level test for it -- the per-tracee check is what keeps a 32-bit process out of the rewrite tables, wherever it came from. `SHARUN_OLD_KERNEL_COMPAT_DEBUG=1` prints each translation to stderr; `SHARUN_OLD_KERNEL_COMPAT_DEBUG_ALL=1` also prints every syscall and its result, which produces tens of megabytes in seconds and slows the traced program down enough to change its timing. While an emulation is running the layer holds back any signal that arrives, so application code cannot run in the middle of it, and delivers it when the emulation is done. On kernels with seccomp-bpf (3.5+) only the affected syscalls are intercepted, but seccomp mode sets `no_new_privs`, so setuid helpers cannot gain privileges; older kernels fall back to tracing every syscall with ptrace, which is much slower. The tracer is only installed from `AppRun`, never from the `bin/*` hardlinks. Kernels older than 2.6.16 cannot be supported because the AppImage runtime itself needs the `*at` syscalls (for example `openat`).

- **Directory structure**: Uses `lib`/`lib32` directly instead of `shared/lib`/`shared/lib32`. Fixes libraries that look for a relative `../share` directory and can't find it.

- **Additional env vars**: Auto sets `LADSPA_PATH`, `FREI0R_PATH`, `MLT_REPOSITORY`, `MLT_PROFILES_PATH`, `MLT_PRESETS_PATH`, `GS_LIB`, `OPENSSL_CONF`, `QT_XKB_CONFIG_ROOT`, `PEAS_PLUGIN_LOADERS_DIR` and likely more in the future.

- **Bun workaround**: Detects Bun binaries and uses alternative execution paths so they run correctly via temp dynamic linker in `/tmp`. (These break when executed with the dynamic linker directly).

- **`sharun-preload` dir**: Every library found in `$SHARUN_DIR/lib/sharun-preload/` (or `lib32/sharun-preload/` for 32-bit binaries) is preloaded automatically, no `.preload` file needed. The classic `.preload` file method keeps working and its entries are resolved by name, so it can also reference libraries that live inside `sharun-preload/`. Files that are not `*.so` are ignored, and `path-mapping.so` is only preloaded when `PATH_MAPPING` is set, which allows shipping the library unconditionally.

- **Prebuilt helper libraries**: The preload libraries used by [quick-sharun](https://github.com/pkgforge-dev/Anylinux-AppImages/blob/main/useful-tools/quick-sharun.sh) originally lived in the [Anylinux-AppImages](https://github.com/pkgforge-dev/Anylinux-AppImages) repo and were compiled on the host at deployment time. They are now kept here (see `lib/`) and built by the CI with `zig cc` against a **glibc 2.31** floor (`2.36` for `loongarch64`, the first glibc version that supports that architecture). This guarantees they load inside any AppImage regardless of the glibc that was deployed, instead of depending on whatever glibc the CI host happened to have. `ppc64` (big-endian) is the exception: it is ELFv2 but zig's `powerpc64-linux-gnu` glibc stub is the ELFv1 one, which archlinuxpower's glibc does not define, so the ppc64 preloads are linked against a big-endian build of zig's ppc64le ELFv2 stub instead (see https://github.com/pkgforge-dev/Anylinux-sharun/issues/11). The libraries:

  - `anylinux.so` - main preload library: unsets problematic environment variables for child/external processes, restores portable home/config/data/cache dirs, fixes broken host locales, redirects `bindtextdomain` to the bundled locales, forces NSS to only use bundled modules, can block libraries from being dlopened with `ANYLINUX_DO_NOT_LOAD_LIBS` and can change the running program name with `OVERRIDE_ARGV0`.
  - `gtk-fix-nonsense.so` - forces the GTK window class / application id to `GTK_WINDOW_CLASS`, fixing broken desktop integration in Wayland where GNOME uses a different window class than in X11. Safe to preload into applications with or without GTK, GLib or glycin.
  - `glycin-fix.so` - disables the bwrap sandbox of GNOME's glycin image loader, which never works inside an AppImage because glycin incorrectly binds AppImage paths to bwrap, resulting in crashes. Only intended for applications that ship real glycin (`libglycin-*`), quick-sharun preloads it only for those, there is nothing to fix in [glycin-ng](https://github.com/QaidVoid/glycin-ng) based applications since it has a working sandbox. Glycin is only reached via `dlsym`/`dlopen(RTLD_NOLOAD)`, so the library does not affect applications that do not make use of glycin at all. Note that with the library preloaded `dlsym(RTLD_DEFAULT, "gly_loader_new")` returns a non-NULL wrapper even before glycin is loaded in, callers must check the returned loader for NULL.
  - `path-mapping.so` - vendored from [pathmap](https://github.com/VHSgunzo/pathmap), only the preload library, the standalone tracer binary is not built. Maps hardcoded paths at runtime with `PATH_MAPPING`/`PATHMAP_*` env variables, sharun only preloads it when `PATH_MAPPING` is set and it replaces the git clone + C compiler build that deployments used to carry out.

  Each release contains, per architecture:

  - `sharun-$ARCH` - the sharun binary.
  - `sharun+helper-libs-$ARCH.tar` - sharun plus the prebuilt libraries in a single flat tar (`sharun`, `anylinux.so`, `gtk-fix-nonsense.so`, `glycin-fix.so`, `path-mapping.so`), so consumers get everything with one download and no C compiler is needed on the build host.
  - A `.sha256` checksum file for each of the released assets.

## What this fork removes

- **`lib4bin`**: Has been removed. Use [quick-sharun](https://github.com/pkgforge-dev/Anylinux-AppImages/blob/main/useful-tools/quick-sharun.sh) instead.

- `xdg-open` wrapper: Has been removed. `quick-sharun` uses [anylinux.so](https://github.com/pkgforge-dev/Anylinux-sharun/blob/main/lib/anylinux.c) which fixes the same issues that the wrapper did and better. (Works on all external binaries, not just `xdg-open`).

- **`sharun-aio`**: The all-in-one binary with bundled `lib4bin` dependencies is removed.

- **`sharun-lite`**: Removed.

- **wrappe integration**: No `--with-wrappe`. Use `quick-sharun --make-static-bin` instead.

- **Python packing with uv**: No `--with-python` support for embedding python/pip packages. `quick-sharun` only supports deploying the system python installation due to many bugs with uv python.

- **Strace mode**: No `strace` for library detection at runtime. `quick-sharun` uses `LD_DEBUG=libs` instead (reduces overdeployment of libraries).

