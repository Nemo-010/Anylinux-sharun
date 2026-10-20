#!/bin/sh

# Builds the static dash that is shipped next to sharun. When sharun is the AppRun
# and there is a `dash` in the sharun dir, AppRun.sh is run with it.
#
#   usage: build-dash.sh <zig> <zig target> <output>
#   example: build-dash.sh zig x86_64-linux-musl dash-x86_64
#
# Needs make, git, curl, tar, gzip, sha512sum and a build host that runs x86_64
# Linux binaries: dash generates its tables with helper programs that run
# during the build, those are always built for x86_64 musl.

set -eu

DASH_VERSION=0.5.13.5
# sha512 of the tarball as published next to it on
# http://gondor.apana.org.au/~herbert/dash/files/
DASH_SHA512=ae326c110713a9da6b7afb977ca6fd931793b03011f0a7aa2c42e873f116ed09448deea9ef5ca4515fe3afe24e210e0aaa580f7de89934edda9cf31ee44c94dd

ZIG=$1
TARGET=$2
OUT=$(realpath -m "$3")
PATCH=$(cd "$(dirname "$0")" && pwd)/dash-pattern-replace.patch

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

# The download is plain http and the checksum below is what protects it.
# DASH_URL replaces the first address, the second is tried when it fails.
curl -fL --retry 3 -o "$work/dash.tar.gz" \
	"${DASH_URL:-http://gondor.apana.org.au/~herbert/dash/files/dash-$DASH_VERSION.tar.gz}" ||
	curl -fL --retry 3 -o "$work/dash.tar.gz" \
		"https://deb.debian.org/debian/pool/main/d/dash/dash_$DASH_VERSION.orig.tar.gz"
echo "$DASH_SHA512  $work/dash.tar.gz" | sha512sum -c -
tar --no-same-owner -xzf "$work/dash.tar.gz" -C "$work"
cd "$work/dash-$DASH_VERSION"

# dash has no ${var/pat/str}, ${var//pat/str}, ${var/#pat/str} and
# ${var/%pat/str}. The patch adds them, with bash semantics (longest match).
# Every file it changes must have the new code, one grep per file.
git apply --whitespace=nowarn -p1 "$PATCH"
for f in src/parser.h src/parser.c src/expand.c; do
	grep -q VSREPLACEALL "$f" || {
		echo "dash-pattern-replace.patch did not change $f" >&2
		exit 1
	}
done
grep -q EXP_STOPSLASH src/expand.h || {
	echo "dash-pattern-replace.patch did not change src/expand.h" >&2
	exit 1
}
# jobs.c prints the expansion in the job table, with its own table of types
grep -qF '"/%"' src/jobs.c || {
	echo "dash-pattern-replace.patch did not change src/jobs.c" >&2
	exit 1
}

# The signal name table comes from a helper that is built and run on the build
# host, so it has to see the signals of the libc the shell runs with. With the
# host gcc (glibc) SIGRTMIN is 34, musl has 35, and every RT signal name would
# be off by one. The signal numbers up to 31 are the same on all the targets.
HELPER_CC="$ZIG cc -target x86_64-linux-musl"

CFLAGS="-Os -flto -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections" \
LDFLAGS="-flto -static -Wl,--gc-sections -Wl,--strip-all" \
CC="$ZIG cc -target $TARGET" CC_FOR_BUILD="$HELPER_CC" \
	./configure --host="$TARGET" --enable-static >configure.log 2>&1 || {
	tail -30 configure.log >&2
	exit 1
}
make -j"$(nproc)" >make.log 2>&1 || {
	tail -30 make.log >&2
	exit 1
}

mkdir -p "$(dirname "$OUT")"
cp src/dash "$OUT"
ls -l "$OUT"
