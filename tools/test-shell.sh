#!/bin/sh

# Runs the cases of tools/shell-tests/*.txt with the shell given as argument,
# compares what each prints with the expected output and exits 1 on any
# difference.
#
# A case is a "? " line with the code, then the expected output as "> " lines.
# The expected output of replace.txt was made with bash (patsub_replacement
# off), which is the reference for ${var/pat/str}.
#
#   usage: test-shell.sh <shell> [<case file>...]

set -u

shell=$1
shift
case $shell in
/*) ;;
*) shell=$PWD/$shell ;;
esac
dir=$(cd "$(dirname "$0")" && pwd)/shell-tests
[ $# -gt 0 ] || set -- "$dir"/*.txt

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
# the cases run in an empty directory so an unquoted * stays what it is
mkdir "$tmp/cwd"

total=0
failed=0

# runs the case collected in $code and $tmp/want
run_case() {
	[ -n "$code" ] || return 0
	total=$((total + 1))
	(cd "$tmp/cwd" && "$shell" -c "$code") > "$tmp/got" 2>&1 < /dev/null
	if ! cmp -s "$tmp/want" "$tmp/got"; then
		failed=$((failed + 1))
		printf 'FAIL: %s\n  want: %s\n  got:  %s\n' "$code" \
			"$(tr '\n' '|' < "$tmp/want")" \
			"$(tr '\n' '|' < "$tmp/got")"
	fi
	code=
}

for file; do
	code=
	: > "$tmp/want"
	while IFS= read -r line; do
		case $line in
		'? '*)
			run_case
			code=${line#'? '}
			: > "$tmp/want"
			;;
		'> '*)
			printf '%s\n' "${line#'> '}" >> "$tmp/want"
			;;
		'')
			run_case
			;;
		esac
	done < "$file"
	# the last case of a file does not need a blank line after it
	run_case
done

printf '%s cases, %s failed\n' "$total" "$failed"
# a case file that is empty or misspelled must not pass
[ "$total" -gt 0 ] && [ "$failed" = 0 ]
