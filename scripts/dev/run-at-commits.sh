#!/usr/bin/env bash
# Run one command at several commits and print a one-line verdict for each: which commit broke a
# test, settled in one CI run (agent-test.yml) instead of one run per commit.
#
#   scripts/dev/run-at-commits.sh '<command>' <commit> [<commit> ...]
#
# Each commit is checked out, in the order given, into ONE temporary detached worktree beside the
# checkout (so a shallow CI clone works: a commit it lacks is fetched from `origin` first), and
# the command runs there through `bash -c`. One target directory serves every commit
# (RUN_AT_TARGET, default target/run-at-commits): the worktree's path stays the same, so cargo
# rebuilds what the checkout changed and reuses the rest. A commit's output goes to
# $RUN_AT_OUT/<sha>.log (default target/run-at-commits-out); a failing commit's last lines are
# printed too. The summary, one line per commit:
#
#   VERDICT <full sha> pass|fail exit=<status> <seconds>s <subject>
#
# Exit status: 0 when every commit was run (whatever its verdict), 2 on a usage or checkout
# error. The verdicts are the result; nothing is asserted about them.
set -uo pipefail

if [ $# -lt 2 ]; then
    sed -n '2,20p' "$0" >&2
    exit 2
fi
command=$1
shift

root=$(git rev-parse --show-toplevel) || exit 2
target=${RUN_AT_TARGET:-$root/target/run-at-commits}
out=${RUN_AT_OUT:-$root/target/run-at-commits-out}
work=$(mktemp -d "${TMPDIR:-/tmp}/run-at-commits.XXXXXX") || exit 2
tree=$work/tree
mkdir -p "$target" "$out"
cleanup() { git -C "$root" worktree remove --force "$tree" >/dev/null 2>&1; rm -rf "$work"; }
trap cleanup EXIT

verdicts=()
for commit in "$@"; do
    if ! git -C "$root" cat-file -e "$commit^{commit}" 2>/dev/null; then
        git -C "$root" fetch --quiet --no-tags --depth=1 origin "$commit" || {
            echo "cannot fetch $commit" >&2
            exit 2
        }
    fi
    sha=$(git -C "$root" rev-parse "$commit^{commit}") || exit 2
    if [ -d "$tree" ]; then
        git -C "$tree" checkout --quiet --force --detach "$sha" || exit 2
        git -C "$tree" clean --quiet -fdx || exit 2
    else
        git -C "$root" worktree add --quiet --detach "$tree" "$sha" || exit 2
    fi
    subject=$(git -C "$root" show -s --format=%s "$sha")
    echo "=== $sha $subject"
    started=$SECONDS
    (cd "$tree" && CARGO_TARGET_DIR=$target bash -c "$command") >"$out/$sha.log" 2>&1
    status=$?
    took=$((SECONDS - started))
    grep -E '^test result:|^test .* \.\.\. FAILED|panicked at' "$out/$sha.log" | head -20
    if [ "$status" -eq 0 ]; then
        verdict=pass
    else
        verdict=fail
        echo "--- last lines of $sha"
        tail -n 40 "$out/$sha.log"
    fi
    verdicts+=("VERDICT $sha $verdict exit=$status ${took}s $subject")
done

echo
printf '%s\n' "${verdicts[@]}"
