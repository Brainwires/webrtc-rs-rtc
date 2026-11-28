#!/usr/bin/env bash
# Runs a key residue measurement and prints what it found: the SRTP one
# (rtci-srtp/tests/key_residue.rs: the controls, anything left outside dead stack frames, the
# inventory per step and its digest, and (Linux) how this system treats thread stacks) or, with
# `dtls` first, the DTLS one (rtci-dtls/tests/key_residue.rs: the control, the inventory per
# step and its digest, and the forms left).
#
#   scripts/key-residue-report.sh [dtls] [+toolchain] [features]
#
#   dtls        the DTLS measurement instead of the SRTP one
#   +toolchain  a rustup toolchain for cargo, e.g. +1.99.1 (default: the active one)
#   features    features of the measured crate to add, e.g. crypto-aws-lc-rs (default: none:
#               ring only)
#
# Environment: OUT (directory for the logs, default a new temporary one), REPEAT (how often the
# tests are run again to compare digests, default 3), PROFILE=release (an optimised build: the
# one in which the packet path is asserted).
# Exit status: that of the tests that are not ignored; 2 when the build fails.
set -u
measure=srtp
[ "${1:-}" = dtls ] && { measure=dtls; shift; }
toolchain=
case "${1:-}" in +*) toolchain=$1; shift ;; esac
features=${1:-}
out=${OUT:-$(mktemp -d)}
repeat=${REPEAT:-3}
mkdir -p "$out"

# $toolchain is left unquoted on purpose: empty, it must vanish from the command line.
# shellcheck disable=SC2206
cargo_test=(cargo $toolchain test -p "rtci-$measure" --test key_residue)
[ -n "$features" ] && cargo_test+=(--features "$features")
[ "${PROFILE:-}" = release ] && cargo_test+=(--release)

# shellcheck disable=SC2086
echo "== $(rustc $toolchain --version), $(uname -srm), features: ${features:-default}, profile: ${PROFILE:-dev}"
# The DTLS measurement asserts the AES-CCM record path in an optimised build (RustCrypto's AES
# in rtci-crypto) where it was measured to hold: rustc 1.99.1 and newer. rustc 1.89 left one
# round key there (run 46012389383); the versions between 1.89 and 1.99.1 are unmeasured and
# treated as the limit too: for a compiler older than 1.99.1 the test is told to print the
# AES-CCM forms instead of asserting none (RTCI_KEY_RESIDUE_CCM_KNOWN_LIMIT=1).
if [ "$measure" = dtls ]; then
  # shellcheck disable=SC2086
  version=$(rustc $toolchain --version | sed -n 's/^rustc \([0-9][0-9.]*\).*/\1/p')
  if [ -n "$version" ] && [ "$(printf '%s\n' "$version" 1.99.1 | sort -V | head -1)" != 1.99.1 ]; then
    export RTCI_KEY_RESIDUE_CCM_KNOWN_LIMIT=1
    echo "== rustc $version is older than 1.99.1: AES-CCM record path printed, not asserted (RTCI_KEY_RESIDUE_CCM_KNOWN_LIMIT=1)"
  else
    echo "== rustc ${version:-unknown}: AES-CCM record path asserted in an optimised build"
  fi
fi
"${cargo_test[@]}" --no-run > "$out/build.log" 2>&1 || { tail -30 "$out/build.log"; exit 2; }
"${cargo_test[@]}" -- --nocapture > "$out/live.log" 2>&1
status=$?
if [ "$measure" = dtls ]; then
  for i in $(seq "$repeat"); do
    "${cargo_test[@]}" -- --include-ignored key_handling the_dtls_record_path --nocapture > "$out/known-limit-$i.log" 2>&1
  done
  echo "== tests"
  grep -h '^test ' "$out/live.log" "$out/known-limit-1.log"
  echo "== control"
  grep -h '^CONTROL\|^SCENARIO FAILED\|CONTROL: ' "$out/live.log" | sort | uniq -c
  echo "== inventory digests (not ignored, then each repeat with the known limit included)"
  grep -h '^INVENTORY\|^NOT ASSERTED\|^RECORD PATH\|^DEEPEST' "$out/live.log"
  grep -h '^INVENTORY' "$out"/known-limit-*.log | sort | uniq -c
  echo "== per provider, kind of step and secret"
  grep -h '^SUMMARY' "$out/known-limit-1.log"
  echo "== steps that left key forms"
  grep -h '^STAGE' "$out/known-limit-1.log" | grep -v '|0 key forms left'
  echo "== the forms left"
  grep -h '^FORM' "$out/known-limit-1.log"
  echo "== panics"
  grep -h -A12 'panicked at' "$out/live.log" | head -60
  grep -h -A3 'panicked at' "$out/known-limit-1.log" | head -24
  exit $status
fi
"${cargo_test[@]}" -- --ignored investigate_ --nocapture > "$out/investigate.log" 2>&1
for i in $(seq "$repeat"); do
  "${cargo_test[@]}" -- --include-ignored key_handling the_packet_path --nocapture > "$out/known-limit-$i.log" 2>&1
done

echo "== tests"
grep -h '^test ' "$out/live.log" "$out/known-limit-1.log"
echo "== thread stacks on this system"
grep -h '^ENV\|^ROUND\|^OWNED' "$out/investigate.log"
echo "== controls, notes, anything left outside dead stack frames"
grep -h '^CONTROL\|^NOTE\|^LEFT' "$out/live.log" "$out/known-limit-1.log" | sort -u
echo "== inventory digests (not ignored, then each repeat with the known limits included)"
grep -h '^INVENTORY' "$out/live.log"
grep -h '^INVENTORY' "$out"/known-limit-*.log | sort | uniq -c
echo "== per key, over the ten profiles"
grep -h '^SUMMARY' "$out/known-limit-1.log"
echo "== per step"
grep -h '^STAGE' "$out/known-limit-1.log"
echo "== every form, first AES-CM and first AES-GCM profile"
grep -h '^FORM [a-z-]*|Aes128CmHmacSha1_80|\|^FORM [a-z-]*|AeadAes128Gcm|' "$out/known-limit-1.log"
echo "== panics"
grep -h -A12 'panicked at' "$out/live.log" "$out/investigate.log" | head -80
grep -h -A3 'panicked at' "$out/known-limit-1.log" | head -24
exit $status
