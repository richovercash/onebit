#!/bin/bash
# P1.4 continuous adversarial harness — runs the JUnit suites (incl. the
# 516-challenge refusal fuzz + attestation/verifier fixtures) and a circuit
# compile+execute smoke check. Red on any regression. Same steps CI runs.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${JAVA_HOME:=/usr/local/android-studio/jbr}"
GRADLE=$(ls -d "$HOME"/.gradle/wrapper/dists/gradle-8.13-bin/*/gradle-8.13/bin/gradle | head -1)
NARGO="${NARGO:-$HOME/.nargo/bin/nargo}"

echo "== JUnit: core (PassiveAuth + 516-challenge fuzz + nullifier) =="
JAVA_HOME="$JAVA_HOME" "$GRADLE" :core:test --console=plain -q

echo "== JUnit: verifier (attestation 7 + wire/dual-proof fixtures) =="
JAVA_HOME="$JAVA_HOME" "$GRADLE" :verifier:test --console=plain -q

echo "== Circuit smoke: compile + witness-solve the live circuits =="
for c in mono_faithful enroll enroll_ecdsa present_amortized enroll_rsa6144 enroll_p384 mono_faithful_ecdsa enroll_dsc_ecdsa mono_faithful_pss enroll_secp256 enroll_bp384 enroll_secp521 enroll_bp512; do
  ( cd "circuits/$c" && "$NARGO" compile >/dev/null 2>&1 \
      && "$NARGO" execute _smoke >/dev/null 2>&1 \
      && echo "  ok: $c" ) || { echo "  FAIL: $c"; exit 1; }
done

echo "== Amortized presentation: real proof verifies via the verifier sidecar =="
if command -v node >/dev/null 2>&1 && [ -f verifier/js/testdata/pa_proof.bin ]; then
  python3 scripts/split_proof.py verifier/js/testdata/pa_proof.bin 4 \
    | ( cd verifier/js && CIRCUIT=present_amortized.json node verify.mjs ) \
    | grep -q ZK_OK && echo "  ok: present_amortized proof -> ZK_OK" \
    || { echo "  FAIL: amortized proof did not verify"; exit 1; }
else
  echo "  skip: node or fixture unavailable"
fi

echo "== CSCA trees: real cert leaf folds to the published per-algorithm root =="
if command -v node >/dev/null 2>&1 && [ -f app/src/main/assets/masterlist/masterlist.pem ]; then
  ( cd verifier/js && node verify_tree.mjs ../../app/src/main/assets/masterlist/masterlist.pem ) \
    | grep -q TREE_OK && echo "  ok: all EC trees fold to their published root" \
    || { echo "  FAIL: tree fold mismatch"; exit 1; }
else
  echo "  skip: node or master list unavailable"
fi

echo "== ECDSA-DSC presentation: real proof verifies via the verifier sidecar =="
if command -v node >/dev/null 2>&1 && [ -f verifier/js/testdata/mfe_proof.bin ]; then
  python3 scripts/split_proof.py verifier/js/testdata/mfe_proof.bin 5 \
    | ( cd verifier/js && CIRCUIT=mono_faithful_ecdsa.json node verify.mjs ) \
    | grep -q ZK_OK && echo "  ok: mono_faithful_ecdsa proof -> ZK_OK" \
    || { echo "  FAIL: ecdsa presentation did not verify"; exit 1; }
fi

echo "ALL GREEN"
