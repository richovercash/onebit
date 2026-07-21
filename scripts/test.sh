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
for c in mono_faithful enroll enroll_ecdsa present_amortized; do
  ( cd "circuits/$c" && "$NARGO" compile >/dev/null 2>&1 \
      && "$NARGO" execute _smoke >/dev/null 2>&1 \
      && echo "  ok: $c" ) || { echo "  FAIL: $c"; exit 1; }
done

echo "ALL GREEN"
