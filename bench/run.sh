#!/usr/bin/env bash
# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Benchmark harness: run a fixed input set through every zkVM executor and
# emit a machine-readable JSON report (bench/report.json). Execution-level
# only (cycle/step counts); proving benchmarks are a separate concern.
# Adapt the report shape to the EF benchmark format once it is defined.
#
# Usage: bench/run.sh [output.json]
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/bench/report.json}"

INPUTS=(
  "mock:$ROOT/conformance/vectors/mock_input.bin"
  "real:$ROOT/conformance/vectors/real_input.bin"
)

declare -a ROWS=()

run_one() { # zkvm binary input_name input_path metric_regex
  local zkvm="$1" bin="$2" name="$3" path="$4" regex="$5"
  if [ ! -x "$bin" ]; then
    echo "  $zkvm/$name: SKIP (executor not built: $bin)" >&2
    return
  fi
  local out cycles
  out=$("$bin" execute --input "$path" 2>&1)
  cycles=$(echo "$out" | grep -Eo "$regex" | grep -Eo '[0-9]+' | tail -1)
  if [ -z "${cycles:-}" ]; then
    echo "  $zkvm/$name: FAIL (no cycle count in output)" >&2
    ROWS+=("{\"zkvm\":\"$zkvm\",\"input\":\"$name\",\"status\":\"fail\"}")
    return
  fi
  echo "  $zkvm/$name: $cycles" >&2
  ROWS+=("{\"zkvm\":\"$zkvm\",\"input\":\"$name\",\"status\":\"ok\",\"cycles\":$cycles}")
}

echo "bench: execution-level cycle counts" >&2
for entry in "${INPUTS[@]}"; do
  name="${entry%%:*}"; path="${entry#*:}"
  run_one sp1    "$ROOT/int-tests/sp1/target/release/z6m_cpp_prover"           "$name" "$path" 'total cycles *: *[0-9]+'
  run_one openvm "$ROOT/int-tests/openvm/target/release/z6m_openvm_prover" "$name" "$path" 'total cycles *: *[0-9]+'
  run_one zisk   "$ROOT/int-tests/zisk/target/release/z6m_zisk_prover"     "$name" "$path" 'execution steps *: *[0-9]+'
done

{
  echo "{"
  echo "  \"schema\": \"zilkworm-bench-v1\","
  echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"git\": \"$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)\","
  echo "  \"zkvm_versions\": {"
  awk -F= 'NF==2 {printf "%s    \"%s\": \"%s\"", sep, $1, $2; sep=",\n"} END {print ""}' "$ROOT/ZKVM_VERSIONS"
  echo "  },"
  echo "  \"results\": ["
  (IFS=,; printf '    %s' "${ROWS[*]//,\{/,\n    \{}") | sed 's/},{/},\n    {/g'
  echo ""
  echo "  ]"
  echo "}"
} > "$OUT"
echo "report: $OUT" >&2
