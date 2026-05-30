#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS_DIR="$ROOT/corpus"
MANIFEST="$CORPUS_DIR/compiler_regression_manifest.tsv"
PROVENANCE="$CORPUS_DIR/compiler_regression_provenance.tsv"
SOURCE_DIR="$CORPUS_DIR/compiler_regression"
ARTIFACTS_DIR="$CORPUS_DIR/compiler_regression_artifacts"

NARGO="${NARGO:-/home/said/noir/target/debug/nargo}"
ADAPTER="${ADAPTER:-$ROOT/target/debug/noir-picus-adapter}"
TIMEOUT_MS="${NOIR_PICUS_TIMEOUT_MS:-3000}"
SCAN_WALL_TIMEOUT_SEC="${NOIR_PICUS_SCAN_WALL_TIMEOUT_SEC:-30}"
OUT_DIR="${NOIR_PICUS_COMPILER_REGRESSION_OUT:-/tmp/noir-picus-compiler-regression}"
KEEP_TARGETS="${NOIR_PICUS_KEEP_TARGETS:-0}"

SUMMARY="$OUT_DIR/summary.tsv"

fail() {
  echo "error: $*" >&2
  exit 1
}

cleanup_targets() {
  if [[ "$KEEP_TARGETS" == "1" ]]; then
    return
  fi
  find "$SOURCE_DIR" -mindepth 2 -maxdepth 2 -type d -name target -prune -exec rm -rf {} +
}

require_executable() {
  local path="$1"
  local name="$2"
  [[ -x "$path" ]] || fail "$name is not executable at $path"
}

assert_header() {
  local file="$1"
  local expected="$2"
  local actual
  actual="$(head -n 1 "$file")"
  [[ "$actual" == "$expected" ]] || fail "unexpected header in $file: $actual"
}

manifest_cases() {
  tail -n +2 "$MANIFEST" | cut -f1 | sort
}

provenance_cases() {
  tail -n +2 "$PROVENANCE" | cut -f1 | sort
}

source_cases() {
  find "$SOURCE_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
}

artifact_cases() {
  find "$ARTIFACTS_DIR" -maxdepth 1 -type f -name '*.json' -printf '%f\n' \
    | sed 's/\.json$//' \
    | sort
}

assert_no_duplicates() {
  local label="$1"
  local duplicate
  duplicate="$(cat | uniq -d | head -n 1)"
  [[ -z "$duplicate" ]] || fail "duplicate $label case: $duplicate"
}

assert_same_cases() {
  local left_label="$1"
  local left_file="$2"
  local right_label="$3"
  local right_file="$4"
  if ! cmp -s "$left_file" "$right_file"; then
    echo "case mismatch: $left_label vs $right_label" >&2
    comm -3 "$left_file" "$right_file" >&2 || true
    exit 1
  fi
}

json_value() {
  local json_file="$1"
  local jq_expr="$2"
  jq -r "$jq_expr" "$json_file"
}

mkdir -p "$OUT_DIR/compile" "$OUT_DIR/execute" "$OUT_DIR/scan" "$OUT_DIR/smt" "$ARTIFACTS_DIR"
rm -f "$SUMMARY"
printf 'case\tcompile_status\tscan_status\texecute_output\treason\n' > "$SUMMARY"
trap cleanup_targets EXIT

command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v rg >/dev/null 2>&1 || fail "rg is required"
command -v cargo >/dev/null 2>&1 || fail "cargo is required"
command -v timeout >/dev/null 2>&1 || fail "coreutils timeout is required"
require_executable "$NARGO" "nargo"

(
  cd "$ROOT"
  cargo build --quiet
)
require_executable "$ADAPTER" "noir-picus-adapter"

assert_header "$MANIFEST" $'case\tartifact\texpected_compile\tscan_fixed\tscan_targets\tscan_solver\tscan_theory\texpected_scan\texpected_execute_output\tsource_family'
assert_header "$PROVENANCE" $'case\tsource_url\tsource_bug_id\taffected_versions\tpatched_versions\tregression_type\tnotes'

tmp_manifest="$(mktemp)"
tmp_provenance="$(mktemp)"
tmp_sources="$(mktemp)"
tmp_artifacts="$(mktemp)"
trap 'rm -f "$tmp_manifest" "$tmp_provenance" "$tmp_sources" "$tmp_artifacts"; cleanup_targets' EXIT

manifest_cases > "$tmp_manifest"
provenance_cases > "$tmp_provenance"
source_cases > "$tmp_sources"

cat "$tmp_manifest" | assert_no_duplicates "manifest"
cat "$tmp_provenance" | assert_no_duplicates "provenance"
cat "$tmp_sources" | assert_no_duplicates "source"

assert_same_cases "manifest" "$tmp_manifest" "provenance" "$tmp_provenance"
assert_same_cases "manifest" "$tmp_manifest" "sources" "$tmp_sources"

while IFS=$'\t' read -r case artifact expected_compile scan_fixed scan_targets scan_solver scan_theory expected_scan expected_execute_output source_family; do
  [[ -n "$case" ]] || continue
  [[ "$expected_compile" == "ok" ]] || fail "$case has unsupported expected_compile: $expected_compile"
  [[ "$expected_scan" == "skip" || "$expected_scan" == "unsafe" || "$expected_scan" == "verified" ]] || fail "$case has unsupported expected_scan: $expected_scan"

  package_dir="$SOURCE_DIR/$case"
  artifact_path="$ROOT/$artifact.json"
  compile_log="$OUT_DIR/compile/$case.log"
  execute_log="$OUT_DIR/execute/$case.log"
  scan_json="$OUT_DIR/scan/$case.json"
  smt_dir="$OUT_DIR/smt/$case"

  [[ -d "$package_dir" ]] || fail "$case source directory is missing"
  [[ "$artifact" == "corpus/compiler_regression_artifacts/$case" ]] || fail "$case artifact path must be corpus/compiler_regression_artifacts/$case"

  echo "== $case =="
  if ! (cd "$package_dir" && "$NARGO" compile --silence-warnings --force >"$compile_log" 2>&1); then
    printf '%s\tcompile_failed\tskip\tskip\tsee %s\n' "$case" "$compile_log" >> "$SUMMARY"
    cat "$compile_log" >&2
    fail "$case failed to compile"
  fi

  jq '{noir_version, bytecode}' "$package_dir/target/$case.json" > "$artifact_path"
  if ! jq -e 'has("noir_version") and has("bytecode") and (keys | length == 2)' "$artifact_path" >/dev/null; then
    fail "$case sanitized artifact has unexpected shape"
  fi
  if rg -n '/home/said|debug_symbols|file_map|source' "$artifact_path" >/dev/null; then
    fail "$case sanitized artifact contains local paths or debug metadata"
  fi

  scan_status="skip"
  reason=""
  if [[ "$expected_scan" != "skip" ]]; then
    rm -rf "$smt_dir"
    mkdir -p "$smt_dir"
    if ! timeout "${SCAN_WALL_TIMEOUT_SEC}s" "$ADAPTER" scan "$ROOT/$artifact" \
      --fixed "$scan_fixed" \
      --targets "$scan_targets" \
      --solver "$scan_solver" \
      --theory "$scan_theory" \
      --format json \
      --timeout "$TIMEOUT_MS" \
      --dump-smt "$smt_dir" > "$scan_json"; then
      printf '%s\tok\tscan_failed\tskip\tsee %s\n' "$case" "$scan_json" >> "$SUMMARY"
      fail "$case scan failed or timed out; see $scan_json and $smt_dir"
    fi
    scan_status="$(json_value "$scan_json" '[.programs[].circuits[].targets[].status] | unique | join(",")')"
    reason="$(json_value "$scan_json" '[.programs[].circuits[].targets[].reason // ""] | unique | join(";")')"
    if [[ "$scan_status" != "$expected_scan" ]]; then
      printf '%s\tok\t%s\tskip\t%s\n' "$case" "$scan_status" "$reason" >> "$SUMMARY"
      fail "$case expected scan $expected_scan, got $scan_status; see $scan_json"
    fi
  fi

  execute_output="skip"
  if [[ "$expected_execute_output" != "skip" ]]; then
    if ! (cd "$package_dir" && "$NARGO" execute --silence-warnings --force >"$execute_log" 2>&1); then
      printf '%s\tok\t%s\texecute_failed\tsee %s\n' "$case" "$scan_status" "$execute_log" >> "$SUMMARY"
      cat "$execute_log" >&2
      fail "$case failed to execute"
    fi
    execute_output="$(awk -F 'Circuit output: ' '/Circuit output:/ { value=$2 } END { print value }' "$execute_log")"
    if [[ "$execute_output" != "$expected_execute_output" ]]; then
      printf '%s\tok\t%s\t%s\texpected %s\n' "$case" "$scan_status" "$execute_output" "$expected_execute_output" >> "$SUMMARY"
      fail "$case expected execute output $expected_execute_output, got $execute_output; see $execute_log"
    fi
  fi

  printf '%s\tok\t%s\t%s\t%s\n' "$case" "$scan_status" "$execute_output" "$reason" >> "$SUMMARY"
done < <(tail -n +2 "$MANIFEST")

artifact_cases > "$tmp_artifacts"
cat "$tmp_artifacts" | assert_no_duplicates "artifact"
assert_same_cases "manifest" "$tmp_manifest" "artifacts" "$tmp_artifacts"

echo
echo "summary: $SUMMARY"
awk -F '\t' 'NR > 1 { print $1 ": scan=" $3 ", execute=" $4 }' "$SUMMARY"
echo "checked $(tail -n +2 "$SUMMARY" | wc -l) compiler regression cases"
