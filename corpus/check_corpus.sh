#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS_DIR="$ROOT/corpus"
MANIFEST="$CORPUS_DIR/manifest.tsv"
PROVENANCE="$CORPUS_DIR/provenance.tsv"
VULNERABLE_DIR="$CORPUS_DIR/vulnerable"
ARTIFACTS_DIR="$CORPUS_DIR/artifacts"

NARGO="${NARGO:-/home/said/noir/target/debug/nargo}"
ADAPTER="${ADAPTER:-$ROOT/target/debug/noir-picus-adapter}"
TIMEOUT_MS="${NOIR_PICUS_TIMEOUT_MS:-3000}"
OUT_DIR="${NOIR_PICUS_CORPUS_OUT:-/tmp/noir-picus-corpus}"
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
  find "$VULNERABLE_DIR" -maxdepth 2 -type d -name target -prune -exec rm -rf {} +
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

sorted_manifest_cases() {
  tail -n +2 "$MANIFEST" | cut -f1 | sort
}

sorted_provenance_cases() {
  tail -n +2 "$PROVENANCE" | cut -f1 | sort
}

sorted_source_cases() {
  find "$VULNERABLE_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
}

sorted_artifact_cases() {
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

mkdir -p "$OUT_DIR/compile" "$OUT_DIR/scan" "$OUT_DIR/verbose" "$OUT_DIR/smt"
rm -f "$SUMMARY"
printf 'case\tstatus\treason\ttarget_count\tunsupported_reasons\n' > "$SUMMARY"
trap cleanup_targets EXIT

command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v rg >/dev/null 2>&1 || fail "rg is required"
command -v cargo >/dev/null 2>&1 || fail "cargo is required"
require_executable "$NARGO" "nargo"

(
  cd "$ROOT"
  cargo build --quiet
)
require_executable "$ADAPTER" "noir-picus-adapter"

assert_header "$MANIFEST" $'case\tartifact\tfixed\ttargets\texpected\tsource_family'
assert_header "$PROVENANCE" $'case\toriginal_dsl\tproject\tsource_url\tsource_bug_id\toriginal_bug_path\ttranslation_notes'

tmp_manifest="$(mktemp)"
tmp_provenance="$(mktemp)"
tmp_sources="$(mktemp)"
tmp_artifacts="$(mktemp)"
trap 'rm -f "$tmp_manifest" "$tmp_provenance" "$tmp_sources" "$tmp_artifacts"; cleanup_targets' EXIT

sorted_manifest_cases > "$tmp_manifest"
sorted_provenance_cases > "$tmp_provenance"
sorted_source_cases > "$tmp_sources"

cat "$tmp_manifest" | assert_no_duplicates "manifest"
cat "$tmp_provenance" | assert_no_duplicates "provenance"
cat "$tmp_sources" | assert_no_duplicates "source"

assert_same_cases "manifest" "$tmp_manifest" "provenance" "$tmp_provenance"
assert_same_cases "manifest" "$tmp_manifest" "sources" "$tmp_sources"

while IFS=$'\t' read -r case artifact fixed targets expected source_family; do
  [[ -n "$case" ]] || continue
  [[ "$expected" == "unsafe" ]] || fail "$case has unsupported expected status: $expected"

  source_dir="$VULNERABLE_DIR/$case"
  artifact_path="$ROOT/$artifact.json"
  compile_log="$OUT_DIR/compile/$case.log"
  scan_json="$OUT_DIR/scan/$case.json"
  verbose_log="$OUT_DIR/verbose/$case.txt"
  smt_dir="$OUT_DIR/smt/$case"

  [[ -d "$source_dir" ]] || fail "$case source directory is missing"
  [[ "$artifact" == "corpus/artifacts/$case" ]] || fail "$case artifact path must be corpus/artifacts/$case"

  echo "== $case =="
  if ! (cd "$source_dir" && "$NARGO" compile --silence-warnings --force >"$compile_log" 2>&1); then
    printf '%s\tcompile_failed\tsee %s\t0\t\n' "$case" "$compile_log" >> "$SUMMARY"
    cat "$compile_log" >&2
    fail "$case failed to compile"
  fi

  jq '{noir_version, bytecode}' "$source_dir/target/$case.json" > "$artifact_path"
  if jq -e 'has("noir_version") and has("bytecode") and (keys | length == 2)' "$artifact_path" >/dev/null; then
    :
  else
    fail "$case sanitized artifact has unexpected shape"
  fi

  if rg -n '/home/said|debug_symbols|file_map|source' "$artifact_path" >/dev/null; then
    fail "$case sanitized artifact contains local paths or debug metadata"
  fi

  rm -rf "$smt_dir"
  mkdir -p "$smt_dir"
  "$ADAPTER" scan "$ROOT/$artifact" \
    --fixed "$fixed" \
    --targets "$targets" \
    --format json \
    --timeout "$TIMEOUT_MS" \
    --dump-smt "$smt_dir" > "$scan_json"

  "$ADAPTER" scan "$ROOT/$artifact" \
    --fixed "$fixed" \
    --targets "$targets" \
    --timeout "$TIMEOUT_MS" \
    --verbose > "$verbose_log"

  status="$(json_value "$scan_json" '[.programs[].circuits[].targets[].status] | unique | join(",")')"
  reason="$(json_value "$scan_json" '[.programs[].circuits[].targets[].reason // ""] | unique | join(";")')"
  target_count="$(json_value "$scan_json" '[.programs[].circuits[].targets[]] | length')"
  unsupported_reasons="$(json_value "$scan_json" '[.programs[].circuits[].unsupported_reasons[]] | unique | join(";")')"

  printf '%s\t%s\t%s\t%s\t%s\n' "$case" "$status" "$reason" "$target_count" "$unsupported_reasons" >> "$SUMMARY"

  if [[ "$target_count" == "0" ]]; then
    fail "$case produced no scan targets; see $verbose_log"
  fi
  if [[ "$status" != "unsafe" ]]; then
    fail "$case expected unsafe, got $status; see $scan_json, $verbose_log, and $smt_dir"
  fi
done < <(tail -n +2 "$MANIFEST")

sorted_artifact_cases > "$tmp_artifacts"
cat "$tmp_artifacts" | assert_no_duplicates "artifact"
assert_same_cases "manifest" "$tmp_manifest" "artifacts" "$tmp_artifacts"

echo
echo "summary: $SUMMARY"
awk -F '\t' 'NR > 1 { counts[$2] += 1 } END { for (status in counts) print status "=" counts[status] }' "$SUMMARY" | sort
echo "checked $(tail -n +2 "$SUMMARY" | wc -l) corpus cases"
