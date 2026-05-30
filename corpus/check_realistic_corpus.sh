#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS_DIR="$ROOT/corpus"
MANIFEST="$CORPUS_DIR/realistic_manifest.tsv"
PROVENANCE="$CORPUS_DIR/realistic_provenance.tsv"
REALISTIC_DIR="$CORPUS_DIR/realistic"
ARTIFACTS_DIR="$CORPUS_DIR/realistic_artifacts"

NARGO="${NARGO:-/home/said/noir/target/debug/nargo}"
ADAPTER="${ADAPTER:-$ROOT/target/debug/noir-picus-adapter}"
TIMEOUT_MS="${NOIR_PICUS_TIMEOUT_MS:-3000}"
SCAN_WALL_TIMEOUT_SEC="${NOIR_PICUS_SCAN_WALL_TIMEOUT_SEC:-60}"
OUT_DIR="${NOIR_PICUS_REALISTIC_OUT:-/tmp/noir-picus-realistic-corpus}"
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
  find "$REALISTIC_DIR" -mindepth 3 -maxdepth 3 -type d -name target -prune -exec rm -rf {} +
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

manifest_variants() {
  tail -n +2 "$MANIFEST" | awk -F '\t' '{ print $1 "\t" $2 }' | sort
}

provenance_variants() {
  tail -n +2 "$PROVENANCE" | awk -F '\t' '{ print $1 "\t" $2 }' | sort
}

source_variants() {
  find "$REALISTIC_DIR" -mindepth 2 -maxdepth 2 -type d \
    \( -name vulnerable -o -name fixed \) \
    -printf '%h\t%f\n' \
    | awk -F '\t' '{ n=split($1, parts, "/"); print parts[n] "\t" $2 }' \
    | sort
}

artifact_variants() {
  find "$ARTIFACTS_DIR" -maxdepth 1 -type f -name '*.json' -printf '%f\n' \
    | sed 's/\.json$//' \
    | awk '
      /_vulnerable$/ { sub(/_vulnerable$/, ""); print $0 "\tvulnerable"; next }
      /_fixed$/ { sub(/_fixed$/, ""); print $0 "\tfixed"; next }
      { print "INVALID\t" $0 }
    ' \
    | sort
}

assert_no_duplicates() {
  local label="$1"
  local duplicate
  duplicate="$(cat | uniq -d | head -n 1)"
  [[ -z "$duplicate" ]] || fail "duplicate $label row: $duplicate"
}

assert_same_rows() {
  local left_label="$1"
  local left_file="$2"
  local right_label="$3"
  local right_file="$4"
  if ! cmp -s "$left_file" "$right_file"; then
    echo "case/variant mismatch: $left_label vs $right_label" >&2
    comm -3 "$left_file" "$right_file" >&2 || true
    exit 1
  fi
}

json_value() {
  local json_file="$1"
  local jq_expr="$2"
  jq -r "$jq_expr" "$json_file"
}

ms_now() {
  date +%s%3N
}

elapsed_since() {
  local start_ms="$1"
  local end_ms
  local elapsed_ms
  end_ms="$(ms_now)"
  elapsed_ms="$(( end_ms - start_ms ))"
  if (( elapsed_ms < 0 )); then
    elapsed_ms=0
  fi
  printf '%s' "$elapsed_ms"
}

mkdir -p "$OUT_DIR/compile" "$OUT_DIR/scan" "$OUT_DIR/verbose" "$OUT_DIR/smt" "$ARTIFACTS_DIR"
rm -f "$SUMMARY"
printf 'case\tvariant\tstatus\tn_wires\torig_constraints\ttarget_count\telapsed_ms\treason\n' > "$SUMMARY"
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

assert_header "$MANIFEST" $'case\tvariant\tartifact\tfixed\ttargets\texpected\ttier\tsource_family'
assert_header "$PROVENANCE" $'case\tvariant\tartifact\tfixed\ttargets\texpected\ttier\tsource_family\toriginal_dsl\tproject\tsource_url\tsource_bug_id\ttranslation_notes'

tmp_manifest="$(mktemp)"
tmp_provenance="$(mktemp)"
tmp_sources="$(mktemp)"
tmp_artifacts="$(mktemp)"
trap 'rm -f "$tmp_manifest" "$tmp_provenance" "$tmp_sources" "$tmp_artifacts"; cleanup_targets' EXIT

manifest_variants > "$tmp_manifest"
provenance_variants > "$tmp_provenance"
source_variants > "$tmp_sources"

cat "$tmp_manifest" | assert_no_duplicates "manifest"
cat "$tmp_provenance" | assert_no_duplicates "provenance"
cat "$tmp_sources" | assert_no_duplicates "source"

assert_same_rows "manifest" "$tmp_manifest" "provenance" "$tmp_provenance"
assert_same_rows "manifest" "$tmp_manifest" "sources" "$tmp_sources"

while IFS=$'\t' read -r case variant artifact fixed targets expected tier source_family; do
  [[ -n "$case" ]] || continue
  [[ "$variant" == "vulnerable" || "$variant" == "fixed" ]] || fail "$case has unsupported variant: $variant"
  [[ "$expected" == "unsafe" || "$expected" == "verified" ]] || fail "$case/$variant has unsupported expected status: $expected"
  if [[ "$variant" == "vulnerable" && "$expected" != "unsafe" ]]; then
    fail "$case/$variant must expect unsafe"
  fi
  if [[ "$variant" == "fixed" && "$expected" != "verified" ]]; then
    fail "$case/$variant must expect verified"
  fi

  source_dir="$REALISTIC_DIR/$case/$variant"
  artifact_path="$ROOT/$artifact.json"
  package_name="${case}_${variant}"
  compile_log="$OUT_DIR/compile/${package_name}.log"
  scan_json="$OUT_DIR/scan/${package_name}.json"
  verbose_log="$OUT_DIR/verbose/${package_name}.txt"
  smt_dir="$OUT_DIR/smt/$package_name"

  [[ -d "$source_dir" ]] || fail "$case/$variant source directory is missing"
  [[ "$artifact" == "corpus/realistic_artifacts/$package_name" ]] || fail "$case/$variant artifact path must be corpus/realistic_artifacts/$package_name"

  echo "== $case/$variant =="
  if ! (cd "$source_dir" && "$NARGO" compile --silence-warnings --force >"$compile_log" 2>&1); then
    printf '%s\t%s\tcompile_failed\t\t\t0\t0\tsee %s\n' "$case" "$variant" "$compile_log" >> "$SUMMARY"
    cat "$compile_log" >&2
    fail "$case/$variant failed to compile"
  fi

  jq '{noir_version, bytecode}' "$source_dir/target/$package_name.json" > "$artifact_path"
  if ! jq -e 'has("noir_version") and has("bytecode") and (keys | length == 2)' "$artifact_path" >/dev/null; then
    fail "$case/$variant sanitized artifact has unexpected shape"
  fi

  if rg -n '/home/said|debug_symbols|file_map|source' "$artifact_path" >/dev/null; then
    fail "$case/$variant sanitized artifact contains local paths or debug metadata"
  fi

  rm -rf "$smt_dir"
  mkdir -p "$smt_dir"

  start_ms="$(ms_now)"
  if ! timeout "${SCAN_WALL_TIMEOUT_SEC}s" "$ADAPTER" scan "$ROOT/$artifact" \
    --fixed "$fixed" \
    --targets "$targets" \
    --format json \
    --timeout "$TIMEOUT_MS" \
    --dump-smt "$smt_dir" > "$scan_json"; then
    elapsed_ms="$(elapsed_since "$start_ms")"
    printf '%s\t%s\tscan_failed\t\t\t0\t%s\tsee %s\n' "$case" "$variant" "$elapsed_ms" "$scan_json" >> "$SUMMARY"
    fail "$case/$variant scan failed or timed out; see $scan_json and $smt_dir"
  fi
  elapsed_ms="$(elapsed_since "$start_ms")"

  timeout "${SCAN_WALL_TIMEOUT_SEC}s" "$ADAPTER" scan "$ROOT/$artifact" \
    --fixed "$fixed" \
    --targets "$targets" \
    --timeout "$TIMEOUT_MS" \
    --verbose > "$verbose_log" || true

  status="$(json_value "$scan_json" '[.programs[].circuits[].targets[].status] | unique | join(",")')"
  reason="$(json_value "$scan_json" '[.programs[].circuits[].targets[].reason // ""] | unique | join(";")')"
  target_count="$(json_value "$scan_json" '[.programs[].circuits[].targets[]] | length')"
  n_wires="$(json_value "$scan_json" '[.programs[].circuits[].n_wires // 0] | add')"
  orig_constraints="$(json_value "$scan_json" '[.programs[].circuits[].orig_constraint_count // 0] | add')"
  unsupported_reasons="$(json_value "$scan_json" '[.programs[].circuits[].unsupported_reasons[]] | unique | join(";")')"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$case" "$variant" "$status" "$n_wires" "$orig_constraints" "$target_count" "$elapsed_ms" "$reason" >> "$SUMMARY"

  if [[ "$target_count" == "0" ]]; then
    fail "$case/$variant produced no scan targets; see $verbose_log"
  fi
  if [[ -n "$unsupported_reasons" ]]; then
    fail "$case/$variant produced unsupported reasons: $unsupported_reasons; see $verbose_log"
  fi
  if [[ "$status" == *unsupported* || "$status" == *unknown* ]]; then
    fail "$case/$variant produced hard-failure status $status; see $scan_json, $verbose_log, and $smt_dir"
  fi
  if [[ "$status" != "$expected" ]]; then
    fail "$case/$variant expected $expected, got $status; see $scan_json, $verbose_log, and $smt_dir"
  fi
done < <(tail -n +2 "$MANIFEST")

artifact_variants > "$tmp_artifacts"
if grep -q $'^INVALID\t' "$tmp_artifacts"; then
  grep $'^INVALID\t' "$tmp_artifacts" >&2
  fail "realistic artifact filenames must end with _vulnerable.json or _fixed.json"
fi
cat "$tmp_artifacts" | assert_no_duplicates "artifact"
assert_same_rows "manifest" "$tmp_manifest" "artifacts" "$tmp_artifacts"

vulnerable_unsafe="$(awk -F '\t' '$2 == "vulnerable" && $3 == "unsafe" { n += 1 } END { print n + 0 }' "$SUMMARY")"
fixed_verified="$(awk -F '\t' '$2 == "fixed" && $3 == "verified" { n += 1 } END { print n + 0 }' "$SUMMARY")"
expected_vulnerable="$(awk -F '\t' '$2 == "vulnerable" && $6 == "unsafe" { n += 1 } END { print n + 0 }' "$MANIFEST")"
expected_fixed="$(awk -F '\t' '$2 == "fixed" && $6 == "verified" { n += 1 } END { print n + 0 }' "$MANIFEST")"
[[ "$vulnerable_unsafe" == "$expected_vulnerable" ]] || fail "expected $expected_vulnerable vulnerable unsafe rows, got $vulnerable_unsafe"
[[ "$fixed_verified" == "$expected_fixed" ]] || fail "expected $expected_fixed fixed verified rows, got $fixed_verified"

echo
echo "summary: $SUMMARY"
awk -F '\t' 'NR > 1 { counts[$2 "/" $3] += 1 } END { for (status in counts) print status "=" counts[status] }' "$SUMMARY" | sort
echo "checked $(tail -n +2 "$SUMMARY" | wc -l) realistic corpus variants"
