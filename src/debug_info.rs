//! Optional source-level debug data parsed from unsanitized Noir artifacts.
//!
//! Full `nargo compile` artifacts carry three extra fields next to `bytecode`:
//! `abi` (parameter/return types of `main`), `debug_symbols` (per-function
//! opcode -> call-stack maps, serialized as base64-encoded DEFLATE-compressed
//! JSON) and `file_map` (file id -> path + source text). The committed example
//! artifacts are sanitized down to `noir_version` + `bytecode`, so everything
//! in this module is strictly optional: scans still work without it, they just
//! lose witness names and source locations in the report.
//!
//! The raw structs below mirror the serde shape produced by the Noir revision
//! pinned in `Cargo.toml` (`tooling/noirc_artifacts/src/debug.rs` and
//! `tooling/noirc_abi/src/lib.rs`). Unknown fields are ignored and parse
//! failures degrade to "no debug info" instead of failing the scan, so older
//! or newer artifacts cannot break loading.

use std::collections::BTreeMap;
use std::io::Read;

use base64::Engine;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ABI (uncompressed JSON in the artifact)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct Abi {
    #[serde(default)]
    pub(crate) parameters: Vec<AbiParameter>,
    #[serde(default)]
    pub(crate) return_type: Option<AbiReturnType>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct AbiParameter {
    pub(crate) name: String,
    #[serde(rename = "type")]
    pub(crate) typ: AbiType,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct AbiReturnType {
    pub(crate) abi_type: AbiType,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub(crate) enum AbiType {
    Field,
    Boolean,
    Integer {},
    Array {
        length: u32,
        #[serde(rename = "type")]
        typ: Box<AbiType>,
    },
    String {
        length: u32,
    },
    Struct {
        fields: Vec<AbiStructField>,
    },
    Tuple {
        fields: Vec<AbiType>,
    },
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct AbiStructField {
    pub(crate) name: String,
    #[serde(rename = "type")]
    pub(crate) typ: AbiType,
}

/// Witness-index -> human name mapping derived from the ABI.
///
/// Soundness of the mapping: `noirc_abi::Abi::encode` flattens `main`
/// parameters in declaration order into witnesses `0..N` (see the pinned Noir
/// revision), so slot `k` of the flattened parameter list is ACIR witness `k`.
/// Return values are reported by `return_index` over the sorted
/// `circuit.return_values` set, which matches flattened return slots when the
/// counts agree; the constructor refuses to guess otherwise.
#[derive(Clone, Debug, Default)]
pub(crate) struct AbiNaming {
    parameter_slots: Vec<String>,
    return_slots: Vec<String>,
}

impl AbiNaming {
    pub(crate) fn new(abi: &Abi, n_param_witnesses: usize, n_return_witnesses: usize) -> Self {
        let mut parameter_slots = Vec::new();
        for parameter in &abi.parameters {
            flatten_abi_type(&parameter.typ, &parameter.name, &mut parameter_slots);
        }
        // The positional layout only holds when the circuit agrees on the
        // parameter witness count; otherwise drop the names rather than
        // mislabel witnesses.
        if parameter_slots.len() != n_param_witnesses {
            parameter_slots.clear();
        }

        let mut return_slots = Vec::new();
        if let Some(return_type) = &abi.return_type {
            flatten_abi_type(&return_type.abi_type, "return", &mut return_slots);
        }
        if return_slots.len() != n_return_witnesses {
            return_slots.clear();
        }

        Self {
            parameter_slots,
            return_slots,
        }
    }

    /// Name of ACIR witness `index` when it is a `main` parameter slot.
    pub(crate) fn parameter_name(&self, witness_index: u32) -> Option<&str> {
        self.parameter_slots
            .get(witness_index as usize)
            .map(String::as_str)
    }

    /// Name of the `return_index`-th return slot (sorted witness order).
    pub(crate) fn return_name(&self, return_index: usize) -> Option<&str> {
        self.return_slots.get(return_index).map(String::as_str)
    }
}

fn flatten_abi_type(typ: &AbiType, prefix: &str, out: &mut Vec<String>) {
    match typ {
        AbiType::Field | AbiType::Boolean | AbiType::Integer {} => out.push(prefix.to_owned()),
        AbiType::Array { length, typ } => {
            for index in 0..*length {
                flatten_abi_type(typ, &format!("{prefix}[{index}]"), out);
            }
        }
        AbiType::String { length } => {
            for index in 0..*length {
                out.push(format!("{prefix}[{index}]"));
            }
        }
        AbiType::Struct { fields } => {
            for field in fields {
                flatten_abi_type(&field.typ, &format!("{prefix}.{}", field.name), out);
            }
        }
        AbiType::Tuple { fields } => {
            for (index, field) in fields.iter().enumerate() {
                flatten_abi_type(field, &format!("{prefix}.{index}"), out);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Debug symbols (base64 + DEFLATE compressed JSON in the artifact)
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct RawProgramDebugInfo {
    #[serde(default)]
    debug_infos: Vec<RawDebugInfo>,
}

#[derive(Debug, Default, Deserialize)]
struct RawDebugInfo {
    /// ACIR opcode index -> call-stack id in `location_tree`.
    #[serde(default)]
    acir_locations: BTreeMap<usize, u32>,
    #[serde(default)]
    location_tree: RawLocationTree,
}

#[derive(Debug, Default, Deserialize)]
struct RawLocationTree {
    #[serde(default)]
    locations: Vec<RawLocationNode>,
}

#[derive(Debug, Deserialize)]
struct RawLocationNode {
    parent: Option<u32>,
    value: RawLocation,
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct RawLocation {
    span: RawSpan,
    file: usize,
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct RawSpan {
    start: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct RawDebugFile {
    pub(crate) source: String,
    pub(crate) path: String,
}

/// A resolved source position, ready for reporting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct SourceLocation {
    pub(crate) file: String,
    /// 1-based.
    pub(crate) line: usize,
    /// 1-based.
    pub(crate) column: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) snippet: Option<String>,
}

impl SourceLocation {
    pub(crate) fn display(&self) -> String {
        let mut rendered = format!("{}:{}:{}", self.file, self.line, self.column);
        if let Some(snippet) = &self.snippet {
            rendered.push_str(&format!("  `{snippet}`"));
        }
        rendered
    }
}

struct SourceFile {
    path: String,
    source: String,
    /// Byte offsets where each line starts; used for offset -> line/column.
    line_starts: Vec<usize>,
}

/// Parsed debug symbols + file map for one program artifact.
pub(crate) struct ProgramDebugData {
    functions: Vec<RawDebugInfo>,
    files: BTreeMap<usize, SourceFile>,
}

impl ProgramDebugData {
    /// Decode the artifact's `debug_symbols` string and `file_map`. Returns an
    /// error string (used as a warning) when the payload does not match the
    /// expected format; callers degrade to source-less reports.
    pub(crate) fn parse(
        debug_symbols_b64: &str,
        file_map: BTreeMap<usize, RawDebugFile>,
    ) -> Result<Self, String> {
        let compressed = base64::prelude::BASE64_STANDARD
            .decode(debug_symbols_b64)
            .map_err(|error| format!("debug_symbols is not valid base64: {error}"))?;
        let mut decoder = flate2::read::DeflateDecoder::new(compressed.as_slice());
        let mut json = Vec::new();
        decoder
            .read_to_end(&mut json)
            .map_err(|error| format!("debug_symbols failed to inflate: {error}"))?;
        let raw: RawProgramDebugInfo = serde_json::from_slice(&json)
            .map_err(|error| format!("debug_symbols JSON does not match expected shape: {error}"))?;

        let files = file_map
            .into_iter()
            .map(|(file_id, file)| {
                let line_starts = compute_line_starts(&file.source);
                (
                    file_id,
                    SourceFile {
                        path: file.path,
                        source: file.source,
                        line_starts,
                    },
                )
            })
            .collect();

        Ok(Self {
            functions: raw.debug_infos,
            files,
        })
    }

    /// Resolve the source call stack of an ACIR opcode, outermost first. The
    /// last entry is the most specific (innermost) location. Empty when the
    /// opcode has no recorded location or `circuit_index` is out of range.
    pub(crate) fn opcode_call_stack(
        &self,
        circuit_index: usize,
        opcode_index: usize,
    ) -> Vec<SourceLocation> {
        let Some(function) = self.functions.get(circuit_index) else {
            return Vec::new();
        };
        let Some(&call_stack_id) = function.acir_locations.get(&opcode_index) else {
            return Vec::new();
        };

        // Mirror of noirc LocationTree::get_call_stack: walk parents up to the
        // root node, collecting locations innermost-last after the reverse.
        // The iteration cap guards against malformed (cyclic) trees.
        let mut raw_locations = Vec::new();
        let mut node_id = call_stack_id as usize;
        for _ in 0..function.location_tree.locations.len() {
            let Some(node) = function.location_tree.locations.get(node_id) else {
                break;
            };
            let Some(parent) = node.parent else {
                break;
            };
            raw_locations.push(node.value);
            node_id = parent as usize;
        }
        raw_locations.reverse();

        raw_locations
            .into_iter()
            .filter_map(|location| self.resolve_location(location))
            .collect()
    }

    /// Innermost resolved location of an ACIR opcode, if any.
    pub(crate) fn opcode_location(
        &self,
        circuit_index: usize,
        opcode_index: usize,
    ) -> Option<SourceLocation> {
        self.opcode_call_stack(circuit_index, opcode_index).pop()
    }

    fn resolve_location(&self, location: RawLocation) -> Option<SourceLocation> {
        let file = self.files.get(&location.file)?;
        let offset = location.span.start as usize;
        let line_index = match file.line_starts.binary_search(&offset) {
            Ok(index) => index,
            Err(index) => index.saturating_sub(1),
        };
        let line_start = file.line_starts.get(line_index).copied()?;
        let snippet = file
            .source
            .get(line_start..)
            .map(|rest| rest.lines().next().unwrap_or("").trim().to_owned())
            .filter(|snippet| !snippet.is_empty());

        Some(SourceLocation {
            file: file.path.clone(),
            line: line_index + 1,
            column: offset.saturating_sub(line_start) + 1,
            snippet,
        })
    }
}

fn compute_line_starts(source: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (offset, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(offset + 1);
        }
    }
    starts
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn compress_b64(json: &str) -> String {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(json.as_bytes()).unwrap();
        base64::prelude::BASE64_STANDARD.encode(encoder.finish().unwrap())
    }

    fn sample_debug_data() -> ProgramDebugData {
        // Node 0 is the root; node 1 -> main call site; node 2 -> inner expr.
        let json = r#"{
            "debug_infos": [{
                "acir_locations": {"0": 1, "3": 2},
                "location_tree": {"locations": [
                    {"parent": null, "value": {"span": {"start": 0, "end": 1}, "file": 9}},
                    {"parent": 0, "value": {"span": {"start": 24, "end": 30}, "file": 9}},
                    {"parent": 1, "value": {"span": {"start": 52, "end": 60}, "file": 9}}
                ]}
            }]
        }"#;
        let mut file_map = BTreeMap::new();
        file_map.insert(
            9,
            RawDebugFile {
                source: "fn main(a: Field) {\n    let q = hint(a);\n    assert(q * 2 == a);\n}\n"
                    .to_owned(),
                path: "src/main.nr".to_owned(),
            },
        );
        ProgramDebugData::parse(&compress_b64(json), file_map).unwrap()
    }

    #[test]
    fn parses_compressed_debug_symbols_and_resolves_locations() {
        let debug = sample_debug_data();

        let location = debug.opcode_location(0, 0).unwrap();
        assert_eq!(location.file, "src/main.nr");
        assert_eq!(location.line, 2);
        assert_eq!(location.column, 5);
        assert_eq!(location.snippet.as_deref(), Some("let q = hint(a);"));

        // Opcode 3 resolves through a two-frame call stack, innermost last.
        let call_stack = debug.opcode_call_stack(0, 3);
        assert_eq!(call_stack.len(), 2);
        assert_eq!(call_stack[1].line, 3);
        assert_eq!(
            call_stack[1].snippet.as_deref(),
            Some("assert(q * 2 == a);")
        );

        // Unknown opcodes and circuits resolve to nothing.
        assert!(debug.opcode_location(0, 7).is_none());
        assert!(debug.opcode_location(1, 0).is_none());
    }

    #[test]
    fn rejects_malformed_debug_symbols() {
        assert!(ProgramDebugData::parse("@@not-base64@@", BTreeMap::new()).is_err());
        let not_deflate = base64::prelude::BASE64_STANDARD.encode(b"plain");
        assert!(ProgramDebugData::parse(&not_deflate, BTreeMap::new()).is_err());
    }

    #[test]
    fn abi_naming_flattens_parameters_and_returns() {
        let abi: Abi = serde_json::from_str(
            r#"{
                "parameters": [
                    {"name": "a", "type": {"kind": "field"}, "visibility": "private"},
                    {"name": "arr", "type": {"kind": "array", "length": 2, "type": {"kind": "field"}}, "visibility": "private"},
                    {"name": "s", "type": {"kind": "struct", "path": "main::S", "fields": [
                        {"name": "x", "type": {"kind": "field"}},
                        {"name": "flags", "type": {"kind": "tuple", "fields": [{"kind": "boolean"}, {"kind": "integer", "sign": "unsigned", "width": 32}]}}
                    ]}, "visibility": "public"}
                ],
                "return_type": {"abi_type": {"kind": "array", "length": 2, "type": {"kind": "field"}}, "visibility": "public"},
                "error_types": {}
            }"#,
        )
        .unwrap();

        let naming = AbiNaming::new(&abi, 6, 2);
        let names: Vec<_> = (0..6)
            .map(|index| naming.parameter_name(index).unwrap().to_owned())
            .collect();
        assert_eq!(names, ["a", "arr[0]", "arr[1]", "s.x", "s.flags.0", "s.flags.1"]);
        assert_eq!(naming.return_name(0), Some("return[0]"));
        assert_eq!(naming.return_name(1), Some("return[1]"));
        assert_eq!(naming.return_name(2), None);

        // Mismatched witness counts disable naming instead of mislabeling.
        let mismatched = AbiNaming::new(&abi, 5, 1);
        assert_eq!(mismatched.parameter_name(0), None);
        assert_eq!(mismatched.return_name(0), None);
    }
}
