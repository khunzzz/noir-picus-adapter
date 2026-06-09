use std::collections::BTreeMap;
use std::path::Path;

use acir::{FieldElement, circuit::Program};
use color_eyre::eyre::{Context, Result, eyre};
use serde::Deserialize;

use crate::debug_info::{Abi, ProgramDebugData, RawDebugFile};

pub(crate) struct LoadedProgram {
    pub(crate) name: String,
    pub(crate) program: Program<FieldElement>,
    /// `main`'s ABI, when the artifact carries one (sanitized artifacts do not).
    pub(crate) abi: Option<Abi>,
    /// Parsed `debug_symbols` + `file_map`, when present and well-formed.
    pub(crate) debug: Option<ProgramDebugData>,
}

#[derive(Deserialize)]
struct ProgramArtifact {
    #[serde(deserialize_with = "Program::deserialize_program_base64")]
    bytecode: Program<FieldElement>,
    #[serde(default)]
    abi: Option<Abi>,
    /// Kept as the raw base64 payload; decoded lazily so a malformed or
    /// version-skewed debug blob can never fail the scan.
    #[serde(default)]
    debug_symbols: Option<String>,
    #[serde(default)]
    file_map: Option<BTreeMap<usize, RawDebugFile>>,
}

#[derive(Deserialize)]
struct ArtifactMetadata {
    noir_version: Option<String>,
}

#[derive(Deserialize)]
struct ContractArtifact {
    name: String,
    functions: Vec<ContractFunctionArtifact>,
    #[serde(default)]
    file_map: Option<BTreeMap<usize, RawDebugFile>>,
}

#[derive(Deserialize)]
struct ContractFunctionArtifact {
    name: String,
    #[serde(deserialize_with = "Program::deserialize_program_base64")]
    bytecode: Program<FieldElement>,
    #[serde(default)]
    abi: Option<Abi>,
    #[serde(default)]
    debug_symbols: Option<String>,
}

enum Artifact {
    Program(ProgramArtifact),
    Contract(ContractArtifact),
}

pub(crate) fn load_programs(path: &Path) -> Result<Vec<LoadedProgram>> {
    let artifact = read_artifact(path)
        .wrap_err_with(|| format!("failed to read Noir artifact {}", path.display()))?;

    match artifact {
        Artifact::Program(program) => {
            let debug = parse_debug_data(
                program.debug_symbols.as_deref(),
                program.file_map,
                "program",
            );
            Ok(vec![LoadedProgram {
                name: artifact_stem(path),
                program: program.bytecode,
                abi: program.abi,
                debug,
            }])
        }
        Artifact::Contract(contract) => {
            let contract_name = contract.name;
            let file_map = contract.file_map;
            Ok(contract
                .functions
                .into_iter()
                .map(|function| {
                    let debug = parse_debug_data(
                        function.debug_symbols.as_deref(),
                        file_map.clone(),
                        &function.name,
                    );
                    LoadedProgram {
                        name: format!("{contract_name}::{}", function.name),
                        program: function.bytecode,
                        abi: function.abi,
                        debug,
                    }
                })
                .collect())
        }
    }
}

fn parse_debug_data(
    debug_symbols: Option<&str>,
    file_map: Option<BTreeMap<usize, RawDebugFile>>,
    label: &str,
) -> Option<ProgramDebugData> {
    let debug_symbols = debug_symbols?;
    match ProgramDebugData::parse(debug_symbols, file_map.unwrap_or_default()) {
        Ok(debug) => Some(debug),
        Err(message) => {
            // Source mapping is best-effort sugar on top of the scan; warn and
            // continue rather than failing on artifacts from other Noir versions.
            eprintln!("warning: ignoring debug symbols of {label}: {message}");
            None
        }
    }
}

fn read_artifact(path: &Path) -> Result<Artifact> {
    let file = path.with_extension("json");
    let json = std::fs::read(&file)
        .wrap_err_with(|| format!("failed to read artifact file {}", file.display()))?;
    let metadata = serde_json::from_slice::<ArtifactMetadata>(&json).ok();

    serde_json::from_slice::<ProgramArtifact>(&json)
        .map(Artifact::Program)
        .or_else(|program_error| {
            serde_json::from_slice::<ContractArtifact>(&json)
                .map(Artifact::Contract)
                .map_err(|contract_error| {
                    let noir_version = metadata
                        .and_then(|metadata| metadata.noir_version)
                        .unwrap_or_else(|| "unknown".to_owned());
                    eyre!(
                        "artifact is neither ProgramArtifact nor ContractArtifact; \
                         artifact noir_version: {noir_version}; \
                         the artifact bytecode must be produced by a Noir/nargo version compatible \
                         with the acir crate used by this binary; \
                         rebuild the artifact with the nargo binary from the matching Noir checkout; \
                         program error: {program_error}; contract error: {contract_error}"
                    )
                })
        })
}

fn artifact_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("program")
        .to_owned()
}
