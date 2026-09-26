use std::collections::BTreeMap;
use std::path::Path;

use acir::{FieldElement, circuit::Program};
use color_eyre::eyre::{Context, Result, eyre};
use serde::Deserialize;

use crate::debug_info::{Abi, ProgramDebugData, RawDebugFile};

/// Everything a scan needs from one artifact file.
pub(crate) struct LoadedArtifact {
    pub(crate) noir_version: Option<String>,
    pub(crate) programs: Vec<LoadedProgram>,
}

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
    /// Kept untyped and parsed lazily, like `debug_symbols`: the ABI is display
    /// sugar, and an unknown `kind` in a newer Noir must not make an otherwise
    /// loadable artifact fail with a misleading "version mismatch" error.
    #[serde(default)]
    abi: Option<serde_json::Value>,
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
    abi: Option<serde_json::Value>,
    #[serde(default)]
    debug_symbols: Option<String>,
}

enum Artifact {
    Program(ProgramArtifact),
    Contract(ContractArtifact),
}

pub(crate) fn load_programs(path: &Path) -> Result<LoadedArtifact> {
    let (artifact, noir_version) = read_artifact(path)
        .wrap_err_with(|| format!("failed to read Noir artifact {}", path.display()))?;

    let programs = match artifact {
        Artifact::Program(program) => {
            let debug = parse_debug_data(
                program.debug_symbols.as_deref(),
                program.file_map,
                "program",
            );
            vec![LoadedProgram {
                name: artifact_stem(path),
                program: program.bytecode,
                abi: parse_abi(program.abi, "program"),
                debug,
            }]
        }
        Artifact::Contract(contract) => {
            let contract_name = contract.name;
            let file_map = contract.file_map;
            contract
                .functions
                .into_iter()
                .map(|function| {
                    let debug = parse_debug_data(
                        function.debug_symbols.as_deref(),
                        file_map.clone(),
                        &function.name,
                    );
                    let abi = parse_abi(function.abi, &function.name);
                    LoadedProgram {
                        name: format!("{contract_name}::{}", function.name),
                        program: function.bytecode,
                        abi,
                        debug,
                    }
                })
                .collect()
        }
    };

    Ok(LoadedArtifact {
        noir_version,
        programs,
    })
}

fn parse_abi(abi: Option<serde_json::Value>, label: &str) -> Option<Abi> {
    let abi = abi?;
    match serde_json::from_value::<Abi>(abi) {
        Ok(abi) => Some(abi),
        Err(message) => {
            eprintln!("warning: ignoring ABI of {label}: {message}");
            None
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

fn read_artifact(path: &Path) -> Result<(Artifact, Option<String>)> {
    // `with_extension` would rewrite the last dot-segment, so `case_v1.2`
    // would silently read `case_v1.json`. Only append when the file is missing.
    let file = if path.exists() {
        path.to_path_buf()
    } else {
        let mut name = path.as_os_str().to_owned();
        name.push(".json");
        std::path::PathBuf::from(name)
    };
    let json = std::fs::read(&file)
        .wrap_err_with(|| format!("failed to read artifact file {}", file.display()))?;
    let metadata = serde_json::from_slice::<ArtifactMetadata>(&json).ok();
    let noir_version = metadata
        .as_ref()
        .and_then(|metadata| metadata.noir_version.clone());

    serde_json::from_slice::<ProgramArtifact>(&json)
        .map(Artifact::Program)
        .or_else(|program_error| {
            serde_json::from_slice::<ContractArtifact>(&json)
                .map(Artifact::Contract)
                .map_err(|contract_error| {
                    let noir_version =
                        noir_version.clone().unwrap_or_else(|| "unknown".to_owned());
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
        .map(|artifact| (artifact, noir_version))
}

fn artifact_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("program")
        .to_owned()
}
