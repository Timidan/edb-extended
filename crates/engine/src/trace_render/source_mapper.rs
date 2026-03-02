// EDB - Trace Render: Source Mapper
// Maps bytecode PCs to source code locations (file, line, function name).
// Replaces the source extraction logic from decodeTraceInit.ts and pcMapper.ts.

use std::collections::HashMap;
use std::path::Path;

use alloy_primitives::Address;
use tracing::info;

use crate::analysis::AnalysisResult;
use crate::Artifact;

/// A parsed source map entry for one opcode.
#[derive(Debug, Clone)]
pub struct SourceMapEntry {
    /// Byte offset in the source file.
    pub offset: usize,
    /// Length in bytes of the source range.
    pub length: usize,
    /// Source file index (from compiler output).
    pub file_index: i32,
    /// Jump type: 'i' = into function, 'o' = out of function, '-' = regular.
    pub jump_type: String,
}

/// Source location for a specific PC, resolved to file path and line number.
#[derive(Debug, Clone)]
pub struct ResolvedSource {
    pub file_path: String,
    pub line: usize,
    pub jump_type: String,
    pub function_name: Option<String>,
    pub contract_name: Option<String>,
}

/// Per-contract source mapping: maps runtime PC → ResolvedSource.
#[derive(Debug, Clone)]
pub struct ContractSourceMap {
    /// Maps PC → ResolvedSource.
    pub pc_map: HashMap<usize, ResolvedSource>,
    /// Maps PC → source-map jump type even when file attribution is unavailable.
    pub jump_type_by_pc: HashMap<usize, String>,
    /// Contract name from the artifact.
    pub contract_name: String,
}

/// All source maps keyed by bytecode_address.
pub type SourceMaps = HashMap<Address, ContractSourceMap>;

/// Build source maps for all contracts in the artifacts.
///
/// For each artifact, parses the deployed bytecode source map and creates
/// a mapping from PC to source location (file, line, function, contract).
pub fn build_source_maps(
    artifacts: &HashMap<Address, Artifact>,
    recompiled_artifacts: &HashMap<Address, Artifact>,
    analysis_results: &HashMap<Address, AnalysisResult>,
    runtime_bytecodes: &HashMap<Address, Vec<u8>>,
) -> SourceMaps {
    let mut maps = SourceMaps::new();

    for (address, artifact) in artifacts {
        if let Some(csm) = build_contract_source_map(
            artifact,
            *address,
            analysis_results,
            runtime_bytecodes.get(address).map(Vec::as_slice),
        ) {
            info!(
                address = %address,
                contract_name = %csm.contract_name,
                pc_map_len = csm.pc_map.len(),
                jump_type_map_len = csm.jump_type_by_pc.len(),
                "source-mapper built contract source map"
            );
            maps.insert(*address, csm);
        } else {
            info!(
                address = %address,
                has_runtime = runtime_bytecodes.get(address).is_some(),
                "source-mapper skipped contract source map"
            );
        }
    }

    // Some bytecode addresses can be present only in recompiled artifacts.
    // Use them as a fallback source-map provider without overriding canonical artifacts.
    for (address, artifact) in recompiled_artifacts {
        if maps.contains_key(address) {
            continue;
        }
        if let Some(csm) = build_contract_source_map(
            artifact,
            *address,
            analysis_results,
            runtime_bytecodes.get(address).map(Vec::as_slice),
        ) {
            info!(
                address = %address,
                contract_name = %csm.contract_name,
                pc_map_len = csm.pc_map.len(),
                jump_type_map_len = csm.jump_type_by_pc.len(),
                "source-mapper built fallback recompiled contract source map"
            );
            maps.insert(*address, csm);
        } else {
            info!(
                address = %address,
                has_runtime = runtime_bytecodes.get(address).is_some(),
                "source-mapper skipped fallback recompiled contract source map"
            );
        }
    }

    maps
}

/// Build a source map for a single contract from its artifact.
fn build_contract_source_map(
    artifact: &Artifact,
    address: Address,
    analysis_results: &HashMap<Address, AnalysisResult>,
    runtime_bytecode: Option<&[u8]>,
) -> Option<ContractSourceMap> {
    let (contract_name, bytecode_bytes, source_map_str) =
        select_best_contract_variant(artifact, runtime_bytecode)?;

    // Build file index → (path, source_content) map from compiler output
    let file_map = build_file_map(artifact);

    // Parse bytecode into opcode steps (pc → opcode_index)
    let opcode_steps = build_opcode_steps(&bytecode_bytes);

    // Parse source map entries
    let source_entries = parse_source_map(&source_map_str);

    // Build function ranges from analysis results for this address
    let function_ranges = build_function_ranges(address, analysis_results, &file_map);

    // Map each PC to its resolved source location
    let mut pc_map = HashMap::new();
    let mut jump_type_by_pc = HashMap::new();
    for (opcode_idx, (pc, _opcode)) in opcode_steps.iter().enumerate() {
        if let Some(entry) = source_entries.get(opcode_idx) {
            jump_type_by_pc.insert(*pc, entry.jump_type.clone());
            if entry.file_index >= 0 {
                let file_idx = entry.file_index as u32;
                if let Some((file_path, source_content)) = file_map.get(&file_idx) {
                    let line = offset_to_line(source_content, entry.offset);
                    let function_name = find_function_at_offset(
                        file_idx,
                        entry.offset,
                        entry.length,
                        &function_ranges,
                    );

                    pc_map.insert(
                        *pc,
                        ResolvedSource {
                            file_path: file_path.clone(),
                            line,
                            jump_type: entry.jump_type.clone(),
                            function_name,
                            contract_name: Some(contract_name.clone()),
                        },
                    );
                }
            }
        }
    }

    Some(ContractSourceMap { pc_map, jump_type_by_pc, contract_name })
}

/// Select the contract variant whose deployed bytecode best matches runtime bytecode.
///
/// Artifacts can contain multiple compiled contracts per file. Choosing by metadata
/// contract name is not always reliable in replay traces; runtime matching is more stable.
fn select_best_contract_variant(
    artifact: &Artifact,
    runtime_bytecode: Option<&[u8]>,
) -> Option<(String, Vec<u8>, String)> {
    const MIN_RUNTIME_PREFIX_RATIO: f64 = 0.45;
    const MIN_RUNTIME_PREFIX_BYTES: usize = 64;
    const MIN_PREFERRED_FALLBACK_PREFIX_BYTES: usize = 256;

    fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
        a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
    }

    fn is_runtime_match_confident(
        prefix_len: usize,
        runtime_len: usize,
        candidate_len: usize,
        min_ratio: f64,
        min_prefix_bytes: usize,
    ) -> bool {
        if runtime_len == 0 || candidate_len == 0 {
            return false;
        }
        let compare_len = runtime_len.min(candidate_len);
        if compare_len == 0 {
            return false;
        }
        let required_prefix = min_prefix_bytes.min(compare_len);
        if prefix_len < required_prefix {
            return false;
        }
        let ratio = prefix_len as f64 / compare_len as f64;
        ratio >= min_ratio
    }

    #[derive(Debug)]
    struct Candidate {
        name: String,
        bytecode: Vec<u8>,
        source_map: String,
        score: usize,
        bytecode_len: usize,
        source_map_len: usize,
        preferred_name: bool,
    }

    let preferred_name = artifact.contract_name();
    let mut candidates: Vec<Candidate> = Vec::new();

    for contracts in artifact.output.contracts.values() {
        for (name, contract) in contracts {
            let evm = match contract.evm.as_ref() {
                Some(v) => v,
                None => continue,
            };
            let deployed = match evm.deployed_bytecode.as_ref() {
                Some(v) => v,
                None => continue,
            };
            let bytecode_obj = match deployed.bytecode.as_ref() {
                Some(v) => v,
                None => continue,
            };
            let source_map = match bytecode_obj.source_map.as_ref() {
                Some(v) if !v.is_empty() => v.clone(),
                _ => continue,
            };
            let bytecode = match extract_bytecode_bytes(&bytecode_obj.object) {
                Some(v) if !v.is_empty() => v,
                _ => continue,
            };

            let mut score = 0usize;
            if let Some(runtime) = runtime_bytecode {
                score = common_prefix_len(runtime, &bytecode);
            }

            candidates.push(Candidate {
                name: name.clone(),
                bytecode_len: bytecode.len(),
                source_map_len: source_map.len(),
                bytecode,
                source_map,
                score,
                preferred_name: !preferred_name.is_empty() && name == preferred_name,
            });
        }
    }

    if candidates.is_empty() {
        return None;
    }

    // With runtime bytecode available, match confidence is mandatory.
    // Fail closed on weak matches to avoid false inline src attribution.
    if let Some(runtime) = runtime_bytecode {
        candidates.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| {
                    // Prefer explicit artifact contract-name match on equal score.
                    b.preferred_name.cmp(&a.preferred_name)
                })
                .then_with(|| b.bytecode_len.cmp(&a.bytecode_len))
                .then_with(|| b.source_map_len.cmp(&a.source_map_len))
        });

        let best = candidates.remove(0);
        if !is_runtime_match_confident(
            best.score,
            runtime.len(),
            best.bytecode_len,
            MIN_RUNTIME_PREFIX_RATIO,
            MIN_RUNTIME_PREFIX_BYTES,
        ) {
            info!(
                preferred_name = ?preferred_name,
                best_name = %best.name,
                best_score = best.score,
                best_bytecode_len = best.bytecode_len,
                runtime_len = runtime.len(),
                second_score = ?candidates.first().map(|candidate| candidate.score),
                best_preferred = best.preferred_name,
                "source-mapper runtime match below confidence threshold"
            );
            // Fallback for contracts whose metadata/optimizer settings yield lower
            // prefix ratios despite correct contract identity (e.g., runtime mutability
            // rewrites). Keep this guarded to avoid broad false attribution.
            if best.preferred_name
                && best.score >= MIN_PREFERRED_FALLBACK_PREFIX_BYTES
                && has_reasonable_runtime_length_parity(runtime.len(), best.bytecode_len)
                && has_clear_score_dominance(
                    best.score,
                    candidates.first().map(|candidate| candidate.score),
                )
            {
                info!(
                    preferred_name = ?preferred_name,
                    best_name = %best.name,
                    best_score = best.score,
                    "source-mapper accepted preferred-name fallback for low-confidence runtime match"
                );
                return Some((best.name, best.bytecode, best.source_map));
            }
            info!(
                preferred_name = ?preferred_name,
                best_name = %best.name,
                best_score = best.score,
                best_preferred = best.preferred_name,
                "source-mapper rejected low-confidence runtime match"
            );
            return None;
        }

        return Some((best.name, best.bytecode, best.source_map));
    }

    // Without runtime hints, trust artifact metadata contract name first.
    candidates.sort_by(|a, b| {
        b.preferred_name
            .cmp(&a.preferred_name)
            .then_with(|| b.bytecode_len.cmp(&a.bytecode_len))
            .then_with(|| b.source_map_len.cmp(&a.source_map_len))
    });
    let best = candidates.into_iter().next()?;
    Some((best.name, best.bytecode, best.source_map))
}

fn extract_bytecode_bytes(
    bytecode_object: &foundry_compilers::artifacts::BytecodeObject,
) -> Option<Vec<u8>> {
    if let Some(bytes) = bytecode_object.as_bytes() {
        if !bytes.is_empty() {
            return Some(bytes.to_vec());
        }
    }

    // Sourcify/solc outputs can contain unresolved link placeholders
    // like "__$abcd...$__". Replace them with zero bytes so opcode
    // boundary mapping can still be constructed deterministically.
    let raw = bytecode_object.as_str()?;
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    if hex.is_empty() {
        return None;
    }

    let chars: Vec<char> = hex.chars().collect();
    let mut normalized = String::with_capacity(chars.len());
    let mut i = 0usize;
    while i < chars.len() {
        if i + 3 < chars.len() && chars[i] == '_' && chars[i + 1] == '_' && chars[i + 2] == '$' {
            let mut end = i + 3;
            while end + 2 < chars.len() {
                if chars[end] == '$' && chars[end + 1] == '_' && chars[end + 2] == '_' {
                    let token_len = end + 3 - i;
                    if token_len % 2 != 0 {
                        return None;
                    }
                    normalized.extend(std::iter::repeat_n('0', token_len));
                    i = end + 3;
                    break;
                }
                end += 1;
            }
            if i > end {
                continue;
            }
            return None;
        }

        let ch = chars[i];
        if !ch.is_ascii_hexdigit() {
            return None;
        }
        normalized.push(ch);
        i += 1;
    }

    if normalized.len() % 2 != 0 {
        return None;
    }

    let mut out = Vec::with_capacity(normalized.len() / 2);
    let bytes = normalized.as_bytes();
    for idx in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[idx])?;
        let lo = hex_nibble(bytes[idx + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn has_reasonable_runtime_length_parity(runtime_len: usize, candidate_len: usize) -> bool {
    if runtime_len == 0 || candidate_len == 0 {
        return false;
    }
    let max_len = runtime_len.max(candidate_len);
    let len_delta = runtime_len.abs_diff(candidate_len);
    let allowed_delta = (max_len / 10).max(64);
    len_delta <= allowed_delta
}

fn has_clear_score_dominance(best_score: usize, second_score: Option<usize>) -> bool {
    match second_score {
        None => true,
        Some(0) => best_score > 0,
        Some(score) => best_score >= score.saturating_mul(2),
    }
}

/// Parse bytecode into a list of (pc, opcode) pairs.
/// PUSH instructions consume extra bytes for their argument.
fn build_opcode_steps(bytecode: &[u8]) -> Vec<(usize, u8)> {
    let mut steps = Vec::new();
    let mut pc = 0;
    while pc < bytecode.len() {
        let op = bytecode[pc];
        steps.push((pc, op));
        // PUSH1..PUSH32 consume 1..32 extra bytes
        if (0x60..=0x7f).contains(&op) {
            pc += 1 + (op - 0x60 + 1) as usize;
        } else {
            pc += 1;
        }
    }
    steps
}

/// Parse a Solidity source map string into entries.
/// Format: "s:l:f:j;s:l:f:j;..." where fields can be omitted (inheriting from previous).
fn parse_source_map(source_map: &str) -> Vec<SourceMapEntry> {
    let segments: Vec<&str> = source_map.split(';').collect();
    let mut entries = Vec::with_capacity(segments.len());

    let mut last_offset: usize = 0;
    let mut last_length: usize = 0;
    let mut last_file: i32 = -1;
    let mut last_jump = String::from("-");

    for segment in segments {
        if !segment.is_empty() {
            let parts: Vec<&str> = segment.split(':').collect();

            if let Some(&s) = parts.first() {
                if !s.is_empty() {
                    if let Ok(v) = s.parse::<usize>() {
                        last_offset = v;
                    }
                }
            }
            if let Some(&l) = parts.get(1) {
                if !l.is_empty() {
                    if let Ok(v) = l.parse::<usize>() {
                        last_length = v;
                    }
                }
            }
            if let Some(&f) = parts.get(2) {
                if !f.is_empty() {
                    if let Ok(v) = f.parse::<i32>() {
                        last_file = v;
                    }
                }
            }
            if let Some(&j) = parts.get(3) {
                if !j.is_empty() {
                    last_jump = j.to_string();
                }
            }
        }

        entries.push(SourceMapEntry {
            offset: last_offset,
            length: last_length,
            file_index: last_file,
            jump_type: last_jump.clone(),
        });
    }

    entries
}

/// Convert a byte offset in a source file to a 1-based line number.
fn offset_to_line(source: &str, offset: usize) -> usize {
    let mut line = 1;
    let mut acc = 0;
    for ln in source.split('\n') {
        acc += ln.len() + 1; // +1 for newline
        if acc > offset {
            return line;
        }
        line += 1;
    }
    line
}

/// A function range in source code.
#[derive(Debug, Clone)]
struct FunctionRange {
    file_index: u32,
    offset: usize,
    length: usize,
    name: String,
}

/// Build function ranges from analysis results.
fn build_function_ranges(
    address: Address,
    analysis_results: &HashMap<Address, AnalysisResult>,
    _file_map: &HashMap<u32, (String, String)>,
) -> Vec<FunctionRange> {
    let mut ranges = Vec::new();

    if let Some(analysis) = analysis_results.get(&address) {
        for (_ufid, func_ref) in &analysis.ufid_to_function {
            let src = func_ref.src();
            ranges.push(FunctionRange {
                file_index: src.file,
                offset: src.start,
                length: src.length,
                name: func_ref.name(),
            });
        }
    }

    // Keep function attribution deterministic across runs.
    ranges.sort_by(|a, b| {
        a.file_index
            .cmp(&b.file_index)
            .then(a.offset.cmp(&b.offset))
            .then(a.length.cmp(&b.length))
            .then(a.name.cmp(&b.name))
    });

    ranges
}

/// Find the function name for a given source offset.
fn find_function_at_offset(
    file_index: u32,
    offset: usize,
    _length: usize,
    function_ranges: &[FunctionRange],
) -> Option<String> {
    // Find the tightest enclosing function range
    let mut best: Option<&FunctionRange> = None;

    for range in function_ranges {
        if range.file_index == file_index
            && offset >= range.offset
            && offset < range.offset + range.length
        {
            match best {
                None => best = Some(range),
                Some(current_best) => {
                    // Prefer tighter (smaller) ranges
                    if range.length < current_best.length {
                        best = Some(range);
                    }
                }
            }
        }
    }

    best.map(|r| r.name.clone())
}

/// Build a map from file index to (file_path, source_content) from the artifact.
fn build_file_map(artifact: &Artifact) -> HashMap<u32, (String, String)> {
    let mut map = HashMap::new();
    let mut input_sources_by_path: HashMap<String, String> = HashMap::new();
    let mut input_sources_by_filename: HashMap<String, String> = HashMap::new();

    // Extract sources from compiler input (has source content).
    // Keep both exact-path and filename indices because compiler output paths can
    // differ from input paths (flattened/project-root normalization differences).
    for (path, source) in &artifact.input.sources {
        let path_str = path.to_string_lossy().to_string();
        let content = source.content.to_string();
        input_sources_by_path.insert(path_str.clone(), content.clone());

        if let Some(filename) = Path::new(&path_str).file_name() {
            let filename = filename.to_string_lossy().to_string();
            input_sources_by_filename.entry(filename).or_insert(content);
        }
    }

    // Build by output.sources IDs first (canonical source-map index order).
    for (out_path, source_file) in &artifact.output.sources {
        let out_path_str = out_path.to_string_lossy().to_string();

        let content = input_sources_by_path.get(&out_path_str).cloned().or_else(|| {
            let filename = Path::new(&out_path_str)
                .file_name()
                .map(|name| name.to_string_lossy().to_string())?;
            input_sources_by_filename.get(&filename).cloned()
        });

        if let Some(content) = content {
            map.insert(source_file.id, (out_path_str, content));
        }
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_source_map() {
        let sm = "26:236:0:-:0;-;-;33:2:1;-;26:236:0";
        let entries = parse_source_map(sm);
        assert_eq!(entries.len(), 6);
        assert_eq!(entries[0].offset, 26);
        assert_eq!(entries[0].length, 236);
        assert_eq!(entries[0].file_index, 0);
        // Entry 1 inherits from entry 0
        assert_eq!(entries[1].offset, 26);
        assert_eq!(entries[1].length, 236);
        // Entry 3 has new values
        assert_eq!(entries[3].offset, 33);
        assert_eq!(entries[3].length, 2);
        assert_eq!(entries[3].file_index, 1);
    }

    #[test]
    fn test_offset_to_line() {
        let source = "line1\nline2\nline3\nline4";
        assert_eq!(offset_to_line(source, 0), 1);
        assert_eq!(offset_to_line(source, 5), 1); // newline after "line1"
        assert_eq!(offset_to_line(source, 6), 2); // start of "line2"
        assert_eq!(offset_to_line(source, 12), 3);
    }

    #[test]
    fn test_build_opcode_steps() {
        // PUSH1 0x40, MSTORE, PUSH1 0x80, PUSH1 0x40
        let bytecode = vec![0x60, 0x40, 0x52, 0x60, 0x80, 0x60, 0x40];
        let steps = build_opcode_steps(&bytecode);
        assert_eq!(steps.len(), 4);
        assert_eq!(steps[0], (0, 0x60)); // PUSH1 at PC 0
        assert_eq!(steps[1], (2, 0x52)); // MSTORE at PC 2
        assert_eq!(steps[2], (3, 0x60)); // PUSH1 at PC 3
        assert_eq!(steps[3], (5, 0x60)); // PUSH1 at PC 5
    }
}
