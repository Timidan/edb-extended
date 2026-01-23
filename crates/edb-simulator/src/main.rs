use std::io::{self, Read};
use std::str::FromStr;

use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{hex, keccak256, Address, Bytes, TxHash, TxKind, U256};
use alloy_provider::{Provider, ProviderBuilder};
use edb_common::{
    fork_and_prepare, get_blob_base_fee_update_fraction_by_spec_id, get_mainnet_spec_id,
    relax_evm_constraints, EdbDB, ForkInfo, ForkResult,
};
use edb_engine::{Artifact, CallTracer, Engine, EngineConfig, find_or_install_solc};
use foundry_compilers::artifacts::{
    output_selection::OutputSelection, CompilerOutput, Settings, SolcInput, Source, Sources,
};
use foundry_compilers::solc::SolcLanguage;
use foundry_block_explorers::contract::Metadata as EtherscanMetadata;
use std::collections::HashMap;
use eyre::WrapErr;
use reqwest::Client;
use revm::{
    context::TxEnv,
    context::result::ExecutionResult,
    context_interface::block::BlobExcessGasAndPrice,
    database::{AlloyDB, CacheDB},
    database_interface::WrapDatabaseAsync,
    primitives::hardfork::SpecId,
    Context, ExecuteEvm, InspectEvm, MainBuilder, MainContext,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, warn};

#[derive(Debug, Error)]
enum SimulatorError {
    #[error("failed to read input: {0}")]
    Io(#[from] io::Error),
    #[error("failed to parse SimulationJob: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("simulation error: {0}")]
    Simulation(String),
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("engine error: {0}")]
    Engine(String),
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum SimulationMode {
    Onchain,
    Local,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SimulationJob {
    mode: SimulationMode,
    rpc_url: String,
    chain_id: u64,
    #[serde(default)]
    block_tag: Option<String>,
    #[serde(default)]
    transaction: Option<TransactionPayload>,
    #[serde(default)]
    tx_hash: Option<String>,
    #[serde(default)]
    artifacts: Vec<SourceArtifact>,
    #[serde(default)]
    storage_overrides: Vec<StorageOverride>,
    #[serde(default)]
    analysis_options: AnalysisOptions,
    #[serde(default)]
    artifact_path: Option<String>,
    #[serde(default, alias = "artifacts_inline")]
    artifacts_inline: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionPayload {
    from: Option<String>,
    to: Option<String>,
    data: String,
    value: Option<String>,
    gas: Option<String>,
    gas_price: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourceArtifact {
    contract_name: String,
    compiler_version: Option<String>,
    sources: Vec<ContractSource>,
    abi: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContractSource {
    path: String,
    content: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StorageOverride {
    address: String,
    slot: String,
    value: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AnalysisOptions {
    #[serde(default)]
    quick_mode: bool,
    #[serde(default)]
    collect_call_tree: bool,
    #[serde(default)]
    collect_events: bool,
    #[serde(default)]
    collect_storage_diff: bool,
    #[serde(default)]
    collect_snapshots: bool,
    #[serde(default)]
    etherscan_api_key: Option<String>,
}

/// Debug session info returned when --keep-alive is used
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DebugSession {
    rpc_url: String,
    rpc_port: u16,
    snapshot_count: u64,
}

/// Indicates the quality level of trace data returned.
/// Higher levels provide more detailed debugging information.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DebugLevel {
    /// Full source-level debugging with instrumented bytecode and variable tracking
    SourceInstrumented,
    /// Opcode-level trace with call tree (no source maps or variable tracking)
    OpcodeTrace,
    /// Basic call trace from lightweight execution (no bytecode tweaking)
    CallTrace,
    /// Minimal data from eth_call/estimateGas only (last resort fallback)
    EthCallOnly,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SimulationResult {
    mode: SimulationMode,
    success: bool,
    error: Option<String>,
    warnings: Vec<String>,
    revert_reason: Option<String>,
    gas_used: Option<String>,
    gas_limit_suggested: Option<String>,
    raw_trace: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    debug_session: Option<DebugSession>,
    /// Indicates the quality level of trace data returned.
    /// Helps frontend understand what debugging features are available.
    #[serde(skip_serializing_if = "Option::is_none")]
    debug_level: Option<DebugLevel>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    jsonrpc: String,
    result: Option<T>,
    error: Option<JsonRpcError>,
    id: Value,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").with_writer(io::stderr).init();

    // Parse --keep-alive flag
    let keep_alive = std::env::args().any(|arg| arg == "--keep-alive");
    if keep_alive {
        info!("Running in keep-alive mode - RPC server will remain active after simulation");
    }

    if let Err(err) = run(keep_alive).await {
        error!("{err:?}");
        let fallback = SimulationResult {
            mode: SimulationMode::Local,
            success: false,
            error: Some(err.to_string()),
            warnings: Vec::new(),
            revert_reason: None,
            gas_used: None,
            gas_limit_suggested: None,
            raw_trace: None,
            debug_session: None,
            debug_level: None, // Error case - no trace data available
        };

        if let Err(e) = serde_json::to_writer(io::stdout(), &fallback) {
            error!("failed to write error response: {e}");
        }
    }
}

/// Derive opcode PC -> line mappings for ALL contracts in the trace using artifact source maps.
/// Stores a JSON object keyed by bytecode address with an array of {pc, line, file, jumpType} entries.
/// This handles Diamond proxies and DELEGATECALL patterns by processing each code_address.
fn enrich_opcodes_with_lines(
    artifacts: &Value,
    _snapshots: &Value,
    trace_inner: Option<&Value>,
) -> Option<Value> {
    // Gather ALL code addresses from the trace (not just the first one)
    let mut all_addrs: Vec<String> = Vec::new();
    fn gather_code_addresses(value: &Value, addrs: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (k, v) in map {
                    if (k == "code_address" || k == "codeAddress") && v.is_string() {
                        if let Some(s) = v.as_str() {
                            addrs.push(s.to_lowercase());
                        }
                    }
                    gather_code_addresses(v, addrs);
                }
            }
            Value::Array(arr) => {
                for v in arr {
                    gather_code_addresses(v, addrs);
                }
            }
            _ => {}
        }
    }

    if let Some(inner) = trace_inner {
        gather_code_addresses(inner, &mut all_addrs);
    }
    all_addrs.sort();
    all_addrs.dedup();

    if all_addrs.is_empty() {
        warn!("opcode mapping: no code_address found in trace");
        return None;
    }

    info!("opcode mapping: found {} unique code addresses in trace: {:?}", all_addrs.len(), all_addrs);

    let mut combined_map = Map::new();

    // Process each code address
    for addr in &all_addrs {
        // Get artifact for this address - try both exact match and case-insensitive
        let artifact = artifacts.get(addr)
            .or_else(|| {
                // Try finding with case-insensitive match
                artifacts.as_object().and_then(|obj| {
                    obj.iter()
                        .find(|(k, _)| k.to_lowercase() == *addr)
                        .map(|(_, v)| v)
                })
            });
        let artifact = match artifact {
            Some(a) => a,
            None => {
                warn!("opcode mapping: no artifact for {addr}, skipping");
                continue;
            }
        };

        let contracts = match artifact
            .get("output")
            .and_then(|o| o.get("contracts"))
            .and_then(Value::as_object)
        {
            Some(c) => c,
            None => {
                warn!("opcode mapping: artifact for {addr} missing output.contracts");
                continue;
            }
        };

        // PRIORITY 1: Use compilationTarget to find the exact contract
        // This is critical for Diamond facets where multiple contracts are compiled together
        // but only one is the actual deployed contract
        let compilation_target = artifact
            .get("input")
            .and_then(|i| i.get("settings"))
            .and_then(|s| s.get("compilationTarget"))
            .and_then(Value::as_object)
            .or_else(|| {
                // Try meta.Settings for Etherscan-like format
                artifact
                    .get("meta")
                    .and_then(|m| m.get("Settings"))
                    .and_then(|s| s.get("compilationTarget"))
                    .and_then(Value::as_object)
            });

        // Get meta.ContractName if present (Etherscan format)
        let contract_name = artifact.get("meta")
            .and_then(|m| m.get("ContractName"))
            .and_then(Value::as_str);

        debug!(
            "opcode mapping: {} compilationTarget={}, meta.ContractName={:?}",
            addr,
            compilation_target.is_some(),
            contract_name
        );

        let mut best: Option<(&Value, Option<&Value>, usize)> = None;
        let mut best_len: usize = 0;

        // Try to find the exact contract from compilationTarget first
        if let Some(ct) = compilation_target {
            for (file_path, contract_name) in ct {
                if let Some(contract_name_str) = contract_name.as_str() {
                    // Look for this exact contract in output.contracts
                    if let Some(file_contracts) = contracts.get(file_path).and_then(Value::as_object) {
                        if let Some(contract) = file_contracts.get(contract_name_str) {
                            if let Some(evm) = contract.get("evm") {
                                let db_val_opt = evm.get("deployedBytecode");
                                let has_srcmap = evm
                                    .get("deployedSourceMap")
                                    .or_else(|| evm.get("deployed_source_map"))
                                    .or_else(|| db_val_opt.and_then(|d| d.get("sourceMap").or_else(|| d.get("source_map"))))
                                    .and_then(Value::as_str)
                                    .map(|s| !s.is_empty())
                                    .unwrap_or(false);
                                if has_srcmap {
                                    let object_len = db_val_opt
                                        .and_then(|d| d.get("object").and_then(Value::as_str))
                                        .map(|s| s.len())
                                        .unwrap_or(0);
                                    debug!(
                                        "opcode mapping: using compilationTarget {}:{} for {}",
                                        file_path, contract_name_str, addr
                                    );
                                    best = Some((evm, db_val_opt, object_len));
                                    best_len = object_len;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        // PRIORITY 2: Use meta.ContractName (Etherscan format) to find the exact contract by name
        // This is critical for Diamond facets where compilationTarget is not available
        if best.is_none() {
            if let Some(target_contract_name) = contract_name {
                'outer: for (file_path, c) in contracts.iter() {
                    if let Some(cobj) = c.as_object() {
                        for (cname, contract) in cobj.iter() {
                            if cname == target_contract_name {
                                if let Some(evm) = contract.get("evm") {
                                    let db_val_opt = evm.get("deployedBytecode");
                                    let has_srcmap = evm
                                        .get("deployedSourceMap")
                                        .or_else(|| evm.get("deployed_source_map"))
                                        .or_else(|| db_val_opt.and_then(|d| d.get("sourceMap").or_else(|| d.get("source_map"))))
                                        .and_then(Value::as_str)
                                        .map(|s| !s.is_empty())
                                        .unwrap_or(false);
                                    if has_srcmap {
                                        let object_len = db_val_opt
                                            .and_then(|d| d.get("object").and_then(Value::as_str))
                                            .map(|s| s.len())
                                            .unwrap_or(0);
                                        debug!(
                                            "opcode mapping: using meta.ContractName match {}:{} for {}",
                                            file_path, target_contract_name, addr
                                        );
                                        best = Some((evm, db_val_opt, object_len));
                                        best_len = object_len;
                                        break 'outer;
                                    }
                                }
                            }
                        }
                    }
                }
                if best.is_none() {
                    debug!("opcode mapping: {} contract '{}' not found or has no source map", addr, target_contract_name);
                }
            }
        }

        // PRIORITY 3: Fallback to largest bytecode with source map (original heuristic)
        if best.is_none() {
            debug!("opcode mapping: {} falling back to largest bytecode heuristic", addr);
            for c in contracts.values() {
                if let Some(cobj) = c.as_object() {
                    for contract in cobj.values() {
                        let evm = match contract.get("evm") {
                            Some(e) => e,
                            None => continue,
                        };
                        let db_val_opt = evm.get("deployedBytecode");
                        let object_len = db_val_opt
                            .and_then(|d| d.get("object").and_then(Value::as_str))
                            .map(|s| s.len())
                            .unwrap_or(0);
                        let candidate_nonempty = evm
                            .get("deployedSourceMap")
                            .or_else(|| evm.get("deployed_source_map"))
                            .or_else(|| db_val_opt.and_then(|d| d.get("sourceMap").or_else(|| d.get("source_map"))))
                            .and_then(Value::as_str)
                            .map(|s| !s.is_empty())
                            .unwrap_or(false);
                        if candidate_nonempty && object_len > best_len {
                            best_len = object_len;
                            best = Some((evm, db_val_opt, object_len));
                        }
                    }
                }
            }
        }

        let (evm_best, db_best_opt, _) = match best {
            Some(t) => t,
            _ => {
                warn!("opcode mapping: no deployed source map found for {addr}");
                continue;
            }
        };

        let deployed_srcmap = match evm_best
            .get("deployedSourceMap")
            .or_else(|| evm_best.get("deployed_source_map"))
            .or_else(|| db_best_opt.and_then(|d| d.get("sourceMap").or_else(|| d.get("source_map"))))
            .and_then(Value::as_str)
        {
            Some(sm) if !sm.is_empty() => sm,
            _ => {
                debug!("opcode mapping: empty source map for {addr}");
                continue;
            }
        };

        let bytecode_hex = db_best_opt
            .and_then(|d| d.get("object").and_then(Value::as_str))
            .unwrap_or_default()
            .trim_start_matches("0x")
            .to_string();
        if bytecode_hex.is_empty() {
            debug!("opcode mapping: no deployed bytecode object for {addr}");
            continue;
        }

        info!(
            "opcode mapping: processing {} (source map entries: {}, bytecode len: {})",
            addr,
            deployed_srcmap.split(';').count(),
            bytecode_hex.len()
        );

        let input_sources_obj = match artifact
            .get("input")
            .and_then(|i| i.get("sources"))
            .and_then(Value::as_object)
        {
            Some(s) => s,
            None => {
                debug!("opcode mapping: no sources found in artifact for {addr}");
                continue;
            }
        };

        // Get output.sources to find the correct file ordering via 'id' field
        // The source map's file index refers to this ordering
        let output_sources_obj = artifact
            .get("output")
            .and_then(|o| o.get("sources"))
            .and_then(Value::as_object);

        // Build ordered source vector to resolve file idx
        // CRITICAL: Use output.sources.id for correct ordering, then map to input.sources content
        let mut source_vec: Vec<(String, String)> = Vec::new();

        if let Some(output_sources) = output_sources_obj {
            // Build a list of (id, path) pairs and sort by id
            let mut ordered_sources: Vec<(usize, String)> = Vec::new();
            for (path, info) in output_sources {
                if let Some(id) = info.get("id").and_then(Value::as_u64) {
                    ordered_sources.push((id as usize, path.clone()));
                }
            }
            ordered_sources.sort_by_key(|(id, _)| *id);

            // Now map to input.sources content in the correct order
            for (_, path) in ordered_sources {
                if let Some(content) = input_sources_obj
                    .get(&path)
                    .and_then(|v| v.get("content").and_then(Value::as_str))
                {
                    source_vec.push((path, content.to_string()));
                }
            }
            debug!("opcode mapping: using output.sources ordering for {addr} ({} files)", source_vec.len());
        } else {
            // Fallback: iterate input.sources directly (order not guaranteed)
            for (path, val) in input_sources_obj {
                if let Some(content) = val.get("content").and_then(Value::as_str) {
                    source_vec.push((path.clone(), content.to_string()));
                }
            }
            debug!("opcode mapping: using input.sources fallback for {addr} ({} files)", source_vec.len());
        }

        if source_vec.is_empty() {
            debug!("opcode mapping: sources missing content for {addr}");
            continue;
        }

        // Build op_idx -> pc mapping in order
        let bytes = match hex::decode(&bytecode_hex) {
            Ok(b) => b,
            Err(e) => {
                warn!("opcode mapping: failed to decode bytecode for {addr}: {e:?}");
                continue;
            }
        };
        let mut op_list = Vec::new();
        let mut pc = 0usize;
        let mut idx = 0usize;
        while pc < bytes.len() {
            let op = bytes[pc];
            op_list.push((idx, pc, op));
            let push_len = if (0x60..=0x7f).contains(&op) { (op - 0x5f) as usize } else { 0 };
            pc += 1 + push_len;
            idx += 1;
        }

        let is_important = |op: u8| {
            matches!(
                op,
                0x54 // SLOAD
                    | 0x55 // SSTORE
                    | 0x56 // JUMP
                    | 0x57 // JUMPI
                    | 0xa0..=0xa4 // LOG0-LOG4
                    | 0xf0 // CREATE
                    | 0xf1 // CALL
                    | 0xf2 // CALLCODE
                    | 0xf3 // RETURN
                    | 0xf4 // DELEGATECALL
                    | 0xf5 // CREATE2
                    | 0xfa // STATICCALL
                    | 0xfd // REVERT
                    | 0xff // SELFDESTRUCT
            )
        };

        // Parse deployed source map
        let mut pc_line_map_full = Vec::new();
        let mut pc_line_map_filtered = Vec::new();
        let mut last = ("0", "0", "-1", "");
        let mut last_line_cache: Option<(String, usize)> = None;
        let map_entries: Vec<&str> = deployed_srcmap.split(';').collect();

        for (op_idx, pc, op_byte) in op_list {
            let segment = map_entries.get(op_idx).copied().unwrap_or("");
            if !segment.is_empty() {
                let parts: Vec<&str> = segment.split(':').collect();
                let offset_part = parts
                    .get(0)
                    .copied()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(last.0);
                let length_part = parts
                    .get(1)
                    .copied()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(last.1);
                let file_part = parts
                    .get(2)
                    .copied()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(last.2);
                let jump_part = parts
                    .get(3)
                    .copied()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(last.3);
                last = (offset_part, length_part, file_part, jump_part);
            }
            let file_idx: isize = last.2.parse().unwrap_or(-1);
            let resolved = if file_idx < 0 || file_idx as usize >= source_vec.len() {
                last_line_cache.clone()
            } else {
                let offset: usize = last.0.parse().unwrap_or(0);
                let (path, content) = &source_vec[file_idx as usize];
                let mut acc = 0usize;
                let mut line = 1usize;
                for (idx, ln) in content.split('\n').enumerate() {
                    acc += ln.len() + 1;
                    if acc > offset {
                        line = idx + 1;
                        break;
                    }
                    line = idx + 1;
                }
                Some((path.clone(), line))
            };
            if let Some((path, line)) = resolved {
                last_line_cache = Some((path.clone(), line));
                let jump_type = last.3;
                pc_line_map_full.push(json!({"pc": pc, "line": line, "file": path, "jumpType": jump_type}));
                if is_important(op_byte) {
                    pc_line_map_filtered.push(json!({"pc": pc, "line": line, "file": path, "jumpType": jump_type}));
                }
            }
        }

        if !pc_line_map_full.is_empty() {
            info!("opcode mapping: {} has {} full entries, {} filtered entries",
                  addr, pc_line_map_full.len(), pc_line_map_filtered.len());
            combined_map.insert(addr.clone(), Value::Array(pc_line_map_full));
            combined_map.insert(format!("{addr}_filtered"), Value::Array(pc_line_map_filtered));
        }
    }

    if combined_map.is_empty() {
        warn!("opcode mapping: no mappings generated for any contract");
        return None;
    }

    info!("opcode mapping: generated mappings for {} contracts", combined_map.len() / 2);
    Some(Value::Object(combined_map))
}
async fn run(keep_alive: bool) -> Result<(), SimulatorError> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    let job: SimulationJob = serde_json::from_str(&buffer)?;

    info!("received simulation request (mode: {:?})", job.mode);

    let (result, engine) = match job.mode {
        SimulationMode::Onchain => simulate_onchain(&job, keep_alive).await,
        SimulationMode::Local => simulate_local(&job, keep_alive).await,
    }?;

    serde_json::to_writer(io::stdout(), &result)?;

    // If keep-alive mode, block until SIGTERM/SIGINT
    // The engine must stay alive to keep the RPC server running
    if keep_alive && result.debug_session.is_some() && engine.is_some() {
        info!("Keep-alive mode: RPC server running. Press Ctrl+C to stop.");
        // Flush stdout so the JSON is available to the parent process
        use std::io::Write;
        io::stdout().flush().ok();
        // Block until signal - engine is kept alive in scope
        tokio::signal::ctrl_c().await.ok();
        info!("Received signal, shutting down...");
        // Engine is dropped here, which triggers RPC server shutdown
        drop(engine);
    }

    Ok(())
}

async fn simulate_onchain(job: &SimulationJob, keep_alive: bool) -> Result<(SimulationResult, Option<Engine>), SimulatorError> {
    let simulation_start = std::time::Instant::now();
    info!("[TIMING] simulate_onchain START");

    let tx_hash_str = job
        .tx_hash
        .as_ref()
        .ok_or_else(|| SimulatorError::Simulation("txHash is required for onchain mode".into()))?;
    let tx_hash =
        TxHash::from_str(tx_hash_str).map_err(|e| SimulatorError::Simulation(e.to_string()))?;

    let quick_mode = job.analysis_options.quick_mode;

    let fork_start = std::time::Instant::now();
    let fork_result = fork_and_prepare(&job.rpc_url, tx_hash, quick_mode)
        .await
        .map_err(|e| SimulatorError::Engine(format!("fork_and_prepare failed: {e:?}")))?;
    info!("[TIMING] fork_and_prepare (main tx): {:.2}s", fork_start.elapsed().as_secs_f64());

    let gas_limit_suggested = Some(fork_result.target_tx_env.gas_limit.to_string());

    let mut engine_config = EngineConfig::default()
        .with_quick_mode(quick_mode)
        .with_precompute_state_variables(keep_alive)
        .with_rpc_proxy_url(job.rpc_url.clone());
    if let Some(ref key) = job.analysis_options.etherscan_api_key {
        engine_config = engine_config.with_etherscan_api_key(key.clone());
    }

    let engine = Engine::new(engine_config);
    let target_tx_hash = fork_result.target_tx_hash;

    // Load user-provided artifacts before engine preparation
    let provided_artifacts = load_user_artifacts(job)?;

    // Convert FE-provided JSON artifacts to engine Artifact format for preloading
    // This allows the engine to skip downloading from Sourcify/Etherscan for these addresses
    let preloaded_artifacts = preload_artifacts_from_job(job)?;
    if let Some(ref preloaded) = preloaded_artifacts {
        info!("Preloading {} FE-compiled artifacts into engine", preloaded.len());
    }

    let prepare_start = std::time::Instant::now();
    let rpc_addr = engine
        .prepare(fork_result, None, preloaded_artifacts)
        .await
        .map_err(|e| SimulatorError::Engine(format!("engine preparation failed: {e:?}")))?;
    info!("[TIMING] engine.prepare(): {:.2}s", prepare_start.elapsed().as_secs_f64());

    let rpc_url = format!("http://{rpc_addr}");
    let rpc_port = rpc_addr.port();
    let client = Client::new();
    let main_client = Client::new();

    let result = async {
        let trace_start = std::time::Instant::now();
        let trace_value: Value = call_edb_rpc(&client, &rpc_url, "edb_getTrace", json!([])).await?;
        info!("[TIMING] edb_getTrace RPC call: {:.2}s", trace_start.elapsed().as_secs_f64());

        let gas_used = fetch_receipt_gas_used(&main_client, &job.rpc_url, tx_hash_str).await.ok();
        let (success, revert_reason) = analyze_trace(&trace_value);

        let enrich_start = std::time::Instant::now();
        // When keep_alive is enabled, use lazy snapshots - frontend will fetch on-demand via RPC
        let mut enriched_trace = enrich_trace_payload(
            &client,
            &rpc_url,
            job.chain_id,
            trace_value,
            provided_artifacts.as_ref(),
            keep_alive, // lazy_snapshots = true when keep_alive is enabled
        )
        .await;
        info!("[TIMING] enrich_trace_payload: {:.2}s", enrich_start.elapsed().as_secs_f64());

        if let Some(g) = gas_used {
            if let Some(obj) = enriched_trace.as_object_mut() {
                obj.insert("gasUsed".into(), Value::String(g.to_string()));
            }
        }

        // Include debug session info when keep_alive is enabled
        let debug_session = if keep_alive {
            // Fetch snapshot count for debug session
            let snapshot_count: u64 = call_edb_rpc(&client, &rpc_url, "edb_getSnapshotCount", json!([]))
                .await
                .unwrap_or(0);
            Some(DebugSession {
                rpc_url: rpc_url.clone(),
                rpc_port,
                snapshot_count,
            })
        } else {
            None
        };

        info!("[TIMING] simulate_onchain TOTAL: {:.2}s", simulation_start.elapsed().as_secs_f64());

        Ok::<SimulationResult, SimulatorError>(SimulationResult {
            mode: SimulationMode::Onchain,
            success,
            error: None,
            warnings: Vec::new(),
            revert_reason,
            gas_used: gas_used.map(|g| g.to_string()),
            gas_limit_suggested,
            raw_trace: Some(enriched_trace),
            debug_session,
            debug_level: Some(DebugLevel::SourceInstrumented),
        })
    }
    .await?;

    // Only shutdown RPC server if not in keep-alive mode
    if !keep_alive {
        if let Err(e) = engine.shutdown_rpc_server(&target_tx_hash) {
            warn!("failed to shutdown engine RPC server cleanly: {e:?}");
        }
        Ok((result, None))
    } else {
        info!("Keep-alive mode: RPC server remains active at {}", rpc_url);
        // Return the engine so it stays alive in the caller
        Ok((result, Some(engine)))
    }
}

async fn simulate_local(job: &SimulationJob, keep_alive: bool) -> Result<(SimulationResult, Option<Engine>), SimulatorError> {
    let transaction = job.transaction.as_ref().ok_or_else(|| {
        SimulatorError::Simulation("transaction payload required for local mode".into())
    })?;

    let provided_artifacts = load_user_artifacts(job)?;

    match simulate_local_with_engine(job, transaction, provided_artifacts.as_ref(), keep_alive).await {
        Ok((result, engine)) => Ok((result, engine)),
        Err(engine_error) => {
            warn!(
                "EDB engine preparation failed: {engine_error:?}. Trying lightweight trace mode."
            );

            // Try lightweight trace first (provides call tree without source instrumentation)
            // Note: fallback modes don't support keep-alive since there's no EDB engine
            match simulate_local_lightweight(job, transaction, &engine_error).await {
                Ok(result) => {
                    info!("Lightweight trace simulation succeeded");
                    Ok((result, None))
                }
                Err(lightweight_error) => {
                    warn!(
                        "Lightweight trace also failed: {lightweight_error:?}. Falling back to eth_call."
                    );
                    let result = simulate_local_fallback(job, transaction, engine_error).await?;
                    Ok((result, None))
                }
            }
        }
    }
}

async fn simulate_local_with_engine(
    job: &SimulationJob,
    transaction: &TransactionPayload,
    provided_artifacts: Option<&Value>,
    keep_alive: bool,
) -> Result<(SimulationResult, Option<Engine>), SimulatorError> {
    let mut tx_env = build_tx_env(transaction, job.chain_id)?;
    let pseudo_tx_hash = compute_tx_hash_hint(transaction);

    let provider = ProviderBuilder::new()
        .connect(&job.rpc_url)
        .await
        .map_err(|error| SimulatorError::Rpc(format!("failed to connect to provider: {error}")))?;

    let chain_id = if job.chain_id != 0 {
        job.chain_id
    } else {
        provider
            .get_chain_id()
            .await
            .map_err(|error| SimulatorError::Rpc(format!("failed to get chain id: {error}")))?
    };

    let block_selector = parse_block_selector(&job.block_tag)?;

    // Try to get block with full transactions first
    let block = match provider.get_block_by_number(block_selector).full().await {
        Ok(Some(block)) => block,
        Ok(None) => return Err(SimulatorError::Simulation("fork block not found".into())),
        Err(full_error) => {
            // If full transactions fail (deserialization error), try with hashes only
            warn!("Failed to fetch block with full transactions: {full_error}. Retrying with transaction hashes only...");

            provider
                .get_block_by_number(block_selector)
                .await
                .map_err(|error| SimulatorError::Rpc(format!("failed to fetch fork block (fallback): {error}")))?
                .ok_or_else(|| SimulatorError::Simulation("fork block not found".into()))?
        }
    };

    let block_number_u64 = block.header.number;
    let spec_id = if chain_id == 1 {
        get_mainnet_spec_id(block_number_u64)
    } else {
        get_mainnet_spec_id(block_number_u64)
    };

    let fork_info = ForkInfo {
        block_number: block_number_u64,
        block_hash: block.header.hash,
        timestamp: block.header.timestamp,
        chain_id,
        spec_id,
    };

    // Determine state block based on whether user specified a specific block number
    // When replaying a historical tx in block N, we need state at end of block N-1
    // because RPC queries at block N return state AFTER block N was applied
    // For "latest"/"pending", we use the actual latest state
    let is_specific_block = matches!(block_selector, BlockNumberOrTag::Number(_));
    let state_block = if is_specific_block && block_number_u64 > 0 {
        block_number_u64 - 1
    } else {
        block_number_u64
    };
    info!(
        "simulate_local_with_engine: blockTag={:?}, fetched_block={}, is_specific={}, state_block={}",
        job.block_tag, block_number_u64, is_specific_block, state_block
    );
    let alloy_db = AlloyDB::new(provider, state_block.into());
    let state_db = WrapDatabaseAsync::new(alloy_db)
        .ok_or_else(|| SimulatorError::Simulation("failed to wrap state database".into()))?;
    let debug_db = EdbDB::new(CacheDB::new(Arc::new(state_db)));
    let cache_db: CacheDB<_> = CacheDB::new(debug_db);

    let context_builder = Context::mainnet()
        .with_db(cache_db)
        .modify_block_chained(|block_env| {
            block_env.number = U256::from(block_number_u64);
            block_env.timestamp = U256::from(block.header.timestamp);
            block_env.basefee = block.header.base_fee_per_gas.unwrap_or_default();
            block_env.difficulty = block.header.difficulty;
            block_env.gas_limit = block.header.gas_limit;
            block_env.prevrandao = Some(block.header.mix_hash);
            // REVM requires blob_excess_gas_and_price for Cancun+ specs
            // Default to 0 if RPC doesn't return excess_blob_gas (some providers omit it)
            block_env.blob_excess_gas_and_price = if spec_id >= SpecId::CANCUN {
                Some(BlobExcessGasAndPrice::new(
                    block.header.excess_blob_gas.unwrap_or(0),
                    get_blob_base_fee_update_fraction_by_spec_id(spec_id),
                ))
            } else {
                block.header.excess_blob_gas.map(|g| {
                    BlobExcessGasAndPrice::new(g, get_blob_base_fee_update_fraction_by_spec_id(spec_id))
                })
            };
            block_env.beneficiary = block.header.beneficiary;
        })
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = chain_id;
            cfg.spec = spec_id;
            cfg.disable_nonce_check = true;
        });

    let mut evm = context_builder.build_mainnet();
    evm.finalize();
    let mut context = evm.ctx;

    tx_env.chain_id = Some(chain_id);
    relax_evm_constraints(&mut context, &mut tx_env);

    let fork_result =
        ForkResult { fork_info, context, target_tx_env: tx_env, target_tx_hash: pseudo_tx_hash };

    let mut engine_config = EngineConfig::default()
        .with_quick_mode(job.analysis_options.quick_mode)
        .with_precompute_state_variables(keep_alive)
        .with_rpc_proxy_url(job.rpc_url.clone());
    if let Some(ref key) = job.analysis_options.etherscan_api_key {
        engine_config = engine_config.with_etherscan_api_key(key.clone());
    }

    let engine = Engine::new(engine_config);
    let target_tx_hash = fork_result.target_tx_hash;

    // Load user-provided artifacts before engine preparation
    let provided_artifacts = load_user_artifacts(job)?;

    // Convert FE-provided JSON artifacts to engine Artifact format for preloading (local mode)
    let preloaded_artifacts = preload_artifacts_from_job(job)?;
    if let Some(ref preloaded) = preloaded_artifacts {
        info!("Preloading {} FE-compiled artifacts into engine (local mode)", preloaded.len());
    }

    let rpc_addr = engine
        .prepare(fork_result, None, preloaded_artifacts)
        .await
        .map_err(|e| SimulatorError::Engine(format!("engine preparation failed: {e:?}")))?;

    let rpc_url = format!("http://{rpc_addr}");
    let rpc_port = rpc_addr.port();
    let client = Client::new();

    let result = async {
        let trace_value: Value = call_edb_rpc(&client, &rpc_url, "edb_getTrace", json!([])).await?;
        let (success, revert_reason) = analyze_trace(&trace_value);

        // PRIORITY 1: Extract total_gas_used from trace root (includes gas refunds from ExecutionResult)
        // This is set by replay_and_collect_trace from ExecutionResult.gas_used
        let total_gas_used = trace_value
            .get("total_gas_used")
            .and_then(|g| g.as_u64())
            .map(|g| g.to_string());

        // FALLBACK: Extract gas_used from root trace entry (inner.inner[0].gas_used)
        // This comes from REVM's outcome.gas.spent() - does NOT include refunds
        let root_gas_used = trace_value
            .get("inner")
            .and_then(|inner| inner.get("inner"))
            .and_then(|entries| entries.get(0))
            .and_then(|root| root.get("gas_used"))
            .and_then(|g| g.as_u64())
            .map(|g| g.to_string());

        // Prefer total_gas_used (with refunds) over root_gas_used (without refunds)
        let gas_used = total_gas_used.or(root_gas_used);

        // Calculate suggested gas limit (120% of gas_used)
        let gas_limit_suggested = gas_used.as_ref().and_then(|g| {
            g.parse::<u64>().ok().map(|gas| {
                gas.saturating_mul(120).saturating_div(100).to_string()
            })
        });

        // When keep_alive is enabled, use lazy snapshots - frontend will fetch on-demand via RPC
        let enriched_trace = enrich_trace_payload(
            &client,
            &rpc_url,
            chain_id,
            trace_value,
            provided_artifacts.as_ref(),
            keep_alive, // lazy_snapshots = true when keep_alive is enabled
        )
        .await;

        // Include debug session info when keep_alive is enabled
        let debug_session = if keep_alive {
            // Fetch snapshot count for debug session
            let snapshot_count: u64 = call_edb_rpc(&client, &rpc_url, "edb_getSnapshotCount", json!([]))
                .await
                .unwrap_or(0);
            Some(DebugSession {
                rpc_url: rpc_url.clone(),
                rpc_port,
                snapshot_count,
            })
        } else {
            None
        };

        Ok::<SimulationResult, SimulatorError>(SimulationResult {
            mode: SimulationMode::Local,
            success,
            error: None,
            warnings: Vec::new(),
            revert_reason,
            gas_used,
            gas_limit_suggested,
            raw_trace: Some(enriched_trace),
            debug_session,
            debug_level: Some(DebugLevel::SourceInstrumented),
        })
    }
    .await?;

    // Only shutdown RPC server if not in keep-alive mode
    if !keep_alive {
        if let Err(e) = engine.shutdown_rpc_server(&target_tx_hash) {
            warn!("failed to shutdown engine RPC server cleanly: {e:?}");
        }
        Ok((result, None))
    } else {
        info!("Keep-alive mode: RPC server remains active at {}", rpc_url);
        // Return the engine so it stays alive in the caller
        Ok((result, Some(engine)))
    }
}

async fn simulate_local_fallback(
    job: &SimulationJob,
    transaction: &TransactionPayload,
    engine_error: SimulatorError,
) -> Result<SimulationResult, SimulatorError> {
    let client = Client::new();

    let tx_object = build_eth_call_payload(transaction)?;
    let block_param = normalize_block_tag(&job.block_tag)?;
    let fallback_warning = format!(
        "Local EDB engine unavailable ({}). Using provider eth_call/estimateGas results only.",
        engine_error
    );

    let gas_estimate_hex: String =
        match call_edb_rpc(&client, &job.rpc_url, "eth_estimateGas", json!([tx_object.clone(), block_param]))
            .await
        {
            Ok(val) => val,
            Err(err) => {
                let message = err.to_string();
                return Ok(SimulationResult {
                    mode: SimulationMode::Local,
                    success: false,
                    error: Some(message.clone()),
                    warnings: vec![fallback_warning],
                    revert_reason: Some(message),
                    gas_used: None,
                    gas_limit_suggested: None,
                    raw_trace: None,
                    debug_session: None,
                    debug_level: Some(DebugLevel::EthCallOnly),
                });
            }
        };

    let gas_estimate_decimal = hex_to_u128(&gas_estimate_hex)?;
    let suggested_limit = gas_estimate_decimal.saturating_mul(120).saturating_div(100);

    let call_response = call_edb_rpc::<String>(
        &client,
        &job.rpc_url,
        "eth_call",
        json!([tx_object.clone(), block_param]),
    )
    .await;

    let mut raw_map = serde_json::Map::new();
    raw_map.insert("gasEstimateHex".into(), Value::String(gas_estimate_hex.clone()));

    match call_response {
        Ok(data) => {
            raw_map.insert("returnData".into(), Value::String(data.clone()));
            Ok(SimulationResult {
                mode: SimulationMode::Local,
                success: true,
                error: None,
                warnings: vec![fallback_warning],
                revert_reason: None,
                gas_used: Some(gas_estimate_decimal.to_string()),
                gas_limit_suggested: Some(suggested_limit.to_string()),
                raw_trace: Some(Value::Object(raw_map)),
                debug_session: None,
                debug_level: Some(DebugLevel::EthCallOnly),
            })
        }
        Err(err) => {
            let message = err.to_string();
            raw_map.insert("error".into(), Value::String(message.clone()));
            Ok(SimulationResult {
                mode: SimulationMode::Local,
                success: false,
                error: Some(message.clone()),
                warnings: vec![fallback_warning],
                revert_reason: Some(message),
                gas_used: Some(gas_estimate_decimal.to_string()),
                gas_limit_suggested: Some(suggested_limit.to_string()),
                raw_trace: Some(Value::Object(raw_map)),
                debug_session: None,
                debug_level: Some(DebugLevel::EthCallOnly),
            })
        }
    }
}

/// Lightweight trace simulation that skips source code fetching and bytecode tweaking.
/// This works on L2 chains where the full engine preparation fails.
async fn simulate_local_lightweight(
    job: &SimulationJob,
    transaction: &TransactionPayload,
    engine_error: &SimulatorError,
) -> Result<SimulationResult, SimulatorError> {
    info!("Attempting lightweight trace simulation (no source code instrumentation)");

    let mut tx_env = build_tx_env(transaction, job.chain_id)?;

    let provider = ProviderBuilder::new()
        .connect(&job.rpc_url)
        .await
        .map_err(|error| SimulatorError::Rpc(format!("failed to connect to provider: {error}")))?;

    let chain_id = if job.chain_id != 0 {
        job.chain_id
    } else {
        provider
            .get_chain_id()
            .await
            .map_err(|error| SimulatorError::Rpc(format!("failed to get chain id: {error}")))?
    };

    let block_selector = parse_block_selector(&job.block_tag)?;

    // Fetch block (with fallback for L2 chains that have special tx types)
    let block = match provider.get_block_by_number(block_selector).full().await {
        Ok(Some(block)) => block,
        Ok(None) => return Err(SimulatorError::Simulation("fork block not found".into())),
        Err(_) => {
            // Fallback to header-only fetch for L2 chains
            provider
                .get_block_by_number(block_selector)
                .await
                .map_err(|error| SimulatorError::Rpc(format!("failed to fetch fork block: {error}")))?
                .ok_or_else(|| SimulatorError::Simulation("fork block not found".into()))?
        }
    };

    let block_number_u64 = block.header.number;
    let spec_id = get_mainnet_spec_id(block_number_u64);

    // Determine state block based on whether user specified a specific block number
    // When replaying a historical tx in block N, we need state at end of block N-1
    // because RPC queries at block N return state AFTER block N was applied
    // For "latest"/"pending", we use the actual latest state
    let is_specific_block = matches!(block_selector, BlockNumberOrTag::Number(_));
    let state_block = if is_specific_block && block_number_u64 > 0 {
        block_number_u64 - 1
    } else {
        block_number_u64
    };
    let alloy_db = AlloyDB::new(provider, state_block.into());
    let state_db = WrapDatabaseAsync::new(alloy_db)
        .ok_or_else(|| SimulatorError::Simulation("failed to wrap state database".into()))?;
    let debug_db = EdbDB::new(CacheDB::new(Arc::new(state_db)));
    let cache_db: CacheDB<_> = CacheDB::new(debug_db);

    // Build EVM context
    let context_builder = Context::mainnet()
        .with_db(cache_db)
        .modify_block_chained(|block_env| {
            block_env.number = alloy_primitives::U256::from(block_number_u64);
            block_env.timestamp = alloy_primitives::U256::from(block.header.timestamp);
            block_env.basefee = block.header.base_fee_per_gas.unwrap_or_default();
            block_env.difficulty = block.header.difficulty;
            block_env.gas_limit = block.header.gas_limit;
            block_env.prevrandao = Some(block.header.mix_hash);
            // REVM requires blob_excess_gas_and_price for Cancun+ specs
            // Default to 0 if RPC doesn't return excess_blob_gas (some providers omit it)
            block_env.blob_excess_gas_and_price = if spec_id >= SpecId::CANCUN {
                Some(BlobExcessGasAndPrice::new(
                    block.header.excess_blob_gas.unwrap_or(0),
                    get_blob_base_fee_update_fraction_by_spec_id(spec_id),
                ))
            } else {
                block.header.excess_blob_gas.map(|g| {
                    BlobExcessGasAndPrice::new(g, get_blob_base_fee_update_fraction_by_spec_id(spec_id))
                })
            };
            block_env.beneficiary = block.header.beneficiary;
        })
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = chain_id;
            cfg.spec = spec_id;
            cfg.disable_nonce_check = true;
            cfg.disable_base_fee = true;
            cfg.disable_block_gas_limit = true;
            cfg.disable_balance_check = true;
        });

    // Set up CallTracer and run with inspector
    let mut tracer = CallTracer::new();
    tx_env.chain_id = Some(chain_id);

    // Build EVM with tracer
    let mut evm = context_builder.build_mainnet_with_inspector(&mut tracer);

    // Execute the transaction
    let exec_result = evm
        .inspect_one_tx(tx_env)
        .map_err(|e| SimulatorError::Simulation(format!("transaction execution failed: {:?}", e)))?;

    // Extract results
    let (success, gas_used, revert_reason) = match exec_result {
        ExecutionResult::Success { gas_used, .. } => (true, gas_used, None),
        ExecutionResult::Revert { gas_used, output } => {
            let reason = decode_revert_bytes(&output);
            (false, gas_used, Some(reason))
        }
        ExecutionResult::Halt { gas_used, reason } => {
            (false, gas_used, Some(format!("Halt: {:?}", reason)))
        }
    };

    // Build trace from CallTracer and set total gas used
    let mut replay_result = tracer.into_replay_result();
    // Set total_gas_used from ExecutionResult (includes refunds)
    replay_result.execution_trace.set_total_gas_used(gas_used);
    let trace_json = serde_json::to_value(&replay_result.execution_trace)
        .unwrap_or_else(|_| json!({"error": "failed to serialize trace"}));

    let warning = format!(
        "Lightweight trace mode (source instrumentation unavailable: {})",
        engine_error
    );

    Ok(SimulationResult {
        mode: SimulationMode::Local,
        success,
        error: None,
        warnings: vec![warning],
        revert_reason,
        gas_used: Some(gas_used.to_string()),
        gas_limit_suggested: Some((gas_used.saturating_mul(120) / 100).to_string()),
        raw_trace: Some(trace_json),
        debug_session: None,
        debug_level: Some(DebugLevel::CallTrace),
    })
}

/// Decode revert reason from output bytes
fn decode_revert_bytes(bytes: &[u8]) -> String {
    if bytes.len() < 4 {
        return format!("0x{}", hex::encode(bytes));
    }

    // Check for Error(string) selector: 0x08c379a0
    if bytes.len() >= 68 && bytes[0..4] == [0x08, 0xc3, 0x79, 0xa0] {
        // Decode the string from ABI encoding
        if let Ok(msg) = decode_abi_string(&bytes[4..]) {
            return msg;
        }
    }

    // Check for Panic(uint256) selector: 0x4e487b71
    if bytes.len() >= 36 && bytes[0..4] == [0x4e, 0x48, 0x7b, 0x71] {
        let panic_code = alloy_primitives::U256::from_be_slice(&bytes[4..36]);
        return format!("Panic(0x{:x})", panic_code);
    }

    // Return hex-encoded bytes as fallback
    format!("0x{}", hex::encode(bytes))
}

/// Decode ABI-encoded string
fn decode_abi_string(data: &[u8]) -> Result<String, ()> {
    if data.len() < 64 {
        return Err(());
    }
    let offset = alloy_primitives::U256::from_be_slice(&data[0..32]).to::<usize>();
    if offset + 32 > data.len() {
        return Err(());
    }
    let length = alloy_primitives::U256::from_be_slice(&data[offset..offset + 32]).to::<usize>();
    if offset + 32 + length > data.len() {
        return Err(());
    }
    String::from_utf8(data[offset + 32..offset + 32 + length].to_vec()).map_err(|_| ())
}

fn compute_tx_hash_hint(transaction: &TransactionPayload) -> TxHash {
    let mut map = serde_json::Map::new();
    if let Some(value) = &transaction.from {
        map.insert("from".into(), Value::String(value.clone()));
    }
    if let Some(value) = &transaction.to {
        map.insert("to".into(), Value::String(value.clone()));
    }
    map.insert("data".into(), Value::String(transaction.data.clone()));
    if let Some(value) = &transaction.value {
        map.insert("value".into(), Value::String(value.clone()));
    }
    if let Some(value) = &transaction.gas {
        map.insert("gas".into(), Value::String(value.clone()));
    }
    if let Some(value) = &transaction.gas_price {
        map.insert("gasPrice".into(), Value::String(value.clone()));
    }

    let serialized = Value::Object(map);
    let bytes = serde_json::to_vec(&serialized).unwrap_or_default();
    let hash = keccak256(bytes);
    TxHash::from(hash)
}

fn build_tx_env(transaction: &TransactionPayload, chain_id: u64) -> Result<TxEnv, SimulatorError> {
    let caller = transaction
        .from
        .as_ref()
        .filter(|value| !value.is_empty())
        .map(|value| parse_address(value, "from"))
        .transpose()?
        .unwrap_or_default();

    let mut builder = TxEnv::builder()
        .caller(caller)
        .chain_id(Some(chain_id))
        .data(parse_call_data(&transaction.data)?)
        .access_list(Default::default());

    let gas_limit = parse_u64_opt(transaction.gas.as_ref(), "gas")?.unwrap_or(30_000_000);
    builder = builder.gas_limit(gas_limit);

    if let Some(value) = parse_u256_opt(transaction.value.as_ref(), "value")? {
        builder = builder.value(value);
    }

    if let Some(gas_price) = parse_u256_opt(transaction.gas_price.as_ref(), "gasPrice")? {
        let gas_price_u128: u128 = gas_price.try_into().map_err(|_| {
            SimulatorError::Simulation(format!("`gasPrice` value {gas_price} exceeds u128 range"))
        })?;
        builder = builder.gas_price(gas_price_u128).gas_priority_fee(Some(gas_price_u128));
    }

    if let Some(to) = transaction
        .to
        .as_ref()
        .filter(|value| !value.is_empty())
        .map(|value| parse_address(value, "to"))
        .transpose()?
    {
        builder = builder.kind(TxKind::Call(to));
    } else {
        builder = builder.kind(TxKind::Create);
    }

    builder.build().map_err(|error| {
        SimulatorError::Simulation(format!("failed to build transaction env: {error:?}"))
    })
}

fn parse_block_selector(block_tag: &Option<String>) -> Result<BlockNumberOrTag, SimulatorError> {
    match block_tag {
        Some(tag) if !tag.trim().is_empty() => {
            let raw = tag.trim();
            match raw.to_ascii_lowercase().as_str() {
                "latest" => Ok(BlockNumberOrTag::Latest),
                "finalized" => Ok(BlockNumberOrTag::Finalized),
                "safe" => Ok(BlockNumberOrTag::Safe),
                "earliest" => Ok(BlockNumberOrTag::Earliest),
                "pending" => Ok(BlockNumberOrTag::Pending),
                other => {
                    if other.starts_with("0x") || other.starts_with("0X") {
                        let slice = other.trim_start_matches("0x").trim_start_matches("0X");
                        let value = u64::from_str_radix(slice, 16).map_err(|error| {
                            SimulatorError::Simulation(format!(
                                "invalid hex blockTag `{tag}`: {error}"
                            ))
                        })?;
                        Ok(BlockNumberOrTag::Number(value))
                    } else {
                        let value = other.parse::<u64>().map_err(|error| {
                            SimulatorError::Simulation(format!("invalid blockTag `{tag}`: {error}"))
                        })?;
                        Ok(BlockNumberOrTag::Number(value))
                    }
                }
            }
        }
        _ => Ok(BlockNumberOrTag::Latest),
    }
}

fn parse_u256_opt(value: Option<&String>, field: &str) -> Result<Option<U256>, SimulatorError> {
    match value {
        Some(raw) if !raw.trim().is_empty() => {
            let trimmed = raw.trim();
            let parsed = if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
                U256::from_str_radix(trimmed.trim_start_matches("0x").trim_start_matches("0X"), 16)
            } else {
                U256::from_str_radix(trimmed, 10)
            }
            .map_err(|error| {
                SimulatorError::Simulation(format!("invalid `{field}` value `{raw}`: {error}"))
            })?;
            Ok(Some(parsed))
        }
        _ => Ok(None),
    }
}

fn parse_u64_opt(value: Option<&String>, field: &str) -> Result<Option<u64>, SimulatorError> {
    if let Some(parsed) = parse_u256_opt(value, field)? {
        parsed.try_into().map(Some).map_err(|_| {
            SimulatorError::Simulation(format!("`{field}` value {parsed} does not fit into u64"))
        })
    } else {
        Ok(None)
    }
}

fn parse_address(value: &str, field: &str) -> Result<Address, SimulatorError> {
    Address::from_str(value).map_err(|error| {
        SimulatorError::Simulation(format!("invalid `{field}` address `{value}`: {error}"))
    })
}

fn parse_call_data(value: &str) -> Result<Bytes, SimulatorError> {
    let normalized =
        if value.starts_with("0x") || value.starts_with("0X") { &value[2..] } else { value };

    let bytes = hex::decode(normalized).map_err(|error| {
        SimulatorError::Simulation(format!("invalid calldata `{value}`: {error}"))
    })?;
    Ok(Bytes::from(bytes))
}

fn build_eth_call_payload(tx: &TransactionPayload) -> Result<Value, SimulatorError> {
    let mut map = Map::new();

    if let Some(from) = tx.from.as_ref().filter(|s| !s.is_empty()) {
        map.insert("from".into(), Value::String(from.clone()));
    }

    if let Some(to) = tx.to.as_ref().filter(|s| !s.is_empty()) {
        map.insert("to".into(), Value::String(to.clone()));
    }

    let data = if tx.data.starts_with("0x") || tx.data.starts_with("0X") {
        tx.data.clone()
    } else {
        format!("0x{}", tx.data)
    };
    map.insert("data".into(), Value::String(data));

    if let Some(value) = normalize_quantity(tx.value.as_ref())? {
        map.insert("value".into(), Value::String(value));
    }

    if let Some(gas) = normalize_quantity(tx.gas.as_ref())? {
        map.insert("gas".into(), Value::String(gas));
    }

    if let Some(gas_price) = normalize_quantity(tx.gas_price.as_ref())? {
        map.insert("gasPrice".into(), Value::String(gas_price));
    }

    Ok(Value::Object(map))
}

fn normalize_quantity(value: Option<&String>) -> Result<Option<String>, SimulatorError> {
    match value {
        Some(v) if !v.trim().is_empty() => {
            let trimmed = v.trim();
            if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
                Ok(Some(trimmed.to_lowercase()))
            } else {
                let parsed = U256::from_str(trimmed).map_err(|e| {
                    SimulatorError::Simulation(format!("invalid numeric value `{trimmed}`: {e}"))
                })?;
                Ok(Some(format!("0x{:x}", parsed)))
            }
        }
        _ => Ok(None),
    }
}

fn normalize_block_tag(tag: &Option<String>) -> Result<Value, SimulatorError> {
    if let Some(tag_str) = tag {
        let trimmed = tag_str.trim();
        let lower = trimmed.to_lowercase();
        match lower.as_str() {
            "latest" | "earliest" | "pending" | "safe" | "finalized" => {
                return Ok(Value::String(lower));
            }
            _ => {}
        }

        if lower.starts_with("0x") {
            return Ok(Value::String(lower));
        }

        let parsed = U256::from_str(trimmed).map_err(|e| {
            SimulatorError::Simulation(format!("invalid blockTag `{trimmed}`: {e}"))
        })?;
        Ok(Value::String(format!("0x{:x}", parsed)))
    } else {
        Ok(Value::String("latest".into()))
    }
}

fn hex_to_u128(value: &str) -> Result<u128, SimulatorError> {
    let trimmed = value.trim();
    let without_prefix =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    if without_prefix.is_empty() {
        return Ok(0);
    }
    u128::from_str_radix(without_prefix, 16).map_err(|e| {
        SimulatorError::Simulation(format!("failed to parse hex quantity `{value}`: {e}"))
    })
}

async fn call_edb_rpc<T>(
    client: &Client,
    url: &str,
    method: &str,
    params: Value,
) -> Result<T, SimulatorError>
where
    T: DeserializeOwned,
{
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });

    let response = client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| SimulatorError::Rpc(format!("RPC request failed: {e}")))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| SimulatorError::Rpc(format!("failed to read RPC response: {e}")))?;

    if !status.is_success() {
        return Err(SimulatorError::Rpc(format!(
            "RPC call failed with status {}: {}",
            status, body
        )));
    }

    let rpc_response: JsonRpcResponse<T> = serde_json::from_str(&body)
        .wrap_err_with(|| format!("failed to parse RPC response body: {body}"))
        .map_err(|e| SimulatorError::Rpc(e.to_string()))?;

    if let Some(error) = rpc_response.error {
        return Err(SimulatorError::Rpc(format!("{} (code {})", error.message, error.code)));
    }

    rpc_response
        .result
        .ok_or_else(|| SimulatorError::Rpc("RPC response missing result field".into()))
}

async fn fetch_receipt_gas_used(
    client: &Client,
    rpc_url: &str,
    tx_hash: &str,
) -> Result<u128, SimulatorError> {
    let receipt: Value =
        call_edb_rpc(client, rpc_url, "eth_getTransactionReceipt", json!([tx_hash])).await?;
    let gas_hex = receipt
        .get("gasUsed")
        .and_then(Value::as_str)
        .ok_or_else(|| SimulatorError::Rpc("receipt missing gasUsed".into()))?;
    hex_to_u128(gas_hex)
}

// When lazy_snapshots=false, export all snapshots upfront (legacy behavior).
// When lazy_snapshots=true, skip snapshot export - frontend fetches on-demand via RPC.
const MAX_EXPORTED_SNAPSHOTS: u64 = u64::MAX;

async fn enrich_trace_payload(
    client: &Client,
    rpc_url: &str,
    chain_id: u64,
    trace_value: Value,
    user_artifacts: Option<&Value>,
    lazy_snapshots: bool,
) -> Value {
    let mut payload = Map::new();
    payload.insert("inner".into(), trace_value.clone());

    // Best-effort fetch of verified sources for any contracts seen in the trace
    if let Some(source_map) = collect_sources(client, rpc_url, &trace_value).await {
        payload.insert("sources".into(), source_map);
    }
    // Best-effort fetch of full artifacts (with metadata/source map) for the same addresses
    // User-provided artifacts have priority ONLY if they have compiled output with source maps.
    // Otherwise, use Sourcify/Engine artifacts to preserve JUMP detection.
    let mut artifacts_obj = Map::new();

    // Helper to check if an artifact has valid source maps for opcode mapping
    fn has_source_maps(artifact: &Value) -> bool {
        artifact
            .get("output")
            .and_then(|o| o.get("contracts"))
            .and_then(Value::as_object)
            .map(|contracts| {
                contracts.values().any(|c| {
                    c.as_object().map(|cobj| {
                        cobj.values().any(|contract| {
                            let evm = contract.get("evm");
                            let deployed_bytecode = evm.and_then(|e| e.get("deployedBytecode"));
                            // Check all possible source map locations:
                            // 1. evm.deployedSourceMap (some compilers)
                            // 2. evm.deployed_source_map (snake_case variant)
                            // 3. evm.deployedBytecode.sourceMap (foundry-compilers)
                            // 4. evm.deployedBytecode.source_map (snake_case variant)
                            let has_srcmap = evm
                                .and_then(|e| e.get("deployedSourceMap").or_else(|| e.get("deployed_source_map")))
                                .and_then(Value::as_str)
                                .map(|s| !s.is_empty())
                                .unwrap_or(false)
                                || deployed_bytecode
                                    .and_then(|d| d.get("sourceMap").or_else(|| d.get("source_map")))
                                    .and_then(Value::as_str)
                                    .map(|s| !s.is_empty())
                                    .unwrap_or(false);
                            let has_bytecode = deployed_bytecode
                                .and_then(|d| d.get("object"))
                                .and_then(Value::as_str)
                                .map(|s| !s.is_empty())
                                .unwrap_or(false);
                            has_srcmap && has_bytecode
                        })
                    }).unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    // 1) Collect ALL user-provided artifacts (not just those with source maps)
    // This allows us to skip Sourcify fetching entirely for addresses frontend already handled
    let user_addrs_all: std::collections::HashSet<String> = user_artifacts
        .and_then(|v| v.as_object())
        .map(|obj| obj.keys().map(|k| k.to_lowercase()).collect())
        .unwrap_or_default();

    // Collect user artifacts that have valid source maps (for priority decisions later)
    let user_addrs_with_srcmaps: std::collections::HashSet<String> = user_artifacts
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter(|(_, artifact)| has_source_maps(artifact))
                .map(|(k, _)| k.to_lowercase())
                .collect()
        })
        .unwrap_or_default();

    // 2) Sourcify metadata - SKIP addresses where user already provided artifacts
    // This is the key optimization: avoid HTTP requests for addresses we already have
    // Always use lowercase keys to avoid duplicate entries
    if let Some(sourcify_map) = collect_sourcify_artifacts(chain_id, &trace_value, &user_addrs_all).await {
        if let Some(obj) = sourcify_map.as_object() {
            info!("Sourcify returned metadata for {} addresses", obj.len());
            for (addr, artifact) in obj {
                let addr_lower = addr.to_lowercase();
                let has_output_contracts = artifact
                    .get("output")
                    .and_then(|o| o.get("contracts"))
                    .is_some();
                let sourcify_has_srcmaps = has_source_maps(artifact);
                info!(
                    "Sourcify artifact for {}: has_output_contracts={}, has_srcmaps={}",
                    addr_lower, has_output_contracts, sourcify_has_srcmaps
                );
                if !user_addrs_with_srcmaps.contains(&addr_lower) {
                    artifacts_obj.insert(addr_lower, artifact.clone());
                }
            }
        }
    } else {
        info!("No Sourcify metadata returned");
    }

    // 3) Engine RPC - prefer these over Sourcify if they have source maps (Sourcify metadata.json doesn't include source maps)
    if let Some(artifact_map) = collect_artifacts(client, rpc_url, &trace_value).await {
        if let Some(obj) = artifact_map.as_object() {
            info!("Engine returned artifacts for {} addresses", obj.len());
            for (addr, artifact) in obj {
                let addr_lower = addr.to_lowercase();
                // Skip if user already provided an artifact with source maps
                if user_addrs_with_srcmaps.contains(&addr_lower) {
                    info!("Skipping Engine artifact for {} - user provided with srcmaps", addr_lower);
                    continue;
                }
                // Check if existing artifact (from Sourcify) has source maps
                let existing_has_srcmaps = artifacts_obj
                    .get(&addr_lower)
                    .map(|a| has_source_maps(a))
                    .unwrap_or(false);
                let engine_has_srcmaps = has_source_maps(artifact);
                let has_output_contracts = artifact
                    .get("output")
                    .and_then(|o| o.get("contracts"))
                    .is_some();
                let has_output_sources = artifact
                    .get("output")
                    .and_then(|o| o.get("sources"))
                    .is_some();
                info!(
                    "Engine artifact for {}: has_output_contracts={}, has_output_sources={}, has_srcmaps={}, existing_has_srcmaps={}",
                    addr_lower, has_output_contracts, has_output_sources, engine_has_srcmaps, existing_has_srcmaps
                );
                // Only skip if existing artifact already has source maps
                if !existing_has_srcmaps {
                    artifacts_obj.insert(addr_lower.clone(), artifact.clone());
                    info!("Inserted Engine artifact for {}", addr_lower);
                } else {
                    info!("Keeping existing artifact for {} (already has srcmaps)", addr_lower);
                }
            }
        }
    } else {
        warn!("No artifacts returned from Engine RPC");
    }

    // 4) User-provided artifacts with source maps get added last (highest priority)
    // Use lowercase keys for consistency
    if let Some(user_obj) = user_artifacts.and_then(|v| v.as_object()) {
        for (addr, artifact) in user_obj {
            if has_source_maps(artifact) {
                artifacts_obj.insert(addr.to_lowercase(), artifact.clone());
            }
        }
    }
    if !artifacts_obj.is_empty() {
        payload.insert("artifacts".into(), Value::Object(artifacts_obj));
    }

    match collect_storage_diff_entries(client, rpc_url).await {
        Ok(storage_value) => {
            if !storage_value.is_null() {
                payload.insert("storageDiffs".into(), storage_value);
            } else {
                payload.insert("storageDiffs".into(), Value::Array(Vec::new()));
            }
        }
        Err(err) => {
            warn!("failed to collect storage diffs: {err:?}");
            payload.insert("storageDiffs".into(), Value::Array(Vec::new()));
        }
    }

    // Snapshot collection: skip if lazy_snapshots is enabled (frontend will fetch on-demand)
    if lazy_snapshots {
        info!("[PERF] Lazy snapshots enabled - skipping upfront snapshot export");
        // Just include the snapshot count so frontend knows how many are available
        match call_edb_rpc::<u64>(client, rpc_url, "edb_getSnapshotCount", json!([])).await {
            Ok(count) => {
                payload.insert("snapshotCount".into(), Value::Number(count.into()));
                info!("[PERF] {} snapshots available for lazy loading", count);
            }
            Err(err) => {
                warn!("failed to get snapshot count: {err:?}");
                payload.insert("snapshotCount".into(), Value::Number(0.into()));
            }
        }
        payload.insert("snapshots".into(), Value::Array(Vec::new()));

        // Fetch lightweight opcode trace for UI display (SLOAD, SSTORE, JUMP, etc.)
        // This is much smaller than full snapshots - only essential fields, no database/memory state
        let opcode_start = std::time::Instant::now();
        match call_edb_rpc::<Value>(client, rpc_url, "edb_getOpcodeTrace", json!([])).await {
            Ok(opcode_trace) => {
                let count = opcode_trace.as_array().map(|a| a.len()).unwrap_or(0);
                info!("[PERF] Fetched lightweight opcode trace with {} entries in {:.2}s",
                    count, opcode_start.elapsed().as_secs_f64());
                payload.insert("opcodeTrace".into(), opcode_trace);
            }
            Err(err) => {
                warn!("failed to get opcode trace: {err:?}");
                payload.insert("opcodeTrace".into(), Value::Array(Vec::new()));
            }
        }
    } else {
        match collect_snapshot_entries(client, rpc_url, MAX_EXPORTED_SNAPSHOTS).await {
            Ok(snapshot_value) => {
                payload.insert("snapshots".into(), snapshot_value);
            }
            Err(err) => {
                warn!("failed to collect snapshots: {err:?}");
                payload.insert("snapshots".into(), Value::Array(Vec::new()));
            }
        }
    }

    // Best-effort: derive opcode source mapping using artifacts + opcode snapshots
    if let Some(artifacts) = payload.get("artifacts") {
        let snapshots_ref = payload.get("snapshots").unwrap_or(&Value::Null);
        let trace_ref = payload.get("inner");
        if let Some(opcode_map) = enrich_opcodes_with_lines(artifacts, snapshots_ref, trace_ref) {
            let count = opcode_map.as_object().map(|o| o.len()).unwrap_or(0);
            info!("embedded opcode line mapping for {} contract(s)", count);
            payload.insert("opcodeLines".into(), opcode_map);
        } else {
            warn!("opcode line mapping not generated (missing source map?)");
        }
    }

    // Best-effort: add tx receipt gasUsed if we know the target hash
    if let Some(tx_hash) = trace_value
        .get("target_tx_hash")
        .or_else(|| trace_value.get("targetTxHash"))
        .and_then(Value::as_str)
    {
        if let Ok(gas_used) = fetch_receipt_gas_used(client, rpc_url, tx_hash).await {
            payload.insert("gasUsed".into(), Value::String(gas_used.to_string()));
        }
    }

    Value::Object(payload)
}

/// Load user-provided artifacts from a path or inline value.
fn load_user_artifacts(job: &SimulationJob) -> Result<Option<Value>, SimulatorError> {
    let mut merged = Map::new();

    if let Some(inline) = job.artifacts_inline.as_ref().and_then(Value::as_object) {
        merged.extend(inline.clone());
    }

    if let Some(path) = job.artifact_path.as_ref() {
        let data = fs::read_to_string(Path::new(path))
            .map_err(|e| SimulatorError::Simulation(format!("failed to read artifact file: {e}")))?;
        let value: Value = serde_json::from_str(&data).map_err(|e| {
            SimulatorError::Simulation(format!("failed to parse artifact file as JSON: {e}"))
        })?;
        if let Some(obj) = value.as_object() {
            merged.extend(obj.clone());
        } else {
            return Err(SimulatorError::Simulation(
                "artifact file must be a JSON object keyed by address".into(),
            ));
        }
    }

    if merged.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Value::Object(merged)))
    }
}

/// Convert FE-provided artifacts_inline JSON to engine Artifact format for preloading.
/// Only processes entries with complete compiler settings; skips those marked with missingSettings.
fn preload_artifacts_from_job(
    job: &SimulationJob,
) -> Result<Option<HashMap<Address, Artifact>>, SimulatorError> {
    let artifacts_json = match job.artifacts_inline.as_ref().and_then(Value::as_object) {
        Some(obj) if !obj.is_empty() => obj,
        _ => return Ok(None),
    };

    let mut preloaded: HashMap<Address, Artifact> = HashMap::new();
    let mut skipped = 0usize;
    let mut failed = 0usize;
    let total = artifacts_json.len();

    for (addr_str, artifact_json) in artifacts_json {
        // Parse address
        let address = match Address::from_str(addr_str) {
            Ok(a) => a,
            Err(e) => {
                warn!("Invalid address in artifacts_inline '{}': {}", addr_str, e);
                failed += 1;
                continue;
            }
        };

        // Skip if marked as missing settings
        if artifact_json.get("missingSettings").and_then(Value::as_bool).unwrap_or(false) {
            debug!("Skipping {} - marked as missingSettings", addr_str);
            skipped += 1;
            continue;
        }

        // Extract input.settings
        let input_obj = match artifact_json.get("input") {
            Some(i) => i,
            None => {
                warn!("Artifact {} missing 'input' field", addr_str);
                skipped += 1;
                continue;
            }
        };

        let settings_json = match input_obj.get("settings") {
            Some(s) if !s.is_null() => s,
            _ => {
                debug!("Artifact {} has no settings, skipping preload", addr_str);
                skipped += 1;
                continue;
            }
        };

        // Try to build Artifact
        match build_artifact_from_json(addr_str, artifact_json, input_obj, settings_json) {
            Ok(artifact) => {
                info!("Preloaded artifact for {} ({})", addr_str, artifact.contract_name());
                preloaded.insert(address, artifact);
            }
            Err(e) => {
                warn!("Failed to preload artifact for {}: {:?}", addr_str, e);
                failed += 1;
            }
        }
    }

    info!(
        "[PRELOAD] Summary: {} received, {} compiled, {} skipped (no settings), {} failed",
        total, preloaded.len(), skipped, failed
    );

    if preloaded.is_empty() {
        Ok(None)
    } else {
        Ok(Some(preloaded))
    }
}

/// Build an Artifact from FE-provided JSON, compiling with the specified settings.
fn build_artifact_from_json(
    addr_str: &str,
    artifact_json: &Value,
    input_obj: &Value,
    settings_json: &Value,
) -> Result<Artifact, eyre::Error> {
    // Extract compiler version from meta
    let compiler_version = artifact_json
        .get("meta")
        .and_then(|m| m.get("CompilerVersion"))
        .and_then(Value::as_str)
        .ok_or_else(|| eyre::eyre!("missing meta.CompilerVersion"))?
        .trim_start_matches('v')
        .to_string();

    // Parse settings
    let mut settings: Settings = serde_json::from_value(settings_json.clone())
        .map_err(|e| eyre::eyre!("failed to parse settings: {}", e))?;

    // Enforce complete output selection for debugging
    settings.output_selection = OutputSelection::complete_output_selection();

    // Build sources
    let sources_json = input_obj
        .get("sources")
        .and_then(Value::as_object)
        .ok_or_else(|| eyre::eyre!("missing input.sources"))?;

    let mut sources = Sources::new();
    for (path, content_obj) in sources_json {
        let content = content_obj
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| eyre::eyre!("source {} missing content", path))?;
        sources.insert(path.clone().into(), Source::new(content.to_string()));
    }

    // Build SolcInput
    let input = SolcInput::new(SolcLanguage::Solidity, sources, settings);

    // Find/install compiler and compile
    let version = semver::Version::parse(&compiler_version)
        .map_err(|e| eyre::eyre!("invalid compiler version '{}': {}", compiler_version, e))?;
    let solc = find_or_install_solc(&version)?;
    let output: CompilerOutput = solc.compile_exact(&input)?;

    // Check for compilation errors
    if output.errors.iter().any(|e| e.is_error()) {
        let errors: Vec<_> = output.errors.iter()
            .filter(|e| e.is_error())
            .map(|e| e.message.clone())
            .collect();
        return Err(eyre::eyre!("compilation errors: {:?}", errors));
    }

    // Synthesize Metadata (same pattern as sourcify.rs)
    let meta_obj = artifact_json.get("meta").cloned().unwrap_or(Value::Null);
    let contract_name = meta_obj.get("ContractName")
        .or_else(|| meta_obj.get("Name"))
        .and_then(Value::as_str)
        .unwrap_or("Contract")
        .to_string();
    let abi_string = meta_obj.get("ABI")
        .and_then(Value::as_str)
        .unwrap_or("[]")
        .to_string();
    let opt_used = meta_obj.get("OptimizationUsed")
        .and_then(Value::as_str)
        .unwrap_or("0")
        .to_string();
    let runs_str = meta_obj.get("Runs")
        .and_then(Value::as_str)
        .unwrap_or("200");
    let runs: u64 = runs_str.parse().unwrap_or(200);
    let evm_version = meta_obj.get("EVMVersion")
        .and_then(Value::as_str)
        .unwrap_or("Default")
        .to_string();

    // Build source_code field in Etherscan format
    let source_code_field = serde_json::json!({
        "language": "Solidity",
        "sources": input_obj.get("sources").cloned().unwrap_or(Value::Null),
        "settings": settings_json.clone()
    });

    // Build Etherscan-compatible metadata JSON
    let synth = serde_json::json!({
        "Language": "Solidity",
        "CompilerVersion": format!("v{}", compiler_version),
        "ContractName": contract_name,
        "SourceCode": source_code_field,
        "ABI": abi_string,
        "OptimizationUsed": opt_used,
        "Runs": runs,
        "ConstructorArguments": "",
        "EVMVersion": evm_version,
        "Library": "",
        "LicenseType": "",
        "Proxy": "0",
        "Implementation": "",
        "SwarmSource": ""
    });

    let metadata: EtherscanMetadata = serde_json::from_value(synth)
        .map_err(|e| eyre::eyre!("failed to synthesize metadata: {}", e))?;

    Ok(Artifact { meta: metadata, input, output })
}

/// Recursively gather code addresses from the trace JSON
fn gather_addresses(value: &Value, addrs: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                if (k == "code_address" || k == "codeAddress") && v.is_string() {
                    if let Some(s) = v.as_str() {
                        addrs.push(s.to_string());
                    }
                }
                gather_addresses(v, addrs);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                gather_addresses(v, addrs);
            }
        }
        _ => {}
    }
}

/// Collect source code for all addresses found in the trace (if artifacts exist)
async fn collect_sources(client: &Client, rpc_url: &str, trace_value: &Value) -> Option<Value> {
    let mut addrs = Vec::new();
    gather_addresses(trace_value, &mut addrs);
    addrs.sort();
    addrs.dedup();

    if addrs.is_empty() {
        return None;
    }

    let mut sources = Map::new();
    for addr in addrs {
        match call_edb_rpc::<Value>(client, rpc_url, "edb_getCodeByAddress", json!([addr])).await {
            Ok(val) => {
                if val.get("Source").is_some() {
                    sources.insert(addr, val);
                }
            }
            Err(err) => {
                warn!("failed to fetch source for {addr}: {err:?}");
            }
        }
    }

    if sources.is_empty() {
        None
    } else {
        Some(Value::Object(sources))
    }
}

/// Collect artifacts for all addresses found in the trace (if available)
async fn collect_artifacts(client: &Client, rpc_url: &str, trace_value: &Value) -> Option<Value> {
    let mut addrs = Vec::new();
    gather_addresses(trace_value, &mut addrs);
    addrs.sort();
    addrs.dedup();

    if addrs.is_empty() {
        return None;
    }

    let mut artifacts = Map::new();
    for addr in addrs {
        match call_edb_rpc::<Value>(client, rpc_url, "edb_getArtifactByAddress", json!([addr]))
            .await
        {
            Ok(val) => {
                // Use lowercase key to match Sourcify artifacts for proper merging
                artifacts.insert(addr.to_lowercase(), val);
            }
            Err(err) => {
                warn!("failed to fetch artifact for {addr}: {err:?}");
            }
        }
    }

    if artifacts.is_empty() {
        None
    } else {
        Some(Value::Object(artifacts))
    }
}

/// Fetch Sourcify metadata (includes deployedSourceMap) for all addresses.
/// Skips addresses in `skip_addrs` to avoid duplicate fetching when frontend already provided artifacts.
async fn collect_sourcify_artifacts(
    chain_id: u64,
    trace_value: &Value,
    skip_addrs: &std::collections::HashSet<String>,
) -> Option<Value> {
    let mut addrs = Vec::new();
    gather_addresses(trace_value, &mut addrs);
    addrs.sort();
    addrs.dedup();

    if addrs.is_empty() {
        return None;
    }

    // Filter out addresses we should skip (already have artifacts from frontend)
    let addrs_to_fetch: Vec<_> = addrs
        .into_iter()
        .filter(|a| !skip_addrs.contains(&a.to_lowercase()))
        .collect();

    if addrs_to_fetch.is_empty() {
        info!("Skipping Sourcify fetch - all {} addresses already have artifacts from frontend", skip_addrs.len());
        return None;
    }

    info!(
        "Fetching Sourcify metadata for {} addresses (skipping {} with frontend artifacts)",
        addrs_to_fetch.len(),
        skip_addrs.len()
    );

    let mut artifacts = Map::new();
    for addr in addrs_to_fetch {
        let addr_lower = addr.to_lowercase();
        if let Some(meta) = fetch_sourcify_metadata(chain_id, &addr_lower).await {
            artifacts.insert(addr_lower, meta);
        }
    }

    if artifacts.is_empty() {
        None
    } else {
        Some(Value::Object(artifacts))
    }
}

/// Try to fetch Sourcify metadata and compile to get full artifact with source maps.
async fn fetch_sourcify_metadata(chain_id: u64, addr: &str) -> Option<Value> {
    let client = reqwest::Client::new();

    // Try full_match first, then partial_match
    // Use the Sourcify server API endpoint directly to avoid 307 redirects
    // repo.sourcify.dev redirects to sourcify.dev/server/repository
    for kind in ["full_match", "partial_match"] {
        let base = format!(
            "https://sourcify.dev/server/repository/contracts/{}/{}/{}/",
            kind, chain_id, addr
        );
        let meta_url = format!("{base}metadata.json");

        let meta_resp = match client.get(&meta_url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };

        if !meta_resp.status().is_success() {
            continue;
        }

        let metadata_json: Value = match meta_resp.json().await {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Extract sources list from metadata
        let sources_json = match metadata_json.get("sources").and_then(Value::as_object) {
            Some(s) => s,
            None => continue,
        };

        // Fetch all source files
        let mut source_entries: serde_json::Map<String, Value> = serde_json::Map::new();
        let mut fetch_failed = false;

        for (path, info) in sources_json {
            let path_str = path.to_string();

            // Get source URL - prefer repo source path over swarm/ipfs URLs
            let url = info
                .get("urls")
                .and_then(Value::as_array)
                .and_then(|arr| arr.first())
                .and_then(Value::as_str)
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{base}sources/{path_str}"));

            let source_url = if url.starts_with("bzzr://")
                || url.starts_with("bzz-raw://")
                || url.starts_with("ipfs://")
                || url.starts_with("dweb://")
                || !url.starts_with("http")
            {
                format!("{base}sources/{path_str}")
            } else {
                url
            };

            let src_resp = match client.get(&source_url).send().await {
                Ok(r) if r.status().is_success() => r,
                _ => {
                    warn!("sourcify source fetch failed for {path_str}");
                    fetch_failed = true;
                    break;
                }
            };

            let content = match src_resp.text().await {
                Ok(c) => c,
                Err(_) => {
                    fetch_failed = true;
                    break;
                }
            };

            source_entries.insert(path_str, json!({ "content": content }));
        }

        if fetch_failed || source_entries.is_empty() {
            continue;
        }

        // Build artifact structure that enrich_opcodes_with_lines expects
        // We need: artifact.output.contracts.*.*.evm.deployedBytecode.sourceMap
        // and: artifact.input.sources

        // Extract contract name from settings.compilationTarget
        // Format: { "path/to/Contract.sol": "ContractName" }
        let contract_name = metadata_json
            .get("settings")
            .and_then(|s| s.get("compilationTarget"))
            .and_then(Value::as_object)
            .and_then(|ct| ct.values().next())
            .and_then(Value::as_str)
            .unwrap_or("Unknown");

        // Since we can't compile in the simulator (no solc), return what we have
        // with the sources in the right format for the traceDecoder to parse
        let artifact = json!({
            "input": {
                "sources": source_entries,
                "settings": metadata_json.get("settings").cloned().unwrap_or(Value::Null)
            },
            "output": metadata_json.get("output").cloned().unwrap_or(Value::Null),
            "meta": {
                "Name": contract_name,
                "ContractName": contract_name,
                "CompilerVersion": metadata_json.get("compiler")
                    .and_then(|c| c.get("version"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                "ABI": metadata_json.get("output")
                    .and_then(|o| o.get("abi"))
                    .map(|a| serde_json::to_string(a).unwrap_or_default())
                    .unwrap_or_default(),
            },
            // Include full sources for the traceDecoder to build fnRanges and fnSignatures
            "sources": source_entries.clone()
        });

        return Some(artifact);
    }

    None
}

async fn collect_storage_diff_entries(
    client: &Client,
    rpc_url: &str,
) -> Result<Value, SimulatorError> {
    let snapshot_count: u64 =
        match call_edb_rpc(client, rpc_url, "edb_getSnapshotCount", json!([])).await {
            Ok(count) => count,
            Err(err) => {
                warn!("failed to read snapshot count: {err:?}");
                return Ok(Value::Array(Vec::new()));
            }
        };
    info!("snapshot_count reported by engine: {}", snapshot_count);

    if snapshot_count == 0 {
        return Ok(Value::Array(Vec::new()));
    }

    let last_snapshot = snapshot_count.saturating_sub(1);
    let entries = collect_storage_entries_for_snapshot(client, rpc_url, last_snapshot).await?;

    Ok(Value::Array(entries))
}

async fn collect_storage_entries_for_snapshot(
    client: &Client,
    rpc_url: &str,
    snapshot_id: u64,
) -> Result<Vec<Value>, SimulatorError> {
    let diff_value: Value =
        call_edb_rpc(client, rpc_url, "edb_getStorageDiff", json!([snapshot_id])).await?;

    let diff_map = match diff_value.as_object() {
        Some(map) if !map.is_empty() => map,
        _ => return Ok(Vec::new()),
    };

    let snapshot_info: Value =
        call_edb_rpc(client, rpc_url, "edb_getSnapshotInfo", json!([snapshot_id])).await?;
    let target_address = snapshot_info
        .get("target_address")
        .or_else(|| snapshot_info.get("targetAddress"))
        .and_then(Value::as_str)
        .map(|s| s.to_string());
    let bytecode_address = snapshot_info
        .get("bytecode_address")
        .or_else(|| snapshot_info.get("bytecodeAddress"))
        .and_then(Value::as_str)
        .map(|s| s.to_string());

    let mut entries = Vec::new();
    for (slot_key, diff_entry) in diff_map {
        let (before, after) = extract_before_after(diff_entry);
        entries.push(json!({
            "address": target_address,
            "bytecodeAddress": bytecode_address,
            "slot": slot_key,
            "before": before,
            "after": after,
            "snapshotId": snapshot_id,
        }));
    }

    Ok(entries)
}

async fn collect_snapshot_entries(
    client: &Client,
    rpc_url: &str,
    limit: u64,
) -> Result<Value, SimulatorError> {
    let snapshot_count: u64 =
        match call_edb_rpc(client, rpc_url, "edb_getSnapshotCount", json!([])).await {
            Ok(count) => count,
            Err(err) => {
                warn!("failed to read snapshot count: {err:?}");
                return Ok(Value::Array(Vec::new()));
            }
        };

    if snapshot_count == 0 {
        return Ok(Value::Array(Vec::new()));
    }

    let max_snapshots = snapshot_count.min(limit);
    let mut snapshots = Vec::with_capacity(max_snapshots as usize);

    for snapshot_id in 0..max_snapshots {
        match call_edb_rpc::<Value>(client, rpc_url, "edb_getSnapshotInfo", json!([snapshot_id]))
            .await
        {
            Ok(info) => snapshots.push(info),
            Err(err) => {
                warn!("failed to fetch snapshot {snapshot_id}: {err:?}");
                break;
            }
        }
    }

    Ok(Value::Array(snapshots))
}

fn extract_before_after(value: &Value) -> (Option<String>, Option<String>) {
    if let Some(arr) = value.as_array() {
        let before = arr.get(0).and_then(value_to_string);
        let after = arr.get(1).and_then(value_to_string);
        return (before, after);
    }

    if let Some(obj) = value.as_object() {
        let before = obj
            .get("before")
            .or_else(|| obj.get("previous"))
            .or_else(|| obj.get("0"))
            .and_then(value_to_string);
        let after = obj
            .get("after")
            .or_else(|| obj.get("current"))
            .or_else(|| obj.get("value"))
            .or_else(|| obj.get("1"))
            .and_then(value_to_string);
        return (before, after);
    }

    (value_to_string(value), None)
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Number(num) => Some(num.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => Some(value.to_string()),
    }
}

fn analyze_trace(trace_value: &Value) -> (bool, Option<String>) {
    // The Trace struct serializes as { "inner": [...], "total_gas_used": N }
    // We need to extract the inner array from the object
    let array = if let Some(obj) = trace_value.as_object() {
        // Trace serialized as object with "inner" field
        match obj.get("inner").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => return (true, None),
        }
    } else if let Some(arr) = trace_value.as_array() {
        // Direct array (backwards compatibility)
        arr
    } else {
        return (true, None);
    };

    let root = array.iter().find(|entry| entry.get("parent_id").map_or(true, |v| v.is_null()));

    let Some(root_entry) = root else {
        return (true, None);
    };

    let result_value = match root_entry.get("result") {
        Some(value) => value,
        None => return (true, None),
    };

    if let Some(obj) = result_value.as_object() {
        if obj.contains_key("Success") {
            return (true, None);
        }
        if let Some(revert) = obj.get("Revert") {
            let revert_reason = revert.get("output").and_then(Value::as_str).map(|s| s.to_string());
            return (false, revert_reason);
        }
        if let Some(error) = obj.get("Error") {
            let revert_reason = error.get("output").and_then(Value::as_str).map(|s| s.to_string());
            return (false, revert_reason);
        }
    }

    (true, None)
}
