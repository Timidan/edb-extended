// EDB - Ethereum Debugger
// Copyright (C) 2024 Zhuo Zhang and Wuqi Zhang
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Orchestration module that handles downloading verified source code,
//! instrumenting it, and generating snapshots for time travel debugging.
use std::{
    collections::{HashMap, HashSet},
    env,
    fs,
    time::{Duration, Instant},
};

use alloy_primitives::Address;
use edb_common::{CachePath, EdbCachePath, DEFAULT_ETHERSCAN_CACHE_TTL};
use eyre::{bail, Result};
use foundry_block_explorers::Client;
use futures::future::join_all;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use semver::Version;
use tracing::{debug, error, info, warn};

use crate::{
    analysis::AnalysisResult, dump_source_for_debugging, find_or_install_solc,
    format_compiler_errors, instrument, Artifact, EngineConfig, OnchainCompiler, TraceReplayResult,
};

/// Returns the correct Etherscan API URL for a chain.
///
/// Many chains (Base, Fraxtal, Mode, etc.) have deprecated their chain-native V1 APIs
/// and now require using the Etherscan V2 unified API (api.etherscan.io/v2/api).
/// The V2 API requires a Pro-tier API key for non-mainnet chains.
///
/// This function returns the correct V2 unified API URL for chains that have migrated,
/// or None to use the default chain mapping for chains that still support V1.
fn get_etherscan_v2_api_url(chain_id: u64) -> Option<String> {
    match chain_id {
        // Base chains - migrated to Etherscan V2 unified API (chain-native API deprecated)
        8453 | 84532 => Some(format!("https://api.etherscan.io/v2/api?chainid={}", chain_id)),
        // Fraxtal chains - migrated to Etherscan V2 unified API
        252 | 2522 => Some(format!("https://api.etherscan.io/v2/api?chainid={}", chain_id)),
        // Mode chains - migrated to Etherscan V2 unified API
        34443 | 919 => Some(format!("https://api.etherscan.io/v2/api?chainid={}", chain_id)),
        // Other chains - use default mapping (chain-native APIs still work)
        _ => None,
    }
}

/// Download and compile verified source code for each contract.
/// If `preloaded_artifacts` is provided, addresses that already exist in it will be skipped.
pub async fn download_verified_source_code(
    config: &EngineConfig,
    replay_result: &TraceReplayResult,
    chain_id: u64,
    preloaded_artifacts: Option<HashMap<Address, Artifact>>,
) -> Result<HashMap<Address, Artifact>> {
    // Start with pre-loaded artifacts if provided
    let mut artifacts = preloaded_artifacts.unwrap_or_default();
    let preloaded_count = artifacts.len();

    if preloaded_count > 0 {
        info!("Starting with {} pre-loaded artifacts from frontend", preloaded_count);
    }

    info!("Downloading verified source code for touched contracts");

    let compiler_cache_root = EdbCachePath::new(env::var(edb_common::env::EDB_CACHE_DIR).ok())
        .compiler_chain_cache_dir(chain_id);
    let compiler = OnchainCompiler::new(compiler_cache_root)?;

    let etherscan_cache_root = EdbCachePath::new(env::var(edb_common::env::EDB_CACHE_DIR).ok())
        .etherscan_chain_cache_dir(chain_id);

    let mut addresses_with_code: HashSet<Address> = HashSet::new();
    for entry in &replay_result.execution_trace {
        if let Some(bytecode) = entry.bytecode.as_ref() {
            if !bytecode.is_empty() && entry.code_address != Address::ZERO {
                addresses_with_code.insert(entry.code_address);
            }
        }
    }

    let visited_with_code = replay_result
        .visited_addresses
        .keys()
        .filter(|addr| addresses_with_code.contains(*addr))
        .count();
    let skipped_no_code = replay_result
        .visited_addresses
        .len()
        .saturating_sub(visited_with_code);
    if skipped_no_code > 0 {
        info!(
            "Skipping {} visited addresses without runtime bytecode (EOAs/precompiles)",
            skipped_no_code
        );
    }

    // Filter out addresses that already have artifacts and those without bytecode
    let addresses: Vec<_> = replay_result
        .visited_addresses
        .keys()
        .filter(|addr| addresses_with_code.contains(*addr))
        .filter(|addr| !artifacts.contains_key(*addr))
        .copied()
        .collect();
    let total_contracts = addresses.len();

    if total_contracts == 0 {
        info!("All {} addresses already have pre-loaded artifacts, skipping download", preloaded_count);
        return Ok(artifacts);
    }

    // Log all addresses that will be downloaded
    info!("Will download artifacts for {} addresses (skipping {} pre-loaded): {:?}",
          total_contracts, preloaded_count,
          addresses.iter().map(|a| format!("{:#x}", a)).collect::<Vec<_>>());

    let console_bar = std::sync::Arc::new(ProgressBar::new(total_contracts as u64));
    console_bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} 📜 Downloading & compiling contracts [{bar:40.cyan/blue}] {pos:>3}/{len:3} 🔧 {msg}"
            )?
            .progress_chars("🟩🟦⬜")
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
        );

    let cache_ttl = env::var(edb_common::env::EDB_ETHERSCAN_CACHE_TTL)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_ETHERSCAN_CACHE_TTL);

    // Create all download futures
    let download_futures = addresses.iter().map(|address| {
        let pb = console_bar.clone();
        let api_key = config.get_etherscan_api_key();
        let etherscan_cache_root = etherscan_cache_root.clone();
        let compiler = compiler.clone();
        let chain_id = chain_id;

        async move {
            let contract_start = Instant::now();
            let short_addr = &address.to_string()[2..10]; // Skip 0x, take 8 chars
            pb.set_message(format!("Downloading: 0x{short_addr}..."));

            // 1) Try Sourcify (partial/full match) to get metadata and sources
            let sourcify_start = Instant::now();
            let result = match crate::utils::sourcify::fetch_artifact_from_sourcify(chain_id, *address).await {
                Ok(Some(artifact)) => {
                    info!("[TIMING] Contract {} sourcify fetch: {:.2}s", address, sourcify_start.elapsed().as_secs_f64());
                    pb.set_message(format!("✅ 0x{short_addr}... sourcify"));
                    Some(artifact)
                }
                Ok(None) => {
                    info!("[TIMING] Contract {} sourcify miss: {:.2}s, trying etherscan", address, sourcify_start.elapsed().as_secs_f64());
                    // Fallback to chain-native Etherscan-compatible API (e.g., api.basescan.org)
                    // V2 unified API requires Pro-tier API key for multi-chain access.
                    // The alloy-chains library incorrectly maps some chains (Base, Fraxtal, etc.)
                    // to the V2 API, so we need to override those here.
                    let etherscan_start = Instant::now();
                    let mut builder = Client::builder()
                        .with_api_key(api_key)
                        .with_cache(etherscan_cache_root, Duration::from_secs(cache_ttl))
                        .chain(chain_id.into())?;

                    // Override API URL for chains that have migrated to Etherscan V2 unified API
                    // (chain-native APIs like api.basescan.org are deprecated and no longer work)
                    if let Some(v2_url) = get_etherscan_v2_api_url(chain_id) {
                        builder = builder.with_api_url(v2_url)?;
                    }

                    let etherscan = builder.build()?;

                    match compiler.compile(&etherscan, *address).await {
                        Ok(Some(artifact)) => {
                            info!("[TIMING] Contract {} etherscan+compile: {:.2}s", address, etherscan_start.elapsed().as_secs_f64());
                            pb.set_message(format!("✅ 0x{short_addr}... compiled"));
                            Some(artifact)
                        }
                        Ok(None) => {
                            info!("[TIMING] Contract {} etherscan no source: {:.2}s", address, etherscan_start.elapsed().as_secs_f64());
                            pb.set_message(format!("⚠️  0x{short_addr}... no source"));
                            debug!("No source code available for contract {}", address);
                            None
                        }
                        Err(e) => {
                            info!("[TIMING] Contract {} etherscan failed: {:.2}s", address, etherscan_start.elapsed().as_secs_f64());
                            pb.set_message(format!("❌ 0x{short_addr}... failed"));
                            warn!("Failed to compile contract {}: {:?}", address, e);
                            None
                        }
                    }
                }
                Err(e) => {
                    // Sourcify error (network issue, etc.) - also fallback to Etherscan
                    info!("[TIMING] Contract {} sourcify error: {:.2}s, falling back", address, sourcify_start.elapsed().as_secs_f64());
                    warn!("Sourcify fetch failed for {}, falling back to Etherscan: {:?}", address, e);

                    // Fallback to chain-native Etherscan-compatible API (e.g., api.basescan.org)
                    // The alloy-chains library incorrectly maps some chains (Base, Fraxtal, etc.)
                    // to the V2 API, so we need to override those here.
                    let etherscan_start = Instant::now();
                    let mut builder = Client::builder()
                        .with_api_key(api_key.clone())
                        .with_cache(etherscan_cache_root.clone(), Duration::from_secs(cache_ttl))
                        .chain(chain_id.into())?;

                    // Override API URL for chains that have migrated to Etherscan V2 unified API
                    // (chain-native APIs like api.basescan.org are deprecated and no longer work)
                    if let Some(v2_url) = get_etherscan_v2_api_url(chain_id) {
                        builder = builder.with_api_url(v2_url)?;
                    }

                    let etherscan = builder.build()?;

                    match compiler.compile(&etherscan, *address).await {
                        Ok(Some(artifact)) => {
                            info!("[TIMING] Contract {} etherscan fallback: {:.2}s", address, etherscan_start.elapsed().as_secs_f64());
                            pb.set_message(format!("✅ 0x{short_addr}... etherscan"));
                            Some(artifact)
                        }
                        Ok(None) => {
                            pb.set_message(format!("⚠️  0x{short_addr}... no source"));
                            debug!("No source code available for contract {}", address);
                            None
                        }
                        Err(e) => {
                            pb.set_message(format!("❌ 0x{short_addr}... failed"));
                            warn!("Failed to compile contract {}: {:?}", address, e);
                            None
                        }
                    }
                }
            };

            info!("[TIMING] Contract {} total download: {:.2}s", address, contract_start.elapsed().as_secs_f64());
            pb.inc(1);
            Ok::<(Address, Option<Artifact>), eyre::Error>((*address, result))
        }
    });

    // Wait for all downloads to complete
    let results = join_all(download_futures).await;

    // Process results and merge into artifacts (which may contain pre-loaded ones)
    let mut downloaded_count = 0;
    for result in results {
        if let Ok((address, Some(artifact))) = result {
            artifacts.insert(address, artifact);
            downloaded_count += 1;
        } else if let Err(e) = result {
            error!("Error during source code download: {:?}", e);
        }
    }

    console_bar.finish_with_message(format!(
        "✨ Done! Compiled {} out of {} contracts (+ {} pre-loaded)",
        downloaded_count,
        total_contracts,
        preloaded_count
    ));

    Ok(artifacts)
}

/// Instrument and recompile the source code
pub fn instrument_and_recompile_source_code(
    artifacts: &HashMap<Address, Artifact>,
    analysis_result: &HashMap<Address, AnalysisResult>,
) -> Result<HashMap<Address, Artifact>> {
    info!("Instrumenting source code based on analysis results");

    // Filter to only process contracts that have analysis results
    // Contracts without analysis results (e.g., due to AST parsing errors) will use opcode-level traces
    let contracts_with_analysis: Vec<_> = artifacts
        .iter()
        .filter(|(address, _)| analysis_result.contains_key(*address))
        .collect();

    let skipped_count = artifacts.len() - contracts_with_analysis.len();
    if skipped_count > 0 {
        info!(
            "Skipping {} contract(s) without analysis results (will use opcode-level traces)",
            skipped_count
        );
    }

    let progress_bar = std::sync::Arc::new(ProgressBar::new(contracts_with_analysis.len() as u64));
    progress_bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} 🔧 Instrumenting & recompiling contracts [{bar:40.cyan/blue}] {pos:>3}/{len:3} {msg}"
            )?
            .progress_chars("🟩🟦⬜")
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
        );

    // Parallel process contracts that have analysis results
    let results: Vec<_> = contracts_with_analysis
            .par_iter()
            .map(|(address, artifact)| {
                let contract_start = Instant::now();
                let pb = progress_bar.clone();
                let short_addr = &address.to_string()[2..10]; // Skip 0x, take 8 chars
                pb.set_message(format!("Recompiling: 0x{short_addr}..."));

                let result = (|| -> Result<Artifact> {
                    let compiler_version =
                        Version::parse(artifact.compiler_version().trim_start_matches('v'))?;

                    // Safe to unwrap since we filtered to only contracts with analysis results
                    let analysis = analysis_result.get(*address).unwrap();

                    let instrument_start = Instant::now();
                    let input = instrument(&compiler_version, &artifact.input, analysis)?;
                    info!("[TIMING] Contract {} instrument(): {:.2}s", address, instrument_start.elapsed().as_secs_f64());

                    let meta = artifact.meta.clone();

                    // prepare the compiler
                    let solc_start = Instant::now();
                    let version = meta.compiler_version()?;
                    let compiler = find_or_install_solc(&version)?;
                    info!("[TIMING] Contract {} find_or_install_solc: {:.2}s", address, solc_start.elapsed().as_secs_f64());

                    // compile the source code
                    let compile_start = Instant::now();
                    let output = match compiler.compile_exact(&input) {
                        Ok(output) => output,
                        Err(compiler_error) => {
                            // Dump source code immediately for debugging
                            let (original_dir, instrumented_dir) =
                                dump_source_for_debugging(address, &artifact.input, &input)?;

                            // Write compiler error to file
                            let error_file = instrumented_dir.parent()
                                .unwrap_or(&instrumented_dir)
                                .join("compilation_errors.txt");

                            let error_content = format!(
                                "Compiler Error for Contract {}\n{}\n\n{}",
                                address,
                                "=".repeat(60),
                                compiler_error
                            );

                            fs::write(&error_file, &error_content)?;

                            bail!(
                                "Compilation failed\n  Error details: {error_file:?}\n  Original source: {original_dir:?}\n  Instrumented source: {instrumented_dir:?}",
                            );
                        }
                    };
                    info!("[TIMING] Contract {} compile_exact: {:.2}s", address, compile_start.elapsed().as_secs_f64());

                    // Check for compilation errors
                    if output.errors.iter().any(|e| e.is_error()) {
                        // Dump source code immediately for debugging
                        let (original_dir, instrumented_dir) =
                            dump_source_for_debugging(address, &artifact.input, &input)?;

                        // Format errors with better source location info
                        let formatted_errors = format_compiler_errors(&output.errors, &instrumented_dir);

                        // Write formatted errors to file
                        let error_file = instrumented_dir.parent()
                            .unwrap_or(&instrumented_dir)
                            .join("compilation_errors.txt");

                        let error_content = format!(
                            "Compilation Errors for Contract {address}\n{}\n\n{formatted_errors}",
                            "=".repeat(60),
                        );

                        fs::write(&error_file, &error_content)?;

                        bail!(
                            "Compilation failed\n  Error details: {error_file:?}\n  Original source: {original_dir:?}\n  Instrumented source: {instrumented_dir:?}",
                        );
                    }

                    debug!(
                        "Recompiled Contract {}: {} vs {}",
                        address,
                        artifact.output.contracts.len(),
                        output.contracts.len()
                    );

                    Ok(Artifact { meta, input, output })
                })();

                match &result {
                    Ok(_) => {
                        info!("[TIMING] Contract {} total instrument+recompile: {:.2}s", address, contract_start.elapsed().as_secs_f64());
                        pb.set_message(format!("✅ 0x{short_addr}... instrumented"));
                    }
                    Err(_) => pb.set_message(format!("❌ 0x{short_addr}... failed")),
                }

                pb.inc(1);
                (**address, result)
            })
            .collect();

    progress_bar.finish_with_message("✨ Instrumentation complete!");

    // Process results and collect errors
    let mut recompiled_artifacts = HashMap::new();
    let mut all_errors = Vec::new();

    for (address, result) in results {
        match result {
            Ok(artifact) => {
                recompiled_artifacts.insert(address, artifact);
            }
            Err(e) => {
                all_errors.push((address, e));
            }
        }
    }

    // If any errors occurred, create a comprehensive error message
    if !all_errors.is_empty() {
        let mut error_msg = format!(
            "Failed to instrument {} contract(s). Debug information saved to:\n\n",
            all_errors.len()
        );

        for (i, (addr, err)) in all_errors.iter().enumerate() {
            // This already contains the paths from the error creation above
            error_msg.push_str(&format!("{}. Contract {addr}:\n{err}\n\n", i + 1,));
        }

        error_msg.push_str("Please check the error details files for full compilation errors.");

        bail!("{error_msg}");
    }

    Ok(recompiled_artifacts)
}
