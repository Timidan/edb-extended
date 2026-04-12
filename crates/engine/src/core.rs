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

//! Core engine functionality for transaction analysis and debugging.
//!
//! This module provides the main engine implementation that orchestrates the complete
//! debugging workflow for Ethereum transactions. It handles source code analysis,
//! contract instrumentation, transaction execution with debugging inspectors,
//! and RPC server management.
//!
//! # Workflow Overview
//!
//! 1. **Preparation**: Accept forked database and transaction configuration
//! 2. **Analysis**: Download and analyze contract source code
//! 3. **Instrumentation**: Inject debugging hooks into contract bytecode
//! 4. **Execution**: Replay transaction with comprehensive debugging inspectors
//! 5. **Collection**: Gather execution snapshots and trace data
//! 6. **API**: Start RPC server for debugging interface
//!
//! # Key Components
//!
//! - [`EngineConfig`] - Engine configuration and settings
//! - [`run_transaction_analysis`] - Main analysis workflow function
//! - Inspector coordination for comprehensive data collection
//! - Source code fetching and compilation management
//! - Snapshot generation and organization
//!
//! # Supported Features
//!
//! - **Multi-contract analysis**: Analyze all contracts involved in execution
//! - **Source fetching**: Automatic download from Etherscan and verification
//! - **Quick mode**: Fast analysis with reduced operations
//! - **Instrumentation**: Automatic debugging hook injection
//! - **Comprehensive inspection**: Opcode and source-level snapshot collection

use alloy_primitives::TxHash;
use dashmap::DashMap;
use edb_common::ForkResult;
use eyre::Result;
use revm::{context::Host, database::CacheDB, Database, DatabaseCommit, DatabaseRef};
use std::{collections::HashSet, net::SocketAddr, panic, sync::Arc, time::Instant};
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use crate::{
    orchestration,
    rpc::{start_debug_server, RpcServerHandle},
    utils::next_etherscan_api_key,
    EngineContext, FinalizeOptions, SnapshotAnalysis,
};

/// Configuration for the EDB debugging engine.
///
/// Contains settings that control the engine's behavior during transaction analysis,
/// source code fetching, and debugging operations.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// RPC provider URL for blockchain interaction (typically a proxy or archive node)
    pub rpc_proxy_url: String,
    /// Optional Etherscan API key for automatic source code downloading and verification
    pub etherscan_api_key: Option<String>,
    /// Quick mode flag - when enabled, skips time-intensive operations for faster analysis
    pub quick: bool,
    /// Precompute state variables for hook snapshots during context finalization
    pub precompute_state_variables: bool,
    /// Collect hook snapshots by tweaking bytecode and replaying instrumented execution.
    /// Disable this for non-debug flows to avoid heavy preparation overhead.
    pub collect_hook_snapshots: bool,
    /// Preferred artifact source priority hint from frontend/config.
    /// Expected values: "sourcify", "etherscan", "blockscout".
    pub artifact_source_priority: Vec<String>,
    /// Capture only significant opcodes during opcode snapshot pass.
    /// This keeps V3 render parity-critical opcodes while cutting non-debug replay cost.
    pub significant_opcode_snapshots_only: bool,
    /// Events-only mode: short-circuit after Step 1 (replay). When enabled, the
    /// engine skips Step 2 (source download from Etherscan/Sourcify) and Step 3
    /// (source analysis) entirely and builds an `EngineContext` with empty
    /// artifacts. The raw execution trace still carries event logs, which is
    /// all that asset-movement / Transfer-extraction consumers read. Drops
    /// engine.prepare() from ~19s to ~2.5s on DepositFlow-style transactions
    /// where the source download dominates.
    pub events_only: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            rpc_proxy_url: "http://localhost:8545".into(),
            etherscan_api_key: None,
            quick: false,
            precompute_state_variables: true,
            collect_hook_snapshots: true,
            artifact_source_priority: Vec::new(),
            significant_opcode_snapshots_only: false,
            events_only: false,
        }
    }
}

impl EngineConfig {
    /// Set the Etherscan API key for source code download
    pub fn with_etherscan_api_key(mut self, key: String) -> Self {
        self.etherscan_api_key = Some(key);
        self
    }

    /// Enable or disable quick mode for faster analysis
    pub fn with_quick_mode(mut self, quick: bool) -> Self {
        self.quick = quick;
        self
    }

    /// Enable or disable state variable precomputation during context finalization
    pub fn with_precompute_state_variables(mut self, precompute_state_variables: bool) -> Self {
        self.precompute_state_variables = precompute_state_variables;
        self
    }

    /// Enable or disable hook snapshot collection during engine preparation
    pub fn with_collect_hook_snapshots(mut self, collect_hook_snapshots: bool) -> Self {
        self.collect_hook_snapshots = collect_hook_snapshots;
        self
    }

    /// Set preferred artifact source priority hint for runtime-discovered contracts.
    pub fn with_artifact_source_priority(mut self, artifact_source_priority: Vec<String>) -> Self {
        self.artifact_source_priority = artifact_source_priority;
        self
    }

    /// Enable significant-opcode-only mode for opcode snapshot capture.
    pub fn with_significant_opcode_snapshots_only(
        mut self,
        significant_opcode_snapshots_only: bool,
    ) -> Self {
        self.significant_opcode_snapshots_only = significant_opcode_snapshots_only;
        self
    }

    /// Enable events-only mode: skips source download and analysis, returns
    /// a minimal context that still carries the raw trace (and its event logs).
    pub fn with_events_only(mut self, events_only: bool) -> Self {
        self.events_only = events_only;
        self
    }

    /// Set the RPC proxy URL for blockchain interactions
    pub fn with_rpc_proxy_url(mut self, url: String) -> Self {
        self.rpc_proxy_url = url;
        self
    }

    /// Get the Etherscan API key, either from config or rotate to the next available key
    pub fn get_etherscan_api_key(&self) -> String {
        self.etherscan_api_key.clone().unwrap_or(next_etherscan_api_key())
    }
}

/// The main Engine struct that performs transaction analysis
///
/// This struct is thread-safe and can be shared across multiple threads.
/// It uses per-transaction locking to ensure that only one thread can analyze
/// a given transaction at a time, while allowing concurrent analysis of different transactions.
#[derive(Debug)]
pub struct Engine {
    /// Concurrent map of transaction hashes to their RPC server handles
    server_handles: Arc<DashMap<TxHash, RpcServerHandle>>,

    /// Per-transaction locks to prevent duplicate analysis of the same transaction
    /// Each transaction hash gets its own lock, allowing parallel analysis of different transactions
    in_flight: Arc<DashMap<TxHash, Arc<Mutex<()>>>>,

    /// Configuration for the engine
    config: EngineConfig,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new(EngineConfig::default())
    }
}

impl Engine {
    /// Create a new Engine instance from configuration
    pub fn new(config: EngineConfig) -> Self {
        Self {
            server_handles: Arc::new(DashMap::new()),
            in_flight: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Get the RPC server address for a given transaction hash, if it exists
    pub fn get_rpc_server_addr(&self, tx_hash: &TxHash) -> Option<SocketAddr> {
        self.server_handles.get(tx_hash).map(|handle| handle.addr())
    }

    /// Shut down the RPC server for a given transaction hash, if it exists
    /// Returns true if the server was found and shut down, false otherwise
    pub fn shutdown_rpc_server(&self, tx_hash: &TxHash) -> Result<bool> {
        if let Some((_, handle)) = self.server_handles.remove(tx_hash) {
            handle.shutdown()?;
            info!("Shut down RPC server for transaction: {:?}", tx_hash);
            Ok(true)
        } else {
            info!("No RPC server found for transaction: {:?}", tx_hash);
            Ok(false)
        }
    }

    /// Main preparation method for the engine
    ///
    /// This method accepts a forked database and EVM configuration prepared by the edb binary.
    /// It focuses on the core debugging workflow:
    /// 1. Replays the target transaction to collect touched contracts
    /// 2. Downloads verified source code for each contract (skipping pre-loaded ones)
    /// 3. Analyzes the source code to identify instrumentation points
    /// 4. Instruments and recompiles the source code
    /// 5. Collect opcode-level step execution results
    /// 6. Re-executes the transaction with state snapshots
    /// 7. Starts a JSON-RPC server with the analysis results and snapshots
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    /// Per-transaction locking ensures that only one thread can analyze a given transaction
    /// at a time. If a transaction is already being analyzed by another thread, subsequent
    /// calls will wait for the analysis to complete and then return the cached result.
    ///
    /// # Pre-loaded Artifacts
    ///
    /// If `preloaded_artifacts` is provided, those artifacts will be used directly and
    /// skipped during the download phase. This allows the frontend to pass Sourcify artifacts
    /// it has already fetched, avoiding duplicate network requests and significantly
    /// improving simulation performance.
    pub async fn prepare<DB>(
        &self,
        fork_result: ForkResult<DB>,
        progress_tx: Option<mpsc::UnboundedSender<edb_common::ProgressMessage>>,
        preloaded_artifacts: Option<
            std::collections::HashMap<alloy_primitives::Address, crate::Artifact>,
        >,
    ) -> Result<SocketAddr>
    where
        DB: Database + DatabaseCommit + DatabaseRef + Clone + Send + Sync + 'static,
        <CacheDB<DB> as Database>::Error: Clone + Send + Sync,
        <DB as Database>::Error: Clone + Send + Sync,
    {
        // a utility macro to send progress message to the progress channel, if it exists
        macro_rules! send_progress {
            // With step tracking: send_progress!(current, total, "message")
            ($current:expr, $total:expr, $($message:tt)*) => {
                progress_tx.as_ref().map(|tx| {
                    tx.send(edb_common::ProgressMessage::with_steps(
                        format!($($message)*),
                        $current,
                        $total
                    )).ok()
                });
            };
            // Without step tracking: send_progress!("message")
            ($($message:tt)*) => {
                progress_tx.as_ref().map(|tx| {
                    tx.send(edb_common::ProgressMessage::new(format!($($message)*))).ok()
                });
            };
        }

        let tx_hash = fork_result.target_tx_hash;

        // Get or create per-transaction lock
        let lock =
            self.in_flight.entry(tx_hash).or_insert_with(|| Arc::new(Mutex::new(()))).clone();

        // Acquire lock - blocks if another thread is processing this transaction
        let _guard = lock.lock().await;

        // Check if this transaction has already been analyzed
        if let Some(existing_handle) = self.server_handles.get(&tx_hash) {
            info!(
                "Transaction {:?} already analyzed, returning existing RPC server at {}",
                tx_hash,
                existing_handle.addr()
            );
            send_progress!("Transaction {:?} already analyzed", tx_hash);
            return Ok(existing_handle.addr());
        }

        info!("Starting engine preparation for transaction: {:?}", tx_hash);
        let engine_start = Instant::now();

        // Step 0: Initialize context and database
        let ForkResult { context: mut ctx, target_tx_env: tx, target_tx_hash: tx_hash, fork_info } =
            fork_result;

        // Step 1: Replay the target transaction to collect call trace and touched contracts
        send_progress!(
            1,
            8,
            "Replaying the target transaction to collect call trace and touched contracts..."
        );
        let step_start = Instant::now();
        let (replay_result, precollected_opcode_snapshots) =
            orchestration::replay_and_collect_trace_and_opcode_snapshots(
                ctx.clone(),
                tx.clone(),
                HashSet::new(),
                self.config.significant_opcode_snapshots_only,
            )?;
        info!(
            "[TIMING] Step 1 - replay_and_collect_trace: {:.2}s",
            step_start.elapsed().as_secs_f64()
        );

        // Step 2: Download verified source code for each contract
        // (skipping addresses that have pre-loaded artifacts from frontend).
        // Events-only callers (e.g. asset-movement extraction) only consume
        // the raw trace's event logs and don't need artifacts at all, so we
        // short-circuit the whole source-fetch pipeline here — this is the
        // dominant cost on DepositFlow-style calls (~16s).
        let artifacts = if self.config.events_only {
            send_progress!(2, 8, "Skipping source download (events-only mode)...");
            info!("[PERF] Skipping Step 2 - download_verified_source_code (events_only)");
            std::collections::HashMap::new()
        } else {
            send_progress!(2, 8, "Downloading verified source code for each contract...");
            let step_start = Instant::now();
            let artifacts = orchestration::download_verified_source_code(
                &self.config,
                &replay_result,
                ctx.chain_id().to::<u64>(),
                preloaded_artifacts,
            )
            .await?;
            info!(
                "[TIMING] Step 2 - download_verified_source_code: {:.2}s ({} contracts)",
                step_start.elapsed().as_secs_f64(),
                artifacts.len()
            );

            // Log degradation warning if no artifacts found - we'll still get opcode-level traces
            let touched_contracts = replay_result.visited_addresses.len();
            if artifacts.is_empty() && touched_contracts > 0 {
                warn!(
                    "No verified source code found for any of the {} touched contracts. \
                     Debugging will use opcode-level traces only (no source-level debugging available).",
                    touched_contracts
                );
            } else if !artifacts.is_empty() && artifacts.len() < touched_contracts {
                info!(
                    "Source code found for {}/{} touched contracts. \
                     Contracts without source will use opcode-level traces.",
                    artifacts.len(),
                    touched_contracts
                );
            }
            artifacts
        };

        // Step 3: Analyze source code to identify instrumentation points.
        // With no artifacts in events-only mode this is a no-op, but we still
        // skip the function call so it doesn't even touch the HashMap iterator.
        let analysis_results = if self.config.events_only {
            send_progress!(3, 8, "Skipping source analysis (events-only mode)...");
            info!("[PERF] Skipping Step 3 - analyze_source_code (events_only)");
            std::collections::HashMap::new()
        } else {
            send_progress!(3, 8, "Analyzing source code to identify instrumentation points...");
            let step_start = Instant::now();
            let analysis_results = orchestration::analyze_source_code(&artifacts)?;
            info!(
                "[TIMING] Step 3 - analyze_source_code: {:.2}s",
                step_start.elapsed().as_secs_f64()
            );
            analysis_results
        };

        // Step 4: Instrument source code (debug/hook pipeline only).
        // Non-debug simulations can render V3 traces from canonical artifacts + opcode snapshots.
        let recompiled_artifacts = if self.config.collect_hook_snapshots {
            send_progress!(4, 8, "Instrumenting source code...");
            let step_start = Instant::now();
            let recompiled =
                orchestration::instrument_and_recompile_source_code(&artifacts, &analysis_results)?;
            info!(
                "[TIMING] Step 4 - instrument_and_recompile: {:.2}s",
                step_start.elapsed().as_secs_f64()
            );
            recompiled
        } else {
            send_progress!(4, 8, "Skipping instrumentation for non-debug simulation...");
            info!("[PERF] Skipping Step 4 - instrument_and_recompile");
            Default::default()
        };

        // Step 5: Collect opcode-level step execution results
        send_progress!(5, 8, "Collecting opcode-level step execution results...");
        let step_start = Instant::now();
        // Reuse snapshots captured during replay to avoid a second full transaction execution.
        let opcode_snapshots = precollected_opcode_snapshots;
        info!(
            "[TIMING] Step 5 - capture_opcode_level_snapshots: {:.2}s (reused from Step 1)",
            step_start.elapsed().as_secs_f64()
        );

        // Step 6/7: Optional hook snapshot pipeline (expensive; required for full debug sessions)
        let hook_snapshots = if self.config.collect_hook_snapshots {
            // Step 6: Replace original bytecode with instrumented versions
            send_progress!(6, 8, "Replacing original bytecode with instrumented versions...");
            let step_start = Instant::now();
            let contracts_in_tx = orchestration::tweak_bytecode(
                &self.config,
                &mut ctx,
                &artifacts,
                &recompiled_artifacts,
                tx_hash,
            )
            .await?;
            info!("[TIMING] Step 6 - tweak_bytecode: {:.2}s", step_start.elapsed().as_secs_f64());

            // Step 7: Re-execute the transaction with hook snapshot collection
            send_progress!(7, 8, "Collecting creation hooks for contracts in transaction...");
            let step_start = Instant::now();
            let hook_creation = orchestration::collect_creation_hooks(
                &artifacts,
                &recompiled_artifacts,
                contracts_in_tx,
            )?;
            // Use catch_unwind to gracefully handle panics during hook snapshot collection
            // (Diamond contracts with many facets can trigger panics in REVM)
            let snapshots = {
                let ctx_clone = ctx.clone();
                let tx_clone = tx.clone();
                let trace_ref = &replay_result.execution_trace;
                let analysis_ref = &analysis_results;

                match panic::catch_unwind(panic::AssertUnwindSafe(|| {
                    orchestration::capture_hook_snapshots(
                        ctx_clone,
                        tx_clone,
                        hook_creation,
                        trace_ref,
                        analysis_ref,
                    )
                })) {
                    Ok(Ok(snapshots)) => snapshots,
                    Ok(Err(e)) => {
                        warn!("Hook snapshot collection failed: {e:?}. Using opcode-level snapshots only.");
                        crate::HookSnapshots::default()
                    }
                    Err(panic_info) => {
                        warn!(
                            "Hook snapshot collection panicked: {:?}. Using opcode-level snapshots only.",
                            panic_info.downcast_ref::<&str>().unwrap_or(&"unknown panic")
                        );
                        crate::HookSnapshots::default()
                    }
                }
            };
            info!(
                "[TIMING] Step 7 - capture_hook_snapshots: {:.2}s",
                step_start.elapsed().as_secs_f64()
            );
            snapshots
        } else {
            send_progress!(6, 8, "Skipping bytecode tweak for non-debug simulation...");
            send_progress!(7, 8, "Skipping hook snapshot collection for non-debug simulation...");
            info!("[PERF] Skipping Step 6/7 (tweak_bytecode + capture_hook_snapshots)");
            crate::HookSnapshots::default()
        };

        // Step 8: Start RPC server with analysis results and snapshots
        send_progress!(8, 8, "Collecting opcode-level and hook-level snapshots...");
        let step_start = Instant::now();
        let mut snapshots =
            orchestration::get_time_travel_snapshots(opcode_snapshots, hook_snapshots)?;
        // Best-effort analysis; skip failures when mixing hook/opcode snapshots.
        // Note: Even if this fails, opcode-level snapshots are still usable for basic debugging.
        if let Err(e) = snapshots.analyze(&replay_result.execution_trace, &analysis_results) {
            warn!(
                "Snapshot analysis skipped (source-level variable tracking unavailable): {e:?}. \
                 Opcode-level trace data is still available for debugging."
            );
        }
        info!(
            "[TIMING] Step 8 - get_time_travel_snapshots + analyze: {:.2}s",
            step_start.elapsed().as_secs_f64()
        );

        // Let's pack the debug context
        let step_start = Instant::now();
        let finalize_options =
            FinalizeOptions { precompute_state_variables: self.config.precompute_state_variables };
        if !finalize_options.precompute_state_variables {
            info!("[PERF] Skipping hook snapshot state-variable precompute");
        }
        let context = EngineContext::build_with_options(
            fork_info,
            ctx.cfg.clone(),
            ctx.block.clone(),
            tx,
            tx_hash,
            snapshots,
            artifacts,
            recompiled_artifacts,
            analysis_results,
            replay_result.execution_trace,
            finalize_options,
        )?;

        let rpc_handle = start_debug_server(context).await?;
        info!(
            "[TIMING] Step 9 - build_context + start_debug_server: {:.2}s",
            step_start.elapsed().as_secs_f64()
        );
        info!("[TIMING] TOTAL engine.prepare(): {:.2}s", engine_start.elapsed().as_secs_f64());
        info!("Debug RPC server started on {}", rpc_handle.addr());

        // Store the server handle for future reference
        let addr = rpc_handle.addr();
        self.server_handles.insert(tx_hash, rpc_handle);

        Ok(addr)
    }
}
