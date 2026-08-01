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

//! Orchestration module that coordinates the main steps of the EDB debugging process.
//! This includes transaction replay, source code analysis, bytecode tweaking,
//! and snapshot generation.

use std::collections::{HashMap, HashSet};

use alloy_primitives::{Address, Log, TxHash, U256};
use edb_common::{is_mezo_chain, EdbContext, MezoPrecompileMockInspector};
use eyre::Result;
use revm::{
    context::{
        result::{ExecutionResult, HaltReason},
        TxEnv,
    },
    database::CacheDB,
    interpreter::{CallInputs, CallOutcome, CreateInputs, CreateOutcome, Interpreter},
    Database, DatabaseCommit, DatabaseRef, InspectEvm, Inspector, MainBuilder,
};
use tracing::{debug, error, info, warn};

use crate::{
    analysis::{analyze, AnalysisResult},
    Artifact, CallTracer, CodeTweaker, EngineConfig, OpcodeSnapshotInspector, OpcodeSnapshots,
    TraceReplayResult,
};

/// Combined inspector that collects both call trace metadata and opcode snapshots
/// in a single transaction replay.
#[derive(Debug)]
struct ReplayWithOpcodeInspector<DB>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone,
    <CacheDB<DB> as Database>::Error: Clone,
    <DB as Database>::Error: Clone,
{
    call_tracer: CallTracer,
    opcode_inspector: OpcodeSnapshotInspector<DB>,
    mezo_precompile_inspector: MezoPrecompileMockInspector,
}

impl<DB> ReplayWithOpcodeInspector<DB>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone,
    <CacheDB<DB> as Database>::Error: Clone,
    <DB as Database>::Error: Clone,
{
    fn new(
        ctx: &EdbContext<DB>,
        excluded_addresses: HashSet<Address>,
        significant_only: bool,
    ) -> Self {
        let mut opcode_inspector = OpcodeSnapshotInspector::new(ctx);
        opcode_inspector.with_excluded_addresses(excluded_addresses);
        opcode_inspector.with_significant_only(significant_only);
        Self {
            call_tracer: CallTracer::new(),
            opcode_inspector,
            mezo_precompile_inspector: MezoPrecompileMockInspector::default(),
        }
    }

    fn into_parts(self) -> (TraceReplayResult, OpcodeSnapshots<DB>) {
        (self.call_tracer.into_replay_result(), self.opcode_inspector.into_snapshots())
    }
}

impl<DB> Inspector<EdbContext<DB>> for ReplayWithOpcodeInspector<DB>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone,
    <CacheDB<DB> as Database>::Error: Clone,
    <DB as Database>::Error: Clone,
{
    fn step(&mut self, interp: &mut Interpreter, context: &mut EdbContext<DB>) {
        self.call_tracer.step(interp, context);
        self.opcode_inspector.step(interp, context);
    }

    fn step_end(&mut self, interp: &mut Interpreter, context: &mut EdbContext<DB>) {
        self.opcode_inspector.step_end(interp, context);
    }

    fn call(
        &mut self,
        context: &mut EdbContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        self.call_tracer
            .call(context, inputs)
            .or_else(|| self.opcode_inspector.call(context, inputs))
            .or_else(|| self.mezo_precompile_inspector.call(context, inputs))
    }

    fn call_end(
        &mut self,
        context: &mut EdbContext<DB>,
        inputs: &CallInputs,
        outcome: &mut CallOutcome,
    ) {
        self.call_tracer.call_end(context, inputs, outcome);
        self.opcode_inspector.call_end(context, inputs, outcome);
    }

    fn create(
        &mut self,
        context: &mut EdbContext<DB>,
        inputs: &mut CreateInputs,
    ) -> Option<CreateOutcome> {
        self.call_tracer
            .create(context, inputs)
            .or_else(|| self.opcode_inspector.create(context, inputs))
    }

    fn create_end(
        &mut self,
        context: &mut EdbContext<DB>,
        inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        self.call_tracer.create_end(context, inputs, outcome);
        self.opcode_inspector.create_end(context, inputs, outcome);
    }

    fn selfdestruct(&mut self, contract: Address, target: Address, value: U256) {
        <CallTracer as Inspector<EdbContext<DB>>>::selfdestruct(
            &mut self.call_tracer,
            contract,
            target,
            value,
        );
        self.opcode_inspector.selfdestruct(contract, target, value);
    }

    fn log(&mut self, context: &mut EdbContext<DB>, log: Log) {
        self.call_tracer.log(context, log.clone());
        self.opcode_inspector.log(context, log);
    }
}

/// Replay the target transaction and collect call trace with all touched addresses
pub fn replay_and_collect_trace<DB>(ctx: EdbContext<DB>, tx: TxEnv) -> Result<TraceReplayResult>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone,
    <CacheDB<DB> as Database>::Error: Clone,
    <DB as Database>::Error: Clone,
{
    info!("Replaying transaction to collect call trace and touched addresses");

    let mut inspector = (CallTracer::new(), MezoPrecompileMockInspector::default());
    let mut evm = ctx.build_mainnet_with_inspector(&mut inspector);

    let exec_result = evm
        .inspect_one_tx(tx)
        .map_err(|e| eyre::eyre!("Failed to inspect the target transaction: {:?}", e))?;

    // Extract gas_used from ExecutionResult - this includes gas refunds
    let gas_used = match &exec_result {
        ExecutionResult::Success { gas_used, .. } => Some(*gas_used),
        ExecutionResult::Revert { gas_used, .. } => Some(*gas_used),
        ExecutionResult::Halt { gas_used, .. } => Some(*gas_used),
    };

    if let ExecutionResult::Halt { reason, .. } = exec_result {
        if matches!(reason, HaltReason::OutOfGas { .. }) {
            error!("EDB cannot debug out-of-gas errors. Proceed at your own risk.")
        }
    }

    drop(evm);
    let mut result = inspector.0.into_replay_result();

    // Set the total gas used on the trace (includes gas refunds from SSTORE, etc.)
    if let Some(gas) = gas_used {
        result.execution_trace.set_total_gas_used(gas);
        debug!("Transaction gas used (with refunds): {}", gas);
    }

    for (address, deployed) in &result.visited_addresses {
        if *deployed {
            debug!("Contract {} was deployed during transaction replay", address);
        } else {
            debug!("Address {} was touched during transaction replay", address);
        }
    }

    // Print the trace tree structure (disabled for simulator - causes stdout pollution)
    // result.execution_trace.print_trace_tree();

    Ok(result)
}

/// Replay the target transaction once and collect both call trace metadata and opcode snapshots.
pub fn replay_and_collect_trace_and_opcode_snapshots<DB>(
    ctx: EdbContext<DB>,
    tx: TxEnv,
    excluded_addresses: HashSet<Address>,
    significant_only: bool,
) -> Result<(TraceReplayResult, OpcodeSnapshots<DB>)>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone,
    <CacheDB<DB> as Database>::Error: Clone,
    <DB as Database>::Error: Clone,
{
    info!("Replaying transaction to collect call trace, touched addresses, and opcode snapshots");

    let mut inspector = ReplayWithOpcodeInspector::new(&ctx, excluded_addresses, significant_only);
    let mut evm = ctx.build_mainnet_with_inspector(&mut inspector);

    let exec_result = evm
        .inspect_one_tx(tx)
        .map_err(|e| eyre::eyre!("Failed to inspect the target transaction: {:?}", e))?;

    let gas_used = match &exec_result {
        ExecutionResult::Success { gas_used, .. } => Some(*gas_used),
        ExecutionResult::Revert { gas_used, .. } => Some(*gas_used),
        ExecutionResult::Halt { gas_used, .. } => Some(*gas_used),
    };

    if let ExecutionResult::Halt { reason, .. } = exec_result {
        if matches!(reason, HaltReason::OutOfGas { .. }) {
            error!("EDB cannot debug out-of-gas errors. Proceed at your own risk.")
        }
    }

    let (mut replay_result, opcode_snapshots) = inspector.into_parts();
    if let Some(gas) = gas_used {
        replay_result.execution_trace.set_total_gas_used(gas);
        debug!("Transaction gas used (with refunds): {}", gas);
    }

    for (address, deployed) in &replay_result.visited_addresses {
        if *deployed {
            debug!("Contract {} was deployed during transaction replay", address);
        } else {
            debug!("Address {} was touched during transaction replay", address);
        }
    }

    Ok((replay_result, opcode_snapshots))
}

/// Analyze the source code for instrumentation points and variable usage
pub fn analyze_source_code(
    artifacts: &HashMap<Address, Artifact>,
) -> Result<HashMap<Address, AnalysisResult>> {
    info!("Analyzing source code to identify instrumentation points");

    let mut analysis_result = HashMap::new();
    for (address, artifact) in artifacts {
        debug!("Analyzing contract at address: {address}");
        match analyze(artifact) {
            Ok(analysis) => {
                debug!("Finished analyzing contract at address: {address}");
                analysis_result.insert(*address, analysis);
            }
            Err(e) => {
                // Log the error but continue with other contracts
                // Contracts that fail AST analysis will use opcode-level traces instead
                warn!(
                    "Failed to analyze contract at address {address}: {e}. \
                     This contract will use opcode-level traces instead of source-level debugging."
                );
            }
        }
    }

    Ok(analysis_result)
}

/// Tweak the bytecode of the contracts
pub async fn tweak_bytecode<DB>(
    config: &EngineConfig,
    ctx: &mut EdbContext<DB>,
    artifacts: &HashMap<Address, Artifact>,
    recompiled_artifacts: &HashMap<Address, Artifact>,
    tx_hash: TxHash,
) -> Result<Vec<Address>>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone,
    <CacheDB<DB> as Database>::Error: Clone,
    <DB as Database>::Error: Clone,
{
    info!("Tweaking bytecode");

    let chain_id = ctx.cfg.chain_id;
    let allow_direct_runtime_tweak = is_mezo_chain(chain_id);
    let mut tweaker =
        CodeTweaker::new(ctx, config.rpc_proxy_url.clone(), config.etherscan_api_key.clone());

    let mut contracts_in_tx = Vec::new();

    for (address, recompiled_artifact) in recompiled_artifacts {
        let artifact = match artifacts.get(address) {
            Some(a) => a,
            None => {
                warn!(
                    "No original artifact found for address {address}. \
                     This contract will use opcode-level traces instead of source-level debugging."
                );
                continue;
            }
        };

        let creation_tx_hash = match tweaker.get_creation_tx(address).await {
            Ok(hash) => hash,
            Err(e) => {
                if allow_direct_runtime_tweak {
                    warn!(
                        "Failed to get creation tx for Mezo contract {address}: {e}. \
                         Falling back to direct runtime bytecode replacement."
                    );
                    match tweaker.tweak_deployed_runtime(address, artifact, recompiled_artifact) {
                        Ok(()) => {}
                        Err(runtime_err) => {
                            warn!(
                                "Direct runtime bytecode replacement failed for contract {address}: \
                                 {runtime_err}. This contract will use opcode-level traces instead \
                                 of source-level debugging."
                            );
                        }
                    }
                } else {
                    warn!(
                        "Failed to get creation tx for contract {address}: {e}. \
                         This contract will use opcode-level traces instead of source-level debugging."
                    );
                }
                continue;
            }
        };
        if creation_tx_hash == tx_hash {
            debug!("Skip tweaking contract {}, since it was created by the transaction under investigation", address);
            contracts_in_tx.push(*address);
            continue;
        }

        let tweak_result = if config.quick {
            match tweaker.tweak(address, artifact, recompiled_artifact, true).await {
                Ok(()) => Ok(()),
                Err(quick_err) => {
                    let quick_err_text = quick_err.to_string();
                    let non_retryable = quick_err_text
                        .contains("no runtime-compatible creation-hook contract")
                        || quick_err_text.contains("no eligible original contract candidates")
                        || quick_err_text
                            .contains("no recompiled contract found for selected original");
                    if non_retryable {
                        Err(quick_err)
                    } else {
                        warn!(
                            "Quick tweak failed for contract {address}: {quick_err_text}. \
                             Retrying with full replay mode."
                        );
                        tweaker.tweak(address, artifact, recompiled_artifact, false).await
                    }
                }
            }
        } else {
            tweaker.tweak(address, artifact, recompiled_artifact, false).await
        };

        if let Err(e) = tweak_result {
            warn!(
                "Failed to tweak bytecode for contract {address}: {e}. \
                 This contract will use opcode-level traces instead of source-level debugging."
            );
            // Continue with other contracts instead of failing the entire operation
        }
    }

    Ok(contracts_in_tx)
}
