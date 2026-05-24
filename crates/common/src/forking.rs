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

//! Chain forking and transaction replay utilities
//!
//! This module provides ACTUAL REVM TRANSACTION EXECUTION with transact_commit()

use crate::{
    get_blob_base_fee_update_fraction_by_spec_id, get_mainnet_spec_id,
    infer_spec_from_block_header, EdbContext, EdbDB, MezoPrecompileMockInspector,
};
use alloy_network::{AnyNetwork, AnyRpcTransaction, TransactionResponse};
use alloy_primitives::{address, Address, TxHash, B256, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::{BlockNumberOrTag, TransactionTrait};
use eyre::Result;
use indicatif::ProgressBar;
use revm::{
    context::{ContextTr, TxEnv},
    context_interface::block::BlobExcessGasAndPrice,
    database::{AlloyDB, CacheDB},
    Context, Database, DatabaseCommit, DatabaseRef, ExecuteEvm, InspectCommitEvm, MainBuilder,
    MainContext,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use revm::{
    // Use re-exported primitives from revm
    context::result::ExecutionResult,
    database_interface::WrapDatabaseAsync,
    primitives::hardfork::SpecId,
};

/// Arbitrum L1 sender address of the first transaction in every block.
/// `0x00000000000000000000000000000000000a4b05`
pub const ARBITRUM_SENDER: Address = address!("0x00000000000000000000000000000000000a4b05");

/// The system address, the sender of the first transaction in every block:
/// `0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001`
///
/// See also <https://github.com/ethereum-optimism/optimism/blob/65ec61dde94ffa93342728d324fecf474d228e1f/specs/deposits.md#l1-attributes-deposited-transaction>
pub const OPTIMISM_SYSTEM_ADDRESS: Address = address!("0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001");

/// Fork configuration details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkInfo {
    /// Block number that was forked
    pub block_number: u64,
    /// Block hash
    pub block_hash: B256,
    /// Timestamp of the block
    pub timestamp: u64,
    /// Chain ID
    pub chain_id: u64,
    /// Spec ID for the hardfork
    pub spec_id: SpecId,
}

/// Result of forking operation containing comprehensive replay information
pub struct ForkResult<DB>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone + Send + Sync + 'static,
    <CacheDB<DB> as Database>::Error: Clone + Send + Sync,
    <DB as Database>::Error: Clone + Send + Sync,
{
    /// Fork information
    pub fork_info: ForkInfo,
    /// Revm context with executed state
    pub context: EdbContext<DB>,
    /// Transaction environment for the target transaction
    pub target_tx_env: TxEnv,
    /// Target transaction hash
    pub target_tx_hash: TxHash,
}

/// Get chain id by querying RPC
pub async fn get_chain_id(rpc_url: &str) -> Result<u64> {
    let provider = ProviderBuilder::new_with_network::<AnyNetwork>().connect(rpc_url).await?;
    let chain_id = provider.get_chain_id().await?;
    Ok(chain_id)
}

/// Fork the chain and ACTUALLY EXECUTE preceding transactions with revm.transact_commit()
///
/// This function:
/// 1. Creates revm database and environment
/// 2. Actually executes each preceding transaction with revm (unless quick mode is enabled)
/// 3. Commits each transaction
/// 4. Returns forked state ready for target transaction
pub async fn fork_and_prepare(
    rpc_url: &str,
    target_tx_hash: TxHash,
    quick: bool,
) -> Result<
    ForkResult<EdbDB<impl Clone + Database + DatabaseCommit + DatabaseRef + Send + Sync + 'static>>,
> {
    info!("forking chain and executing transactions with revm for {:?}", target_tx_hash);

    let provider = ProviderBuilder::new_with_network::<AnyNetwork>().connect(rpc_url).await?;

    let chain_id = provider
        .get_chain_id()
        .await
        .map_err(|e| eyre::eyre!("Failed to get chain ID: {:?}", e))?;

    // Get the target transaction to find which block it's in
    let target_tx = provider
        .get_transaction_by_hash(target_tx_hash)
        .await?
        .ok_or_else(|| eyre::eyre!("Target transaction not found: {:?}", target_tx_hash))?;

    // check if the tx is a system transaction
    if is_known_system_sender(target_tx.from()) {
        return Err(eyre::eyre!(
            "{:?} is a system transaction.\nReplaying system transactions is currently not supported.",
            target_tx.tx_hash()
        ));
    }

    let target_block_number = target_tx
        .block_number
        .ok_or_else(|| eyre::eyre!("Target transaction not mined: {:?}", target_tx_hash))?;

    info!("Target transaction is in block {}", target_block_number);

    // Get the full block with transactions - with fallback for L2 chains
    let (block, full_tx_available) = match provider
        .get_block_by_number(BlockNumberOrTag::Number(target_block_number))
        .full()
        .await
    {
        Ok(Some(block)) => (block, true),
        Ok(None) => {
            return Err(eyre::eyre!("Block {} not found", target_block_number));
        }
        Err(full_error) => {
            // L2 chains may have special transaction types (e.g., type 0x7e deposits on Base/OP)
            // that can't be deserialized. Fall back to header-only fetch.
            let raw_error_text = full_error.to_string();
            let mut error_text = raw_error_text
                .lines()
                .next()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .unwrap_or("unknown full block fetch error")
                .to_string();
            const MAX_FORK_ERROR_LOG_CHARS: usize = 240;
            if error_text.len() > MAX_FORK_ERROR_LOG_CHARS {
                error_text.truncate(MAX_FORK_ERROR_LOG_CHARS);
                error_text.push_str("...");
            }
            warn!(
                "Failed to fetch block with full transactions: {error_text}. \
                 Falling back to header-only fetch (quick mode will be forced)."
            );
            let fallback_block = provider
                .get_block_by_number(BlockNumberOrTag::Number(target_block_number))
                .await
                .map_err(|e| eyre::eyre!("Failed to fetch block (fallback): {e}"))?
                .ok_or_else(|| eyre::eyre!("Block {} not found (fallback)", target_block_number))?;
            (fallback_block, false)
        }
    };

    // Get the transactions in the block (may be empty if full_tx_available is false)
    let transactions = block.transactions.as_transactions().unwrap_or_default();

    // If we couldn't get full transactions, force quick mode
    let quick = if !full_tx_available && !quick {
        warn!("Forcing quick mode because full transactions are not available");
        true
    } else {
        quick
    };

    // Find target transaction index and get preceding transactions
    // If full_tx_available is false, we skip this (no preceding txs to replay in quick mode)
    let preceding_txs: Vec<&AnyRpcTransaction> = if full_tx_available {
        let target_index = transactions
            .iter()
            .position(|tx| tx.tx_hash() == target_tx_hash)
            .ok_or_else(|| eyre::eyre!("Target transaction not found in block"))?;
        transactions.iter().take(target_index).collect()
    } else {
        // In fallback mode, we can't determine preceding transactions
        Vec::new()
    };

    // Get the spec ID — use mainnet block-number mapping for chain 1,
    // infer from block header features for all other chains (testnets, L2s, etc.)
    let spec_id = if chain_id == 1 {
        get_mainnet_spec_id(target_block_number)
    } else {
        infer_spec_from_block_header(
            block.header.base_fee_per_gas,
            block.header.excess_blob_gas,
            block.header.difficulty,
            block.header.withdrawals_root,
            block.header.requests_hash,
        )
    };
    info!("Block {} is under {:?} hardfork", target_block_number, spec_id);
    let evm_version_label =
        if chain_id == 1 { "mainnet block-number mapping" } else { "block header inference" };
    info!("The evm verision is {:?} (detected via {})", spec_id, evm_version_label);

    // Create fork info
    let fork_info = ForkInfo {
        block_number: target_block_number,
        block_hash: block.header.hash,
        timestamp: block.header.timestamp,
        chain_id,
        spec_id,
    };

    // Create revm database: we start with AlloyDB.
    let alloy_db = AlloyDB::new(provider, (target_block_number - 1).into());

    // Try to use the current runtime handle for WrapDatabaseAsync
    // If we're in a LocalSet or CurrentThread runtime, this will return None
    // In that case, we cannot use WrapDatabaseAsync and must fail gracefully
    let state_db = match WrapDatabaseAsync::new(alloy_db) {
        Some(db) => db,
        None => {
            return Err(eyre::eyre!(
                "Cannot create WrapDatabaseAsync: current runtime context doesn't support it. \
                 This can happen if running inside a LocalSet or single-threaded runtime. \
                 fork_and_prepare must be called from a multi-threaded Tokio runtime context."
            ));
        }
    };

    let debug_db = EdbDB::new(CacheDB::new(Arc::new(state_db)));
    let cache_db: CacheDB<_> = CacheDB::new(debug_db);

    let ctx = Context::mainnet()
        .with_db(cache_db)
        .modify_block_chained(|b| {
            b.number = U256::from(target_block_number);
            b.timestamp = U256::from(block.header.timestamp);
            b.basefee = block.header.base_fee_per_gas.unwrap_or_default();
            b.difficulty = block.header.difficulty;
            b.gas_limit = block.header.gas_limit;
            b.prevrandao = block.header.mix_hash;
            // REVM requires blob_excess_gas_and_price for Cancun+ specs
            // Default to 0 if RPC doesn't return excess_blob_gas (some providers omit it)
            b.blob_excess_gas_and_price = if spec_id >= SpecId::CANCUN {
                Some(BlobExcessGasAndPrice::new(
                    block.header.excess_blob_gas.unwrap_or(0),
                    get_blob_base_fee_update_fraction_by_spec_id(spec_id),
                ))
            } else {
                block.header.excess_blob_gas.map(|g| {
                    BlobExcessGasAndPrice::new(
                        g,
                        get_blob_base_fee_update_fraction_by_spec_id(spec_id),
                    )
                })
            };
            b.beneficiary = block.header.beneficiary;
        })
        .modify_cfg_chained(|c| {
            c.chain_id = chain_id;
            c.spec = spec_id;
            c.disable_nonce_check = quick; // Disable nonce check in quick mode
        });

    let mut mezo_precompile_inspector = MezoPrecompileMockInspector::default();
    let mut evm = ctx.build_mainnet_with_inspector(&mut mezo_precompile_inspector);
    info!("The evm verision is {}", evm.cfg().spec);

    // Skip replaying preceding transactions if quick mode is enabled
    if quick {
        info!(
            "Quick mode enabled - skipping replay of {} preceding transactions",
            preceding_txs.len()
        );
    } else {
        debug!("Executing {} preceding transactions", preceding_txs.len());

        // Actually execute each transaction with revm
        let console_bar = Arc::new(ProgressBar::new(preceding_txs.len() as u64));
        let template = format!("{{spinner:.green}} 🔮 Replaying blockchain history for {} [{{bar:40.cyan/blue}}] {{pos:>3}}/{{len:3}} ⛽ {{msg}}", &target_tx_hash.to_string()[2..10]);
        console_bar.set_style(
            indicatif::ProgressStyle::with_template(&template)?
                .progress_chars("🟩🟦⬜")
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
        );

        for (i, tx) in preceding_txs.iter().enumerate() {
            // System transactions such as on L2s don't contain any pricing info so
            // we skip them otherwise this would cause
            // reverts
            if is_known_system_sender(tx.from()) {
                console_bar.inc(1);
                continue;
            }

            let tx_hash = tx.tx_hash();
            let short_hash = &tx_hash.to_string()[2..10]; // Skip 0x, take 8 chars
            console_bar.set_message(format!("tx {}: 0x{}...", i + 1, short_hash));

            debug!("Executing transaction {}/{}: {:?}", i + 1, preceding_txs.len(), tx_hash);

            let tx_env = get_tx_env_from_tx(tx, chain_id)?;

            // Actually execute the transaction with commit
            match evm.inspect_tx_commit(tx_env.clone()) {
                Ok(result) => match result {
                    ExecutionResult::Success { gas_used, .. } => {
                        console_bar.set_message(format!("✅ 0x{short_hash}... gas: {gas_used}"));
                        debug!(
                            "Transaction {} executed and committed successfully, gas used: {}",
                            i + 1,
                            gas_used
                        );
                    }
                    ExecutionResult::Revert { gas_used, output } => {
                        console_bar.set_message(format!("⚠️  0x{short_hash}... reverted"));
                        debug!(
                            "Transaction {} reverted but committed, gas used: {}, output: {:?}",
                            i + 1,
                            gas_used,
                            output
                        );
                    }
                    ExecutionResult::Halt { reason, gas_used } => {
                        console_bar.set_message(format!("❌ 0x{short_hash}... halted"));
                        debug!(
                            "Transaction {} halted, gas used: {}, reason: {:?}",
                            i + 1,
                            gas_used,
                            reason
                        );
                    }
                },
                Err(e) => {
                    error!("Failed to execute transaction {}: {:?}", i + 1, e);
                    return Err(eyre::eyre!(
                        "Transaction execution failed at index {} ({}): {:?}",
                        i,
                        tx_hash,
                        e
                    ));
                }
            }

            console_bar.inc(1);
        }

        console_bar.finish_with_message(format!(
            "✨ Ready! Replayed {} transactions before {}",
            preceding_txs.len(),
            &target_tx_hash.to_string()[2..10]
        ));
    }

    // Get the target transaction environment
    let target_tx_env = get_tx_env_from_tx(&target_tx, chain_id)?;

    // Extract the context from the EVM
    evm.finalize();
    let context = evm.ctx;

    Ok(ForkResult { fork_info, context, target_tx_env, target_tx_hash })
}

/// Get the transaction environment from the transaction.
pub fn get_tx_env_from_tx(tx: &AnyRpcTransaction, chain_id: u64) -> Result<TxEnv> {
    let mut b = TxEnv::builder()
        .caller(tx.from())
        .gas_limit(tx.gas_limit())
        .gas_price(TransactionTrait::gas_price(tx).unwrap_or(TransactionTrait::max_fee_per_gas(tx)))
        .value(tx.value())
        .data(tx.input().to_owned())
        .gas_priority_fee(tx.max_priority_fee_per_gas())
        .chain_id(Some(chain_id))
        .nonce(tx.nonce())
        .access_list(tx.access_list().cloned().unwrap_or_default())
        .kind(tx.kind());

    // Fees
    if let Some(gp) = TransactionTrait::gas_price(tx) {
        b = b.gas_price(gp);
    } else {
        b = b
            .gas_price(TransactionTrait::max_fee_per_gas(tx))
            .gas_priority_fee(tx.max_priority_fee_per_gas());
    }

    // EIP-4844
    if let Some(mfb) = tx.max_fee_per_blob_gas() {
        b = b.max_fee_per_blob_gas(mfb);
    }
    if let Some(hashes) = tx.blob_versioned_hashes() {
        b = b.blob_hashes(hashes.to_vec());
    }

    // EIP-7702 (post-Pectra)
    if let Some(authz) = tx.authorization_list() {
        b = b.authorization_list_signed(authz.to_vec());
    }

    b.build().map_err(|e| eyre::eyre!("TxEnv build failed: {:?}", e))
}

fn is_known_system_sender(sender: Address) -> bool {
    [ARBITRUM_SENDER, OPTIMISM_SYSTEM_ADDRESS, Address::ZERO].contains(&sender)
}
