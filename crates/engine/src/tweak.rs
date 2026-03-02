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

//! Contract bytecode modification for debugging through creation transaction replay.
//!
//! This module provides the [`CodeTweaker`] utility for modifying deployed contract bytecode
//! by replaying their creation transactions with replacement init code. This enables debugging
//! with instrumented or modified contracts without requiring redeployment to the network.
//!
//! # Core Functionality
//!
//! ## Contract Bytecode Replacement
//! The [`CodeTweaker`] handles the complete process of:
//! 1. **Creation Transaction Discovery**: Finding the original deployment transaction
//! 2. **Transaction Replay**: Re-executing the creation with modified init code
//! 3. **Bytecode Extraction**: Capturing the resulting runtime bytecode
//! 4. **State Update**: Replacing the deployed bytecode in the debugging database
//!
//! ## Etherscan Integration
//! - **Creation Data Caching**: Local caching of contract creation transaction data
//! - **API Key Management**: Automatic API key rotation for rate limit handling
//! - **Chain Support**: Multi-chain support through configurable Etherscan endpoints
//!
//! # Workflow Integration
//!
//! The code tweaking process is typically used in the debugging workflow to:
//! 1. Replace original contracts with instrumented versions for hook-based debugging
//! 2. Substitute contracts with modified versions for testing different scenarios
//! 3. Enable debugging of contracts that weren't originally compiled with debug information
//!
//! # Usage Example
//!
//! ```rust,ignore
//! let mut tweaker = CodeTweaker::new(&mut edb_context, rpc_url, etherscan_api_key);
//! tweaker.tweak(&contract_address, &original_artifact, &instrumented_artifact, false).await?;
//! ```
//!
//! This replaces the deployed bytecode at `contract_address` with the instrumented version,
//! enabling advanced debugging features on the modified contract.

use std::{env, time::Instant};

use alloy_primitives::{Address, Bytes, TxHash};
use edb_common::{
    fork_and_prepare, relax_evm_constraints, Cache, CachePath, EdbCache, EdbCachePath, EdbContext,
    ForkResult,
};
use eyre::{eyre, Result};
use foundry_block_explorers::{contract::ContractCreationData, Client};
use foundry_compilers::{artifacts::Contract, Artifact as _};
use revm::{
    context::{Cfg, ContextTr},
    database::CacheDB,
    primitives::KECCAK_EMPTY,
    state::Bytecode,
    Database, DatabaseCommit, DatabaseRef, InspectEvm, MainBuilder,
};
use tracing::{debug, error, info};

use crate::{next_etherscan_api_key, Artifact, TweakInspector};

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

/// Utility for modifying deployed contract bytecode through creation transaction replay.
///
/// The [`CodeTweaker`] enables replacing deployed contract bytecode by:
/// 1. Finding the original contract creation transaction
/// 2. Replaying that transaction with modified init code from recompiled artifacts
/// 3. Extracting the resulting runtime bytecode
/// 4. Updating the contract's bytecode in the debugging database
///
/// This allows debugging with instrumented contracts without requiring network redeployment.
pub struct CodeTweaker<'a, DB>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone,
    <CacheDB<DB> as Database>::Error: Clone,
    <DB as Database>::Error: Clone,
{
    ctx: &'a mut EdbContext<DB>,
    rpc_url: String,
    etherscan_api_key: Option<String>,
}

impl<'a, DB> CodeTweaker<'a, DB>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone,
    <CacheDB<DB> as Database>::Error: Clone,
    <DB as Database>::Error: Clone,
{
    const MIN_RUNTIME_PREFIX_RATIO: f64 = 0.45;
    const MIN_RUNTIME_PREFIX_BYTES: usize = 64;

    /// Creates a new `CodeTweaker` instance.
    ///
    /// # Arguments
    ///
    /// * `ctx` - Mutable reference to the EDB context containing the database
    /// * `rpc_url` - RPC endpoint URL for fetching blockchain data
    /// * `etherscan_api_key` - Optional Etherscan API key for fetching contract creation data
    pub fn new(
        ctx: &'a mut EdbContext<DB>,
        rpc_url: String,
        etherscan_api_key: Option<String>,
    ) -> Self {
        Self { ctx, rpc_url, etherscan_api_key }
    }

    /// Replaces deployed contract bytecode with instrumented bytecode from artifacts.
    ///
    /// This method performs the complete bytecode replacement workflow:
    /// 1. Finds the contract creation transaction using Etherscan API
    /// 2. Replays the transaction with the recompiled artifact's init code
    /// 3. Extracts the resulting runtime bytecode
    /// 4. Updates the contract's bytecode in the debugging database
    ///
    /// # Arguments
    ///
    /// * `addr` - Address of the deployed contract to modify
    /// * `artifact` - Original compiled artifact for constructor argument extraction
    /// * `recompiled_artifact` - Recompiled artifact containing the replacement init code
    /// * `quick` - Whether to use quick mode (faster but potentially less accurate)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the bytecode replacement succeeds, or an error if any step fails.
    pub async fn tweak(
        &mut self,
        addr: &Address,
        artifact: &Artifact,
        recompiled_artifact: &Artifact,
        quick: bool,
    ) -> Result<()> {
        let tweak_start = Instant::now();
        let tweaked_code =
            self.get_tweaked_code(addr, artifact, recompiled_artifact, quick).await?;
        info!(
            "[TIMING] Contract {} get_tweaked_code: {:.2}s",
            addr,
            tweak_start.elapsed().as_secs_f64()
        );

        if tweaked_code.is_empty() {
            error!(addr=?addr, quick=?quick, "Tweaked code is empty");
            return Err(eyre!("tweaked bytecode is empty (addr={}, quick={})", addr, quick));
        }

        let db = self.ctx.db_mut();

        let mut info = db
            .basic(*addr)
            .map_err(|e| eyre::eyre!("Failed to get account info for {}: {}", addr, e))?
            .unwrap_or_default();
        // Code hash will be update within `db.insert_account_info(&mut info);`
        info.code_hash = KECCAK_EMPTY;
        info.code = Some(Bytecode::new_raw(tweaked_code));
        db.insert_account_info(*addr, info);

        Ok(())
    }

    /// Generate the tweaked runtime bytecode by replaying the creation transaction.
    ///
    /// This internal method handles the complex process of:
    /// 1. Forking the blockchain state at the creation transaction
    /// 2. Setting up the replay environment with modified constraints
    /// 3. Using the TweakInspector to intercept and modify the deployment
    /// 4. Extracting the resulting runtime bytecode
    async fn get_tweaked_code(
        &mut self,
        addr: &Address,
        artifact: &Artifact,
        recompiled_artifact: &Artifact,
        quick: bool,
    ) -> Result<Bytes> {
        let creation_tx_start = Instant::now();
        let creation_tx_hash = self.get_creation_tx(addr).await?;
        info!(
            "[TIMING] Contract {} get_creation_tx: {:.2}s",
            addr,
            creation_tx_start.elapsed().as_secs_f64()
        );
        debug!("Creation tx: {} -> {}", creation_tx_hash, addr);

        // Create replay environment
        let fork_start = Instant::now();
        let ForkResult { context: mut replay_ctx, target_tx_env: mut creation_tx_env, .. } =
            fork_and_prepare(&self.rpc_url, creation_tx_hash, quick).await?;
        info!(
            "[TIMING] Contract {} fork_and_prepare (creation tx): {:.2}s",
            addr,
            fork_start.elapsed().as_secs_f64()
        );
        relax_evm_constraints(&mut replay_ctx, &mut creation_tx_env);

        // Select the best-matching contract pair for this address.
        // Artifacts can include multiple contracts per file; selecting by largest init bytecode
        // alone can pick the wrong contract and cause hook replay divergence.
        let runtime_bytecode = self.get_runtime_bytecode(addr);
        let runtime_for_match = runtime_bytecode.as_deref();
        let runtime_len = runtime_for_match.map(|bytes| bytes.len());
        let preferred_name = artifact.contract_name();

        #[derive(Clone)]
        struct OriginalCandidate<'b> {
            original: &'b Contract,
            path: &'b std::path::Path,
            file_path: String,
            contract_name: String,
            original_creation_len: usize,
            deployed_len: usize,
            runtime_prefix_len: usize,
            preferred_name: bool,
        }

        // Recompiled artifacts can normalize source paths differently from originals.
        // Resolve by exact path+name first, then fallback to best same-name contract.
        let resolve_recompiled_contract =
            |path: &std::path::Path, name: &str| -> Option<&Contract> {
                if let Some(contract) =
                    recompiled_artifact.output.contracts.get(path).and_then(|c| c.get(name))
                {
                    return Some(contract);
                }

                let mut best: Option<&Contract> = None;
                let mut best_creation_len = 0usize;
                for contracts in recompiled_artifact.output.contracts.values() {
                    let Some(contract) = contracts.get(name) else { continue };
                    let creation_len =
                        contract.get_bytecode_bytes().map(|bytes| bytes.len()).unwrap_or(0);
                    if best.is_none() || creation_len > best_creation_len {
                        best = Some(contract);
                        best_creation_len = creation_len;
                    }
                }
                best
            };

        let mut candidates: Vec<OriginalCandidate<'_>> = Vec::new();
        for (path, contracts) in &artifact.output.contracts {
            for (name, original_contract) in contracts {
                let original_creation_len =
                    original_contract.get_bytecode_bytes().map(|bytes| bytes.len()).unwrap_or(0);

                let deployed_len = original_contract
                    .evm
                    .as_ref()
                    .and_then(|evm| evm.deployed_bytecode.as_ref())
                    .and_then(|deployed| deployed.bytes())
                    .map(|bytes| bytes.len())
                    .unwrap_or(0);
                let runtime_prefix_len = if let Some(runtime) = runtime_for_match {
                    original_contract
                        .evm
                        .as_ref()
                        .and_then(|evm| evm.deployed_bytecode.as_ref())
                        .and_then(|deployed| deployed.bytes())
                        .map(|deployed| Self::common_prefix_len(runtime, deployed.as_ref()))
                        .unwrap_or(0)
                } else {
                    0
                };
                if runtime_for_match.is_some() && deployed_len == 0 {
                    continue;
                }

                candidates.push(OriginalCandidate {
                    original: original_contract,
                    path,
                    file_path: path.display().to_string(),
                    contract_name: name.clone(),
                    original_creation_len,
                    deployed_len,
                    runtime_prefix_len,
                    preferred_name: !preferred_name.is_empty() && name == preferred_name,
                });
            }
        }

        let mut selected = candidates
            .iter()
            .max_by(|a, b| {
                // Runtime-first tie-breaker for multi-contract artifacts.
                b.runtime_prefix_len
                    .cmp(&a.runtime_prefix_len)
                    .then_with(|| b.preferred_name.cmp(&a.preferred_name))
                    .then_with(|| b.deployed_len.cmp(&a.deployed_len))
                    .then_with(|| b.original_creation_len.cmp(&a.original_creation_len))
            })
            .cloned()
            .ok_or_else(|| {
                let available_original_names: Vec<String> = artifact
                    .output
                    .contracts
                    .values()
                    .flat_map(|contracts| contracts.keys().cloned())
                    .collect();
                eyre!(
                    "no eligible original contract candidates for {} (preferred='{}', available={:?})",
                    addr,
                    preferred_name,
                    available_original_names
                )
            })?;

        // If runtime matching is weak/absent, prefer explicit metadata contract-name match.
        if let Some(runtime_len) = runtime_len {
            let compare_len = runtime_len.min(selected.deployed_len);
            let runtime_confident =
                Self::is_runtime_match_confident(selected.runtime_prefix_len, compare_len);
            if !runtime_confident && !selected.preferred_name {
                if let Some(preferred) = candidates
                    .iter()
                    .filter(|candidate| candidate.preferred_name)
                    .max_by(|a, b| {
                        b.runtime_prefix_len
                            .cmp(&a.runtime_prefix_len)
                            .then_with(|| b.deployed_len.cmp(&a.deployed_len))
                            .then_with(|| b.original_creation_len.cmp(&a.original_creation_len))
                    })
                    .cloned()
                {
                    selected = preferred;
                }
            }
        } else if !selected.preferred_name && !preferred_name.is_empty() {
            if let Some(preferred) = candidates
                .iter()
                .filter(|candidate| candidate.preferred_name)
                .max_by(|a, b| {
                    b.original_creation_len
                        .cmp(&a.original_creation_len)
                        .then_with(|| b.deployed_len.cmp(&a.deployed_len))
                })
                .cloned()
            {
                selected = preferred;
            }
        }

        if runtime_for_match.is_some() && selected.runtime_prefix_len == 0 {
            return Err(eyre!(
                "no runtime-compatible creation-hook contract for {} (preferred='{}', selected='{}', file='{}')",
                addr,
                preferred_name,
                selected.contract_name,
                selected.file_path
            ));
        }

        let recompiled_contract = resolve_recompiled_contract(selected.path, &selected.contract_name)
            .ok_or_else(|| {
                let available_recompiled_names: Vec<String> = recompiled_artifact
                    .output
                    .contracts
                    .values()
                    .flat_map(|contracts| contracts.keys().cloned())
                    .collect();
                eyre!(
                    "no recompiled contract found for selected original {}:{} (available recompiled contracts={:?})",
                    selected.file_path,
                    selected.contract_name,
                    available_recompiled_names
                )
            })?;
        let recompiled_creation_len =
            recompiled_contract.get_bytecode_bytes().map(|bytes| bytes.len()).unwrap_or(0);
        if recompiled_creation_len == 0 {
            return Err(eyre!(
                "selected recompiled contract {}:{} has empty creation bytecode",
                selected.file_path,
                selected.contract_name
            ));
        }

        info!(
            target_address = %addr,
            selected_contract = %selected.contract_name,
            selected_file = %selected.file_path,
            selected_original_creation_len = selected.original_creation_len,
            selected_recompiled_creation_len = recompiled_creation_len,
            selected_deployed_len = selected.deployed_len,
            selected_runtime_prefix_len = selected.runtime_prefix_len,
            runtime_len = ?runtime_len,
            preferred_contract_name = preferred_name,
            selected_preferred_name = selected.preferred_name,
            "Selected creation-hook contract pair"
        );

        let contract = selected.original;

        let constructor_args = recompiled_artifact.constructor_arguments();

        let mut inspector =
            TweakInspector::new(*addr, contract, recompiled_contract, constructor_args);

        let mut evm = replay_ctx.build_mainnet_with_inspector(&mut inspector);

        let inspect_start = Instant::now();
        evm.inspect_one_tx(creation_tx_env)
            .map_err(|e| eyre::eyre!("Failed to inspect the target transaction: {:?}", e))?;
        info!(
            "[TIMING] Contract {} inspect_one_tx (creation replay): {:.2}s",
            addr,
            inspect_start.elapsed().as_secs_f64()
        );

        inspector.into_deployed_code()
    }

    fn get_runtime_bytecode(&mut self, addr: &Address) -> Option<Vec<u8>> {
        let db = self.ctx.db_mut();
        let account = db.basic(*addr).ok().flatten()?;
        if let Some(code) = account.code {
            let bytes = code.original_bytes();
            if !bytes.is_empty() {
                return Some(bytes.to_vec());
            }
        }
        if account.code_hash == KECCAK_EMPTY {
            return None;
        }
        db.code_by_hash(account.code_hash)
            .ok()
            .map(|bytecode| bytecode.original_bytes().to_vec())
            .filter(|bytes| !bytes.is_empty())
    }

    #[inline]
    fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
        a.iter().zip(b.iter()).take_while(|(lhs, rhs)| lhs == rhs).count()
    }

    #[inline]
    fn is_runtime_match_confident(prefix_len: usize, compare_len: usize) -> bool {
        if compare_len == 0 {
            return false;
        }
        let required_prefix = Self::MIN_RUNTIME_PREFIX_BYTES.min(compare_len);
        if prefix_len < required_prefix {
            return false;
        }
        (prefix_len as f64 / compare_len as f64) >= Self::MIN_RUNTIME_PREFIX_RATIO
    }

    /// Retrieves the transaction hash that created a contract at the given address.
    ///
    /// This method first checks the local cache for the creation transaction data.
    /// If not cached, it queries Etherscan API and caches the result for future use.
    /// Note that Etherscan Client will NOT cache the result itself.
    ///
    /// # Arguments
    ///
    /// * `addr` - Address of the deployed contract
    ///
    /// # Returns
    ///
    /// Returns the transaction hash that deployed the contract, or an error if not found.
    pub async fn get_creation_tx(&self, addr: &Address) -> Result<TxHash> {
        let chain_id = self.ctx.cfg().chain_id();

        // Cache directory
        let etherscan_cache_dir = EdbCachePath::new(env::var(edb_common::env::EDB_CACHE_DIR).ok())
            .etherscan_chain_cache_dir(chain_id)
            .map(|p| p.join("contract_creation_txs"));

        let cache = EdbCache::<ContractCreationData>::new(etherscan_cache_dir, None)?;
        let label = addr.to_string();

        if let Some(creation_data) = cache.load_cache(&label) {
            Ok(creation_data.transaction_hash)
        } else {
            let etherscan_api_key =
                self.etherscan_api_key.clone().unwrap_or(next_etherscan_api_key());

            // Use chain-native Etherscan-compatible API (e.g., api.basescan.org for Base)
            // instead of V2 unified API which requires Pro-tier API key for multi-chain.
            // The alloy-chains library incorrectly maps some chains (Base, Fraxtal, etc.)
            // to the V2 API, so we need to override those here.
            let mut builder =
                Client::builder().with_api_key(etherscan_api_key).chain(chain_id.into())?;

            // Override API URL for chains that have migrated to Etherscan V2 unified API
            // (chain-native APIs like api.basescan.org are deprecated and no longer work)
            if let Some(v2_url) = get_etherscan_v2_api_url(chain_id) {
                builder = builder.with_api_url(v2_url)?;
            }

            let etherscan = builder.build()?;

            // Get creation tx
            let creation_data = etherscan.contract_creation_data(*addr).await?;
            cache.save_cache(&label, &creation_data)?;
            Ok(creation_data.transaction_hash)
        }
    }
}
