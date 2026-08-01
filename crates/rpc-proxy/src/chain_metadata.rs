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

//! Built-in chain metadata used for RPC proxy defaults.

use edb_common::{
    MEZO_MAINNET_CHAIN_ID, MEZO_MAINNET_DEFAULT_RPC, MEZO_MAINNET_NATIVE_DECIMALS,
    MEZO_MAINNET_NATIVE_SYMBOL, MEZO_TESTNET_CHAIN_ID, MEZO_TESTNET_DEFAULT_RPC,
    MEZO_TESTNET_NATIVE_DECIMALS, MEZO_TESTNET_NATIVE_SYMBOL,
};

/// Ethereum mainnet chain id.
pub const ETHEREUM_MAINNET_CHAIN_ID: u64 = 1;

/// Default Ethereum mainnet RPC endpoints.
///
/// These are free public endpoints from chainlist.org, sorted by latency.
pub const DEFAULT_MAINNET_RPCS: &[&str] = &[
    "https://rpc.eth.gateway.fm",
    // "https://ethereum-rpc.publicnode.com", // disabled due to publicnode's temporary issues
    // "https://rpc.flashbots.net/fast", // disabled due to flashbots' temporary issues
    // "https://rpc.flashbots.net", // disabled due to flashbots' temporary issues
    "https://eth-mainnet.public.blastapi.io",
    "https://ethereum-mainnet.gateway.tatum.io",
    "https://eth.api.onfinality.io/public",
    "https://eth.llamarpc.com",
    "https://api.zan.top/eth-mainnet",
    "https://eth.drpc.org",
    "https://ethereum.rpc.subquery.network/public",
];

/// Default Mezo testnet RPC endpoints.
pub const DEFAULT_MEZO_TESTNET_RPCS: &[&str] = &[MEZO_TESTNET_DEFAULT_RPC];

/// Default Mezo mainnet RPC endpoints.
pub const DEFAULT_MEZO_MAINNET_RPCS: &[&str] = &[MEZO_MAINNET_DEFAULT_RPC];

/// Chain metadata needed to choose built-in RPC defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainMetadata {
    /// EIP-155 chain id.
    pub chain_id: u64,
    /// Stable CLI/docs label.
    pub slug: &'static str,
    /// Human-readable chain name.
    pub name: &'static str,
    /// Native token symbol used by the chain.
    pub native_token_symbol: &'static str,
    /// Native token decimals used by the chain.
    pub native_token_decimals: u8,
    /// Built-in public RPC endpoints for this chain.
    pub default_rpc_urls: &'static [&'static str],
}

/// Ethereum mainnet metadata.
pub const ETHEREUM_MAINNET: ChainMetadata = ChainMetadata {
    chain_id: ETHEREUM_MAINNET_CHAIN_ID,
    slug: "ethereum-mainnet",
    name: "Ethereum Mainnet",
    native_token_symbol: "ETH",
    native_token_decimals: 18,
    default_rpc_urls: DEFAULT_MAINNET_RPCS,
};

/// Mezo testnet metadata.
pub const MEZO_TESTNET: ChainMetadata = ChainMetadata {
    chain_id: MEZO_TESTNET_CHAIN_ID,
    slug: "mezo-testnet",
    name: "Mezo Testnet",
    native_token_symbol: MEZO_TESTNET_NATIVE_SYMBOL,
    native_token_decimals: MEZO_TESTNET_NATIVE_DECIMALS,
    default_rpc_urls: DEFAULT_MEZO_TESTNET_RPCS,
};

/// Mezo mainnet metadata.
pub const MEZO_MAINNET: ChainMetadata = ChainMetadata {
    chain_id: MEZO_MAINNET_CHAIN_ID,
    slug: "mezo",
    name: "Mezo",
    native_token_symbol: MEZO_MAINNET_NATIVE_SYMBOL,
    native_token_decimals: MEZO_MAINNET_NATIVE_DECIMALS,
    default_rpc_urls: DEFAULT_MEZO_MAINNET_RPCS,
};

/// Chains that have built-in RPC defaults.
pub const BUILT_IN_CHAINS: &[ChainMetadata] = &[ETHEREUM_MAINNET, MEZO_TESTNET, MEZO_MAINNET];

/// Returns built-in metadata for a chain id.
pub fn chain_metadata_by_id(chain_id: u64) -> Option<&'static ChainMetadata> {
    BUILT_IN_CHAINS.iter().find(|metadata| metadata.chain_id == chain_id)
}

/// Returns a comma-separated list of chain ids with built-in defaults.
pub fn supported_default_chain_ids() -> String {
    BUILT_IN_CHAINS
        .iter()
        .map(|metadata| metadata.chain_id.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mezo_testnet_metadata_is_registered() {
        let metadata = chain_metadata_by_id(MEZO_TESTNET_CHAIN_ID).unwrap();

        assert_eq!(metadata.slug, "mezo-testnet");
        assert_eq!(metadata.native_token_symbol, "BTC");
        assert_eq!(metadata.native_token_decimals, 18);
        assert_eq!(metadata.default_rpc_urls, DEFAULT_MEZO_TESTNET_RPCS);
    }

    #[test]
    fn mezo_mainnet_metadata_is_registered() {
        let metadata = chain_metadata_by_id(MEZO_MAINNET_CHAIN_ID).unwrap();

        assert_eq!(metadata.slug, "mezo");
        assert_eq!(metadata.native_token_symbol, "BTC");
        assert_eq!(metadata.native_token_decimals, 18);
        assert_eq!(metadata.default_rpc_urls, DEFAULT_MEZO_MAINNET_RPCS);
    }
}
