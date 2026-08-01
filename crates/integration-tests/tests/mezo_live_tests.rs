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

//! Env-gated live Mezo testnet fork/replay smoke tests.

use alloy_primitives::TxHash;
use edb_common::{fork_and_prepare, types::RenderedTrace};
use edb_engine::{Engine, EngineConfig};
use edb_integration_tests::{rpc_test_utils::RpcTestClient, test_utils::init};
use eyre::Result;
use serde_json::json;

const MEZO_LIVE_TEST_ENV: &str = "EDB_MEZO_LIVE_TEST";
const MEZO_TESTNET_CHAIN_ID: u64 = 31_611;
const MEZO_RPC_URL: &str = "https://rpc.test.mezo.org";

// Stable smoke transaction found through Blockscout and verified through
// eth_getTransactionByHash/eth_getTransactionReceipt on 2026-05-23.
//
// The missing parent-repo scripts/mezo-day-0-artifacts.md meant there was no
// canonical saved smoke hash to reuse. This one is a successful Day-0-style
// BorrowerOperations.openTrove(uint256,address,address) call:
// - tx: 0xe838ed1eedc762c9b338b45ad96664c18ef9dd90d018e6250791cdcb3004fb5e
// - block: 13221805 (0xc9bfad), timestamp 2026-05-23T05:08:57Z
// - to: BorrowerOperations 0xCdF7028ceAB81fA0C6971208e83fa7872994beE5
// - receipt: status 0x1, gasUsed 0x91863, 15 logs
// - block contained only this transaction, so full replay has no preceding
//   in-block transactions to execute.
const MEZO_OPEN_TROVE_TX: &str =
    "0xe838ed1eedc762c9b338b45ad96664c18ef9dd90d018e6250791cdcb3004fb5e";
const MEZO_OPEN_TROVE_BLOCK: u64 = 13_221_805;

fn mezo_live_enabled() -> bool {
    matches!(std::env::var(MEZO_LIVE_TEST_ENV).as_deref(), Ok("1"))
}

fn print_rendered_source_summary(label: &str, tx_hash: TxHash, rendered: &RenderedTrace) {
    let source_rows = rendered.rows.iter().filter(|row| row.source_file.is_some()).count();
    eprintln!(
        "{label}: tx={tx_hash:?} rows={} source_rows={} source_files={}",
        rendered.rows.len(),
        source_rows,
        rendered.source_texts.len()
    );

    for row in rendered.rows.iter().filter(|row| row.source_file.is_some()).take(12) {
        eprintln!(
            "{label}: source frame id={} contract={} fn={} pc={} op={} at {}:{}",
            row.id,
            row.contract.as_deref().unwrap_or("<unknown>"),
            row.function_name.as_deref().unwrap_or("<unknown>"),
            row.pc,
            row.name,
            row.source_file.as_deref().unwrap_or("<unknown>"),
            row.line.unwrap_or_default()
        );
    }
}

async fn render_mezo_open_trove(
    config: EngineConfig,
) -> Result<(Engine, TxHash, RenderedTrace, RpcTestClient)> {
    init::init_test_environment(true);

    let tx_hash: TxHash = MEZO_OPEN_TROVE_TX.parse()?;
    let fork_result = fork_and_prepare(MEZO_RPC_URL, tx_hash, false).await?;

    assert_eq!(fork_result.fork_info.chain_id, MEZO_TESTNET_CHAIN_ID);
    assert_eq!(fork_result.fork_info.block_number, MEZO_OPEN_TROVE_BLOCK);

    let engine = Engine::new(config);
    let rpc_addr = engine.prepare(fork_result, None, None).await?;
    let rpc_url = format!("http://{rpc_addr}");

    let client = RpcTestClient::new(&rpc_url);
    let rendered: RenderedTrace =
        serde_json::from_value(client.call_raw("edb_getRenderedTrace", None).await?)?;

    Ok((engine, tx_hash, rendered, client))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mezo_open_trove_live_trace_renders_when_enabled() -> Result<()> {
    if !mezo_live_enabled() {
        eprintln!(
            "skipping Mezo live fork/replay; set {MEZO_LIVE_TEST_ENV}=1 to use {MEZO_RPC_URL}"
        );
        return Ok(());
    }

    // Keep this smoke scoped to Mezo fork/replay/render behavior. Source
    // retrieval and hook instrumentation depend on explorer/tooling paths and
    // should not make this live RPC scaffold harder to run.
    let config = EngineConfig::default()
        .with_rpc_proxy_url(MEZO_RPC_URL.to_string())
        .with_quick_mode(false)
        .with_events_only(true)
        .with_collect_hook_snapshots(false)
        .with_precompute_state_variables(false)
        .with_significant_opcode_snapshots_only(true);
    let (engine, tx_hash, rendered, _client) = render_mezo_open_trove(config).await?;
    print_rendered_source_summary("mezo-smoke", tx_hash, &rendered);

    assert_eq!(rendered.schema_version, 3);
    assert!(!rendered.rows.is_empty(), "Mezo rendered trace should contain rows");
    assert!(
        !rendered.raw_events.is_empty(),
        "Mezo openTrove smoke transaction should render emitted events"
    );

    engine.shutdown_rpc_server(&tx_hash)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mezo_open_trove_live_debugger_renders_when_enabled() -> Result<()> {
    if !mezo_live_enabled() {
        eprintln!(
            "skipping Mezo live debugger render; set {MEZO_LIVE_TEST_ENV}=1 to use {MEZO_RPC_URL}"
        );
        return Ok(());
    }

    std::env::set_var("EDB_DEBUG_MAX_SOURCE_CONTRACTS", "24");

    let config = EngineConfig::default()
        .with_rpc_proxy_url(MEZO_RPC_URL.to_string())
        .with_quick_mode(false)
        .with_events_only(false)
        .with_collect_hook_snapshots(true)
        .with_precompute_state_variables(true)
        .with_significant_opcode_snapshots_only(true)
        .with_artifact_source_priority(vec!["blockscout".to_string()]);
    let (engine, tx_hash, rendered, client) = render_mezo_open_trove(config).await?;
    print_rendered_source_summary("mezo-debugger", tx_hash, &rendered);

    assert_eq!(rendered.schema_version, 3);
    assert!(!rendered.rows.is_empty(), "Mezo rendered trace should contain rows");

    let source_rows = rendered.rows.iter().filter(|row| row.source_file.is_some()).count();
    assert!(source_rows > 0, "Mezo debugger render should contain source-anchored rows");
    assert!(
        rendered.source_texts.keys().any(|path| path.ends_with("MUSD.sol")),
        "Mezo debugger render should include MUSD.sol source text"
    );
    assert!(
        rendered
            .rows
            .iter()
            .any(|row| row.source_file.as_deref().is_some_and(|path| path.ends_with("MUSD.sol"))),
        "Mezo debugger render should include source frames anchored to MUSD.sol"
    );

    let snapshot_count: usize =
        serde_json::from_value(client.call_raw("edb_getSnapshotCount", None).await?)?;
    let mut hook_snapshot_path = None;
    for snapshot_id in 0..snapshot_count {
        let Ok(info) = client.call_raw("edb_getSnapshotInfo", Some(json!([snapshot_id]))).await
        else {
            continue;
        };
        if let Some(path) = info
            .get("detail")
            .and_then(|detail| detail.get("Hook"))
            .and_then(|hook| hook.get("path"))
            .and_then(|path| path.as_str())
        {
            hook_snapshot_path = Some((snapshot_id, path.to_string()));
            break;
        }
    }
    let (hook_snapshot_id, hook_path) =
        hook_snapshot_path.expect("Mezo debugger run should collect hook snapshots");
    eprintln!("mezo-debugger: first hook snapshot id={hook_snapshot_id} path={hook_path}");

    engine.shutdown_rpc_server(&tx_hash)?;
    Ok(())
}
