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

use std::sync::Arc;

use alloy_primitives::{map::HashMap, Address, U256};
use revm::{database::CacheDB, Database, DatabaseCommit, DatabaseRef};
use serde_json::Value;
use tracing::debug;

use crate::{error_codes, EngineContext, RpcError, SnapshotDetail};

pub fn get_storage_diff<DB>(
    context: &Arc<EngineContext<DB>>,
    params: Option<Value>,
) -> Result<Value, RpcError>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone + Send + Sync + 'static,
    <CacheDB<DB> as Database>::Error: Clone + Send + Sync,
    <DB as Database>::Error: Clone + Send + Sync,
{
    // Parse the snapshot ID from parameters
    let snapshot_id = params
        .as_ref()
        .and_then(|p| p.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError {
            code: error_codes::INVALID_PARAMS,
            message: "Invalid params: expected [snapshot_id, slot]".to_string(),
            data: None,
        })? as usize;

    let (f_id, snapshot) = context.snapshots.get(snapshot_id).ok_or_else(|| RpcError {
        code: error_codes::SNAPSHOT_OUT_OF_BOUNDS,
        message: format!("Snapshot with id {snapshot_id} not found"),
        data: None,
    })?;

    let target_address = context
        .trace
        .get(f_id.trace_entry_id())
        .ok_or_else(|| RpcError {
            code: error_codes::INTERNAL_ERROR,
            message: format!("Execution frame id {f_id} not found in trace"),
            data: None,
        })?
        .target;

    let empty_storage = HashMap::default();
    let dst_db = snapshot.db();
    let dst_cached_storage = dst_db
        .cache
        .accounts
        .get(&target_address)
        .map(|acc| &acc.storage)
        .unwrap_or(&empty_storage);

    let src_db = context
        .snapshots
        .first()
        .ok_or_else(|| RpcError {
            code: error_codes::SNAPSHOT_OUT_OF_BOUNDS,
            message: "Initial snapshot (id 0) not found".to_string(),
            data: None,
        })?
        .1
        .db();

    let mut changes = HashMap::new();
    for (slot, dst_value) in dst_cached_storage.iter() {
        let src_value = src_db.storage_ref(target_address, *slot).map_err(|e| RpcError {
            code: error_codes::INTERNAL_ERROR,
            message: format!("Failed to retrieve storage at {target_address} for slot {slot}: {e}"),
            data: None,
        })?;
        if &src_value != dst_value {
            changes.insert(*slot, (src_value, *dst_value));
        }
    }

    // Serialize the SnapshotInfo enum to JSON
    let json_value = serde_json::to_value(changes).map_err(|e| RpcError {
        code: error_codes::INTERNAL_ERROR,
        message: format!("Failed to serialize storage diff: {e}"),
        data: None,
    })?;

    debug!("Retrieved storage diff for snapshot {}", snapshot_id);
    Ok(json_value)
}

pub fn get_storage<DB>(
    context: &Arc<EngineContext<DB>>,
    params: Option<Value>,
) -> Result<Value, RpcError>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone + Send + Sync + 'static,
    <CacheDB<DB> as Database>::Error: Clone + Send + Sync,
    <DB as Database>::Error: Clone + Send + Sync,
{
    // Parse the snapshot ID from parameters
    let snapshot_id = params
        .as_ref()
        .and_then(|p| p.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError {
            code: error_codes::INVALID_PARAMS,
            message: "Invalid params: expected [snapshot_id, slot]".to_string(),
            data: None,
        })? as usize;

    // Parse recompiled as the second argument
    let slot: U256 = params
        .as_ref()
        .and_then(|p| p.as_array())
        .and_then(|arr| arr.get(1))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(|| RpcError {
            code: error_codes::INVALID_PARAMS,
            message: "Invalid params: expected [snapshot_id, slot]".to_string(),
            data: None,
        })?;

    let (f_id, snapshot) = context.snapshots.get(snapshot_id).ok_or_else(|| RpcError {
        code: error_codes::SNAPSHOT_OUT_OF_BOUNDS,
        message: format!("Snapshot with id {snapshot_id} not found"),
        data: None,
    })?;

    let target_address = context
        .trace
        .get(f_id.trace_entry_id())
        .ok_or_else(|| RpcError {
            code: error_codes::INTERNAL_ERROR,
            message: format!("Execution frame id {f_id} not found in trace"),
            data: None,
        })?
        .target;

    let db = snapshot.db();
    let value = db.storage_ref(target_address, slot).map_err(|e| RpcError {
        code: error_codes::INTERNAL_ERROR,
        message: format!("Failed to retrieve storage at {target_address} for slot {slot}: {e}"),
        data: None,
    })?;

    // Serialize the SnapshotInfo enum to JSON
    let json_value = serde_json::to_value(value).map_err(|e| RpcError {
        code: error_codes::INTERNAL_ERROR,
        message: format!("Failed to serialize storage info: {e}"),
        data: None,
    })?;

    debug!("Retrieved storage info for snapshot {}", snapshot_id);
    Ok(json_value)
}

/// Returns all SLOAD/SSTORE-touched storage slots across all opcode snapshots for
/// a given address. If an optional address parameter is provided, only slots for that
/// address are returned. Otherwise, slots for all addresses are collected.
///
/// ## Parameters
/// `[address?]` — optional hex-encoded contract address filter.
///
/// ## Returns
/// ```json
/// {
///   "0xContractAddr": [
///     { "slot": "0x...", "reads": [{ "snapshotId": N, "value": "0x..." }],
///       "writes": [{ "snapshotId": N, "before": "0x...", "after": "0x..." }] }
///   ]
/// }
/// ```
pub fn get_storage_touched<DB>(
    context: &Arc<EngineContext<DB>>,
    params: Option<Value>,
) -> Result<Value, RpcError>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone + Send + Sync + 'static,
    <CacheDB<DB> as Database>::Error: Clone + Send + Sync,
    <DB as Database>::Error: Clone + Send + Sync,
{
    // Optional address filter
    let filter_address: Option<Address> = params
        .as_ref()
        .and_then(|p| p.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| serde_json::from_value(v.clone()).ok());

    // Collect per-address, per-slot evidence
    // Key: (address, slot) → { reads: [...], writes: [...] }
    let mut touched: HashMap<Address, HashMap<U256, (Vec<Value>, Vec<Value>)>> = HashMap::default();

    for (idx, (_frame_id, snapshot)) in context.snapshots.iter().enumerate() {
        if let SnapshotDetail::Opcode(ref opcode_snap) = *snapshot.detail() {
            let target = snapshot.target_address();

            // Apply address filter
            if let Some(ref addr) = filter_address {
                if &target != addr {
                    continue;
                }
            }

            // Check SLOAD (opcode 0x54)
            if opcode_snap.opcode == 0x54 {
                if let Some(slot_val) = opcode_snap.stack.peek(0) {
                    let slot = *slot_val;
                    let value =
                        opcode_snap.database.storage_ref(target, slot).unwrap_or(U256::ZERO);

                    let entry = touched
                        .entry(target)
                        .or_default()
                        .entry(slot)
                        .or_insert_with(|| (Vec::new(), Vec::new()));

                    entry.0.push(serde_json::json!({
                        "snapshotId": idx,
                        "value": value
                    }));
                }
            }

            // Check SSTORE (opcode 0x55)
            if opcode_snap.opcode == 0x55 {
                let slot_opt = opcode_snap.stack.peek(1);
                let after_opt = opcode_snap.stack.peek(0);
                if let (Some(slot_val), Some(after_val)) = (slot_opt, after_opt) {
                    let slot = *slot_val;
                    let after = *after_val;
                    let before =
                        opcode_snap.database.storage_ref(target, slot).unwrap_or(U256::ZERO);

                    let entry = touched
                        .entry(target)
                        .or_default()
                        .entry(slot)
                        .or_insert_with(|| (Vec::new(), Vec::new()));

                    entry.1.push(serde_json::json!({
                        "snapshotId": idx,
                        "before": before,
                        "after": after
                    }));
                }
            }
        }
    }

    // Build the response object
    let mut result = serde_json::Map::new();
    for (address, slots) in &touched {
        let mut slot_entries = Vec::new();
        for (slot, (reads, writes)) in slots {
            slot_entries.push(serde_json::json!({
                "slot": slot,
                "reads": reads,
                "writes": writes,
            }));
        }
        result.insert(format!("{address:?}"), Value::Array(slot_entries));
    }

    debug!(
        "Retrieved storage touched: {} addresses, {} total slots",
        touched.len(),
        touched.values().map(|s| s.len()).sum::<usize>()
    );
    Ok(Value::Object(result))
}

/// Returns all cached storage slots and their current values for a given address
/// at the last snapshot (end of execution). This is a batch read that returns every
/// slot the EVM touched during execution for the specified contract.
///
/// ## Parameters
/// `[address]` — hex-encoded contract address.
///
/// ## Returns
/// ```json
/// { "0xSlotHex": "0xValueHex", ... }
/// ```
pub fn get_storage_range<DB>(
    context: &Arc<EngineContext<DB>>,
    params: Option<Value>,
) -> Result<Value, RpcError>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone + Send + Sync + 'static,
    <CacheDB<DB> as Database>::Error: Clone + Send + Sync,
    <DB as Database>::Error: Clone + Send + Sync,
{
    let target_address: Address = params
        .as_ref()
        .and_then(|p| p.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(|| RpcError {
            code: error_codes::INVALID_PARAMS,
            message: "Invalid params: expected [address]".to_string(),
            data: None,
        })?;

    // Use the last snapshot's database state (end of execution)
    let last_snapshot = context.snapshots.last().ok_or_else(|| RpcError {
        code: error_codes::SNAPSHOT_OUT_OF_BOUNDS,
        message: "No snapshots available".to_string(),
        data: None,
    })?;

    let db = last_snapshot.1.db();
    let empty_storage = HashMap::default();
    let cached_storage =
        db.cache.accounts.get(&target_address).map(|acc| &acc.storage).unwrap_or(&empty_storage);

    let mut result = serde_json::Map::new();
    for (slot, value) in cached_storage.iter() {
        result.insert(
            serde_json::to_value(slot)
                .map(|v| v.as_str().unwrap_or_default().to_string())
                .unwrap_or_default(),
            serde_json::to_value(value).unwrap_or(Value::Null),
        );
    }

    debug!("Retrieved storage range for {}: {} slots", target_address, cached_storage.len());
    Ok(Value::Object(result))
}
