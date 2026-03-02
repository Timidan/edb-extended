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

//! Code retrieval RPC method implementation

use std::collections::HashMap;
use std::sync::Arc;

use alloy_primitives::{Address, Bytes};
use edb_common::types::{Code, OpcodeInfo, SourceInfo};
use revm::{database::CacheDB, Database, DatabaseCommit, DatabaseRef};
use serde_json::{Map, Value};
use tracing::debug;

use crate::{
    error_codes, utils::disasm::disassemble, utils::Artifact, EngineContext, SnapshotDetail,
};

use super::super::types::RpcError;

/// Get code for a specific snapshot
///
/// This method returns either disassembled opcodes (for opcode snapshots)
/// or source code (for hook snapshots).
///
/// # Parameters
/// - `id`: The snapshot ID (0-indexed)
///
/// # Returns
/// - For opcode snapshots: Disassembled bytecode with PC mappings
/// - For hook snapshots: Source code files from the artifact
pub fn get_code<DB>(
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
            message: "Invalid params: expected [snapshot_id]".to_string(),
            data: None,
        })? as usize;

    // Get the snapshot at the specified index
    let (frame_id, snapshot) = context.snapshots.get(snapshot_id).ok_or_else(|| RpcError {
        code: error_codes::SNAPSHOT_OUT_OF_BOUNDS,
        message: format!("Snapshot with id {snapshot_id} not found"),
        data: None,
    })?;

    let trace_entry = context.trace.get(frame_id.trace_entry_id()).ok_or_else(|| RpcError {
        code: error_codes::TRACE_ENTRY_NOT_FOUND,
        message: format!("Trace entry with id {} not found", frame_id.trace_entry_id()),
        data: None,
    })?;

    let bytecode_address = trace_entry.code_address;

    let code = match snapshot.detail() {
        SnapshotDetail::Opcode(..) => {
            // For opcode snapshots, return disassembled bytecode
            // Get the bytecode from the database
            let bytecode = trace_entry.bytecode.as_ref().ok_or_else(|| RpcError {
                code: error_codes::CODE_NOT_FOUND,
                message: format!("No bytecode found for trace entry {}", frame_id.trace_entry_id()),
                data: None,
            })?;

            let codes = get_disassembled_code(bytecode);

            Code::Opcode(OpcodeInfo { bytecode_address, codes })
        }
        SnapshotDetail::Hook(..) => {
            // Get the artifact for this address
            let artifact = context.artifacts.get(&bytecode_address).ok_or_else(|| RpcError {
                code: error_codes::INVALID_ADDRESS,
                message: format!("No artifact found for address {bytecode_address}"),
                data: None,
            })?;

            // Extract sources from the SolcInput
            let mut sources = HashMap::new();
            for (path, source) in &artifact.input.sources {
                sources.insert(path.clone(), source.content.to_string());
            }

            Code::Source(SourceInfo { bytecode_address, sources })
        }
    };

    // Serialize the Code enum to JSON
    let json_value = serde_json::to_value(code).map_err(|e| RpcError {
        code: error_codes::INTERNAL_ERROR,
        message: format!("Failed to serialize code: {e}"),
        data: None,
    })?;

    debug!("Retrieved code for snapshot {}", snapshot_id);
    Ok(json_value)
}

/// Get code for a specific address
///
/// This method retrieves the code (either opcode or source) associated with a given
/// contract address, if available in the artifact metadata.
///
/// # Parameters
/// - `address`: The contract address
///
/// # Returns
/// - For opcode snapshots: Disassembled bytecode with PC mappings
/// - For hook snapshots: Source code files from the artifact
pub fn get_code_by_address<DB>(
    context: &Arc<EngineContext<DB>>,
    params: Option<Value>,
) -> Result<serde_json::Value, RpcError>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone + Send + Sync + 'static,
    <CacheDB<DB> as Database>::Error: Clone + Send + Sync,
    <DB as Database>::Error: Clone + Send + Sync,
{
    // Parse the address as the first argument
    let address: Address = params
        .as_ref()
        .and_then(|p| p.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(|| RpcError {
            code: error_codes::INVALID_PARAMS,
            message: "Invalid params: expected [address]".to_string(),
            data: None,
        })?;

    let code = match context.artifacts.get(&address) {
        Some(artifact) => {
            // Extract sources from the SolcInput
            let mut sources = HashMap::new();
            for (path, source) in &artifact.input.sources {
                sources.insert(path.clone(), source.content.to_string());
            }
            Code::Source(SourceInfo { bytecode_address: address, sources })
        }
        None => context
            .trace
            .iter()
            .find_map(|entry| {
                if entry.code_address == address {
                    let bytecode = entry.bytecode.as_ref()?;
                    let codes = get_disassembled_code(bytecode);
                    Some(Code::Opcode(OpcodeInfo { bytecode_address: address, codes }))
                } else {
                    None
                }
            })
            .ok_or_else(|| RpcError {
                code: error_codes::CODE_NOT_FOUND,
                message: format!("No code found for address {address}"),
                data: None,
            })?,
    };

    let json_value = serde_json::to_value(code).map_err(|e| RpcError {
        code: error_codes::INTERNAL_ERROR,
        message: format!("Failed to serialize code: {e}"),
        data: None,
    })?;
    debug!("Retrieved code for address {}", address);
    Ok(json_value)
}

/// Get full artifact (metadata + sources + source maps) for a contract address
pub fn get_artifact_by_address<DB>(
    context: &Arc<EngineContext<DB>>,
    params: Option<Value>,
) -> Result<serde_json::Value, RpcError>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone + Send + Sync + 'static,
    <CacheDB<DB> as Database>::Error: Clone + Send + Sync,
    <DB as Database>::Error: Clone + Send + Sync,
{
    let address: Address = params
        .as_ref()
        .and_then(|p| p.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(|| RpcError {
            code: error_codes::INVALID_PARAMS,
            message: "Invalid params: expected [address]".to_string(),
            data: None,
        })?;

    let artifact: &Artifact = context.artifacts.get(&address).ok_or_else(|| RpcError {
        code: error_codes::INVALID_ADDRESS,
        message: format!("No artifact found for address {address}"),
        data: None,
    })?;

    let json_value = serde_json::to_value(artifact).map_err(|e| RpcError {
        code: error_codes::INTERNAL_ERROR,
        message: format!("Failed to serialize artifact: {e}"),
        data: None,
    })?;

    debug!("Retrieved artifact for address {}", address);
    Ok(json_value)
}

/// Get full artifacts (metadata + sources + source maps) for multiple contract addresses.
///
/// # Parameters
/// - `addresses`: Array of contract addresses, wrapped as first RPC param
///   - Expected JSON-RPC shape: `[[address1, address2, ...]]`
///
/// # Returns
/// - JSON object keyed by lowercase address containing artifact JSON for each hit.
///   Missing addresses are skipped.
pub fn get_artifacts_by_addresses<DB>(
    context: &Arc<EngineContext<DB>>,
    params: Option<Value>,
) -> Result<serde_json::Value, RpcError>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone + Send + Sync + 'static,
    <CacheDB<DB> as Database>::Error: Clone + Send + Sync,
    <DB as Database>::Error: Clone + Send + Sync,
{
    let addresses = parse_address_list_param(params)?;
    let mut artifacts = Map::with_capacity(addresses.len());

    for address in addresses {
        let Some(artifact) = context.artifacts.get(&address) else {
            continue;
        };

        let json_value = serde_json::to_value(artifact).map_err(|e| RpcError {
            code: error_codes::INTERNAL_ERROR,
            message: format!("Failed to serialize artifact: {e}"),
            data: None,
        })?;

        artifacts.insert(address.to_string().to_lowercase(), json_value);
    }

    debug!("Retrieved {} artifacts in bulk", artifacts.len());
    Ok(Value::Object(artifacts))
}

/// Get full recompiled (instrumented) artifact for a contract address.
/// Recompiled artifacts have source maps that match instrumented bytecode PCs,
/// which is required for correct opcode-to-line mapping in Diamond/DELEGATECALL scenarios.
pub fn get_recompiled_artifact_by_address<DB>(
    context: &Arc<EngineContext<DB>>,
    params: Option<Value>,
) -> Result<serde_json::Value, RpcError>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone + Send + Sync + 'static,
    <CacheDB<DB> as Database>::Error: Clone + Send + Sync,
    <DB as Database>::Error: Clone + Send + Sync,
{
    let address: Address = params
        .as_ref()
        .and_then(|p| p.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(|| RpcError {
            code: error_codes::INVALID_PARAMS,
            message: "Invalid params: expected [address]".to_string(),
            data: None,
        })?;

    let artifact = context.recompiled_artifacts.get(&address).ok_or_else(|| RpcError {
        code: error_codes::INVALID_ADDRESS,
        message: format!("No recompiled artifact found for address {address}"),
        data: None,
    })?;

    let json_value = serde_json::to_value(artifact).map_err(|e| RpcError {
        code: error_codes::INTERNAL_ERROR,
        message: format!("Failed to serialize recompiled artifact: {e}"),
        data: None,
    })?;

    debug!("Retrieved recompiled artifact for address {}", address);
    Ok(json_value)
}

/// Get full recompiled artifacts for multiple contract addresses.
///
/// # Parameters
/// - `addresses`: Array of contract addresses, wrapped as first RPC param
///   - Expected JSON-RPC shape: `[[address1, address2, ...]]`
///
/// # Returns
/// - JSON object keyed by lowercase address containing recompiled artifact JSON for each hit.
///   Missing addresses are skipped.
pub fn get_recompiled_artifacts_by_addresses<DB>(
    context: &Arc<EngineContext<DB>>,
    params: Option<Value>,
) -> Result<serde_json::Value, RpcError>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone + Send + Sync + 'static,
    <CacheDB<DB> as Database>::Error: Clone + Send + Sync,
    <DB as Database>::Error: Clone + Send + Sync,
{
    let addresses = parse_address_list_param(params)?;
    let mut artifacts = Map::with_capacity(addresses.len());

    for address in addresses {
        let Some(artifact) = context.recompiled_artifacts.get(&address) else {
            continue;
        };

        let json_value = serde_json::to_value(artifact).map_err(|e| RpcError {
            code: error_codes::INTERNAL_ERROR,
            message: format!("Failed to serialize recompiled artifact: {e}"),
            data: None,
        })?;

        artifacts.insert(address.to_string().to_lowercase(), json_value);
    }

    debug!("Retrieved {} recompiled artifacts in bulk", artifacts.len());
    Ok(Value::Object(artifacts))
}

/// Get constructor arguments for a contract at a specific address
///
/// This method retrieves the constructor arguments used during the deployment
/// of a contract, if available in the artifact metadata.
///
/// # Parameters
/// - `address`: The contract address
///    
/// # Returns
/// - The constructor arguments as a JSON value, or null if not available
pub fn get_constructor_args<DB>(
    context: &Arc<EngineContext<DB>>,
    params: Option<Value>,
) -> Result<serde_json::Value, RpcError>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone + Send + Sync + 'static,
    <CacheDB<DB> as Database>::Error: Clone + Send + Sync,
    <DB as Database>::Error: Clone + Send + Sync,
{
    // Parse the address as the first argument
    let address: Address = params
        .as_ref()
        .and_then(|p| p.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(|| RpcError {
            code: error_codes::INVALID_PARAMS,
            message: "Invalid params: expected [address]".to_string(),
            data: None,
        })?;

    let args =
        context.artifacts.get(&address).map(|artifact| artifact.meta.constructor_arguments.clone());

    let json_value = serde_json::to_value(args).map_err(|e| RpcError {
        code: error_codes::INTERNAL_ERROR,
        message: format!("Failed to serialize ABI: {e}"),
        data: None,
    })?;

    debug!("Retrieved contract ABI for address {}", address);
    Ok(json_value)
}

/// Get storage layout for a contract at a specific address
///
/// This method retrieves the storage layout information for a contract,
/// which includes slot positions, byte offsets, and type definitions for
/// all state variables including struct fields.
///
/// # Parameters
/// - `address`: The contract address
///
/// # Returns
/// - The storage layout JSON object with:
///   - `storage`: Array of storage entries (slot, offset, label, type)
///   - `types`: Map of type definitions with encoding, size, and members
///
/// # Example Response
/// ```json
/// {
///   "storage": [
///     { "astId": 123, "label": "_owner", "offset": 0, "slot": "0", "type": "t_address" },
///     { "astId": 456, "label": "myStruct", "offset": 0, "slot": "1", "type": "t_struct_MyStruct" }
///   ],
///   "types": {
///     "t_address": { "encoding": "inplace", "label": "address", "numberOfBytes": "20" },
///     "t_struct_MyStruct": {
///       "encoding": "inplace",
///       "label": "struct MyStruct",
///       "numberOfBytes": "64",
///       "members": [
///         { "label": "field1", "offset": 0, "slot": "0", "type": "t_uint256" }
///       ]
///     }
///   }
/// }
/// ```
pub fn get_storage_layout<DB>(
    context: &Arc<EngineContext<DB>>,
    params: Option<Value>,
) -> Result<serde_json::Value, RpcError>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone + Send + Sync + 'static,
    <CacheDB<DB> as Database>::Error: Clone + Send + Sync,
    <DB as Database>::Error: Clone + Send + Sync,
{
    // Parse the address as the first argument
    let address: Address = params
        .as_ref()
        .and_then(|p| p.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(|| RpcError {
            code: error_codes::INVALID_PARAMS,
            message: "Invalid params: expected [address]".to_string(),
            data: None,
        })?;

    // Optional: contract name for multi-contract artifacts
    let contract_name: Option<String> = params
        .as_ref()
        .and_then(|p| p.as_array())
        .and_then(|arr| arr.get(1))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let artifact = context.artifacts.get(&address).ok_or_else(|| RpcError {
        code: error_codes::INVALID_ADDRESS,
        message: format!("No artifact found for address {address}"),
        data: None,
    })?;

    let storage_layout = match &contract_name {
        Some(name) => artifact.storage_layout_for(name),
        None => artifact.storage_layout(),
    }
    .ok_or_else(|| RpcError {
        code: error_codes::INTERNAL_ERROR,
        message: format!(
            "No storage layout found for contract {}",
            contract_name.as_deref().unwrap_or(artifact.contract_name())
        ),
        data: None,
    })?;

    let json_value = serde_json::to_value(storage_layout).map_err(|e| RpcError {
        code: error_codes::INTERNAL_ERROR,
        message: format!("Failed to serialize storage layout: {e}"),
        data: None,
    })?;

    debug!(
        "Retrieved storage layout for address {} (contract: {})",
        address,
        contract_name.as_deref().unwrap_or(artifact.contract_name())
    );
    Ok(json_value)
}

fn get_disassembled_code(bytecode: &Bytes) -> HashMap<usize, String> {
    let disasm_result = disassemble(bytecode);

    let mut codes = HashMap::new();
    for instruction in disasm_result.instructions {
        let pc = instruction.pc;
        let opcode_str = if instruction.is_push() && !instruction.push_data.is_empty() {
            // Format PUSH instructions with their data
            let data_hex = hex::encode(&instruction.push_data);
            format!("{} 0x{}", instruction.opcode, data_hex)
        } else {
            instruction.opcode.to_string()
        };
        codes.insert(pc, opcode_str);
    }
    codes
}

fn parse_address_list_param(params: Option<Value>) -> Result<Vec<Address>, RpcError> {
    let raw_addresses = params
        .as_ref()
        .and_then(|p| p.as_array())
        .and_then(|arr| arr.first())
        .and_then(Value::as_array)
        .ok_or_else(|| RpcError {
            code: error_codes::INVALID_PARAMS,
            message: "Invalid params: expected [[address1, address2, ...]]".to_string(),
            data: None,
        })?;

    let mut addresses = Vec::with_capacity(raw_addresses.len());
    for raw_address in raw_addresses {
        let address: Address =
            serde_json::from_value(raw_address.clone()).map_err(|_| RpcError {
                code: error_codes::INVALID_PARAMS,
                message: "Invalid params: expected [[address1, address2, ...]]".to_string(),
                data: None,
            })?;
        addresses.push(address);
    }

    Ok(addresses)
}
