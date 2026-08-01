// EDB - Trace Render: Opcode Rows
// Creates RenderedTraceRow from opcode snapshots.
// Replaces the row construction logic from decodeTraceInit.ts.

use std::sync::Arc;

use edb_common::types::{
    RenderedLogInfo, RenderedRowKind, RenderedStorageRead, RenderedStorageWrite, RenderedTraceRow,
};
use revm::{Database, DatabaseCommit, DatabaseRef};

use crate::context::EngineContext;
use crate::snapshot::SnapshotDetail;

use super::source_mapper::SourceMaps;

/// Opcode names lookup table.
fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0x00 => "STOP",
        0x01 => "ADD",
        0x02 => "MUL",
        0x03 => "SUB",
        0x04 => "DIV",
        0x05 => "SDIV",
        0x06 => "MOD",
        0x07 => "SMOD",
        0x08 => "ADDMOD",
        0x09 => "MULMOD",
        0x0a => "EXP",
        0x0b => "SIGNEXTEND",
        0x10 => "LT",
        0x11 => "GT",
        0x12 => "SLT",
        0x13 => "SGT",
        0x14 => "EQ",
        0x15 => "ISZERO",
        0x16 => "AND",
        0x17 => "OR",
        0x18 => "XOR",
        0x19 => "NOT",
        0x1a => "BYTE",
        0x1b => "SHL",
        0x1c => "SHR",
        0x1d => "SAR",
        0x20 => "SHA3",
        0x30 => "ADDRESS",
        0x31 => "BALANCE",
        0x32 => "ORIGIN",
        0x33 => "CALLER",
        0x34 => "CALLVALUE",
        0x35 => "CALLDATALOAD",
        0x36 => "CALLDATASIZE",
        0x37 => "CALLDATACOPY",
        0x38 => "CODESIZE",
        0x39 => "CODECOPY",
        0x3a => "GASPRICE",
        0x3b => "EXTCODESIZE",
        0x3c => "EXTCODECOPY",
        0x3d => "RETURNDATASIZE",
        0x3e => "RETURNDATACOPY",
        0x3f => "EXTCODEHASH",
        0x40 => "BLOCKHASH",
        0x41 => "COINBASE",
        0x42 => "TIMESTAMP",
        0x43 => "NUMBER",
        0x44 => "PREVRANDAO",
        0x45 => "GASLIMIT",
        0x46 => "CHAINID",
        0x47 => "SELFBALANCE",
        0x48 => "BASEFEE",
        0x49 => "BLOBHASH",
        0x4a => "BLOBBASEFEE",
        0x50 => "POP",
        0x51 => "MLOAD",
        0x52 => "MSTORE",
        0x53 => "MSTORE8",
        0x54 => "SLOAD",
        0x55 => "SSTORE",
        0x56 => "JUMP",
        0x57 => "JUMPI",
        0x58 => "PC",
        0x59 => "MSIZE",
        0x5a => "GAS",
        0x5b => "JUMPDEST",
        0x5c => "TLOAD",
        0x5d => "TSTORE",
        0x5e => "MCOPY",
        0x5f => "PUSH0",
        op @ 0x60..=0x7f => {
            // PUSH1 to PUSH32 — return static str
            const PUSH_NAMES: [&str; 32] = [
                "PUSH1", "PUSH2", "PUSH3", "PUSH4", "PUSH5", "PUSH6", "PUSH7", "PUSH8", "PUSH9",
                "PUSH10", "PUSH11", "PUSH12", "PUSH13", "PUSH14", "PUSH15", "PUSH16", "PUSH17",
                "PUSH18", "PUSH19", "PUSH20", "PUSH21", "PUSH22", "PUSH23", "PUSH24", "PUSH25",
                "PUSH26", "PUSH27", "PUSH28", "PUSH29", "PUSH30", "PUSH31", "PUSH32",
            ];
            PUSH_NAMES[(op - 0x60) as usize]
        }
        op @ 0x80..=0x8f => {
            const DUP_NAMES: [&str; 16] = [
                "DUP1", "DUP2", "DUP3", "DUP4", "DUP5", "DUP6", "DUP7", "DUP8", "DUP9", "DUP10",
                "DUP11", "DUP12", "DUP13", "DUP14", "DUP15", "DUP16",
            ];
            DUP_NAMES[(op - 0x80) as usize]
        }
        op @ 0x90..=0x9f => {
            const SWAP_NAMES: [&str; 16] = [
                "SWAP1", "SWAP2", "SWAP3", "SWAP4", "SWAP5", "SWAP6", "SWAP7", "SWAP8", "SWAP9",
                "SWAP10", "SWAP11", "SWAP12", "SWAP13", "SWAP14", "SWAP15", "SWAP16",
            ];
            SWAP_NAMES[(op - 0x90) as usize]
        }
        0xa0 => "LOG0",
        0xa1 => "LOG1",
        0xa2 => "LOG2",
        0xa3 => "LOG3",
        0xa4 => "LOG4",
        0xf0 => "CREATE",
        0xf1 => "CALL",
        0xf2 => "CALLCODE",
        0xf3 => "RETURN",
        0xf4 => "DELEGATECALL",
        0xf5 => "CREATE2",
        0xfa => "STATICCALL",
        0xfd => "REVERT",
        0xfe => "INVALID",
        0xff => "SELFDESTRUCT",
        _ => "UNKNOWN",
    }
}

/// Build opcode rows from all opcode snapshots in the engine context.
pub fn build_opcode_rows<DB>(
    context: &Arc<EngineContext<DB>>,
    source_maps: &SourceMaps,
) -> Vec<RenderedTraceRow>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone + Send + Sync + 'static,
    <revm::database::CacheDB<DB> as Database>::Error: Clone + Send + Sync,
    <DB as Database>::Error: Clone + Send + Sync,
{
    #[derive(Clone, Copy)]
    struct OpcodeMeta {
        snapshot_idx: usize,
        global_index: usize,
        trace_entry_id: usize,
        pc: usize,
        opcode: u8,
        gas_remaining: u64,
    }

    let total = context.snapshots.len();
    let mut opcode_meta = Vec::with_capacity(total);
    for idx in 0..total {
        let Some((frame_id, snapshot)) = context.snapshots.get(idx) else {
            continue;
        };
        let SnapshotDetail::Opcode(ref opcode_snap) = snapshot.detail() else {
            continue;
        };
        opcode_meta.push(OpcodeMeta {
            snapshot_idx: idx,
            global_index: opcode_snap.global_index,
            trace_entry_id: frame_id.trace_entry_id(),
            pc: opcode_snap.pc,
            opcode: opcode_snap.opcode,
            gas_remaining: opcode_snap.gas_remaining,
        });
    }
    // Keep opcode rows in true execution order.
    // With hook snapshots enabled, merged snapshots can be frame-grouped;
    // global_index preserves original cross-frame opcode capture order.
    opcode_meta.sort_by_key(|meta| (meta.global_index, meta.snapshot_idx));

    let mut rows = Vec::with_capacity(opcode_meta.len());
    let trace_entries: Vec<_> = context.trace.iter().collect();
    let mut gas_cum: u64 = 0;

    for (row_idx, meta) in opcode_meta.iter().enumerate() {
        let Some((frame_id, snapshot)) = context.snapshots.get(meta.snapshot_idx) else {
            continue;
        };
        let SnapshotDetail::Opcode(ref opcode_snap) = snapshot.detail() else {
            continue;
        };

        let pc = meta.pc;
        let opcode = meta.opcode;
        let gas_remaining = meta.gas_remaining;
        let bytecode_address = snapshot.bytecode_address();
        let target_address = snapshot.target_address();
        let trace_entry_id = meta.trace_entry_id;

        // Match FE legacy semantics: gas delta belongs to the current opcode row.
        // Compute current - next across opcode snapshots and clamp frame-boundary artifacts.
        let next_gas_remaining = opcode_meta.get(row_idx + 1).map(|n| n.gas_remaining);
        let mut gas_delta: i64 =
            next_gas_remaining.map(|next| gas_remaining as i64 - next as i64).unwrap_or(0);
        if !(0..=100_000).contains(&gas_delta) {
            gas_delta = 0;
        }
        gas_cum = gas_cum.saturating_add(gas_delta as u64);

        // Get depth and contract name from trace entry
        let depth = trace_entries.get(trace_entry_id).map(|e| e.depth).unwrap_or(0);

        // Resolve contract name from artifacts. Fall back to target address to avoid "Unknown".
        let contract_label = trace_entries.get(trace_entry_id).and_then(|e| {
            context
                .artifacts
                .get(&e.target)
                .map(|a| a.contract_name().to_string())
                .filter(|n| !n.is_empty())
                .or_else(|| {
                    context
                        .artifacts
                        .get(&e.code_address)
                        .map(|a| a.contract_name().to_string())
                        .filter(|n| !n.is_empty())
                })
                .or_else(|| {
                    e.target_label.clone().filter(|label| {
                        let trimmed = label.trim();
                        !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("unknown")
                    })
                })
                .or_else(|| Some(format!("{}", e.target)))
        });

        // Resolve source location from source maps
        let resolved = source_maps.get(&bytecode_address).and_then(|csm| csm.pc_map.get(&pc));

        // Build stack info
        let stack_len = opcode_snap.stack.len();
        let stack_top = opcode_snap.stack.peek(0).map(|v| format!("{v:#x}"));

        let storage_read = if opcode == 0x54 {
            opcode_snap.stack.peek(0).map(|slot| {
                // Primary source of truth: storage value from the snapshot DB view.
                // This keeps SLOAD rows stable even when significant-opcode sampling
                // changes adjacency assumptions for stack-based inference.
                let mut loaded_value = opcode_snap
                    .database
                    .storage_ref(target_address, *slot)
                    .map(|v| format!("{v:#x}"))
                    .unwrap_or_default();

                // Fallback when DB lookup is unavailable:
                // infer from the immediate next opcode snapshot in the same frame.
                // Guard on contiguous global index to avoid sampling gaps.
                if loaded_value.is_empty() {
                    if let Some(next_meta) = opcode_meta.get(row_idx + 1) {
                        let is_contiguous = next_meta.global_index == meta.global_index + 1;
                        if is_contiguous {
                            if let Some((next_frame_id, next_snapshot)) =
                                context.snapshots.get(next_meta.snapshot_idx)
                            {
                                let same_frame = next_frame_id.trace_entry_id()
                                    == frame_id.trace_entry_id()
                                    && next_frame_id.re_entry_count() == frame_id.re_entry_count();
                                if same_frame {
                                    if let SnapshotDetail::Opcode(ref next_opcode_snap) =
                                        next_snapshot.detail()
                                    {
                                        if let Some(v) = next_opcode_snap.stack.peek(0) {
                                            loaded_value = format!("{v:#x}");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                RenderedStorageRead { slot: format!("{slot:#x}"), value: loaded_value }
            })
        } else {
            None
        };

        let storage_write = if opcode == 0x55 {
            opcode_snap.stack.peek(0).map(|slot| RenderedStorageWrite {
                slot: format!("{slot:#x}"),
                before: opcode_snap
                    .database
                    .storage_ref(target_address, *slot)
                    .map(|v| format!("{v:#x}"))
                    .unwrap_or_default(),
                after: opcode_snap.stack.peek(1).map(|v| format!("{v:#x}")).unwrap_or_default(),
            })
        } else {
            None
        };

        // Extract log_info for LOG0-LOG4 opcodes from the stack
        // Keep legacy FE semantics:
        // size is stack top, offset is next item down, then topics.
        let log_info = if (0xa0..=0xa4).contains(&opcode) {
            let topic_count = (opcode - 0xa0) as usize;
            let needed = 2 + topic_count; // offset + size + topics
            if stack_len >= needed {
                let size = opcode_snap.stack.peek(0).map(|v| format!("{v:#x}")).unwrap_or_default();
                let offset =
                    opcode_snap.stack.peek(1).map(|v| format!("{v:#x}")).unwrap_or_default();
                let mut topics = Vec::with_capacity(topic_count);
                for t in 0..topic_count {
                    if let Some(topic_val) = opcode_snap.stack.peek(2 + t) {
                        topics.push(serde_json::Value::String(format!("{topic_val:#066x}")));
                    }
                }
                Some(RenderedLogInfo {
                    address: Some(format!("{target_address}")),
                    offset,
                    size,
                    topics,
                })
            } else {
                None
            }
        } else {
            None
        };

        let op_name = opcode_name(opcode).to_string();

        let row = RenderedTraceRow {
            id: meta.snapshot_idx as i64,
            trace_id: Some(trace_entry_id),
            kind: RenderedRowKind::Opcode,
            name: op_name,
            pc,
            input: None,
            output: None,
            gas_used: None,
            gas_delta: gas_delta.to_string(),
            gas_cum: Some(gas_cum.to_string()),
            gas_remaining: gas_remaining.to_string(),
            frame_id: Some(vec![
                serde_json::Value::Number(serde_json::Number::from(frame_id.trace_entry_id())),
                serde_json::Value::Number(serde_json::Number::from(frame_id.re_entry_count())),
            ]),
            depth: Some(depth),
            visual_depth: Some(depth), // Will be refined by hierarchy pass
            internal_parent_id: None,
            is_internal_call: None,
            is_internal_return: None,
            is_leaf_call: None,
            has_children: None,
            child_end_id: None,
            // Original snapshot index — used by jump_detector after renumbering.
            first_snapshot_id: Some(meta.snapshot_idx),
            external_parent_trace_id: None,
            entry_jumpdest: None,
            is_confirmed_call: None,
            line: resolved.map(|r| r.line),
            source_file: resolved.map(|r| r.file_path.clone()),
            dest_source_file: None,
            dest_line: None,
            src_source_file: None,
            src_line: None,
            stack_depth: Some(stack_len),
            stack_top,
            storage_read,
            storage_write,
            jump_marker: None,
            dest_pc: None,
            dest_fn: None,
            jump_args_decoded: None,
            jump_args_origin: None,
            jump_args_truncated: None,
            jump_result: None,
            jump_result_source: None,
            entry_meta: None,
            log_info,
            decoded_log: None,
            event_fallback: None,
            is_unverified_contract: None,
            function_name: resolved.and_then(|r| r.function_name.clone()),
            contract: resolved
                .and_then(|r| r.contract_name.clone())
                .filter(|n| {
                    let trimmed = n.trim();
                    !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("unknown")
                })
                .or(contract_label),
        };

        rows.push(row);
    }

    rows
}
