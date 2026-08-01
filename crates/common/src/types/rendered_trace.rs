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

//! Rendered trace types for frontend consumption.
//!
//! These types represent fully-decoded trace rows ready for UI rendering.
//! They are the Rust equivalent of the TypeScript `DecodedTraceRow` interface
//! defined in `src/utils/traceDecoder/types.ts`.
//!
//! The `render_trace` function in `edb-engine/src/trace_render/` produces
//! these types from the raw `EngineContext`, replacing the 3-phase TypeScript
//! decode pipeline (decodeTraceInit → decodeTraceAnalysis → decodeTraceFinalize).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Kind of rendered trace row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RenderedRowKind {
    /// An EVM opcode step
    Opcode,
    /// A synthetic call frame entry (CALL/DELEGATECALL/STATICCALL/CREATE)
    Entry,
}

/// A single decoded argument with name and string value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedArg {
    pub name: String,
    pub value: String,
}

/// An argument type descriptor (name + type string).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedArgType {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<RenderedArgType>>,
}

/// Storage read information (SLOAD).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedStorageRead {
    pub slot: String,
    pub value: String,
}

/// Storage write information (SSTORE) with before/after values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedStorageWrite {
    pub slot: String,
    pub before: String,
    pub after: String,
}

/// Decoded log/event information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedDecodedLog {
    pub name: String,
    pub args: Vec<RenderedLogArg>,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
}

/// A decoded log argument (name can be positional index or string).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedLogArg {
    pub name: serde_json::Value, // string or number to match TS `string | number`
    pub value: String,
}

/// LOG opcode info (memory offset, size, topics).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedLogInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    pub offset: String,
    pub size: String,
    pub topics: Vec<serde_json::Value>,
}

/// Entry metadata for call frame rows (CALL/DELEGATECALL/STATICCALL entries).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedEntryMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// For DELEGATECALL: the contract whose code is being executed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_contract_name: Option<String>,
    /// For DELEGATECALL: the proxy/storage context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_contract_name: Option<String>,
    /// Call type: "CALL", "DELEGATECALL", "STATICCALL", etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_type: Option<String>,
    /// Function selector (first 4 bytes of input)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    /// Decoded function name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// Decoded call arguments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<RenderedArg>>,
    /// Expected output types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputs: Option<Vec<RenderedArgType>>,
    /// ETH value sent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// A single fully-rendered trace row ready for UI consumption.
///
/// This struct is the 1:1 Rust equivalent of the TypeScript `DecodedTraceRow`
/// interface. Every field here maps directly to a field the frontend expects.
///
/// The serde representation uses camelCase to match the JavaScript conventions
/// that the frontend already consumes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedTraceRow {
    // ── Core Identity ──────────────────────────────────────────────────
    /// Opcode ID from EDB snapshot. Negative for synthetic call frame entries.
    pub id: i64,
    /// Original trace ID for call frame entries (id is negative to avoid conflicts)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<usize>,
    /// Always "opcode" in current implementation
    pub kind: RenderedRowKind,
    /// Opcode name (JUMP, SLOAD, ADD, CALL, DELEGATECALL, etc.)
    pub name: String,
    /// Program counter
    pub pc: usize,

    // ── Gas Tracking ───────────────────────────────────────────────────
    /// Call input data (for call frame entries)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
    /// Call output data (for call frame entries)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    /// Per-opcode gas cost from EDB
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_used: Option<String>,
    /// Computed gas delta (current - next)
    pub gas_delta: String,
    /// Cumulative gas used up to this point
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_cum: Option<String>,
    /// Gas remaining (string to preserve BigInt precision)
    pub gas_remaining: String,

    // ── Frame & Depth Hierarchy ────────────────────────────────────────
    /// Frame hierarchy from EDB [trace_entry_id, re_entry_count]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_id: Option<Vec<serde_json::Value>>,
    /// External call depth derived from frame_id
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<usize>,
    /// Combined external + internal function depth for hierarchy visualization
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visual_depth: Option<usize>,

    // ── Internal Call Hierarchy ─────────────────────────────────────────
    /// Parent internal call id for hierarchy grouping
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_parent_id: Option<i64>,
    /// True if this row represents an internal function call (JUMP with destFn)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_internal_call: Option<bool>,
    /// True if this row represents return from internal function
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_internal_return: Option<bool>,
    /// True if this internal call has no nested calls (leaf function)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_leaf_call: Option<bool>,
    /// True if this internal call contains nested calls (parent frame - collapsible)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_children: Option<bool>,
    /// The opcode ID where this function's children end (for rail calculation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_end_id: Option<i64>,
    /// For entry rows: links to first opcode snapshot in this frame.
    /// For opcode rows: original snapshot index (used by jump_detector after ID renumbering).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_snapshot_id: Option<usize>,
    /// From EDB parent_id: explicit external call parent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_parent_trace_id: Option<i64>,
    /// True if this call was confirmed via source map jump type 'i'
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_confirmed_call: Option<bool>,
    /// True if this call is to a contract without source code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_unverified_contract: Option<bool>,

    // ── Source Mapping ──────────────────────────────────────────────────
    /// Source line number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// Source file name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    /// Function name at this PC
    #[serde(rename = "fn", skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
    /// Contract name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract: Option<String>,

    // ── Stack State (lightweight) ───────────────────────────────────────
    /// Stack depth
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_depth: Option<usize>,
    /// Top of stack value (hex string)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_top: Option<String>,

    // ── Storage Operations ──────────────────────────────────────────────
    /// Storage read information (SLOAD)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_read: Option<RenderedStorageRead>,
    /// Storage write information (SSTORE) with before/after
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_write: Option<RenderedStorageWrite>,

    // ── Jump Analysis (Internal Function Calls) ─────────────────────────
    /// True if this is a JUMP/JUMPI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump_marker: Option<bool>,
    /// Destination PC for JUMPs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_pc: Option<usize>,
    /// Destination function name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_fn: Option<String>,
    /// For JUMPs: file where destination function is defined
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_source_file: Option<String>,
    /// For JUMPs: line number in destination file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_line: Option<usize>,
    /// For JUMPs: file where the JUMP instruction is (caller side)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_source_file: Option<String>,
    /// For JUMPs: line number where the JUMP happens (caller side)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_line: Option<usize>,
    /// Decoded jump arguments (with ABI parameter names and values)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump_args_decoded: Option<Vec<RenderedArg>>,
    /// Origin of jump args ("abi", "stack", etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump_args_origin: Option<String>,
    /// True if args were truncated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump_args_truncated: Option<bool>,
    /// Return value from internal call
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump_result: Option<String>,
    /// Source of return value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump_result_source: Option<String>,

    // ── Entry Metadata (Call Frame Entries) ──────────────────────────────
    /// True if this is a function entry point
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_jumpdest: Option<bool>,
    /// Call frame metadata (caller, target, args, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_meta: Option<RenderedEntryMeta>,

    // ── Event/Log Decoding ──────────────────────────────────────────────
    /// LOG opcode info (memory offset, size, topics)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_info: Option<RenderedLogInfo>,
    /// Decoded event/log data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_log: Option<RenderedDecodedLog>,
    /// Fallback event data (raw)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_fallback: Option<serde_json::Value>,
}

/// Transaction-level call metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedCallMeta {
    /// Display label for the sender
    pub from: String,
    /// Display label for the target
    pub to: String,
    /// Function name or selector
    pub function: String,
    /// Formatted arguments string
    pub args: String,
    /// ETH value sent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Total gas used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_used: Option<String>,
}

/// A raw event log extracted from the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedRawEvent {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    /// Trace entry that emitted this event
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_entry_id: Option<usize>,
    /// Decoded event name from ABI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_name: Option<String>,
    /// Decoded event arguments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_args: Option<Vec<RenderedArg>>,
}

/// Quality statistics for the rendered trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedTraceQuality {
    pub total_rows: usize,
    pub empty_rows: usize,
    pub rows_with_source: usize,
    pub jump_rows: usize,
    pub entry_rows: usize,
}

/// Complete rendered trace output ready for frontend consumption.
///
/// This is the top-level struct returned by `render_trace()` and serialized
/// through `edb_getRenderedTrace` RPC. It replaces the entire output of the
/// TypeScript `decodeTrace()` function.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedTrace {
    /// Schema version for this rendered trace format
    pub schema_version: u32,
    /// Fully-decoded trace rows ready for UI rendering
    pub rows: Vec<RenderedTraceRow>,
    /// Map of source file path → source code content
    pub source_texts: HashMap<String, String>,
    /// Sorted list of source file paths (keys of source_texts)
    pub source_lines: Vec<String>,
    /// Transaction-level call metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_meta: Option<RenderedCallMeta>,
    /// Raw event logs for token movement analysis
    pub raw_events: Vec<RenderedRawEvent>,
    /// Diamond/proxy mapping: implementation address → proxy address
    pub implementation_to_proxy: HashMap<String, String>,
    /// Quality statistics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality: Option<RenderedTraceQuality>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rendered_row_kind_serialization() {
        let kind = RenderedRowKind::Opcode;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"opcode\"");

        let deserialized: RenderedRowKind = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, kind);
    }

    #[test]
    fn test_rendered_trace_row_minimal() {
        let row = RenderedTraceRow {
            id: 42,
            trace_id: None,
            kind: RenderedRowKind::Opcode,
            name: "PUSH1".to_string(),
            pc: 100,
            input: None,
            output: None,
            gas_used: None,
            gas_delta: "3".to_string(),
            gas_cum: None,
            gas_remaining: "999997".to_string(),
            frame_id: None,
            depth: Some(0),
            visual_depth: Some(1),
            internal_parent_id: None,
            is_internal_call: None,
            is_internal_return: None,
            is_leaf_call: None,
            has_children: None,
            child_end_id: None,
            first_snapshot_id: None,
            external_parent_trace_id: None,
            is_confirmed_call: None,
            is_unverified_contract: None,
            line: Some(42),
            source_file: Some("Test.sol".to_string()),
            function_name: Some("transfer".to_string()),
            contract: Some("TestContract".to_string()),
            stack_depth: Some(2),
            stack_top: Some("0xff".to_string()),
            storage_read: None,
            storage_write: None,
            jump_marker: None,
            dest_pc: None,
            dest_fn: None,
            dest_source_file: None,
            dest_line: None,
            src_source_file: None,
            src_line: None,
            jump_args_decoded: None,
            jump_args_origin: None,
            jump_args_truncated: None,
            jump_result: None,
            jump_result_source: None,
            entry_jumpdest: None,
            entry_meta: None,
            log_info: None,
            decoded_log: None,
            event_fallback: None,
        };

        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("\"id\":42"));
        assert!(json.contains("\"kind\":\"opcode\""));
        assert!(json.contains("\"name\":\"PUSH1\""));
        assert!(json.contains("\"fn\":\"transfer\""));

        // Verify None fields are skipped
        assert!(!json.contains("\"traceId\""));
        assert!(!json.contains("\"jumpMarker\""));
        assert!(!json.contains("\"entryMeta\""));

        let deserialized: RenderedTraceRow = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, 42);
        assert_eq!(deserialized.name, "PUSH1");
        assert_eq!(deserialized.function_name.as_deref(), Some("transfer"));
    }

    #[test]
    fn test_rendered_trace_row_with_call_frame() {
        let row = RenderedTraceRow {
            id: -1,
            trace_id: Some(5),
            kind: RenderedRowKind::Entry,
            name: "CALL".to_string(),
            pc: 0,
            input: Some("0xdeadbeef".to_string()),
            output: None,
            gas_used: Some("21000".to_string()),
            gas_delta: "21000".to_string(),
            gas_cum: Some("21000".to_string()),
            gas_remaining: "79000".to_string(),
            frame_id: Some(vec![
                serde_json::Value::Number(5.into()),
                serde_json::Value::Number(0.into()),
            ]),
            depth: Some(1),
            visual_depth: Some(2),
            internal_parent_id: None,
            is_internal_call: None,
            is_internal_return: None,
            is_leaf_call: None,
            has_children: Some(true),
            child_end_id: Some(100),
            first_snapshot_id: Some(10),
            external_parent_trace_id: Some(0),
            is_confirmed_call: None,
            is_unverified_contract: Some(false),
            line: None,
            source_file: None,
            function_name: None,
            contract: Some("Target".to_string()),
            stack_depth: None,
            stack_top: None,
            storage_read: None,
            storage_write: None,
            jump_marker: None,
            dest_pc: None,
            dest_fn: None,
            dest_source_file: None,
            dest_line: None,
            src_source_file: None,
            src_line: None,
            jump_args_decoded: None,
            jump_args_origin: None,
            jump_args_truncated: None,
            jump_result: None,
            jump_result_source: None,
            entry_jumpdest: Some(true),
            entry_meta: Some(RenderedEntryMeta {
                caller: Some("0xabc".to_string()),
                target: Some("0xdef".to_string()),
                code_address: None,
                code_contract_name: None,
                target_contract_name: Some("Target".to_string()),
                call_type: Some("CALL".to_string()),
                selector: Some("0xdeadbeef".to_string()),
                function: Some("transfer".to_string()),
                args: Some(vec![RenderedArg {
                    name: "to".to_string(),
                    value: "0x123".to_string(),
                }]),
                outputs: Some(vec![RenderedArgType {
                    name: "success".to_string(),
                    ty: "bool".to_string(),
                    components: None,
                }]),
                value: Some("0".to_string()),
            }),
            log_info: None,
            decoded_log: None,
            event_fallback: None,
        };

        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("\"id\":-1"));
        assert!(json.contains("\"traceId\":5"));
        assert!(json.contains("\"entryJumpdest\":true"));
        assert!(json.contains("\"entryMeta\""));
        assert!(json.contains("\"callType\":\"CALL\""));

        let deserialized: RenderedTraceRow = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, -1);
        assert_eq!(deserialized.trace_id, Some(5));
        assert!(deserialized.entry_meta.is_some());
    }

    #[test]
    fn test_rendered_trace_complete() {
        let trace = RenderedTrace {
            schema_version: 3,
            rows: vec![],
            source_texts: HashMap::from([("Test.sol".to_string(), "contract Test {}".to_string())]),
            source_lines: vec!["Test.sol".to_string()],
            call_meta: Some(RenderedCallMeta {
                from: "0xabc".to_string(),
                to: "Target".to_string(),
                function: "transfer".to_string(),
                args: "to=0x123, amount=100".to_string(),
                value: Some("0".to_string()),
                gas_used: Some("21000".to_string()),
            }),
            raw_events: vec![RenderedRawEvent {
                address: "0xabc".to_string(),
                topics: vec!["0x123".to_string()],
                data: "0x456".to_string(),
                trace_entry_id: None,
                event_name: None,
                decoded_args: None,
            }],
            implementation_to_proxy: HashMap::new(),
            quality: Some(RenderedTraceQuality {
                total_rows: 252,
                empty_rows: 0,
                rows_with_source: 252,
                jump_rows: 51,
                entry_rows: 10,
            }),
        };

        let json = serde_json::to_string(&trace).unwrap();
        assert!(json.contains("\"schemaVersion\":3"));
        assert!(json.contains("\"rows\":[]"));
        assert!(json.contains("\"sourceTexts\""));
        assert!(json.contains("\"rawEvents\""));

        let deserialized: RenderedTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.schema_version, 3);
        assert_eq!(deserialized.source_texts.len(), 1);
        assert_eq!(deserialized.raw_events.len(), 1);
        assert!(deserialized.quality.is_some());
    }

    #[test]
    fn test_rendered_entry_meta_serialization() {
        let meta = RenderedEntryMeta {
            caller: Some("0xabc".to_string()),
            target: Some("0xdef".to_string()),
            code_address: Some("0x111".to_string()),
            code_contract_name: Some("Implementation".to_string()),
            target_contract_name: Some("Proxy".to_string()),
            call_type: Some("DELEGATECALL".to_string()),
            selector: Some("0xabcdef01".to_string()),
            function: Some("execute".to_string()),
            args: Some(vec![RenderedArg { name: "data".to_string(), value: "0x123".to_string() }]),
            outputs: None,
            value: None,
        };

        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("\"codeAddress\":\"0x111\""));
        assert!(json.contains("\"callType\":\"DELEGATECALL\""));
        // None fields should be skipped
        assert!(!json.contains("\"outputs\""));
        // Note: "value" appears inside args[].value, so we check for top-level "value":null absence
        // by verifying the entry_meta level field is not present as a key with null
        assert!(!json.contains("\"value\":null"));

        let deserialized: RenderedEntryMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.call_type.as_deref(), Some("DELEGATECALL"));
    }

    #[test]
    fn test_rendered_storage_operations() {
        let read = RenderedStorageRead { slot: "0x0".to_string(), value: "0xff".to_string() };
        let json = serde_json::to_string(&read).unwrap();
        let deserialized: RenderedStorageRead = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.slot, "0x0");
        assert_eq!(deserialized.value, "0xff");

        let write = RenderedStorageWrite {
            slot: "0x1".to_string(),
            before: "0x00".to_string(),
            after: "0xff".to_string(),
        };
        let json = serde_json::to_string(&write).unwrap();
        let deserialized: RenderedStorageWrite = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.before, "0x00");
        assert_eq!(deserialized.after, "0xff");
    }

    #[test]
    fn test_rendered_decoded_log() {
        let log = RenderedDecodedLog {
            name: "Transfer".to_string(),
            args: vec![
                RenderedLogArg {
                    name: serde_json::Value::String("from".to_string()),
                    value: "0xabc".to_string(),
                },
                RenderedLogArg {
                    name: serde_json::Value::Number(1.into()),
                    value: "100".to_string(),
                },
            ],
            source: "abi".to_string(),
            truncated: None,
        };

        let json = serde_json::to_string(&log).unwrap();
        assert!(json.contains("\"Transfer\""));
        assert!(json.contains("\"from\""));

        let deserialized: RenderedDecodedLog = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "Transfer");
        assert_eq!(deserialized.args.len(), 2);
    }
}
