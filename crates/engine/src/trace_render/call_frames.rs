// EDB - Trace Render: Call Frames
// Creates synthetic call frame entry rows for CALL/DELEGATECALL/STATICCALL/CREATE.
// Replaces the call frame creation logic from decodeTraceInit.ts.

use std::collections::HashMap;

use alloy_primitives::Address;
use edb_common::types::{
    CallResult, RenderedArg, RenderedArgType, RenderedEntryMeta, RenderedRowKind, RenderedTraceRow,
    Trace, TraceEntry,
};

use crate::Artifact;

/// Insert synthetic call frame entries into the row list.
///
/// For each TraceEntry, creates a synthetic row (with negative id) that represents
/// the CALL/DELEGATECALL/STATICCALL/CREATE entry point. These entries carry the
/// decoded function selector, arguments, and caller/target metadata.
pub fn insert_call_frames(
    rows: &mut Vec<RenderedTraceRow>,
    trace: &Trace,
    artifacts: &HashMap<Address, Artifact>,
) {
    // Precompute trace_id → first row index for O(1) lookup
    let mut trace_id_to_first_idx: HashMap<usize, usize> = HashMap::new();
    for (idx, r) in rows.iter().enumerate() {
        if let Some(tid) = r.trace_id {
            trace_id_to_first_idx.entry(tid).or_insert(idx);
        }
    }

    // Build entry rows with their target insertion positions, sorted by trace entry id
    // for deterministic ordering of entries with equal insertion positions
    let mut insertions: Vec<(usize, usize, RenderedTraceRow)> = Vec::new();
    for entry in trace.iter() {
        let insert_pos = trace_id_to_first_idx.get(&entry.id).copied().unwrap_or(rows.len());
        let first_opcode_row = rows.get(insert_pos).filter(|row| row.trace_id == Some(entry.id));
        let source_anchor_row = {
            // FE parity: prefer parent call-site anchoring for nested frames.
            // Only fall back to the callee frame's first mapped opcode when no
            // parent-mapped row exists.
            let parent_anchor = entry.parent_id.and_then(|parent_id| {
                rows[..insert_pos].iter().rev().find(|row| {
                    row.trace_id == Some(parent_id)
                        && row.line.is_some()
                        && row.source_file.as_ref().is_some()
                })
            });
            parent_anchor.or(first_opcode_row)
        };
        let entry_row = build_entry_row(entry, trace, artifacts, source_anchor_row);
        insertions.push((insert_pos, entry.id, entry_row));
    }

    // Sort by (position ASC, trace entry id ASC) for stable deterministic ordering
    insertions.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    // Build merged vector in one pass (avoids O(n²) repeated Vec::insert)
    let mut merged = Vec::with_capacity(rows.len() + insertions.len());
    let mut insert_iter = insertions.into_iter().peekable();
    for (idx, row) in rows.drain(..).enumerate() {
        // Insert all entry rows that belong before this index
        while let Some(&(pos, _, _)) = insert_iter.peek() {
            if pos <= idx {
                let (_, _, entry_row) = insert_iter.next().unwrap();
                merged.push(entry_row);
            } else {
                break;
            }
        }
        merged.push(row);
    }
    // Append any remaining entry rows (for trace entries with no matching opcode rows)
    for (_, _, entry_row) in insert_iter {
        merged.push(entry_row);
    }

    *rows = merged;
}

/// Build a synthetic entry row for a trace entry.
fn build_entry_row(
    entry: &TraceEntry,
    trace: &Trace,
    artifacts: &HashMap<Address, Artifact>,
    first_opcode_row: Option<&RenderedTraceRow>,
) -> RenderedTraceRow {
    let call_type_str = format_call_type(entry);

    // Try to decode the function selector and arguments
    let (selector, function_name, decoded_args, decoded_outputs) =
        decode_entry_calldata(entry, artifacts);

    // Resolve target label from target metadata only.
    // For DELEGATECALL, `target` is proxy/storage context while `code_address`
    // is implementation/facet code. We must avoid attributing code contract names
    // to target/proxy addresses.
    let target_contract_name = artifacts
        .get(&entry.target)
        .map(|a| a.contract_name().to_string())
        .filter(|n| !n.is_empty())
        .or_else(|| {
            entry.target_label.as_deref().and_then(|label| {
                let trimmed = label.trim();
                if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
        });
    let target_display_name =
        target_contract_name.clone().unwrap_or_else(|| format!("{}", entry.target));

    // Keep legacy FE-compatible opcode labels for entry rows.
    // Rich call details are carried via `entry_meta` (function, args, selector, contract names).
    let name = call_type_str.clone();
    let row_function_name =
        function_name.as_ref().map(|f| f.split('(').next().unwrap_or(f).to_string());

    // Get caller label from parent trace entry
    let _caller_label = entry
        .parent_id
        .and_then(|pid| trace.iter().find(|e| e.id == pid))
        .map(|parent| {
            // Resolve parent contract name from artifacts too
            let from_target =
                artifacts.get(&parent.target).map(|a| a.contract_name()).filter(|n| !n.is_empty());
            let from_code = artifacts
                .get(&parent.code_address)
                .map(|a| a.contract_name())
                .filter(|n| !n.is_empty());
            from_target
                .or(from_code)
                .or(parent.target_label.as_deref())
                .unwrap_or("Unknown")
                .to_string()
        })
        .unwrap_or_else(|| format!("{}", entry.caller));

    // Build entry metadata
    let entry_meta = RenderedEntryMeta {
        caller: Some(format!("{}", entry.caller)),
        target: Some(format!("{}", entry.target)),
        code_address: if entry.code_address != entry.target {
            Some(format!("{}", entry.code_address))
        } else {
            None
        },
        code_contract_name: artifacts
            .get(&entry.code_address)
            .map(|a| a.contract_name().to_string()),
        target_contract_name: Some(target_display_name),
        call_type: Some(call_type_str.clone()),
        selector: selector.clone(),
        function: function_name.clone(),
        args: if decoded_args.is_empty() { None } else { Some(decoded_args) },
        outputs: if decoded_outputs.is_empty() { None } else { Some(decoded_outputs) },
        value: if !entry.value.is_zero() { Some(format!("{}", entry.value)) } else { None },
    };

    // FE parity: entry rows should carry frame gas in gas_delta as well.
    let gas_used = entry.gas_used.map(|g| g.to_string());
    let gas_delta = gas_used.clone().unwrap_or_else(|| String::from("0"));

    // Determine result status
    let result_output = entry.result.as_ref().map(|r| match r {
        CallResult::Success { output, .. } => format!("0x{}", hex::encode(output)),
        CallResult::Revert { output, .. } => format!("revert: 0x{}", hex::encode(output)),
        CallResult::Error { output, .. } => format!("error: 0x{}", hex::encode(output)),
    });

    RenderedTraceRow {
        id: -(entry.id as i64) - 1, // Temporary; will be renumbered
        trace_id: Some(entry.id),
        kind: RenderedRowKind::Entry,
        name,
        pc: 0,
        input: Some(format!("0x{}", hex::encode(&entry.input))),
        output: result_output,
        gas_used,
        gas_delta,
        gas_cum: None,
        gas_remaining: String::from("0"),
        // FE parity: entry rows use a single trace-id frame marker.
        frame_id: Some(vec![serde_json::Value::Number(serde_json::Number::from(entry.id))]),
        depth: Some(entry.depth),
        visual_depth: Some(entry.depth),
        internal_parent_id: None,
        is_internal_call: None,
        is_internal_return: None,
        is_leaf_call: None,
        has_children: Some(true), // Entry rows always have children (the opcodes within)
        child_end_id: None,       // Will be computed by hierarchy pass
        first_snapshot_id: entry.first_snapshot_id,
        external_parent_trace_id: entry.parent_id.map(|id| id as i64),
        entry_jumpdest: Some(true),
        is_confirmed_call: None,
        line: first_opcode_row.and_then(|row| row.line),
        source_file: first_opcode_row.and_then(|row| row.source_file.clone()),
        dest_source_file: None,
        dest_line: None,
        src_source_file: None,
        src_line: None,
        stack_depth: None,
        stack_top: None,
        storage_read: None,
        storage_write: None,
        jump_marker: None,
        dest_pc: None,
        dest_fn: None,
        jump_args_decoded: None,
        jump_args_origin: None,
        jump_args_truncated: None,
        jump_result: None,
        jump_result_source: None,
        entry_meta: Some(entry_meta),
        log_info: None,
        decoded_log: None,
        event_fallback: None,
        is_unverified_contract: Some(artifacts.get(&entry.code_address).is_none()),
        function_name: row_function_name
            .or_else(|| first_opcode_row.and_then(|row| row.function_name.clone())),
        contract: target_contract_name,
    }
}

/// Format the call type of a trace entry as a stable human-readable string.
fn format_call_type(entry: &TraceEntry) -> String {
    use edb_common::types::CallType;
    use revm::context::CreateScheme;
    use revm::interpreter::CallScheme;
    match &entry.call_type {
        CallType::Call(CallScheme::Call) => "CALL".to_string(),
        CallType::Call(CallScheme::CallCode) => "CALLCODE".to_string(),
        CallType::Call(CallScheme::DelegateCall) => "DELEGATECALL".to_string(),
        CallType::Call(CallScheme::StaticCall) => "STATICCALL".to_string(),
        CallType::Create(CreateScheme::Create) => "CREATE".to_string(),
        CallType::Create(CreateScheme::Create2 { .. }) => "CREATE2".to_string(),
        CallType::Create(CreateScheme::Custom { .. }) => "CREATE".to_string(),
    }
}

/// Decode the function selector and arguments from calldata using ABI.
///
/// Fix 3: Tries code_address first, then target address, then all artifacts
/// to find a matching function selector (handles proxy/diamond patterns).
fn decode_entry_calldata(
    entry: &TraceEntry,
    artifacts: &HashMap<Address, Artifact>,
) -> (Option<String>, Option<String>, Vec<RenderedArg>, Vec<RenderedArgType>) {
    let input = &entry.input;

    // Need at least 4 bytes for a selector
    if input.len() < 4 {
        return (None, None, vec![], vec![]);
    }

    let selector = format!("0x{}", hex::encode(&input[..4]));

    // Try to find the function in the contract ABI.
    // Order: code_address (implementation) → target (proxy) → all artifacts (diamond facets)
    let addresses_to_try: Vec<&Address> = {
        let mut addrs = Vec::with_capacity(3);
        addrs.push(&entry.code_address);
        if entry.target != entry.code_address {
            addrs.push(&entry.target);
        }
        addrs
    };

    // Try primary addresses first
    for addr in &addresses_to_try {
        if let Some(result) = try_decode_from_artifact(addr, input, entry, artifacts) {
            return result;
        }
    }

    // Fallback: scan all artifacts for matching selector (handles diamond facets
    // where the function lives in a facet contract not directly referenced)
    for (addr, _) in artifacts.iter() {
        if addresses_to_try.contains(&addr) {
            continue; // Already tried
        }
        if let Some(result) = try_decode_from_artifact(addr, input, entry, artifacts) {
            return result;
        }
    }

    (Some(selector), None, vec![], vec![])
}

/// Try to decode calldata using a specific artifact's ABI.
fn try_decode_from_artifact(
    addr: &Address,
    input: &[u8],
    entry: &TraceEntry,
    artifacts: &HashMap<Address, Artifact>,
) -> Option<(Option<String>, Option<String>, Vec<RenderedArg>, Vec<RenderedArgType>)> {
    let artifact = artifacts.get(addr)?;
    let contract = artifact.contract()?;
    let abi = contract.abi.as_ref()?;

    for func in abi.functions() {
        if func.selector().as_slice() == &input[..4] {
            let selector = format!("0x{}", hex::encode(&input[..4]));
            let function_name = format!(
                "{}({})",
                func.name,
                func.inputs.iter().map(|param| param.ty.clone()).collect::<Vec<_>>().join(",")
            );
            let decoded_args = decode_function_args(func, &input[4..]);
            let decoded_outputs = entry
                .result
                .as_ref()
                .and_then(|r| match r {
                    CallResult::Success { output, .. } => Some(output.as_ref()),
                    _ => None,
                })
                .map(|output| decode_function_outputs(func, output))
                .unwrap_or_default();

            return Some((Some(selector), Some(function_name), decoded_args, decoded_outputs));
        }
    }

    None
}

/// Decode function input arguments using alloy ABI decoding.
fn decode_function_args(func: &alloy_json_abi::Function, calldata: &[u8]) -> Vec<RenderedArg> {
    use alloy_dyn_abi::DynSolType;

    // All-or-nothing: if any param type fails to parse, skip decoding entirely
    // to avoid misaligned arg indexing
    let param_types: Result<Vec<DynSolType>, _> =
        func.inputs.iter().map(|p| DynSolType::parse(&canonical_abi_type(p))).collect();
    let param_types = match param_types {
        Ok(types) => types,
        Err(_) => return vec![],
    };

    if param_types.is_empty() || calldata.is_empty() {
        return vec![];
    }

    let tuple_type = DynSolType::Tuple(param_types);
    match tuple_type.abi_decode(calldata) {
        Ok(decoded) => {
            if let alloy_dyn_abi::DynSolValue::Tuple(values) = decoded {
                values
                    .into_iter()
                    .enumerate()
                    .map(|(idx, val)| {
                        let param = func.inputs.get(idx);
                        RenderedArg {
                            name: param.map(|p| p.name.clone()).unwrap_or_default(),
                            value: format_sol_value(&val),
                        }
                    })
                    .collect()
            } else {
                vec![]
            }
        }
        Err(_) => vec![],
    }
}

/// Decode function output type descriptors.
fn decode_function_outputs(
    func: &alloy_json_abi::Function,
    _output: &[u8],
) -> Vec<RenderedArgType> {
    func.outputs.iter().map(to_rendered_arg_type).collect()
}

fn to_rendered_arg_type(param: &alloy_json_abi::Param) -> RenderedArgType {
    let components = if param.components.is_empty() {
        None
    } else {
        Some(param.components.iter().map(to_rendered_arg_type).collect())
    };
    RenderedArgType { name: param.name.clone(), ty: param.ty.clone(), components }
}

/// Build a canonical ABI type string, including tuple component shapes.
///
/// Examples:
/// - `uint256` -> `uint256`
/// - `tuple` with `(uint256,address)` -> `(uint256,address)`
/// - `tuple[]` with `(uint256,address)` -> `(uint256,address)[]`
fn canonical_abi_type(param: &alloy_json_abi::Param) -> String {
    if !param.ty.starts_with("tuple") {
        return param.ty.clone();
    }
    let tuple_suffix = &param.ty["tuple".len()..];
    let inner = param.components.iter().map(canonical_abi_type).collect::<Vec<_>>().join(",");
    format!("({inner}){tuple_suffix}")
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, U256};
    use edb_common::types::RenderedArgType;

    use super::{canonical_abi_type, decode_function_args, decode_function_outputs};

    #[test]
    fn decode_function_outputs_keeps_tuple_components() {
        let func: alloy_json_abi::Function = serde_json::from_value(serde_json::json!({
            "type": "function",
            "name": "getItemType",
            "inputs": [{ "name": "_itemId", "type": "uint256" }],
            "outputs": [{
                "name": "itemType_",
                "type": "tuple",
                "components": [
                    { "name": "name", "type": "string" },
                    { "name": "ghstPrice", "type": "uint256" },
                    { "name": "allowedCollateralTypes", "type": "uint8[]" }
                ]
            }]
        }))
        .expect("valid function abi");

        let outputs = decode_function_outputs(&func, &[]);
        assert_eq!(outputs.len(), 1);
        let item_type = &outputs[0];
        assert_eq!(item_type.name, "itemType_");
        assert_eq!(item_type.ty, "tuple");
        let components = item_type.components.as_ref().expect("tuple components");
        assert_eq!(
            components.iter().map(|c| (c.name.as_str(), c.ty.as_str())).collect::<Vec<_>>(),
            vec![
                ("name", "string"),
                ("ghstPrice", "uint256"),
                ("allowedCollateralTypes", "uint8[]"),
            ]
        );
    }

    #[test]
    fn canonical_abi_type_expands_tuple_arrays() {
        let tuple_param: alloy_json_abi::Param = serde_json::from_value(serde_json::json!({
            "name": "items",
            "type": "tuple[]",
            "components": [
                { "name": "id", "type": "uint256" },
                { "name": "owner", "type": "address" },
                {
                    "name": "meta",
                    "type": "tuple",
                    "components": [
                        { "name": "active", "type": "bool" },
                        { "name": "tag", "type": "bytes32" }
                    ]
                }
            ]
        }))
        .expect("valid tuple param");

        let canonical = canonical_abi_type(&tuple_param);
        assert_eq!(canonical, "(uint256,address,(bool,bytes32))[]");
    }

    #[test]
    fn decode_function_args_handles_tuple_inputs() {
        let func: alloy_json_abi::Function = serde_json::from_value(serde_json::json!({
            "type": "function",
            "name": "setConfig",
            "inputs": [{
                "name": "cfg",
                "type": "tuple",
                "components": [
                    { "name": "admin", "type": "address" },
                    { "name": "threshold", "type": "uint256" }
                ]
            }],
            "outputs": []
        }))
        .expect("valid function abi");

        let tuple_value = alloy_dyn_abi::DynSolValue::Tuple(vec![
            alloy_dyn_abi::DynSolValue::Address(Address::from([0x11; 20])),
            alloy_dyn_abi::DynSolValue::Uint(U256::from(42u64), 256),
        ]);
        let calldata = tuple_value.abi_encode();

        let decoded = decode_function_args(&func, &calldata);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, "cfg");
        assert!(
            decoded[0].value.contains("0x1111111111111111111111111111111111111111"),
            "decoded tuple should include address, got: {}",
            decoded[0].value
        );
        assert!(
            decoded[0].value.contains("42"),
            "decoded tuple should include uint value, got: {}",
            decoded[0].value
        );
    }

    #[test]
    fn rendered_arg_type_roundtrip_with_components() {
        let output = RenderedArgType {
            name: "itemType_".to_string(),
            ty: "tuple".to_string(),
            components: Some(vec![
                RenderedArgType {
                    name: "name".to_string(),
                    ty: "string".to_string(),
                    components: None,
                },
                RenderedArgType {
                    name: "allowances".to_string(),
                    ty: "uint256[]".to_string(),
                    components: None,
                },
            ]),
        };

        let json = serde_json::to_string(&output).expect("serialize");
        assert!(json.contains("\"components\""));
        assert!(json.contains("\"type\":\"tuple\""));
        let de: RenderedArgType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(de.components.as_ref().map(|c| c.len()), Some(2));
    }
}

/// Format a DynSolValue into a human-readable string.
fn format_sol_value(val: &alloy_dyn_abi::DynSolValue) -> String {
    use alloy_dyn_abi::DynSolValue;
    match val {
        DynSolValue::Bool(b) => b.to_string(),
        DynSolValue::Int(v, _) => v.to_string(),
        DynSolValue::Uint(v, _) => v.to_string(),
        DynSolValue::FixedBytes(v, _) => format!("0x{}", hex::encode(v)),
        DynSolValue::Address(a) => format!("{a}"),
        DynSolValue::Function(f) => format!("0x{}", hex::encode(f)),
        DynSolValue::Bytes(b) => format!("0x{}", hex::encode(b)),
        DynSolValue::String(s) => s.clone(),
        DynSolValue::Array(arr) => {
            let items: Vec<String> = arr.iter().map(format_sol_value).collect();
            format!("[{}]", items.join(", "))
        }
        DynSolValue::FixedArray(arr) => {
            let items: Vec<String> = arr.iter().map(format_sol_value).collect();
            format!("[{}]", items.join(", "))
        }
        DynSolValue::Tuple(vals) => {
            let items: Vec<String> = vals.iter().map(format_sol_value).collect();
            format!("({})", items.join(", "))
        }
        _ => format!("{val:?}"),
    }
}
