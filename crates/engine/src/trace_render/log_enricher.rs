// EDB - Trace Render: Log Enricher
// Decodes LOG opcode rows by matching them to trace entry events and using ABI.
// Replaces the decodeLogWithFallback logic from eventDecoding.ts.
//
// Strategy:
//   1. For each LOG row, find its trace entry and match against the entry's events
//      by topic0 signature (events are already captured by the EDB engine).
//   2. If a matching event is found, decode indexed args from topics and use the
//      ABI event definition for parameter names.
//   3. Fallback: common ERC-20/ERC-721/ERC-1155 signatures.

use std::collections::HashMap;

use alloy_primitives::{Address, B256};
use edb_common::types::{RenderedDecodedLog, RenderedLogArg, RenderedTraceRow, Trace};

use crate::Artifact;

/// Common ERC-20/ERC-721 event signatures (keccak256 of the event signature).
const TRANSFER_SIG: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const APPROVAL_SIG: &str = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
const TRANSFER_SINGLE_SIG: &str =
    "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62";
const TRANSFER_BATCH_SIG: &str =
    "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb";

/// Enrich LOG rows with decoded event information.
///
/// For each LOG row, tries to:
///   1. Match against trace entry events (highest fidelity — uses real emitted data)
///   2. Decode using contract ABI events
///   3. Fallback to common ERC-20/ERC-721/ERC-1155 event signatures
pub fn enrich_log_rows(
    rows: &mut [RenderedTraceRow],
    trace: &Trace,
    artifacts: &HashMap<Address, Artifact>,
) {
    // Build trace_entry_id → TraceEntry lookup
    let trace_entries: Vec<_> = trace.iter().collect();

    // Track how many LOG opcodes we've seen per trace_entry_id
    // so we can match them positionally to the entry's events list
    let mut log_count_per_entry: HashMap<usize, usize> = HashMap::new();
    // Per-entry fallback cursor keyed by (trace_entry_id, topic0).
    let mut topic_cursor_per_entry: HashMap<(usize, B256), usize> = HashMap::new();
    // Global fallback index: topic0 -> [(trace_entry_index, event_index)] in trace order.
    let mut events_by_topic: HashMap<B256, Vec<(usize, usize)>> = HashMap::new();
    for (entry_idx, entry) in trace_entries.iter().enumerate() {
        for (event_idx, event) in entry.events.iter().enumerate() {
            if let Some(topic0) = event.topics().first().copied() {
                events_by_topic.entry(topic0).or_default().push((entry_idx, event_idx));
            }
        }
    }
    let mut global_topic_cursor: HashMap<B256, usize> = HashMap::new();

    for row in rows.iter_mut() {
        if !row.name.starts_with("LOG") {
            continue;
        }

        // Find the trace entry for this row
        let trace_entry_id = match row.trace_id {
            Some(tid) => tid,
            None => continue,
        };
        let trace_entry = trace_entries.get(trace_entry_id);

        // Always increment LOG counter for this trace entry, even if log_info is missing.
        // This prevents positional desync when a LOG row lacks log_info.
        let log_idx = *log_count_per_entry.entry(trace_entry_id).or_insert(0);
        *log_count_per_entry.get_mut(&trace_entry_id).unwrap() += 1;

        let log_info = match &row.log_info {
            Some(li) => li,
            None => continue,
        };

        // Get topic0 for ABI matching
        let topic0 = log_info.topics.first().and_then(|t| match t {
            serde_json::Value::String(s) => Some(s.clone()),
            _ => None,
        });
        let topic0_b256 = topic0.as_deref().and_then(parse_topic0);

        // Try to match against the trace entry's events by position
        let matched_event = trace_entry.and_then(|entry| entry.events.get(log_idx));

        // Strategy 1: Decode using matched trace entry event + ABI
        if let (Some(event), Some(entry)) = (matched_event, trace_entry) {
            let event_topic0 = event.topics().first().copied();
            if let Some(decoded) = event_topic0.and_then(|t0| {
                try_decode_event_with_topics(
                    t0,
                    event.topics(),
                    &event.data,
                    &entry.code_address,
                    &entry.target,
                    artifacts,
                )
            }) {
                row.decoded_log = Some(decoded);
                continue;
            }
        }

        // Strategy 1b: same-trace-entry fallback by topic0 (when positional alignment drifts).
        if let (Some(entry), Some(t0)) = (trace_entry, topic0_b256) {
            let entry_key = (trace_entry_id, t0);
            let start_idx = *topic_cursor_per_entry.get(&entry_key).unwrap_or(&0);
            let candidate = entry
                .events
                .iter()
                .enumerate()
                .skip(start_idx)
                .find(|(_, event)| event.topics().first().copied() == Some(t0));
            if let Some((event_idx, event)) = candidate {
                if let Some(decoded) = try_decode_event_with_topics(
                    t0,
                    event.topics(),
                    &event.data,
                    &entry.code_address,
                    &entry.target,
                    artifacts,
                ) {
                    topic_cursor_per_entry.insert(entry_key, event_idx + 1);
                    row.decoded_log = Some(decoded);
                    continue;
                }
            }
        }

        // Strategy 1c: global fallback by topic0 (handles trace_id/event attribution drift).
        if let Some(t0) = topic0_b256 {
            if let Some(candidates) = events_by_topic.get(&t0) {
                let cursor = *global_topic_cursor.get(&t0).unwrap_or(&0);
                if let Some((entry_idx, event_idx)) = candidates.get(cursor).copied() {
                    if let Some(entry) = trace_entries.get(entry_idx) {
                        if let Some(event) = entry.events.get(event_idx) {
                            if let Some(decoded) = try_decode_event_with_topics(
                                t0,
                                event.topics(),
                                &event.data,
                                &entry.code_address,
                                &entry.target,
                                artifacts,
                            ) {
                                global_topic_cursor.insert(t0, cursor + 1);
                                row.decoded_log = Some(decoded);
                                continue;
                            }
                        }
                    }
                }
            }
        }

        // Strategy 2: Decode from log_info topics using ABI
        if let Some(ref topic0_str) = topic0 {
            let code_address = trace_entry.map(|e| e.code_address);
            let target_address = trace_entry.map(|e| e.target);

            let decoded = code_address
                .and_then(|addr| {
                    try_decode_event_name(topic0_str, &addr, &log_info.topics, artifacts)
                })
                .or_else(|| {
                    target_address.and_then(|addr| {
                        try_decode_event_name(topic0_str, &addr, &log_info.topics, artifacts)
                    })
                })
                .or_else(|| {
                    for (addr, _) in artifacts.iter() {
                        if let Some(d) =
                            try_decode_event_name(topic0_str, addr, &log_info.topics, artifacts)
                        {
                            return Some(d);
                        }
                    }
                    None
                })
                .or_else(|| decode_common_event(topic0_str, &log_info.topics));

            if let Some(decoded) = decoded {
                row.decoded_log = Some(decoded);
                continue;
            }
        }

        // Strategy 3: Common event signatures from log_info topics
        if let Some(ref topic0_str) = topic0 {
            if let Some(decoded) = decode_common_event(topic0_str, &log_info.topics) {
                row.decoded_log = Some(decoded);
            }
        }
    }
}

fn parse_topic0(topic0: &str) -> Option<B256> {
    let clean = topic0.strip_prefix("0x").unwrap_or(topic0);
    let bytes = hex::decode(clean).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    Some(B256::from_slice(&bytes))
}

/// Decode an event using actual emitted topics and data + ABI.
/// This is the highest fidelity path since we have the real log data from execution.
fn try_decode_event_with_topics(
    topic0: B256,
    topics: &[B256],
    data: &alloy_primitives::Bytes,
    code_address: &Address,
    target_address: &Address,
    artifacts: &HashMap<Address, Artifact>,
) -> Option<RenderedDecodedLog> {
    // Try code_address first, then target
    for addr in [code_address, target_address] {
        if let Some(decoded) = try_decode_with_abi(topic0, topics, data, addr, artifacts) {
            return Some(decoded);
        }
    }
    // Scan all artifacts
    for (addr, _) in artifacts.iter() {
        if addr != code_address && addr != target_address {
            if let Some(decoded) = try_decode_with_abi(topic0, topics, data, addr, artifacts) {
                return Some(decoded);
            }
        }
    }
    // Common event fallback with B256 topics
    let topic_strs: Vec<serde_json::Value> =
        topics.iter().map(|t| serde_json::Value::String(format!("{t:#066x}"))).collect();
    decode_common_event(&format!("{topic0:#066x}"), &topic_strs)
}

/// Try to decode an event using a specific artifact's ABI with real topic/data.
fn try_decode_with_abi(
    topic0: B256,
    topics: &[B256],
    data: &alloy_primitives::Bytes,
    addr: &Address,
    artifacts: &HashMap<Address, Artifact>,
) -> Option<RenderedDecodedLog> {
    use alloy_dyn_abi::DynSolType;

    let artifact = artifacts.get(addr)?;
    let contract = artifact.contract()?;
    let abi = contract.abi.as_ref()?;

    for event in abi.events() {
        if event.selector() != topic0 {
            continue;
        }

        // Pre-decode non-indexed args from data so we can interleave in ABI order
        let non_indexed: Vec<_> = event.inputs.iter().filter(|i| !i.indexed).collect();
        let decoded_data_values: Vec<alloy_dyn_abi::DynSolValue> = if !non_indexed.is_empty()
            && !data.is_empty()
        {
            let param_types: Result<Vec<DynSolType>, _> =
                non_indexed.iter().map(|p| DynSolType::parse(p.selector_type().as_ref())).collect();
            if let Ok(types) = param_types {
                let tuple_type = DynSolType::Tuple(types);
                if let Ok(decoded) = tuple_type.abi_decode(data) {
                    if let alloy_dyn_abi::DynSolValue::Tuple(values) = decoded {
                        values
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        // Build args in ABI declaration order (not indexed-first)
        let mut args = Vec::new();
        let mut topic_idx = 1; // Skip topic0 (event selector)
        let mut data_idx = 0;

        for input in &event.inputs {
            if input.indexed {
                // Indexed args come from topics
                let val = if topic_idx < topics.len() {
                    let topic = topics[topic_idx];
                    topic_idx += 1;
                    if input.ty == "address" {
                        let addr_bytes = &topic.0[12..]; // Last 20 bytes
                        format!("0x{}", hex::encode(addr_bytes))
                    } else if input.ty == "bool" {
                        if topic.is_zero() {
                            "false".to_string()
                        } else {
                            "true".to_string()
                        }
                    } else if input.ty.starts_with("uint") || input.ty.starts_with("int") {
                        let u = alloy_primitives::U256::from_be_bytes(topic.0);
                        u.to_string()
                    } else {
                        format!("{topic:#x}")
                    }
                } else {
                    "?".to_string()
                };
                args.push(RenderedLogArg {
                    name: if input.name.is_empty() {
                        serde_json::Value::Number(serde_json::Number::from(args.len()))
                    } else {
                        serde_json::Value::String(input.name.clone())
                    },
                    value: val,
                });
            } else {
                // Non-indexed args from pre-decoded data
                let val = decoded_data_values
                    .get(data_idx)
                    .map(|v| format_event_input_value(v, input))
                    .unwrap_or_else(|| format!("[data] ({})", input.ty));
                data_idx += 1;
                args.push(RenderedLogArg {
                    name: if input.name.is_empty() {
                        serde_json::Value::Number(serde_json::Number::from(args.len()))
                    } else {
                        serde_json::Value::String(input.name.clone())
                    },
                    value: val,
                });
            }
        }

        return Some(RenderedDecodedLog {
            name: event.name.clone(),
            args,
            source: "call-event".to_string(),
            truncated: None,
        });
    }

    None
}

/// Try to decode an event name and indexed args from topic hex strings using ABI.
fn try_decode_event_name(
    topic0: &str,
    addr: &Address,
    topics: &[serde_json::Value],
    artifacts: &HashMap<Address, Artifact>,
) -> Option<RenderedDecodedLog> {
    let artifact = artifacts.get(addr)?;
    let contract = artifact.contract()?;
    let abi = contract.abi.as_ref()?;

    let topic0_clean = topic0.strip_prefix("0x").unwrap_or(topic0);
    let topic0_bytes = hex::decode(topic0_clean).ok()?;
    if topic0_bytes.len() != 32 {
        return None;
    }
    let topic0_b256 = B256::from_slice(&topic0_bytes);

    for event in abi.events() {
        if event.selector() != topic0_b256 {
            continue;
        }

        let mut args = Vec::new();
        let mut topic_idx = 1;

        for input in &event.inputs {
            if input.indexed && topic_idx < topics.len() {
                let val = format_topic_value(&topics[topic_idx], &input.ty);
                topic_idx += 1;
                args.push(RenderedLogArg {
                    name: if input.name.is_empty() {
                        serde_json::Value::Number(serde_json::Number::from(args.len()))
                    } else {
                        serde_json::Value::String(input.name.clone())
                    },
                    value: val,
                });
            } else if !input.indexed {
                args.push(RenderedLogArg {
                    name: if input.name.is_empty() {
                        serde_json::Value::Number(serde_json::Number::from(args.len()))
                    } else {
                        serde_json::Value::String(input.name.clone())
                    },
                    value: format!("[data] ({})", input.ty),
                });
            }
        }

        return Some(RenderedDecodedLog {
            name: event.name.clone(),
            args,
            source: "abi".to_string(),
            truncated: None,
        });
    }

    None
}

/// Decode common ERC-20/ERC-721/ERC-1155 events by their well-known topic0 signatures.
fn decode_common_event(topic0: &str, topics: &[serde_json::Value]) -> Option<RenderedDecodedLog> {
    let topic0_lower = topic0.to_lowercase();

    if topic0_lower == TRANSFER_SIG {
        let mut args = Vec::new();
        if topics.len() > 1 {
            args.push(RenderedLogArg {
                name: serde_json::Value::String("from".to_string()),
                value: format_topic_as_address(&topics[1]),
            });
        }
        if topics.len() > 2 {
            args.push(RenderedLogArg {
                name: serde_json::Value::String("to".to_string()),
                value: format_topic_as_address(&topics[2]),
            });
        }
        return Some(RenderedDecodedLog {
            name: "Transfer".to_string(),
            args,
            source: "common-abi".to_string(),
            truncated: None,
        });
    }

    if topic0_lower == APPROVAL_SIG {
        let mut args = Vec::new();
        if topics.len() > 1 {
            args.push(RenderedLogArg {
                name: serde_json::Value::String("owner".to_string()),
                value: format_topic_as_address(&topics[1]),
            });
        }
        if topics.len() > 2 {
            args.push(RenderedLogArg {
                name: serde_json::Value::String("spender".to_string()),
                value: format_topic_as_address(&topics[2]),
            });
        }
        return Some(RenderedDecodedLog {
            name: "Approval".to_string(),
            args,
            source: "common-abi".to_string(),
            truncated: None,
        });
    }

    if topic0_lower == TRANSFER_SINGLE_SIG {
        let mut args = Vec::new();
        if topics.len() > 1 {
            args.push(RenderedLogArg {
                name: serde_json::Value::String("operator".to_string()),
                value: format_topic_as_address(&topics[1]),
            });
        }
        if topics.len() > 2 {
            args.push(RenderedLogArg {
                name: serde_json::Value::String("from".to_string()),
                value: format_topic_as_address(&topics[2]),
            });
        }
        if topics.len() > 3 {
            args.push(RenderedLogArg {
                name: serde_json::Value::String("to".to_string()),
                value: format_topic_as_address(&topics[3]),
            });
        }
        return Some(RenderedDecodedLog {
            name: "TransferSingle".to_string(),
            args,
            source: "common-abi".to_string(),
            truncated: None,
        });
    }

    if topic0_lower == TRANSFER_BATCH_SIG {
        let mut args = Vec::new();
        if topics.len() > 1 {
            args.push(RenderedLogArg {
                name: serde_json::Value::String("operator".to_string()),
                value: format_topic_as_address(&topics[1]),
            });
        }
        if topics.len() > 2 {
            args.push(RenderedLogArg {
                name: serde_json::Value::String("from".to_string()),
                value: format_topic_as_address(&topics[2]),
            });
        }
        if topics.len() > 3 {
            args.push(RenderedLogArg {
                name: serde_json::Value::String("to".to_string()),
                value: format_topic_as_address(&topics[3]),
            });
        }
        return Some(RenderedDecodedLog {
            name: "TransferBatch".to_string(),
            args,
            source: "common-abi".to_string(),
            truncated: None,
        });
    }

    None
}

/// Format a topic value based on the expected type.
fn format_topic_value(topic: &serde_json::Value, ty: &str) -> String {
    match topic {
        serde_json::Value::String(s) => {
            if ty == "address" {
                format_topic_as_address(topic)
            } else if ty == "bool" {
                let hex = s.strip_prefix("0x").unwrap_or(s);
                if hex.chars().all(|c| c == '0') {
                    "false".to_string()
                } else {
                    "true".to_string()
                }
            } else if ty.starts_with("uint") || ty.starts_with("int") {
                let hex = s.strip_prefix("0x").unwrap_or(s);
                if let Ok(bytes) = hex::decode(hex) {
                    if bytes.len() == 32 {
                        let u =
                            alloy_primitives::U256::from_be_bytes::<32>(bytes.try_into().unwrap());
                        return u.to_string();
                    }
                }
                s.clone()
            } else {
                s.clone()
            }
        }
        _ => format!("{topic}"),
    }
}

/// Format a topic value as an Ethereum address (take last 20 bytes of 32-byte topic).
fn format_topic_as_address(topic: &serde_json::Value) -> String {
    match topic {
        serde_json::Value::String(s) => {
            let hex = s.strip_prefix("0x").unwrap_or(s);
            if hex.len() >= 40 {
                let addr_hex = &hex[hex.len() - 40..];
                format!("0x{addr_hex}")
            } else {
                s.clone()
            }
        }
        _ => format!("{topic}"),
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

/// Format an event input value using its ABI parameter shape.
///
/// For tuple and tuple-array inputs, this produces JSON with named fields so
/// the frontend can render nested data structures instead of opaque placeholders.
fn format_event_input_value(
    val: &alloy_dyn_abi::DynSolValue,
    input: &alloy_json_abi::EventParam,
) -> String {
    if !input.ty.starts_with("tuple") {
        return format_sol_value(val);
    }

    let json = format_value_with_components_as_json(val, &input.ty, &input.components);
    serde_json::to_string(&json).unwrap_or_else(|_| format_sol_value(val))
}

fn format_value_with_components_as_json(
    val: &alloy_dyn_abi::DynSolValue,
    ty: &str,
    components: &[alloy_json_abi::Param],
) -> serde_json::Value {
    use alloy_dyn_abi::DynSolValue;

    let tuple_suffix = ty.strip_prefix("tuple").unwrap_or("");
    let is_tuple = ty.starts_with("tuple");
    let is_tuple_array = is_tuple && tuple_suffix.starts_with('[');

    if is_tuple_array {
        return match val {
            DynSolValue::Array(values) | DynSolValue::FixedArray(values) => {
                serde_json::Value::Array(
                    values
                        .iter()
                        .map(|entry| format_tuple_value_as_json(entry, components))
                        .collect(),
                )
            }
            _ => serde_json::Value::String(format_sol_value(val)),
        };
    }

    if is_tuple {
        return format_tuple_value_as_json(val, components);
    }

    match val {
        DynSolValue::Array(values) | DynSolValue::FixedArray(values) => serde_json::Value::Array(
            values.iter().map(|entry| serde_json::Value::String(format_sol_value(entry))).collect(),
        ),
        _ => serde_json::Value::String(format_sol_value(val)),
    }
}

fn format_tuple_value_as_json(
    val: &alloy_dyn_abi::DynSolValue,
    components: &[alloy_json_abi::Param],
) -> serde_json::Value {
    use alloy_dyn_abi::DynSolValue;

    let DynSolValue::Tuple(values) = val else {
        return serde_json::Value::String(format_sol_value(val));
    };
    if components.is_empty() {
        return serde_json::Value::String(format_sol_value(val));
    }

    let mut obj = serde_json::Map::with_capacity(components.len());
    for (idx, component) in components.iter().enumerate() {
        let key =
            if component.name.is_empty() { format!("field{idx}") } else { component.name.clone() };
        let value = values.get(idx).map_or(serde_json::Value::Null, |entry| {
            format_value_with_components_as_json(entry, &component.ty, &component.components)
        });
        obj.insert(key, value);
    }

    serde_json::Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use alloy_dyn_abi::DynSolValue;
    use alloy_primitives::{Address, U256};

    use super::format_event_input_value;

    #[test]
    fn tuple_event_arg_formats_with_named_fields() {
        let input = alloy_json_abi::EventParam {
            ty: "tuple".to_string(),
            name: "tokenTranfer".to_string(),
            indexed: false,
            components: vec![
                alloy_json_abi::Param {
                    ty: "address".to_string(),
                    name: "token".to_string(),
                    components: vec![],
                    internal_type: None,
                },
                alloy_json_abi::Param {
                    ty: "uint256".to_string(),
                    name: "amount".to_string(),
                    components: vec![],
                    internal_type: None,
                },
            ],
            internal_type: None,
        };

        let token = Address::from_slice(
            &hex::decode("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").expect("valid hex"),
        );
        let tuple_value = DynSolValue::Tuple(vec![
            DynSolValue::Address(token),
            DynSolValue::Uint(U256::from(14854970008800000u128), 256),
        ]);

        let formatted = format_event_input_value(&tuple_value, &input);
        let parsed: serde_json::Value = serde_json::from_str(&formatted).expect("valid json");
        assert_eq!(parsed["amount"], "14854970008800000");
        let token = parsed["token"].as_str().expect("token string");
        assert_eq!(token.to_lowercase(), "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
    }
}
