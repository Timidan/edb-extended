// EDB - Trace Render: Hierarchy
// Computes childEndId, visualDepth, hasChildren, isLeafCall, and internalParentId.
//
// Critical parity note:
// Legacy FE logic derived internal call hierarchy from FULL opcode rows before filtering.
// A filtered-only pass loses return/context signals and flattens rails.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use edb_common::types::{RenderedRowKind, RenderedTraceRow};

#[derive(Debug, Clone, Copy)]
struct InternalCallInfo {
    end_snapshot: usize,
    has_nested_calls: bool,
    has_child_opcodes: bool,
}

#[derive(Debug, Default)]
struct InternalAnalysis {
    // snapshot_id -> nearest parent internal-call snapshot_id (or None when no parent)
    parent_by_snapshot: HashMap<usize, Option<usize>>,
    // internal-call start snapshot_id -> info
    call_info_by_snapshot: HashMap<usize, InternalCallInfo>,
    // internal-call start snapshot_id -> call metadata
    call_meta_by_snapshot: HashMap<usize, InternalCallMeta>,
    // opcode snapshots in execution order with trace/frame metadata
    op_rows: Vec<OpMeta>,
    // sid-sorted helpers need this copy; stack analysis and entry anchoring
    // should use execution order to avoid sid-order drift.
    op_rows_exec: Vec<OpMeta>,
    // trace_id -> first opcode EXECUTION index in that frame
    first_opcode_exec_index_by_trace: HashMap<usize, usize>,
}

#[derive(Debug, Clone)]
struct OpMeta {
    sid: usize,
    trace_id: Option<usize>,
    name: String,
    has_line: bool,
    line: Option<usize>,
    source_file: Option<String>,
    fn_name: Option<String>,
    is_internal_return: bool,
    is_internal_call: bool,
}

#[derive(Debug, Clone)]
struct InternalCallMeta {
    start_fn: String,
    caller_fn: Option<String>,
    frame_trace_id: Option<usize>,
}

/// Compute hierarchy information for final filtered rows.
///
/// `full_rows` must be the pre-filter row set (after jump detection).
pub fn compute_hierarchy(rows: &mut [RenderedTraceRow], full_rows: &[RenderedTraceRow]) {
    // Keep existing external frame range behavior.
    compute_child_end_ids(rows);

    // Derive internal call parent/child relationships from full rows, then project.
    let internal_analysis = analyze_internal_hierarchy(full_rows);
    project_internal_hierarchy(rows, &internal_analysis);

    // Recompute depth using projected internal parents to restore nested rails.
    compute_visual_depth(rows);
    recompute_internal_ranges_by_visual_depth(rows);
    apply_internal_call_gas(rows, full_rows, &internal_analysis);
    compute_has_children(rows);
    mark_leaf_calls(rows);
}

fn snapshot_id(row: &RenderedTraceRow) -> Option<usize> {
    row.first_snapshot_id.or_else(|| usize::try_from(row.id).ok())
}

fn normalize_fn_name(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    let without_args = raw.split('(').next().unwrap_or(raw).trim();
    let last_segment = without_args.rsplit('.').next().unwrap_or(without_args).trim();
    if last_segment.is_empty() {
        None
    } else {
        Some(last_segment.to_string())
    }
}

fn is_contract_or_library_name(name: &str) -> bool {
    let n = name.trim();
    if n.is_empty() {
        return false;
    }
    let starts_upper = n.chars().next().is_some_and(|c| c.is_ascii_uppercase());
    let looks_contract = n.contains("Diamond")
        || n.contains("Facet")
        || n.contains("Storage")
        || n.contains("Contract")
        || n.contains("Interface")
        || n.starts_with("Lib");
    let looks_erc = n.starts_with("ERC") || n.starts_with("IERC");
    looks_contract || looks_erc || starts_upper
}

fn analyze_internal_hierarchy(full_rows: &[RenderedTraceRow]) -> InternalAnalysis {
    let mut analysis = InternalAnalysis::default();
    let mut internal_call_meta_by_sid: HashMap<usize, InternalCallMeta> = HashMap::new();

    for row in full_rows {
        if row.kind == RenderedRowKind::Entry {
            continue;
        }
        // Derive hierarchy from opcode rows only; entry rows are projected later.
        if row.kind != RenderedRowKind::Opcode {
            continue;
        }

        let Some(sid) = snapshot_id(row) else {
            continue;
        };
        let row_trace_id = row.trace_id;
        let row_fn = normalize_fn_name(row.function_name.as_deref());

        let exec_idx = analysis.op_rows.len();
        analysis.op_rows.push(OpMeta {
            sid,
            trace_id: row_trace_id,
            name: row.name.clone(),
            has_line: row.line.is_some(),
            line: row.line,
            source_file: row.source_file.clone(),
            fn_name: row_fn.clone(),
            is_internal_return: row.is_internal_return.unwrap_or(false),
            is_internal_call: row.is_internal_call.unwrap_or(false),
        });
        if let Some(trace_id) = row_trace_id {
            analysis.first_opcode_exec_index_by_trace.entry(trace_id).or_insert(exec_idx);
        }

        if row.is_internal_call.unwrap_or(false) {
            let start_fn = normalize_fn_name(row.dest_fn.as_deref())
                .or_else(|| row.dest_fn.clone())
                .unwrap_or_default();
            let caller_fn = row_fn.clone();
            internal_call_meta_by_sid.insert(
                sid,
                InternalCallMeta { start_fn, caller_fn, frame_trace_id: row_trace_id },
            );
            if let Some(meta) = internal_call_meta_by_sid.get(&sid).cloned() {
                analysis.call_meta_by_snapshot.insert(sid, meta);
            }
            analysis.call_info_by_snapshot.entry(sid).or_insert(InternalCallInfo {
                end_snapshot: sid,
                has_nested_calls: false,
                has_child_opcodes: false,
            });
        }
    }

    // Analyze push/pop in render/execution order. Snapshot IDs can be non-monotonic
    // across merged frame captures, and sid-order traversal can leak parents across
    // unrelated frames.
    analysis.op_rows_exec = analysis.op_rows.clone();
    let op_rows_exec = analysis.op_rows_exec.clone();
    // Keep a sid-ordered view for sid-range lookup helpers used by entry projection.
    analysis.op_rows.sort_by_key(|op| op.sid);
    let mut internal_stack: Vec<usize> = Vec::new();

    for (exec_idx, op) in op_rows_exec.iter().enumerate() {
        let sid = op.sid;
        let op_fn = op.fn_name.clone();

        // Keep internal-call stack anchored to explicit call/return signals.
        // Function-name transitions can legitimately occur within a still-open
        // internal call (modifiers/helpers), and aggressive fn-switch popping
        // flattens the expected parent/child rails.
        if let Some(current_trace_id) = op.trace_id {
            let is_frame_resume = analysis
                .first_opcode_exec_index_by_trace
                .get(&current_trace_id)
                .is_some_and(|first_idx| *first_idx != exec_idx);
            // When execution resumes in an already-open frame after an external
            // call returns, caller-side internals from the callee frame are stale.
            // Unwind those stale cross-frame parents but keep caller internals for
            // the resumed frame itself.
            if is_frame_resume {
                while let Some(top_sid) = internal_stack.last().copied() {
                    let top_frame = internal_call_meta_by_sid
                        .get(&top_sid)
                        .and_then(|meta| meta.frame_trace_id);
                    if top_frame == Some(current_trace_id) {
                        break;
                    }
                    internal_stack.pop();
                    if let Some(info) = analysis.call_info_by_snapshot.get_mut(&top_sid) {
                        info.end_snapshot = sid;
                    }
                }
            }
        }

        if let Some(call_meta) = internal_call_meta_by_sid.get(&sid) {
            let caller_fn_for_pop = call_meta.caller_fn.as_deref();
            let is_contract_name =
                caller_fn_for_pop.map(is_contract_or_library_name).unwrap_or(false);
            let this_frame = call_meta.frame_trace_id;
            let top_sid = internal_stack.last().copied();
            let top_frame = top_sid
                .and_then(|sid| internal_call_meta_by_sid.get(&sid))
                .and_then(|meta| meta.frame_trace_id);
            let same_frame = this_frame.is_some() && this_frame == top_frame;
            let top_start_is_contract = top_sid
                .and_then(|sid| internal_call_meta_by_sid.get(&sid))
                .map(|meta| is_contract_or_library_name(&meta.start_fn))
                .unwrap_or(false);
            let top_caller_matches = top_sid
                .and_then(|sid| internal_call_meta_by_sid.get(&sid))
                .and_then(|meta| meta.caller_fn.as_deref())
                == caller_fn_for_pop;
            // Same-frame mismatches can indicate stale parent edges around
            // facet/library wrapper transitions. Cross-frame transitions are
            // common in diamond/facet execution and should not auto-close
            // caller-side internal calls.
            let should_auto_pop =
                same_frame && ((!is_contract_name && top_start_is_contract) || top_caller_matches);

            if should_auto_pop {
                while let Some(top_sid) = internal_stack.last().copied() {
                    let Some(top_meta) = internal_call_meta_by_sid.get(&top_sid) else {
                        break;
                    };
                    let Some(caller_fn) = caller_fn_for_pop else {
                        break;
                    };
                    // Never auto-pop across trace/frame boundaries. Cross-frame
                    // transitions are expected around STATICCALL/DELEGATECALL legs
                    // and popping caller-side frames here flattens later rails.
                    if top_meta.frame_trace_id != this_frame {
                        break;
                    }
                    let top_start_mismatch = caller_fn != top_meta.start_fn;
                    let top_caller_match = top_meta.caller_fn.as_deref() == Some(caller_fn);
                    let top_is_contract = is_contract_or_library_name(&top_meta.start_fn);
                    let pop_contract_wrapper =
                        top_start_mismatch && !is_contract_name && top_is_contract;
                    let pop_stale_sibling = top_start_mismatch && top_caller_match;

                    if pop_contract_wrapper || pop_stale_sibling {
                        internal_stack.pop();
                        if let Some(info) = analysis.call_info_by_snapshot.get_mut(&top_sid) {
                            info.end_snapshot = sid;
                        }
                    } else {
                        break;
                    }
                }
            }

            let current_parent = internal_stack.last().copied();
            analysis.parent_by_snapshot.insert(sid, current_parent);
            if let Some(parent_sid) = current_parent {
                if let Some(parent_info) = analysis.call_info_by_snapshot.get_mut(&parent_sid) {
                    parent_info.has_nested_calls = true;
                }
            }
            internal_stack.push(sid);
        } else {
            let current_parent = internal_stack.last().copied();
            analysis.parent_by_snapshot.insert(sid, current_parent);
            if let Some(parent_sid) = current_parent {
                if let Some(parent_info) = analysis.call_info_by_snapshot.get_mut(&parent_sid) {
                    parent_info.has_child_opcodes = true;
                    if is_call_entry_opcode(&op.name) {
                        parent_info.has_nested_calls = true;
                    }
                }
            }
        }

        if matches!(op.name.as_str(), "JUMP" | "JUMPI") && op.is_internal_return {
            if let Some(top_sid) = internal_stack.last().copied() {
                if let Some(top_meta) = internal_call_meta_by_sid.get(&top_sid) {
                    let same_frame_return =
                        top_meta.frame_trace_id.is_some() && op.trace_id == top_meta.frame_trace_id;
                    let name_matches =
                        op_fn.as_deref().is_some_and(|current_fn| top_meta.start_fn == current_fn);
                    // Keep frame-only fallback narrow: contract/library wrapper frames
                    // (uppercase-ish names) may miss precise fn attribution, but
                    // regular internal functions should close on explicit name match.
                    let can_use_frame_fallback = is_contract_or_library_name(&top_meta.start_fn);
                    // Return attribution can be lossy in optimized/facet code.
                    // Treat same-frame return markers as authoritative for closing
                    // the currently-open internal call.
                    if name_matches || (same_frame_return && can_use_frame_fallback) {
                        internal_stack.pop();
                        if let Some(info) = analysis.call_info_by_snapshot.get_mut(&top_sid) {
                            info.end_snapshot = sid;
                        }
                    }
                }
            }
        }
    }

    if let Some(last_sid) = op_rows_exec.last().map(|op| op.sid) {
        for open_sid in internal_stack {
            if let Some(info) = analysis.call_info_by_snapshot.get_mut(&open_sid) {
                info.end_snapshot = last_sid;
            }
        }
    }

    analysis
}

fn resolve_parent_snapshot(
    sid: usize,
    parent_by_snapshot: &HashMap<usize, Option<usize>>,
    filtered_snapshot_to_row_id: &HashMap<usize, i64>,
) -> Option<usize> {
    let mut cursor = parent_by_snapshot.get(&sid).copied().flatten();
    // Defensive guard against malformed cycles.
    for _ in 0..1024 {
        let current = cursor?;
        if filtered_snapshot_to_row_id.contains_key(&current) {
            return Some(current);
        }
        cursor = parent_by_snapshot.get(&current).copied().flatten();
    }
    None
}

fn is_call_entry_opcode(name: &str) -> bool {
    matches!(name, "CALL" | "DELEGATECALL" | "STATICCALL" | "CALLCODE" | "CREATE" | "CREATE2")
}

fn resolve_entry_call_opcode_sid(
    _sid: usize,
    frame_trace_id: Option<usize>,
    parent_trace_id: Option<usize>,
    expected_call_opcode: &str,
    analysis: &InternalAnalysis,
) -> Option<usize> {
    // Resolve parent call opcode from parent frame before this frame starts.
    // We intentionally avoid the legacy "sid-1 backscan" shortcut because it can
    // attach entries to unrelated opcodes when snapshot IDs shift between runs.
    // Deterministic parent-frame matching preserves stable rail hierarchy.
    let frame_trace_id = frame_trace_id?;
    let parent_trace_id = parent_trace_id?;
    let first_opcode_exec_index =
        *analysis.first_opcode_exec_index_by_trace.get(&frame_trace_id)?;

    let mut best_specific: Option<usize> = None;
    let mut best_generic: Option<usize> = None;
    let mut best_parent_mapped: Option<usize> = None;

    for (idx, op) in analysis.op_rows_exec.iter().enumerate() {
        if idx >= first_opcode_exec_index {
            break;
        }
        if op.trace_id != Some(parent_trace_id) {
            continue;
        }

        if op.has_line {
            best_parent_mapped = Some(op.sid);
        }
        if !is_call_entry_opcode(&op.name) {
            continue;
        }

        if op.name == expected_call_opcode {
            best_specific = Some(op.sid);
        }
        best_generic = Some(op.sid);
    }

    best_specific.or(best_generic).or(best_parent_mapped)
}

fn source_paths_match(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let a_name = Path::new(a).file_name().and_then(|name| name.to_str());
    let b_name = Path::new(b).file_name().and_then(|name| name.to_str());
    matches!((a_name, b_name), (Some(x), Some(y)) if x == y)
}

fn resolve_entry_source_anchor_sid(
    frame_trace_id: Option<usize>,
    parent_trace_id: Option<usize>,
    entry_line: Option<usize>,
    entry_source_file: Option<&str>,
    analysis: &InternalAnalysis,
) -> Option<usize> {
    let frame_trace_id = frame_trace_id?;
    let parent_trace_id = parent_trace_id?;
    let entry_line = entry_line?;
    let entry_source_file = entry_source_file?;
    let first_opcode_exec_index =
        *analysis.first_opcode_exec_index_by_trace.get(&frame_trace_id)?;

    let mut best_anchor: Option<usize> = None;
    for (idx, op) in analysis.op_rows_exec.iter().enumerate() {
        if idx >= first_opcode_exec_index {
            break;
        }
        if op.trace_id != Some(parent_trace_id) || !op.is_internal_call {
            continue;
        }
        if op.line != Some(entry_line) {
            continue;
        }
        let Some(op_source_file) = op.source_file.as_deref() else {
            continue;
        };
        if !source_paths_match(op_source_file, entry_source_file) {
            continue;
        }
        best_anchor = Some(op.sid);
    }

    best_anchor
}

fn entry_call_type(row: &RenderedTraceRow) -> String {
    row.entry_meta
        .as_ref()
        .and_then(|meta| meta.call_type.as_ref())
        .map(|ct| ct.to_ascii_uppercase())
        .unwrap_or_else(|| row.name.to_ascii_uppercase())
}

fn is_modifier_like_fn_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty() && (trimmed.starts_with("only") || trimmed.starts_with("when"))
}

fn resolve_modifier_anchor_parent_sid(
    call_opcode_sid: usize,
    parent_trace_id: usize,
    analysis: &InternalAnalysis,
) -> Option<usize> {
    let current_fn = analysis
        .op_rows
        .iter()
        .find(|op| op.sid == call_opcode_sid)
        .and_then(|op| op.fn_name.as_deref())?;

    if !is_modifier_like_fn_name(current_fn) {
        return None;
    }

    for op in analysis.op_rows.iter().rev() {
        if op.sid >= call_opcode_sid {
            continue;
        }
        if op.trace_id != Some(parent_trace_id) {
            continue;
        }
        let Some(meta) = analysis.call_meta_by_snapshot.get(&op.sid) else {
            continue;
        };
        if meta.caller_fn.as_deref() == Some(current_fn) {
            return Some(op.sid);
        }
    }

    None
}

fn find_last_filtered_row_id(
    by_trace: &HashMap<Option<usize>, Vec<(usize, i64)>>,
    trace_id: Option<usize>,
    start_sid: usize,
    end_sid: usize,
) -> Option<i64> {
    by_trace.get(&trace_id).and_then(|rows| {
        rows.iter().rev().find(|(sid, _)| *sid >= start_sid && *sid <= end_sid).map(|(_, id)| *id)
    })
}

fn upper_bound_sid(sorted_sids: &[usize], target: usize) -> usize {
    let mut lo = 0usize;
    let mut hi = sorted_sids.len();
    while lo < hi {
        let mid = lo + ((hi - lo) / 2);
        if sorted_sids[mid] <= target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

fn build_opcode_gas_index(
    full_rows: &[RenderedTraceRow],
) -> (Vec<usize>, Vec<u128>, HashMap<usize, usize>) {
    let mut opcode_pairs: Vec<(usize, u128)> = Vec::new();

    for row in full_rows {
        if row.kind != RenderedRowKind::Opcode {
            continue;
        }
        let Some(sid) = snapshot_id(row) else {
            continue;
        };
        let gas = row.gas_delta.parse::<u128>().unwrap_or(0);
        opcode_pairs.push((sid, gas));
    }

    opcode_pairs.sort_by_key(|(sid, _)| *sid);

    let mut sids = Vec::with_capacity(opcode_pairs.len());
    let mut prefix = Vec::with_capacity(opcode_pairs.len() + 1);
    let mut sid_to_index = HashMap::with_capacity(opcode_pairs.len());
    prefix.push(0u128);

    for (idx, (sid, gas)) in opcode_pairs.into_iter().enumerate() {
        sids.push(sid);
        sid_to_index.insert(sid, idx);
        let next = prefix[idx].saturating_add(gas);
        prefix.push(next);
    }

    (sids, prefix, sid_to_index)
}

fn apply_internal_call_gas(
    rows: &mut [RenderedTraceRow],
    full_rows: &[RenderedTraceRow],
    analysis: &InternalAnalysis,
) {
    let (sids, prefix, sid_to_index) = build_opcode_gas_index(full_rows);
    if sids.is_empty() {
        return;
    }
    let row_id_to_sid: HashMap<i64, usize> =
        rows.iter().filter_map(|row| snapshot_id(row).map(|sid| (row.id, sid))).collect();

    for row in rows.iter_mut() {
        if row.kind != RenderedRowKind::Opcode || !row.is_internal_call.unwrap_or(false) {
            continue;
        }

        let Some(start_sid) = snapshot_id(row) else {
            continue;
        };
        let Some(&start_idx) = sid_to_index.get(&start_sid) else {
            continue;
        };

        let child_end_sid = row
            .child_end_id
            .and_then(|row_id| row_id_to_sid.get(&row_id).copied())
            .filter(|sid| *sid > start_sid);
        let analysis_end_sid =
            analysis.call_info_by_snapshot.get(&start_sid).map(|info| info.end_snapshot);
        // Prefer the wider boundary when both projections are available.
        // Filtered child_end_id can be conservative; call_info may preserve
        // additional post-child opcodes still attributed to the internal call.
        let end_sid = match (child_end_sid, analysis_end_sid) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let Some(end_sid) = end_sid else {
            continue;
        };

        let end_exclusive = upper_bound_sid(&sids, end_sid);
        if end_exclusive <= start_idx + 1 {
            continue;
        }

        // Internal-call span starts after the jump opcode itself.
        let start_sum = start_idx + 1;
        let total_gas = prefix[end_exclusive].saturating_sub(prefix[start_sum]);
        if total_gas > 0 {
            row.gas_delta = total_gas.to_string();
        }
    }
}

fn project_internal_hierarchy(rows: &mut [RenderedTraceRow], analysis: &InternalAnalysis) {
    let mut filtered_snapshot_to_row_id: HashMap<usize, i64> = HashMap::new();
    let mut filtered_by_trace: HashMap<Option<usize>, Vec<(usize, i64)>> = HashMap::new();
    let mut trace_parent_by_trace: HashMap<usize, usize> = HashMap::new();

    for row in rows.iter() {
        if let Some(sid) = row.first_snapshot_id {
            filtered_snapshot_to_row_id.insert(sid, row.id);
            filtered_by_trace.entry(row.trace_id).or_default().push((sid, row.id));
        }
        if row.kind == RenderedRowKind::Entry {
            if let (Some(trace_id), Some(parent_trace_id)) = (
                row.trace_id,
                row.external_parent_trace_id.and_then(|tid| usize::try_from(tid).ok()),
            ) {
                trace_parent_by_trace.entry(trace_id).or_insert(parent_trace_id);
            }
        }
    }
    for per_trace in filtered_by_trace.values_mut() {
        per_trace.sort_by_key(|(sid, _)| *sid);
    }

    for row in rows.iter_mut() {
        let Some(sid) = row.first_snapshot_id else {
            continue;
        };

        let resolved_parent_sid = if row.kind == RenderedRowKind::Entry {
            let row_call_type = entry_call_type(row);
            let expected_call_opcode = row_call_type.clone();
            let parent_trace_id = row
                .external_parent_trace_id
                .and_then(|tid| usize::try_from(tid).ok())
                .or_else(|| row.trace_id.and_then(|tid| trace_parent_by_trace.get(&tid).copied()));

            let map_to_filtered_parent_sid = |candidate_sid: usize| {
                if filtered_snapshot_to_row_id.contains_key(&candidate_sid) {
                    Some(candidate_sid)
                } else {
                    resolve_parent_snapshot(
                        candidate_sid,
                        &analysis.parent_by_snapshot,
                        &filtered_snapshot_to_row_id,
                    )
                }
            };

            let call_opcode_sid = resolve_entry_call_opcode_sid(
                sid,
                row.trace_id,
                parent_trace_id,
                &expected_call_opcode,
                analysis,
            );

            let mut resolved_parent_sid = call_opcode_sid
                .and_then(|resolved_sid| {
                    analysis.parent_by_snapshot.get(&resolved_sid).copied().flatten()
                })
                .and_then(map_to_filtered_parent_sid);

            // Source-anchor fallback: nested external entries often originate from an
            // internal call wrapper on the same source line in the parent trace. When
            // call-opcode ancestry is ambiguous, prefer that latest source-aligned rail.
            if let Some(anchor_sid) = resolve_entry_source_anchor_sid(
                row.trace_id,
                parent_trace_id,
                row.line,
                row.source_file.as_deref(),
                analysis,
            ) {
                if let Some(anchored_parent_sid) = map_to_filtered_parent_sid(anchor_sid) {
                    resolved_parent_sid = Some(anchored_parent_sid);
                }
            }

            if row_call_type == "DELEGATECALL" {
                if let (Some(resolved_sid), Some(parent_trace_id)) =
                    (call_opcode_sid, parent_trace_id)
                {
                    if let Some(anchor_sid) =
                        resolve_modifier_anchor_parent_sid(resolved_sid, parent_trace_id, analysis)
                    {
                        let anchored_parent_sid = map_to_filtered_parent_sid(anchor_sid);
                        if anchored_parent_sid.is_some() {
                            resolved_parent_sid = anchored_parent_sid;
                        }
                    }
                }
            }

            resolved_parent_sid
        } else {
            resolve_parent_snapshot(sid, &analysis.parent_by_snapshot, &filtered_snapshot_to_row_id)
        };

        if let Some(parent_sid) = resolved_parent_sid {
            if let Some(parent_row_id) = filtered_snapshot_to_row_id.get(&parent_sid).copied() {
                row.internal_parent_id = Some(parent_row_id);
            }
        } else {
            row.internal_parent_id = None;
        }

        if !row.is_internal_call.unwrap_or(false) {
            continue;
        }

        if let Some(info) = analysis.call_info_by_snapshot.get(&sid) {
            let has_children = info.has_nested_calls || info.has_child_opcodes;
            row.has_children = Some(has_children);
            row.is_leaf_call = Some(!has_children);

            if has_children {
                if let Some(end_row_id) = find_last_filtered_row_id(
                    &filtered_by_trace,
                    row.trace_id,
                    sid,
                    info.end_snapshot,
                ) {
                    row.child_end_id = Some(end_row_id);
                }
            } else {
                row.child_end_id = Some(row.id);
            }
        }
    }

    // FE parity: nested DELEGATECALL entries inherit the internal parent of
    // their external parent entry (when that parent entry already resolved one).
    let mut entry_parent_by_trace: HashMap<usize, i64> = HashMap::new();
    for row in rows.iter() {
        if row.kind != RenderedRowKind::Entry {
            continue;
        }
        let Some(trace_id) = row.trace_id else {
            continue;
        };
        let Some(parent_id) = row.internal_parent_id else {
            continue;
        };
        entry_parent_by_trace.entry(trace_id).or_insert(parent_id);
    }

    for row in rows.iter_mut() {
        if row.kind != RenderedRowKind::Entry {
            continue;
        }
        let call_type = entry_call_type(row);
        if call_type != "DELEGATECALL" {
            continue;
        }
        if row.internal_parent_id.is_some() {
            continue;
        }
        let Some(parent_trace_id) = row
            .external_parent_trace_id
            .and_then(|tid| usize::try_from(tid).ok())
            .or_else(|| row.trace_id.and_then(|tid| trace_parent_by_trace.get(&tid).copied()))
        else {
            continue;
        };
        if let Some(inherited_parent) = entry_parent_by_trace.get(&parent_trace_id).copied() {
            row.internal_parent_id = Some(inherited_parent);
        }
    }

    // Generic unresolved-entry fallback: repeat inheritance until stable so
    // multi-hop nested entries can resolve after intermediate parents are filled.
    loop {
        let mut inherited_any = false;
        let mut updated_entry_parent_by_trace: HashMap<usize, i64> = HashMap::new();
        for row in rows.iter() {
            if row.kind != RenderedRowKind::Entry {
                continue;
            }
            let Some(trace_id) = row.trace_id else {
                continue;
            };
            let Some(parent_id) = row.internal_parent_id else {
                continue;
            };
            updated_entry_parent_by_trace.entry(trace_id).or_insert(parent_id);
        }

        for row in rows.iter_mut() {
            if row.kind != RenderedRowKind::Entry || row.internal_parent_id.is_some() {
                continue;
            }
            let Some(parent_trace_id) = row
                .external_parent_trace_id
                .and_then(|tid| usize::try_from(tid).ok())
                .or_else(|| row.trace_id.and_then(|tid| trace_parent_by_trace.get(&tid).copied()))
            else {
                continue;
            };
            if let Some(inherited_parent) =
                updated_entry_parent_by_trace.get(&parent_trace_id).copied()
            {
                row.internal_parent_id = Some(inherited_parent);
                inherited_any = true;
            }
        }

        if !inherited_any {
            break;
        }
    }

    // FE parity: opcodes before first internal call in STATICCALL traces remain
    // under the same internal parent as that trace's entry row.
    let mut static_entry_parent_by_trace: HashMap<usize, (usize, i64)> = HashMap::new();
    for (idx, row) in rows.iter().enumerate() {
        if row.kind != RenderedRowKind::Entry {
            continue;
        }
        let call_type = row
            .entry_meta
            .as_ref()
            .and_then(|meta| meta.call_type.as_ref())
            .map(|ct| ct.to_ascii_uppercase())
            .unwrap_or_else(|| row.name.to_ascii_uppercase());
        if call_type != "STATICCALL" {
            continue;
        }
        let (Some(trace_id), Some(parent_id)) = (row.trace_id, row.internal_parent_id) else {
            continue;
        };
        static_entry_parent_by_trace.entry(trace_id).or_insert((idx, parent_id));
    }

    for (trace_id, (entry_idx, entry_parent_id)) in static_entry_parent_by_trace {
        let first_internal_idx = rows
            .iter()
            .enumerate()
            .skip(entry_idx + 1)
            .find(|(_, r)| r.trace_id == Some(trace_id) && r.is_internal_call.unwrap_or(false))
            .map(|(idx, _)| idx)
            .unwrap_or(rows.len());

        for row in rows.iter_mut().take(first_internal_idx).skip(entry_idx + 1) {
            if row.trace_id == Some(trace_id) && row.kind == RenderedRowKind::Opcode {
                row.internal_parent_id = Some(entry_parent_id);
            }
        }
    }

    // FE parity: DELEGATECALL trace opcodes before the first internal-call jump
    // should not inherit the entry row's internal parent. This avoids
    // over-nesting foreign-code frame prologues under caller-side rails.
    let mut delegate_entry_idx_by_trace: HashMap<usize, usize> = HashMap::new();
    for (idx, row) in rows.iter().enumerate() {
        if row.kind != RenderedRowKind::Entry {
            continue;
        }
        let call_type = row
            .entry_meta
            .as_ref()
            .and_then(|meta| meta.call_type.as_ref())
            .map(|ct| ct.to_ascii_uppercase())
            .unwrap_or_else(|| row.name.to_ascii_uppercase());
        if call_type != "DELEGATECALL" {
            continue;
        }
        if let Some(trace_id) = row.trace_id {
            delegate_entry_idx_by_trace.entry(trace_id).or_insert(idx);
        }
    }

    for (trace_id, entry_idx) in delegate_entry_idx_by_trace {
        let entry_row_id = rows[entry_idx].id;
        let Some(first_internal_idx) = rows
            .iter()
            .enumerate()
            .skip(entry_idx + 1)
            .find(|(_, r)| r.trace_id == Some(trace_id) && r.is_internal_call.unwrap_or(false))
            .map(|(idx, _)| idx)
        else {
            // If a delegatecall trace has no kept internal-call rails after filtering,
            // attach same-trace opcode rows to the delegate entry itself. This keeps
            // proper nested depth for frames where helper jumps were filtered.
            for row in rows.iter_mut().skip(entry_idx + 1) {
                if row.trace_id == Some(trace_id)
                    && row.kind == RenderedRowKind::Opcode
                    && row.internal_parent_id.is_none()
                {
                    row.internal_parent_id = Some(entry_row_id);
                }
            }
            continue;
        };

        for row in rows.iter_mut().take(first_internal_idx).skip(entry_idx + 1) {
            if row.trace_id == Some(trace_id) && row.kind == RenderedRowKind::Opcode {
                row.internal_parent_id = None;
            }
        }
    }
}

/// Stack-based O(n) computation of childEndId for entry rows and fallback jumps.
fn compute_child_end_ids(rows: &mut [RenderedTraceRow]) {
    // Stack of (row_index, trace_id, depth, is_entry)
    let mut stack: Vec<(usize, Option<usize>, usize, bool)> = Vec::new();

    for i in 0..rows.len() {
        let row_depth = rows[i].depth.unwrap_or(0);
        let row_trace_id = rows[i].trace_id;
        let is_entry = rows[i].kind == RenderedRowKind::Entry;
        let is_jump = rows[i].is_internal_call.unwrap_or(false);

        while let Some(&(open_idx, open_trace_id, open_depth, open_is_entry)) = stack.last() {
            let should_close = if is_entry {
                open_depth >= row_depth
                    || (open_depth == row_depth && open_trace_id != row_trace_id)
            } else if is_jump {
                if !open_is_entry && open_depth >= row_depth {
                    true
                } else {
                    open_depth > row_depth
                }
            } else {
                open_depth > row_depth
            };

            if should_close {
                let last_child_idx = i.saturating_sub(1);
                rows[open_idx].child_end_id = Some(rows[last_child_idx].id);
                stack.pop();
            } else {
                break;
            }
        }

        if is_entry || is_jump {
            stack.push((i, row_trace_id, row_depth, is_entry));
        }
    }

    let last_idx = rows.len().saturating_sub(1);
    while let Some((open_idx, _, _, _)) = stack.pop() {
        rows[open_idx].child_end_id = Some(rows[last_idx].id);
    }
}

/// Compute visual depth using projected internal-parent hierarchy.
fn compute_visual_depth(rows: &mut [RenderedTraceRow]) {
    let is_entry_like = |row: &RenderedTraceRow| {
        row.kind == RenderedRowKind::Entry || row.entry_meta.is_some() || row.id < 0
    };

    let mut trace_depth: HashMap<usize, usize> = HashMap::new();
    let mut delegate_no_internal_traces: HashSet<usize> = HashSet::new();
    let mut delegate_no_internal_entry_ids: HashSet<i64> = HashSet::new();

    let mut entry_call_type_by_trace: HashMap<usize, String> = HashMap::new();
    for row in rows.iter() {
        if !is_entry_like(row) {
            continue;
        }
        let Some(trace_id) = row.trace_id else {
            continue;
        };
        entry_call_type_by_trace.entry(trace_id).or_insert_with(|| entry_call_type(row));
    }

    for (&trace_id, call_type) in &entry_call_type_by_trace {
        if call_type != "DELEGATECALL" {
            continue;
        }
        let has_internal_opcode = rows.iter().any(|r| {
            r.trace_id == Some(trace_id)
                && r.kind == RenderedRowKind::Opcode
                && r.is_internal_call.unwrap_or(false)
        });
        if !has_internal_opcode {
            delegate_no_internal_traces.insert(trace_id);
        }
    }

    for row in rows.iter() {
        if !is_entry_like(row) {
            continue;
        }
        if let Some(trace_id) = row.trace_id {
            if delegate_no_internal_traces.contains(&trace_id) {
                delegate_no_internal_entry_ids.insert(row.id);
            }
        }
    }

    for row in rows.iter() {
        if is_entry_like(row) {
            if let (Some(trace_id), Some(depth)) = (row.trace_id, row.depth) {
                trace_depth.entry(trace_id).or_insert(depth);
            }
        }
    }

    let mut internal_depth_by_id: HashMap<i64, usize> = HashMap::new();
    let mut has_children_by_id: HashMap<i64, bool> =
        rows.iter().map(|r| (r.id, r.has_children.unwrap_or(false))).collect();

    for row in rows.iter_mut() {
        let external_depth = row.depth.unwrap_or(0);
        let parent_internal_id = row.internal_parent_id;
        let is_internal_entry = row.is_internal_call.unwrap_or(false);

        if is_internal_entry {
            let parent_depth = parent_internal_id
                .and_then(|pid| internal_depth_by_id.get(&pid).copied())
                .unwrap_or(0);
            internal_depth_by_id.insert(row.id, parent_depth + 1);
            row.visual_depth = Some(external_depth + parent_depth + 1);
        } else if let Some(parent_id) = parent_internal_id {
            let parent_depth = internal_depth_by_id.get(&parent_id).copied().unwrap_or(0);
            let parent_has_children = has_children_by_id.get(&parent_id).copied().unwrap_or(false);

            // Legacy FE parity: entry rows can inherit external depth from the parent
            // external frame, which avoids over-indenting nested entry branches.
            let mut effective_external_depth = external_depth;
            if row.entry_meta.is_some() {
                if let Some(parent_trace_id) =
                    row.external_parent_trace_id.and_then(|tid| usize::try_from(tid).ok())
                {
                    if let Some(parent_external_depth) = trace_depth.get(&parent_trace_id).copied()
                    {
                        effective_external_depth = parent_external_depth;
                    }
                }
            }

            let delegate_no_internal_child = row
                .trace_id
                .is_some_and(|trace_id| delegate_no_internal_traces.contains(&trace_id))
                && delegate_no_internal_entry_ids.contains(&parent_id);

            if delegate_no_internal_child {
                row.visual_depth = Some(effective_external_depth + parent_depth + 2);
            } else if parent_has_children {
                row.visual_depth = Some(effective_external_depth + parent_depth + 1);
            } else {
                row.visual_depth = Some(effective_external_depth + parent_depth);
            }
        } else if is_entry_like(row) {
            row.visual_depth = Some(external_depth);
        } else {
            if row.trace_id.is_some_and(|trace_id| delegate_no_internal_traces.contains(&trace_id))
            {
                row.visual_depth = Some(external_depth + 2);
            } else {
                row.visual_depth = Some(external_depth + 1);
            }
        }

        if matches!(row.name.as_str(), "RETURN" | "REVERT" | "STOP")
            && row.internal_parent_id.is_some()
        {
            row.is_internal_return = Some(true);
        }

        has_children_by_id.insert(row.id, row.has_children.unwrap_or(false));
    }
}

fn recompute_internal_ranges_by_visual_depth(rows: &mut [RenderedTraceRow]) {
    let len = rows.len();
    for i in 0..len {
        if !rows[i].is_internal_call.unwrap_or(false) {
            continue;
        }
        // If full-row projection already provided stable internal ranges, preserve them.
        // Legacy FE parity depends on these projected ranges for leaf helper calls where
        // child opcodes can render at the same visual depth as the call marker.
        if rows[i].child_end_id.is_some() && rows[i].has_children.is_some() {
            continue;
        }

        let call_depth = rows[i].visual_depth.unwrap_or_else(|| rows[i].depth.unwrap_or(0));
        let mut end_idx = i;

        for (j, candidate) in rows.iter().enumerate().skip(i + 1) {
            let candidate_depth =
                candidate.visual_depth.unwrap_or_else(|| candidate.depth.unwrap_or(0));
            if candidate_depth <= call_depth {
                break;
            }
            end_idx = j;
        }

        rows[i].child_end_id = Some(rows[end_idx].id);
        rows[i].has_children = Some(end_idx > i);
        rows[i].is_leaf_call = Some(end_idx == i);
    }
}

/// Compute hasChildren flag for entry rows and missing internal-call values.
fn compute_has_children(rows: &mut [RenderedTraceRow]) {
    let id_to_idx: HashMap<i64, usize> =
        rows.iter().enumerate().map(|(idx, r)| (r.id, idx)).collect();

    for i in 0..rows.len() {
        let is_entry = rows[i].kind == RenderedRowKind::Entry;
        let is_internal = rows[i].is_internal_call.unwrap_or(false);
        if !is_entry && !is_internal {
            continue;
        }
        // Preserve projected internal-call values from full-row analysis.
        if is_internal && rows[i].has_children.is_some() {
            continue;
        }

        let child_end_idx =
            rows[i].child_end_id.and_then(|id| id_to_idx.get(&id).copied()).unwrap_or(i);
        rows[i].has_children = Some(child_end_idx > i);
    }
}

/// Mark leaf calls for entry rows and internal calls without projected leaf info.
fn mark_leaf_calls(rows: &mut [RenderedTraceRow]) {
    let id_to_idx: HashMap<i64, usize> =
        rows.iter().enumerate().map(|(idx, r)| (r.id, idx)).collect();

    for i in 0..rows.len() {
        let is_entry = rows[i].kind == RenderedRowKind::Entry;
        let is_internal = rows[i].is_internal_call.unwrap_or(false);
        if !is_entry && !is_internal {
            continue;
        }
        if is_internal && rows[i].is_leaf_call.is_some() {
            continue;
        }

        let child_end_idx =
            rows[i].child_end_id.and_then(|id| id_to_idx.get(&id).copied()).unwrap_or(i);

        if child_end_idx <= i {
            rows[i].is_leaf_call = Some(true);
            continue;
        }

        let end = child_end_idx.min(rows.len() - 1);
        let has_nested = rows[i + 1..=end]
            .iter()
            .any(|r| r.kind == RenderedRowKind::Entry || r.is_internal_call.unwrap_or(false));

        rows[i].is_leaf_call = Some(!has_nested);
    }
}
