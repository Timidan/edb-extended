// EDB - Trace Render: Finalizer
// Final pass: builds source_texts, implementation_to_proxy map, callMeta, and quality stats.
// Replaces the finalization logic from decodeTraceFinalize.ts.

use std::collections::{BTreeMap, HashMap};

use alloy_primitives::Address;
use edb_common::types::{CallType, RenderedCallMeta, RenderedTraceRow, Trace};

use crate::analysis::AnalysisResult;
use crate::Artifact;

/// Finalize the trace: build source texts, detect proxies, build call metadata.
///
/// Returns (source_texts, source_lines, implementation_to_proxy, call_meta).
pub fn finalize(
    rows: &mut [RenderedTraceRow],
    artifacts: &HashMap<Address, Artifact>,
    recompiled_artifacts: &HashMap<Address, Artifact>,
    analysis_results: &HashMap<Address, AnalysisResult>,
    trace: &Trace,
) -> (HashMap<String, String>, Vec<String>, HashMap<String, String>, Option<RenderedCallMeta>) {
    let source_texts = build_source_texts(rows, artifacts, recompiled_artifacts, analysis_results);
    let source_lines = build_source_lines(&source_texts);
    let implementation_to_proxy = detect_proxy_relationships(trace, artifacts);
    let call_meta = build_call_meta(rows, trace);

    (source_texts, source_lines, implementation_to_proxy, call_meta)
}

/// Build source_texts map: file_path → source_content.
fn build_source_texts(
    rows: &[RenderedTraceRow],
    artifacts: &HashMap<Address, Artifact>,
    recompiled_artifacts: &HashMap<Address, Artifact>,
    _analysis_results: &HashMap<Address, AnalysisResult>,
) -> HashMap<String, String> {
    let mut candidates: BTreeMap<String, Vec<String>> = BTreeMap::new();
    collect_source_candidates(artifacts, &mut candidates);
    collect_source_candidates(recompiled_artifacts, &mut candidates);

    // Source line hints from rendered rows let us resolve path collisions where
    // multiple artifacts provide different source variants for the same path.
    // We pick the variant whose hinted lines map to non-empty content most often.
    let mut line_hints: HashMap<String, Vec<usize>> = HashMap::new();
    for row in rows {
        let Some(path) = row.source_file.as_ref() else {
            continue;
        };
        let Some(line) = row.line else {
            continue;
        };
        if line == 0 {
            continue;
        }
        line_hints.entry(path.clone()).or_default().push(line);
    }

    let mut texts = HashMap::with_capacity(candidates.len());
    for (path, variants) in candidates {
        if variants.is_empty() {
            continue;
        }
        if variants.len() == 1 {
            texts.insert(path, variants[0].clone());
            continue;
        }

        let hints = line_hints.get(&path).map(Vec::as_slice).unwrap_or(&[]);
        let mut best_idx = 0usize;
        let mut best_score = score_source_candidate(&variants[0], hints);

        for (idx, variant) in variants.iter().enumerate().skip(1) {
            let score = score_source_candidate(variant, hints);
            if score > best_score {
                best_idx = idx;
                best_score = score;
            }
        }

        texts.insert(path, variants[best_idx].clone());
    }

    texts
}

fn collect_source_candidates(
    artifacts: &HashMap<Address, Artifact>,
    out: &mut BTreeMap<String, Vec<String>>,
) {
    let mut ordered: Vec<_> = artifacts.iter().collect();
    ordered.sort_by_key(|(address, _)| *address);

    for (_address, artifact) in ordered {
        let mut sources: Vec<_> = artifact.input.sources.iter().collect();
        sources.sort_by_key(|(path, _)| path.to_string_lossy().to_string());

        for (path, source) in sources {
            let path_str = path.to_string_lossy().to_string();
            let content = source.content.to_string();
            let entry = out.entry(path_str).or_default();
            if !entry.iter().any(|existing| existing == &content) {
                entry.push(content);
            }
        }
    }
}

// Score tuple order is lexicographic:
// 1) non-empty hinted lines, 2) valid hinted lines, 3) total line count.
fn score_source_candidate(source: &str, line_hints: &[usize]) -> (usize, usize, usize) {
    let lines: Vec<&str> = source.split('\n').collect();
    let total = lines.len();
    let mut valid = 0usize;
    let mut non_empty = 0usize;

    for line in line_hints {
        if *line == 0 || *line > total {
            continue;
        }
        valid += 1;
        if !lines[*line - 1].trim().is_empty() {
            non_empty += 1;
        }
    }

    (non_empty, valid, total)
}

/// Build sorted list of source file paths.
fn build_source_lines(source_texts: &HashMap<String, String>) -> Vec<String> {
    let mut lines: Vec<String> = source_texts.keys().cloned().collect();
    lines.sort();
    lines
}

/// Detect proxy/implementation relationships from the trace.
///
/// In DELEGATECALL: `code_address` is the implementation (where code comes from),
/// `target` is the proxy (storage context). We build a map: implementation → proxy.
fn detect_proxy_relationships(
    trace: &Trace,
    _artifacts: &HashMap<Address, Artifact>,
) -> HashMap<String, String> {
    let mut impl_to_proxy = HashMap::new();

    for entry in trace.iter() {
        // Check if this is a DELEGATECALL
        if let CallType::Call(scheme) = &entry.call_type {
            if matches!(scheme, revm::interpreter::CallScheme::DelegateCall) {
                // In DELEGATECALL: code_address = implementation, target = proxy (storage context)
                let impl_addr = format!("{}", entry.code_address);
                let proxy_addr = format!("{}", entry.target);

                // Only add if implementation != proxy (avoid self-delegates)
                if impl_addr != proxy_addr {
                    impl_to_proxy.entry(impl_addr).or_insert(proxy_addr);
                }
            }
        }
    }

    impl_to_proxy
}

/// Build call metadata from the first entry row.
fn build_call_meta(rows: &[RenderedTraceRow], trace: &Trace) -> Option<RenderedCallMeta> {
    // Find the first entry row (the top-level call)
    let first_entry = rows
        .iter()
        .find(|r| r.kind == edb_common::types::RenderedRowKind::Entry && r.depth == Some(0))?;

    let entry_meta = first_entry.entry_meta.as_ref()?;

    // Build a summary of the call
    let function_display = entry_meta
        .function
        .as_ref()
        .or(entry_meta.selector.as_ref())
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());

    let args_display = entry_meta
        .args
        .as_ref()
        .map(|args| {
            args.iter()
                .map(|a| {
                    if a.name.is_empty() {
                        a.value.clone()
                    } else {
                        format!("{}={}", a.name, a.value)
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();

    let from_label = entry_meta.caller.clone().unwrap_or_default();
    // Keep header parity with legacy UI: prefer the raw target address in `to`.
    // Contract names are still available in row metadata and contract tabs.
    let to_label = entry_meta
        .target
        .as_ref()
        .filter(|target| {
            let trimmed = target.trim();
            !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("unknown")
        })
        .cloned()
        .or_else(|| {
            entry_meta
                .target_contract_name
                .as_ref()
                .filter(|name| {
                    let trimmed = name.trim();
                    !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("unknown")
                })
                .cloned()
        })
        .unwrap_or_default();

    // Get total gas from trace
    let total_gas = trace.total_gas_used.map(|g| g.to_string());

    Some(RenderedCallMeta {
        from: from_label,
        to: to_label,
        function: function_display,
        args: args_display,
        value: entry_meta.value.clone(),
        gas_used: total_gas,
    })
}
