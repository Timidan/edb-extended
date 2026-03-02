// EDB - Ethereum Debugger
// Trace Render Module — Produces ready-to-render decoded trace rows from EngineContext.
// Replaces the 3-phase TypeScript decode pipeline (decodeTraceInit → decodeTraceAnalysis → decodeTraceFinalize).

pub mod call_frames;
pub mod events;
pub mod finalizer;
pub mod hierarchy;
pub mod jump_detector;
pub mod log_enricher;
pub mod opcode_rows;
pub mod row_filter;
pub mod source_mapper;

use std::sync::Arc;
use std::time::Instant;

use edb_common::types::{RenderedTrace, RenderedTraceQuality, RenderedTraceRow};
use revm::{Database, DatabaseCommit, DatabaseRef};
use serde_json::Value;
use tracing::info;

use crate::context::EngineContext;

/// Error type for trace rendering failures.
#[derive(Debug)]
pub enum TraceRenderError {
    NoSnapshots,
    NoTrace,
    SerializationError(String),
    InternalError(String),
}

impl std::fmt::Display for TraceRenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSnapshots => write!(f, "No snapshots available in context"),
            Self::NoTrace => write!(f, "No trace available in context"),
            Self::SerializationError(e) => write!(f, "Serialization error: {e}"),
            Self::InternalError(e) => write!(f, "Internal error: {e}"),
        }
    }
}

impl std::error::Error for TraceRenderError {}

/// Render a fully decoded trace from the engine context.
///
/// Pipeline order matches the FE decoder:
///   1. Build opcode rows (decodeTraceInit)
///   2. Insert call frames (decodeTraceInit)
///   3. Detect jumps (decodeTraceAnalysis)
///   4. **Filter rows** (decodeTraceAnalysis — 17K→~237 rows)
///   5. Compute hierarchy (decodeTraceFinalize — on filtered rows)
///   6. Extract events (decodeTraceInit + eventDecoding)
///   7. Finalize (decodeTraceFinalize — source texts, proxy detection)
pub fn render_trace<DB>(context: &Arc<EngineContext<DB>>) -> Result<RenderedTrace, TraceRenderError>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone + Send + Sync + 'static,
    <revm::database::CacheDB<DB> as Database>::Error: Clone + Send + Sync,
    <DB as Database>::Error: Clone + Send + Sync,
{
    let total_start = Instant::now();
    let trace = &context.trace;
    if trace.is_empty() {
        return Err(TraceRenderError::NoTrace);
    }

    // Phase 1: Build source maps from artifacts (replaces decodeTraceInit source extraction)
    // Use runtime bytecode hints from trace entries to choose the best contract variant
    // in multi-contract artifacts.
    let phase_start = Instant::now();
    let mut runtime_bytecodes = std::collections::HashMap::new();
    for entry in trace {
        if let Some(bytecode) = entry.bytecode.as_ref() {
            runtime_bytecodes.entry(entry.code_address).or_insert_with(|| bytecode.to_vec());
        }
    }
    let source_maps = source_mapper::build_source_maps(
        &context.artifacts,
        &context.recompiled_artifacts,
        &context.analysis_results,
        &runtime_bytecodes,
    );
    info!(
        "[TIMING] render_trace phase 1 - build_source_maps: {:.2}s",
        phase_start.elapsed().as_secs_f64()
    );

    // Phase 2: Build opcode rows from snapshots (replaces decodeTraceInit row construction)
    let phase_start = Instant::now();
    let mut rows = opcode_rows::build_opcode_rows(context, &source_maps);
    info!(
        "[TIMING] render_trace phase 2 - build_opcode_rows: {:.2}s",
        phase_start.elapsed().as_secs_f64()
    );

    // Phase 3: Insert synthetic call frame entries (replaces decodeTraceInit call frame creation)
    let phase_start = Instant::now();
    call_frames::insert_call_frames(&mut rows, trace, &context.artifacts);
    info!(
        "[TIMING] render_trace phase 3 - insert_call_frames: {:.2}s",
        phase_start.elapsed().as_secs_f64()
    );

    // Phase 4: Detect internal JUMP calls (replaces decodeTraceAnalysis jump detection)
    // Must happen BEFORE filtering so jump_detector can access full snapshot data
    let phase_start = Instant::now();
    jump_detector::detect_jumps(&mut rows, context, &source_maps);
    info!(
        "[TIMING] render_trace phase 4 - detect_jumps: {:.2}s",
        phase_start.elapsed().as_secs_f64()
    );
    let full_rows = rows.clone();

    // Phase 5: FILTER — keep only meaningful rows (replaces decodeTraceAnalysis filtering)
    // This is the critical step that reduces ~17K raw opcode rows to ~237 rich rows.
    // Entry rows, significant jumps, and important opcodes are kept.
    let phase_start = Instant::now();
    let mut rows = row_filter::filter_rows(rows);
    info!(
        "[TIMING] render_trace phase 5 - filter_rows: {:.2}s",
        phase_start.elapsed().as_secs_f64()
    );

    // Phase 6: Compute hierarchy on FILTERED rows (replaces decodeTraceFinalize hierarchy)
    // Must happen after filtering so childEndId/visualDepth reflect the actual rendered row set.
    let phase_start = Instant::now();
    hierarchy::compute_hierarchy(&mut rows, &full_rows);
    info!(
        "[TIMING] render_trace phase 6 - compute_hierarchy: {:.2}s",
        phase_start.elapsed().as_secs_f64()
    );

    // Phase 7: Enrich LOG rows with decoded event info (replaces decodeLogWithFallback)
    let phase_start = Instant::now();
    log_enricher::enrich_log_rows(&mut rows, trace, &context.artifacts);
    info!(
        "[TIMING] render_trace phase 7 - enrich_log_rows: {:.2}s",
        phase_start.elapsed().as_secs_f64()
    );

    // Phase 8: Extract events from trace entries (replaces decodeTraceInit + eventDecoding)
    let phase_start = Instant::now();
    let raw_events = events::extract_events(trace, &context.artifacts);
    info!(
        "[TIMING] render_trace phase 8 - extract_events: {:.2}s",
        phase_start.elapsed().as_secs_f64()
    );

    // Phase 9: Finalize — source texts, proxy detection, callMeta
    let phase_start = Instant::now();
    let (source_texts, source_lines, implementation_to_proxy, call_meta) = finalizer::finalize(
        &mut rows,
        &context.artifacts,
        &context.recompiled_artifacts,
        &context.analysis_results,
        trace,
    );
    info!("[TIMING] render_trace phase 9 - finalize: {:.2}s", phase_start.elapsed().as_secs_f64());

    // Compute quality stats on final filtered rows
    let phase_start = Instant::now();
    let quality = compute_quality(&rows);
    info!(
        "[TIMING] render_trace phase 10 - compute_quality: {:.2}s",
        phase_start.elapsed().as_secs_f64()
    );
    info!("[TIMING] render_trace TOTAL: {:.2}s", total_start.elapsed().as_secs_f64());

    Ok(RenderedTrace {
        schema_version: 3,
        rows,
        source_texts,
        source_lines,
        call_meta,
        raw_events,
        implementation_to_proxy,
        quality: Some(quality),
    })
}

/// Serialize a RenderedTrace to a JSON Value for RPC transport.
pub fn rendered_trace_to_json(trace: &RenderedTrace) -> Result<Value, TraceRenderError> {
    let start = Instant::now();
    let value = serde_json::to_value(trace)
        .map_err(|e| TraceRenderError::SerializationError(e.to_string()))?;
    info!("[TIMING] render_trace serialize_to_json: {:.2}s", start.elapsed().as_secs_f64());
    Ok(value)
}

/// Compute quality stats for the rendered trace.
fn compute_quality(rows: &[RenderedTraceRow]) -> RenderedTraceQuality {
    let total_rows = rows.len();
    let mut empty_rows = 0;
    let mut rows_with_source = 0;
    let mut jump_rows = 0;
    let mut entry_rows = 0;

    for row in rows {
        if row.name.is_empty() {
            empty_rows += 1;
        }
        if row.source_file.is_some() {
            rows_with_source += 1;
        }
        if row.jump_marker.unwrap_or(false) {
            jump_rows += 1;
        }
        if row.id < 0 {
            entry_rows += 1;
        }
    }

    RenderedTraceQuality { total_rows, empty_rows, rows_with_source, jump_rows, entry_rows }
}
