// EDB - Ethereum Debugger
// RPC method: edb_getRenderedTrace
// Returns fully decoded trace rows ready for frontend rendering.

use std::sync::Arc;

use revm::{database::CacheDB, Database, DatabaseCommit, DatabaseRef};

use crate::trace_render;
use crate::{error_codes, EngineContext, RpcError};

/// Return a fully rendered trace with all decode logic applied server-side.
///
/// The result is a `RenderedTrace` JSON object containing decoded rows,
/// source texts, call metadata, events, and quality stats. The frontend
/// can consume this directly with zero processing (schema version 3).
pub fn get_rendered_trace<DB>(
    context: &Arc<EngineContext<DB>>,
) -> Result<serde_json::Value, RpcError>
where
    DB: Database + DatabaseCommit + DatabaseRef + Clone + Send + Sync + 'static,
    <CacheDB<DB> as Database>::Error: Clone + Send + Sync,
    <DB as Database>::Error: Clone + Send + Sync,
{
    let rendered = trace_render::render_trace(context).map_err(|e| RpcError {
        code: error_codes::INTERNAL_ERROR,
        message: format!("trace render failed: {e}"),
        data: None,
    })?;

    trace_render::rendered_trace_to_json(&rendered).map_err(|e| RpcError {
        code: error_codes::INTERNAL_ERROR,
        message: format!("trace serialization failed: {e}"),
        data: None,
    })
}
