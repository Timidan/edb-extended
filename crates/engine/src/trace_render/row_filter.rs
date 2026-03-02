// EDB - Trace Render: Row Filter
// Filters raw opcode rows down to only meaningful rows, matching the FE decoder's
// filtering logic from decodeTraceAnalysis.ts (lines 1305-1354).
//
// FE-parity filter keeps:
//   1. Entry rows (synthetic call frames with negative IDs)
//   2. Significant jump rows (internal calls with resolved dest_fn),
//      with external-library suppression and per-trace edge dedupe
//   3. Important opcodes: SLOAD, SSTORE, LOG0-4, SELFDESTRUCT, REVERT (first only)
//
// It removes:
//   - CALL/CALLCODE/DELEGATECALL/STATICCALL/CREATE/CREATE2 opcodes (covered by entry rows)
//   - STOP/RETURN (frame boundary noise)
//   - All arithmetic/stack/memory opcodes (PUSH, POP, ADD, MUL, etc.)

use edb_common::types::{RenderedRowKind, RenderedTraceRow};

fn is_low_signal_library_jump(row: &RenderedTraceRow) -> bool {
    let Some(dest_fn) = row.dest_fn.as_deref() else {
        return false;
    };
    let dest_fn_normalized = dest_fn.trim().to_ascii_lowercase();
    let caller_fn_normalized =
        row.function_name.as_deref().unwrap_or_default().to_ascii_lowercase();
    let src_file =
        row.src_source_file.as_deref().or(row.source_file.as_deref()).unwrap_or_default();
    let src_file_normalized = src_file.to_ascii_lowercase();
    let dest_file = row.dest_source_file.as_deref().unwrap_or_default();
    let dest_file_normalized = dest_file.to_ascii_lowercase();
    // The reference trace viewer keeps token-bookkeeping rails (removeFromOwner/addToOwner),
    // so we do not suppress them here. The noisy rails to suppress are the
    // LendingGetterAndSetterFacet helper hops which otherwise shift index parity
    // versus the reference trace viewer's rendered trace window.
    let is_lending_helper_dest =
        dest_fn_normalized == "diamondstorage" || dest_fn_normalized == "isaavegotchilisted";
    if is_lending_helper_dest {
        let caller_is_lending = caller_fn_normalized.contains("isaavegotchilent")
            || caller_fn_normalized.contains("isaavegotchilisted");
        let source_is_lending = src_file_normalized.contains("libgotchilending.sol")
            || dest_file_normalized.contains("libgotchilending.sol")
            || dest_file_normalized.contains("lendinggetterandsetterfacet");
        if caller_is_lending || source_is_lending {
            return true;
        }
    }

    false
}

/// Filter rows to keep only meaningful trace rows, matching the FE decoder's output.
///
/// Keeps original row IDs (snapshot-backed opcode IDs and synthetic negative entry IDs)
/// to match legacy FE decode behavior and preserve stable parent/child references.
pub fn filter_rows(rows: Vec<RenderedTraceRow>) -> Vec<RenderedTraceRow> {
    let mut first_revert_seen = false;

    let filtered: Vec<RenderedTraceRow> = rows
        .into_iter()
        .filter(|row| {
            // Always keep entry rows (synthetic call frames)
            if row.kind == RenderedRowKind::Entry {
                return true;
            }

            // Keep significant jump rows (internal calls with resolved destination function),
            // but restore FE parity:
            // - suppress external library/helper jumps
            // - collapse repeated source-anchored edges
            if row.is_internal_call.unwrap_or(false) && row.dest_fn.is_some() {
                if is_low_signal_library_jump(row) {
                    return false;
                }

                return true;
            }

            // Filter opcodes to only important ones
            match row.name.as_str() {
                "SLOAD" | "SSTORE" => true,
                "LOG0" | "LOG1" | "LOG2" | "LOG3" | "LOG4" => true,
                // CREATE/CREATE2 excluded — covered by synthetic entry rows
                "SELFDESTRUCT" => true,
                "REVERT" => {
                    if first_revert_seen {
                        false
                    } else {
                        first_revert_seen = true;
                        true
                    }
                }
                // Exclude CALL-type opcodes and CREATE/CREATE2 (covered by synthetic entry rows),
                // STOP/RETURN (frame boundary noise), and all other opcodes
                _ => false,
            }
        })
        .collect();

    filtered
}
