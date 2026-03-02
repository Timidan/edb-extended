// EDB - Trace Render: Events
// Extracts events from trace entries and decodes them using ABI.
// Replaces the event extraction from decodeTraceInit.ts and eventDecoding.ts.

use std::collections::HashMap;

use alloy_primitives::{Address, B256};
use edb_common::types::{RenderedRawEvent, Trace};

use crate::Artifact;

/// Extract events from all trace entries and convert to RenderedRawEvent.
pub fn extract_events(
    trace: &Trace,
    artifacts: &HashMap<Address, Artifact>,
) -> Vec<RenderedRawEvent> {
    let mut events = Vec::new();

    for entry in trace.iter() {
        for log in &entry.events {
            // Get event name from ABI if possible
            let event_name = if let Some(topic0) = log.topics().first() {
                resolve_event_name(*topic0, entry.code_address, artifacts)
            } else {
                None
            };

            let raw_event = RenderedRawEvent {
                address: format!("{}", entry.target),
                topics: log.topics().iter().map(|t| format!("{t:#x}")).collect(),
                data: format!("0x{}", hex::encode(&log.data)),
                trace_entry_id: Some(entry.id),
                event_name,
                decoded_args: None, // Could add ABI-decoded event args here
            };

            events.push(raw_event);
        }
    }

    events
}

/// Resolve an event name from the ABI using the topic0 (event signature hash).
fn resolve_event_name(
    topic0: B256,
    code_address: Address,
    artifacts: &HashMap<Address, Artifact>,
) -> Option<String> {
    let artifact = artifacts.get(&code_address)?;
    let contract = artifact.contract()?;
    let abi = contract.abi.as_ref()?;

    for event in abi.events() {
        if event.selector() == topic0 {
            return Some(event.name.clone());
        }
    }

    None
}
