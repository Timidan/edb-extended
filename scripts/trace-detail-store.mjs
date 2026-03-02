// =============================================================================
// Trace Detail Store — Server-side storage for heavy trace payloads
// =============================================================================

import { gzipSync, gunzipSync } from "node:zlib";
import {
  TRACE_DETAIL_TTL_MS,
  TRACE_DETAIL_MAX_ENTRIES,
  TRACE_DETAIL_MAX_TOTAL_BYTES,
  TRACE_DETAIL_GZIP_MIN_BYTES,
} from "./bridge-config.mjs";

/**
 * @typedef {Object} TraceDetailEntry
 * @property {string} id
 * @property {number} createdAt
 * @property {number} expiresAt
 * @property {Buffer} payload
 * @property {"json" | "gzip"} encoding
 * @property {number} bytes
 * @property {number} uncompressedBytes
 * @property {string[]} fields
 */

/** @type {Map<string, TraceDetailEntry>} */
export const traceDetailStore = new Map();

/**
 * @param {TraceDetailEntry} entry
 * @returns {number}
 */
export function getTraceDetailEntryBytes(entry) {
  if (!entry || typeof entry !== "object") return 0;
  if (typeof entry.bytes === "number" && Number.isFinite(entry.bytes)) {
    return Math.max(0, entry.bytes);
  }
  return Buffer.isBuffer(entry.payload) ? entry.payload.length : 0;
}

/**
 * @param {Record<string, unknown>} rawTraceFields
 * @returns {{ payload: Buffer; encoding: "json" | "gzip"; bytes: number; uncompressedBytes: number }}
 */
export function encodeTraceDetailPayload(rawTraceFields) {
  const rawJson = JSON.stringify(rawTraceFields || {});
  const jsonBuffer = Buffer.from(rawJson, "utf8");
  const uncompressedBytes = jsonBuffer.length;

  if (uncompressedBytes < TRACE_DETAIL_GZIP_MIN_BYTES) {
    return {
      payload: jsonBuffer,
      encoding: "json",
      bytes: jsonBuffer.length,
      uncompressedBytes,
    };
  }

  try {
    // Level 1 keeps CPU overhead lower while still shrinking large trace payloads.
    const gzBuffer = gzipSync(jsonBuffer, { level: 1 });
    if (gzBuffer.length < jsonBuffer.length) {
      return {
        payload: gzBuffer,
        encoding: "gzip",
        bytes: gzBuffer.length,
        uncompressedBytes,
      };
    }
  } catch (error) {
    console.warn("[simulator-bridge] failed to gzip trace detail payload:", error);
  }

  return {
    payload: jsonBuffer,
    encoding: "json",
    bytes: jsonBuffer.length,
    uncompressedBytes,
  };
}

/**
 * @param {TraceDetailEntry} entry
 * @returns {Record<string, unknown>}
 */
export function decodeTraceDetailPayload(entry) {
  if (!entry || !Buffer.isBuffer(entry.payload)) {
    throw new Error("Invalid trace detail payload");
  }

  let rawJson;
  if (entry.encoding === "gzip") {
    rawJson = gunzipSync(entry.payload).toString("utf8");
  } else {
    rawJson = entry.payload.toString("utf8");
  }
  const parsed = JSON.parse(rawJson);
  if (!parsed || typeof parsed !== "object") {
    throw new Error("Decoded trace detail payload is not an object");
  }
  return parsed;
}

export function pruneTraceDetailStore() {
  const now = Date.now();
  for (const [id, entry] of traceDetailStore.entries()) {
    if (entry.expiresAt <= now) {
      traceDetailStore.delete(id);
    }
  }

  const entries = Array.from(traceDetailStore.values()).sort((a, b) => a.createdAt - b.createdAt);
  let totalBytes = 0;
  for (const entry of traceDetailStore.values()) {
    totalBytes += getTraceDetailEntryBytes(entry);
  }

  const hasEntryOverflow = traceDetailStore.size > TRACE_DETAIL_MAX_ENTRIES;
  const hasByteOverflow =
    TRACE_DETAIL_MAX_TOTAL_BYTES > 0 && totalBytes > TRACE_DETAIL_MAX_TOTAL_BYTES;
  if (!hasEntryOverflow && !hasByteOverflow) return;

  while (entries.length > 0) {
    const entryOverflow = traceDetailStore.size > TRACE_DETAIL_MAX_ENTRIES;
    const byteOverflow =
      TRACE_DETAIL_MAX_TOTAL_BYTES > 0 && totalBytes > TRACE_DETAIL_MAX_TOTAL_BYTES;
    if (!entryOverflow && !byteOverflow) break;

    const oldest = entries.shift();
    if (!oldest) break;
    if (traceDetailStore.delete(oldest.id)) {
      totalBytes -= getTraceDetailEntryBytes(oldest);
    }
  }
}
