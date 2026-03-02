// =============================================================================
// Trace Processing — Opcode names, traceLite builder, V3 parse, lite transport
// =============================================================================

import {
  TRACE_HEAVY_FIELDS,
  TRACE_DETAIL_TTL_MS,
  TRACE_DETAIL_STRIP_OPCODE_TRACE,
  TRACE_V2_BRIDGE_JS_FALLBACK,
} from "./bridge-config.mjs";
import { extractStorageLayoutFromArtifact, buildCompactArtifactMap } from "./artifact-compactor.mjs";
import {
  traceDetailStore,
  encodeTraceDetailPayload,
  pruneTraceDetailStore,
} from "./trace-detail-store.mjs";

// =============================================================================
// EVM Opcode Name Mapping
// =============================================================================

export const OPCODE_NAMES = {
  0x00: "STOP",
  0x01: "ADD",
  0x02: "MUL",
  0x03: "SUB",
  0x04: "DIV",
  0x05: "SDIV",
  0x06: "MOD",
  0x07: "SMOD",
  0x08: "ADDMOD",
  0x09: "MULMOD",
  0x0a: "EXP",
  0x0b: "SIGNEXTEND",
  0x10: "LT",
  0x11: "GT",
  0x12: "SLT",
  0x13: "SGT",
  0x14: "EQ",
  0x15: "ISZERO",
  0x16: "AND",
  0x17: "OR",
  0x18: "XOR",
  0x19: "NOT",
  0x1a: "BYTE",
  0x20: "KECCAK256",
  0x30: "ADDRESS",
  0x31: "BALANCE",
  0x32: "ORIGIN",
  0x33: "CALLER",
  0x34: "CALLVALUE",
  0x35: "CALLDATALOAD",
  0x36: "CALLDATASIZE",
  0x37: "CALLDATACOPY",
  0x38: "CODESIZE",
  0x39: "CODECOPY",
  0x3b: "EXTCODESIZE",
  0x3c: "EXTCODECOPY",
  0x3d: "RETURNDATASIZE",
  0x3e: "RETURNDATACOPY",
  0x3f: "EXTCODEHASH",
  0x40: "BLOCKHASH",
  0x41: "COINBASE",
  0x42: "TIMESTAMP",
  0x43: "NUMBER",
  0x44: "PREVRANDAO",
  0x45: "GASLIMIT",
  0x46: "CHAINID",
  0x47: "SELFBALANCE",
  0x48: "BASEFEE",
  0x50: "POP",
  0x51: "MLOAD",
  0x52: "MSTORE",
  0x53: "MSTORE8",
  0x54: "SLOAD",
  0x55: "SSTORE",
  0x56: "JUMP",
  0x57: "JUMPI",
  0x58: "PC",
  0x59: "MSIZE",
  0x5a: "GAS",
  0x5b: "JUMPDEST",
  0x80: "DUP1",
  0x81: "DUP2",
  0x82: "DUP3",
  0x83: "DUP4",
  0x84: "DUP5",
  0x85: "DUP6",
  0x86: "DUP7",
  0x87: "DUP8",
  0x88: "DUP9",
  0x89: "DUP10",
  0x8a: "DUP11",
  0x8b: "DUP12",
  0x8c: "DUP13",
  0x8d: "DUP14",
  0x8e: "DUP15",
  0x8f: "DUP16",
  0x90: "SWAP1",
  0x91: "SWAP2",
  0x92: "SWAP3",
  0x93: "SWAP4",
  0x94: "SWAP5",
  0x95: "SWAP6",
  0x96: "SWAP7",
  0x97: "SWAP8",
  0x98: "SWAP9",
  0x99: "SWAP10",
  0x9a: "SWAP11",
  0x9b: "SWAP12",
  0x9c: "SWAP13",
  0x9d: "SWAP14",
  0x9e: "SWAP15",
  0x9f: "SWAP16",
  0xa0: "LOG0",
  0xa1: "LOG1",
  0xa2: "LOG2",
  0xa3: "LOG3",
  0xa4: "LOG4",
  0xf0: "CREATE",
  0xf1: "CALL",
  0xf2: "CALLCODE",
  0xf3: "RETURN",
  0xf4: "DELEGATECALL",
  0xf5: "CREATE2",
  0xfa: "STATICCALL",
  0xfd: "REVERT",
  0xfe: "INVALID",
  0xff: "SELFDESTRUCT",
};

export function opcodeName(opcodeValue) {
  const value = Number(opcodeValue);
  if (!Number.isInteger(value) || value < 0 || value > 255) {
    return "OP_UNKNOWN";
  }
  if (value >= 0x60 && value <= 0x7f) return `PUSH${value - 0x5f}`;
  const known = OPCODE_NAMES[value];
  if (known) return known;
  return `OP_${value.toString(16).toUpperCase().padStart(2, "0")}`;
}

// =============================================================================
// Trace Index Helpers
// =============================================================================

export function parseTraceIdFromFrameId(frameId) {
  if (Array.isArray(frameId) && frameId.length > 0) {
    const id = Number(frameId[0]);
    return Number.isFinite(id) ? id : null;
  }
  if (!frameId || typeof frameId !== "object") return null;
  const obj = frameId;
  const candidate =
    obj.trace_entry_id ??
    obj.traceEntryId ??
    obj.trace_id ??
    obj.traceId ??
    obj.id;
  const id = Number(candidate);
  return Number.isFinite(id) ? id : null;
}

export function buildTraceEntryIndex(traceInner) {
  const index = new Map();
  const visit = (node) => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const child of node) visit(child);
      return;
    }
    const idRaw = node.id ?? node.trace_id;
    const id = Number(idRaw);
    if (Number.isFinite(id)) {
      index.set(id, node);
    }
    for (const value of Object.values(node)) {
      if (value && typeof value === "object") visit(value);
    }
  };
  visit(traceInner);
  return index;
}

export function buildOpcodeLineIndex(opcodeLines) {
  const index = new Map();
  if (!opcodeLines || typeof opcodeLines !== "object") return index;
  for (const [addr, rows] of Object.entries(opcodeLines)) {
    if (addr.endsWith("_filtered") || !Array.isArray(rows)) continue;
    const pcMap = new Map();
    for (const row of rows) {
      if (!row || typeof row !== "object") continue;
      const pc = Number(row.pc);
      if (!Number.isFinite(pc)) continue;
      pcMap.set(pc, row);
    }
    index.set(addr.toLowerCase(), pcMap);
  }
  return index;
}

export function buildContractNameIndex(rawTrace) {
  const names = new Map();
  const artifacts = rawTrace?.artifacts;
  if (!artifacts || typeof artifacts !== "object") return names;

  for (const [addr, artifact] of Object.entries(artifacts)) {
    if (!artifact || typeof artifact !== "object") continue;
    const lower = addr.toLowerCase();
    const metaName = artifact?.meta?.ContractName || artifact?.meta?.Name;
    if (typeof metaName === "string" && metaName.length > 0) {
      names.set(lower, metaName);
      continue;
    }
    const contracts = artifact?.output?.contracts;
    if (contracts && typeof contracts === "object") {
      for (const contractGroup of Object.values(contracts)) {
        if (!contractGroup || typeof contractGroup !== "object") continue;
        const firstName = Object.keys(contractGroup)[0];
        if (firstName) {
          names.set(lower, firstName);
          break;
        }
      }
    }
  }

  return names;
}

// =============================================================================
// TraceLite Builder (JS fallback)
// =============================================================================

export function buildTraceLite(rawTrace) {
  if (!rawTrace || typeof rawTrace !== "object") return null;
  const opcodeTrace = Array.isArray(rawTrace.opcodeTrace) ? rawTrace.opcodeTrace : [];
  if (opcodeTrace.length === 0) return null;

  const traceEntryIndex = buildTraceEntryIndex(rawTrace.inner);
  const opcodeLineIndex = buildOpcodeLineIndex(rawTrace.opcodeLines);
  const contractNames = buildContractNameIndex(rawTrace);

  const rows = [];
  let rowsWithSrc = 0;
  let internalCallRows = 0;

  for (const entry of opcodeTrace) {
    if (!entry || typeof entry !== "object") continue;
    const rowId = Number(entry.id ?? entry.ID);
    const pc = Number(entry.pc);
    const opcodeValue = Number(entry.opcode);
    if (!Number.isFinite(rowId) || !Number.isFinite(pc) || !Number.isFinite(opcodeValue)) {
      continue;
    }

    const frameId = entry.frame_id ?? entry.frameId;
    const traceId = parseTraceIdFromFrameId(frameId);
    const traceEntry = traceId !== null ? traceEntryIndex.get(traceId) : null;

    const bytecodeAddress =
      (entry.bytecode_address || entry.bytecodeAddress || traceEntry?.code_address || traceEntry?.codeAddress || "")
        .toString()
        .toLowerCase();
    const targetAddress =
      (entry.target_address || entry.targetAddress || traceEntry?.target || "")
        .toString()
        .toLowerCase();
    const mappingAddress = bytecodeAddress || targetAddress;
    const pcInfo = mappingAddress ? opcodeLineIndex.get(mappingAddress)?.get(pc) : null;

    const contract =
      traceEntry?.target_label ||
      traceEntry?.targetLabel ||
      (mappingAddress ? contractNames.get(mappingAddress) : null) ||
      null;
    const functionName =
      traceEntry?.function_name ||
      traceEntry?.functionName ||
      traceEntry?.function ||
      null;

    const srcRef =
      pcInfo && (pcInfo.file || Number.isFinite(Number(pcInfo.line)) || pcInfo.jumpType)
        ? {
            file: typeof pcInfo.file === "string" ? pcInfo.file : null,
            line: Number.isFinite(Number(pcInfo.line)) ? Number(pcInfo.line) : null,
            jumpType:
              typeof pcInfo.jumpType === "string" && pcInfo.jumpType.length > 0
                ? pcInfo.jumpType
                : null,
          }
        : null;

    const jumpType = srcRef?.jumpType || null;
    if (srcRef?.line) rowsWithSrc += 1;
    if (jumpType === "i") internalCallRows += 1;

    const row = {
      id: rowId,
      rowType: "opcode",
      depth:
        Number(traceEntry?.depth ?? traceEntry?.call_depth ?? traceEntry?.callDepth ?? 0) || 0,
      parentId:
        Number.isFinite(Number(traceEntry?.parent_id ?? traceEntry?.parentId))
          ? Number(traceEntry?.parent_id ?? traceEntry?.parentId)
          : null,
      opcode: opcodeName(opcodeValue),
      opcodeValue,
      pc,
      gasDelta:
        entry.gas_used !== undefined || entry.gasUsed !== undefined
          ? String(entry.gas_used ?? entry.gasUsed)
          : null,
      gasRemaining:
        entry.gas_remaining !== undefined || entry.gasRemaining !== undefined
          ? String(entry.gas_remaining ?? entry.gasRemaining)
          : null,
      contract,
      function: functionName,
      frameId: frameId ?? null,
      srcRef,
      entry: {
        traceId,
        target: targetAddress || null,
        codeAddress: bytecodeAddress || null,
        callType: traceEntry?.kind || traceEntry?.type || null,
      },
      storage: {
        read: entry.storage_read ?? entry.storageRead ?? null,
        write: entry.storage_write ?? entry.storageWrite ?? null,
      },
      flags: {
        isUnverifiedFrame: !pcInfo,
        srcMapConfidence: srcRef?.line ? "high" : "low",
      },
    };

    rows.push(row);
  }

  const contracts = [];
  for (const [addr, name] of contractNames.entries()) {
    contracts.push({
      address: addr,
      name: name || null,
      verified: opcodeLineIndex.has(addr),
    });
  }

  const sourceFileSet = new Set();
  for (const row of rows) {
    const file = row?.srcRef?.file;
    if (typeof file === "string" && file.length > 0) {
      sourceFileSet.add(file);
    }
  }

  const sourceFiles = Array.from(sourceFileSet).map((path, i) => ({ fileId: i + 1, path }));

  return {
    traceLite: {
      version: 2,
      rows,
    },
    traceMeta: {
      sourceFiles,
      contracts,
    },
    traceQuality: {
      stats: {
        totalRows: rows.length,
        rowsWithSrc,
        internalCalls: internalCallRows,
      },
    },
  };
}

// =============================================================================
// Simulation Result Parsing (V3 rendered trace)
// =============================================================================

export function parseSimulationResult(raw) {
  let result;
  if (raw && typeof raw === "object") {
    result = raw;
  } else if (typeof raw === "string") {
    result = JSON.parse(raw);
    if (!result || typeof result !== "object") {
      throw new Error("simulator returned non-object JSON response");
    }
  } else {
    throw new Error("simulator returned unsupported response type");
  }

  // V3 rendered trace: when the Rust engine provides fully-decoded rows,
  // set traceSchemaVersion=3 so the frontend can skip TypeScript decode.
  if (result.renderedTrace && typeof result.renderedTrace === "object") {
    const rt = result.renderedTrace;
    if (Array.isArray(rt.rows) && rt.rows.length > 0) {
      result.traceSchemaVersion = 3;

      const rawTrace = result.rawTrace;
      if (rawTrace && typeof rawTrace === "object") {
        const heavyFields = ["snapshots", "sources", "opcodeTrace"];
        const strippedSizes = {};
        for (const field of heavyFields) {
          if (rawTrace[field]) {
            const size = Array.isArray(rawTrace[field]) ? rawTrace[field].length : "object";
            strippedSizes[field] = size;
            delete rawTrace[field];
          }
          if (rawTrace.inner && typeof rawTrace.inner === "object" && rawTrace.inner[field]) {
            delete rawTrace.inner[field];
          }
        }
        if (rawTrace.artifacts && typeof rawTrace.artifacts === "object") {
          let artifactCount = 0;
          for (const [addr, artifact] of Object.entries(rawTrace.artifacts)) {
            if (artifact && typeof artifact === "object") {
              const meta = artifact.meta || null;
              const cName = meta?.ContractName || meta?.Name || null;
              const storageLayout = extractStorageLayoutFromArtifact(artifact, cName);
              rawTrace.artifacts[addr] = {
                ...(meta ? { meta } : {}),
                ...(storageLayout ? { storageLayout } : {}),
              };
              artifactCount++;
            }
          }
          strippedSizes["artifacts"] = `${artifactCount} contracts (kept meta)`;
        }
        console.log(
          `[simulator-bridge] V3 rendered trace: ${rt.rows.length} rows, ` +
          `${Object.keys(rt.sourceTexts || {}).length} source files — ` +
          `stripped heavy fields: ${JSON.stringify(strippedSizes)}`
        );
      } else {
        console.log(
          `[simulator-bridge] V3 rendered trace: ${rt.rows.length} rows, ` +
          `${Object.keys(rt.sourceTexts || {}).length} source files, ` +
          `schemaVersion=${rt.schemaVersion}`
        );
      }
    }
  }

  return result;
}

// =============================================================================
// Lite Trace Transport — strip heavy fields into server-side handle
// =============================================================================

/**
 * Strip heavy rawTrace fields into an expiring server-side handle.
 * @param {Record<string, any>} simulationResult
 * @returns {Record<string, any>}
 */
export function applyLiteTraceTransport(simulationResult) {
  if (!simulationResult || typeof simulationResult !== "object") return simulationResult;
  const rawTrace = simulationResult.rawTrace;
  if (!rawTrace || typeof rawTrace !== "object") return simulationResult;

  let hasV2LiteRows =
    Number(simulationResult.traceSchemaVersion ?? 0) >= 2 &&
    Array.isArray(simulationResult.traceLite?.rows) &&
    simulationResult.traceLite.rows.length > 0;
  if (!hasV2LiteRows && TRACE_V2_BRIDGE_JS_FALLBACK) {
    const litePayload = buildTraceLite(rawTrace);
    if (litePayload) {
      simulationResult.traceLite = litePayload.traceLite;
      simulationResult.traceMeta = litePayload.traceMeta;
      simulationResult.traceQuality = litePayload.traceQuality;
      simulationResult.traceSchemaVersion = simulationResult.traceSchemaVersion ?? 2;
      hasV2LiteRows = true;
    }
  }
  if (hasV2LiteRows) {
    simulationResult.traceSchemaVersion = simulationResult.traceSchemaVersion ?? 2;
  }

  const heavyFields = TRACE_HEAVY_FIELDS.slice();
  if (TRACE_DETAIL_STRIP_OPCODE_TRACE && hasV2LiteRows) {
    heavyFields.push("opcodeTrace");
  }

  const extracted = {};
  const extractedFields = [];
  for (const field of heavyFields) {
    if (!(field in rawTrace)) continue;
    const value = rawTrace[field];
    const hasData =
      Array.isArray(value) ? value.length > 0 : value && typeof value === "object" ? Object.keys(value).length > 0 : value !== null && value !== undefined;
    if (!hasData) {
      delete rawTrace[field];
      continue;
    }
    if (field === "artifacts") {
      const compactArtifacts = buildCompactArtifactMap(value, rawTrace.opcodeLines);
      if (compactArtifacts) {
        rawTrace.artifacts = compactArtifacts;
      } else {
        delete rawTrace.artifacts;
      }
      extracted[field] = value;
      extractedFields.push(field);
      continue;
    }
    extracted[field] = value;
    extractedFields.push(field);
    delete rawTrace[field];
  }

  if (extractedFields.length === 0) return simulationResult;

  pruneTraceDetailStore();
  const now = Date.now();
  const detailId = `trace-${now}-${Math.random().toString(36).slice(2, 10)}`;
  const encodedPayload = encodeTraceDetailPayload(extracted);
  const detailEntry = {
    id: detailId,
    createdAt: now,
    expiresAt: now + TRACE_DETAIL_TTL_MS,
    payload: encodedPayload.payload,
    encoding: encodedPayload.encoding,
    bytes: encodedPayload.bytes,
    uncompressedBytes: encodedPayload.uncompressedBytes,
    fields: extractedFields,
  };
  traceDetailStore.set(detailId, detailEntry);

  if (Array.isArray(extracted.snapshots)) {
    rawTrace._snapshotCount = extracted.snapshots.length;
  }
  if (extracted.artifacts && typeof extracted.artifacts === "object") {
    rawTrace._artifactCount = Object.keys(extracted.artifacts).length;
  }
  if (extracted.sources && typeof extracted.sources === "object") {
    rawTrace._sourceAddressCount = Object.keys(extracted.sources).length;
  }
  if (extracted.opcodeLines && typeof extracted.opcodeLines === "object") {
    rawTrace._opcodeLineAddressCount = Object.keys(extracted.opcodeLines).length;
  }
  if (Array.isArray(extracted.opcodeTrace)) {
    rawTrace._opcodeTraceCount = extracted.opcodeTrace.length;
  }

  simulationResult.traceDetailHandle = {
    id: detailId,
    fields: extractedFields,
    expiresAt: detailEntry.expiresAt,
  };

  return simulationResult;
}
