// scripts/heimdall-manager.mjs
//
// Bridge endpoints for Heimdall decompilation and storage dump.
// Dispatches POST /heimdall/{version,decompile,dump}.

import { createHash } from "node:crypto";
import {
  HEIMDALL_BIN_PATH,
  HEIMDALL_DECOMPILE_TIMEOUT_MS,
  HEIMDALL_DUMP_TIMEOUT_MS,
  HEIMDALL_CACHE_MAX_ENTRIES,
  HEIMDALL_CACHE_TTL_MS,
  HEIMDALL_CONCURRENCY,
  resolveHeimdallRpcUrl,
} from "./bridge-config.mjs";
import { runHeimdallSubprocess, HeimdallRunError } from "./heimdall-runner.mjs";
import { createLruCache } from "./heimdall-cache.mjs";

const resultCache = createLruCache({
  maxEntries: HEIMDALL_CACHE_MAX_ENTRIES,
  ttlMs: HEIMDALL_CACHE_TTL_MS,
});

export function _clearHeimdallCache() { resultCache.clear(); }

let activeHeimdall = 0;
const heimdallWaiters = [];
function acquireHeimdallSlot() {
  if (activeHeimdall < HEIMDALL_CONCURRENCY) {
    activeHeimdall++;
    return Promise.resolve();
  }
  return new Promise((resolve) => { heimdallWaiters.push(resolve); });
}
function releaseHeimdallSlot() {
  const next = heimdallWaiters.shift();
  if (next) next();
  else activeHeimdall--;
}
async function withHeimdallSlot(fn) {
  await acquireHeimdallSlot();
  try { return await fn(); }
  finally { releaseHeimdallSlot(); }
}

let cachedHeimdallVersion = null;

function isHexByteString(s) {
  return typeof s === "string" && /^0x[0-9a-fA-F]*$/.test(s) && s.length >= 4;
}
function isAddress(s) {
  return typeof s === "string" && /^0x[0-9a-fA-F]{40}$/.test(s);
}

function sha256Hex(bytes) {
  const h = createHash("sha256");
  h.update(bytes);
  return "0x" + h.digest("hex");
}

async function fetchCodeHash(rpcUrl, address) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    const resp = await fetch(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_getCode",
        params: [address, "latest"],
      }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!resp.ok) return { ok: false, reason: `rpc_http_${resp.status}` };
    const payload = await resp.json();
    if (payload?.error) return { ok: false, reason: `rpc_error:${payload.error.message ?? "unknown"}` };
    const code = payload?.result;
    if (typeof code !== "string" || !/^0x[0-9a-fA-F]*$/.test(code)) {
      return { ok: false, reason: "rpc_bad_result" };
    }
    if (code === "0x" || code.length <= 2) {
      return { ok: false, reason: "eoa_or_empty_code" };
    }
    return { ok: true, hash: sha256Hex(Buffer.from(code.slice(2), "hex")) };
  } catch (err) {
    return { ok: false, reason: err?.name === "AbortError" ? "rpc_timeout" : "rpc_fetch_failed" };
  }
}

function sendError(res, status, code, message, details) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: code, message, details }));
}
function sendOk(res, body) {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

async function resolveHeimdallVersion() {
  if (cachedHeimdallVersion) return cachedHeimdallVersion;
  try {
    const result = await runHeimdallSubprocess({
      bin: HEIMDALL_BIN_PATH,
      args: ["--version"],
      timeoutMs: 5000,
    });
    const match = result.stdout.match(/\b(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)\b/);
    cachedHeimdallVersion = match?.[1] ?? "unknown";
  } catch {
    cachedHeimdallVersion = "unknown";
  }
  return cachedHeimdallVersion;
}

function classifyRunError(err) {
  if (err instanceof HeimdallRunError || err?.code) {
    switch (err.code) {
      case "HEIMDALL_NOT_INSTALLED": return { status: 503, code: "heimdall_not_installed" };
      case "HEIMDALL_TIMEOUT":       return { status: 504, code: "heimdall_timeout" };
      case "HEIMDALL_SPAWN_FAILED":  return { status: 500, code: "heimdall_crash" };
      default:                       return { status: 500, code: "heimdall_upstream_error" };
    }
  }
  return { status: 500, code: "heimdall_upstream_error" };
}

async function handleVersion(res) {
  try {
    const v = await resolveHeimdallVersion();
    sendOk(res, { available: v !== "unknown", version: v !== "unknown" ? v : undefined });
  } catch {
    sendOk(res, { available: false });
  }
}

async function handleDecompile(body, res) {
  const { bytecode, address, chainId, rpcUrl: rejectedRpcUrl } = body ?? {};

  if (rejectedRpcUrl !== undefined) {
    return sendError(
      res,
      400,
      "bad_request",
      "rpcUrl is not accepted from the client; pass chainId and the server will resolve RPC",
    );
  }

  let cacheKey;
  let args;
  let resolvedHash;

  if (bytecode !== undefined) {
    if (!isHexByteString(bytecode)) {
      return sendError(res, 400, "bad_request", "bytecode must be 0x-prefixed hex");
    }
    resolvedHash = sha256Hex(Buffer.from(bytecode.slice(2), "hex"));
    cacheKey = `decompile:${resolvedHash}`;
    args = ["decompile", bytecode, "--output", "json", "--skip-resolving", "--no-tui"];
  } else if (address !== undefined) {
    if (!isAddress(address)) {
      return sendError(res, 400, "bad_request", "address must be 0x-prefixed 20-byte hex");
    }
    if (!Number.isInteger(chainId) || chainId <= 0) {
      return sendError(res, 400, "bad_request", "chainId must be a positive integer");
    }
    const resolved = resolveHeimdallRpcUrl(chainId);
    if (!resolved.ok) {
      return sendError(res, 400, "bad_request", `chain ${chainId} not allowlisted`, { reason: resolved.reason });
    }
    const fetched = await fetchCodeHash(resolved.url, address);
    if (!fetched.ok) {
      return sendError(res, 502, "heimdall_rpc_failed", fetched.reason);
    }
    resolvedHash = fetched.hash;
    cacheKey = `decompile:${chainId}:${address.toLowerCase()}:${resolvedHash}`;
    args = ["decompile", address, "--rpc-url", resolved.url, "--output", "json", "--skip-resolving", "--no-tui"];
  } else {
    return sendError(res, 400, "bad_request", "Provide either bytecode or (address + chainId)");
  }

  const cached = resultCache.get(cacheKey);
  if (cached) {
    return sendOk(res, { ...cached, cacheHit: true });
  }

  const heimdallVersion = await resolveHeimdallVersion();

  let result;
  try {
    result = await withHeimdallSlot(() => runHeimdallSubprocess({
      bin: HEIMDALL_BIN_PATH,
      args,
      timeoutMs: HEIMDALL_DECOMPILE_TIMEOUT_MS,
    }));
  } catch (err) {
    const { status, code } = classifyRunError(err);
    return sendError(res, status, code, err?.message, err?.stderr);
  }

  if (result.exitCode !== 0) {
    return sendError(res, 502, "heimdall_upstream_error", `heimdall exit ${result.exitCode}`, result.stderr);
  }

  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    return sendError(res, 502, "heimdall_invalid_output", "heimdall did not return JSON", result.stdout.slice(0, 500));
  }

  if (typeof parsed.source !== "string" || !Array.isArray(parsed.abi)) {
    return sendError(res, 502, "heimdall_invalid_output", "heimdall JSON missing source/abi", JSON.stringify(parsed).slice(0, 500));
  }

  const response = {
    source: parsed.source,
    abi: parsed.abi,
    bytecodeHash: resolvedHash,
    heimdallVersion,
    cacheHit: false,
    generatedAt: Date.now(),
  };

  resultCache.set(cacheKey, response);
  sendOk(res, response);
}

function normalizeBlockTag(input) {
  if (input === undefined || input === null) return { tag: "latest", cacheTag: "latest", cacheable: false };
  if (typeof input === "number" && Number.isFinite(input) && input >= 0) {
    return { tag: String(input), cacheTag: String(input), cacheable: true };
  }
  if (typeof input === "string") {
    if (/^(latest|pending)$/i.test(input)) {
      return { tag: input.toLowerCase(), cacheTag: input.toLowerCase(), cacheable: false };
    }
    if (/^earliest$/i.test(input)) {
      return { tag: "earliest", cacheTag: "earliest", cacheable: true };
    }
    if (/^\d+$/.test(input) || /^0x[0-9a-fA-F]+$/.test(input)) {
      return { tag: input, cacheTag: input.toLowerCase(), cacheable: true };
    }
  }
  return null;
}

function normalizeDumpSlots(raw) {
  if (Array.isArray(raw)) {
    return raw.map((e) => ({
      slot: String(e.slot),
      value: String(e.value),
      modifiers: Array.isArray(e.modifiers) ? e.modifiers : undefined,
    }));
  }
  if (raw && typeof raw === "object") {
    return Object.entries(raw).map(([slot, v]) => ({
      slot,
      value: typeof v === "string" ? v : String(v.value),
      modifiers: v && Array.isArray(v.modifiers) ? v.modifiers : undefined,
    }));
  }
  return null;
}

async function handleDump(body, res) {
  const { address, chainId, rpcUrl: rejectedRpcUrl, blockNumber, blockTag } = body ?? {};

  if (rejectedRpcUrl !== undefined) {
    return sendError(
      res,
      400,
      "bad_request",
      "rpcUrl is not accepted from the client; pass chainId and the server will resolve RPC",
    );
  }

  if (!isAddress(address)) {
    return sendError(res, 400, "bad_request", "address must be 20-byte 0x-prefixed hex");
  }
  if (!Number.isInteger(chainId) || chainId <= 0) {
    return sendError(res, 400, "bad_request", "chainId must be a positive integer");
  }
  const resolved = resolveHeimdallRpcUrl(chainId);
  if (!resolved.ok) {
    return sendError(res, 400, "bad_request", `chain ${chainId} not allowlisted`, { reason: resolved.reason });
  }

  const blockInput = blockNumber !== undefined ? blockNumber : blockTag;
  const block = normalizeBlockTag(blockInput);
  if (!block) {
    return sendError(res, 400, "bad_request", "blockNumber/blockTag invalid");
  }

  const normalizedAddress = address.toLowerCase();
  const cacheKey = block.cacheable
    ? `dump:${chainId}:${normalizedAddress}:${block.cacheTag}`
    : null;
  if (cacheKey) {
    const cached = resultCache.get(cacheKey);
    if (cached) return sendOk(res, { ...cached, cacheHit: true });
  }

  const heimdallVersion = await resolveHeimdallVersion();

  let result;
  try {
    result = await withHeimdallSlot(() => runHeimdallSubprocess({
      bin: HEIMDALL_BIN_PATH,
      args: ["dump", address, "--rpc-url", resolved.url, "--block", block.tag, "--output", "json"],
      timeoutMs: HEIMDALL_DUMP_TIMEOUT_MS,
    }));
  } catch (err) {
    const { status, code } = classifyRunError(err);
    return sendError(res, status, code, err?.message, err?.stderr);
  }

  if (result.exitCode !== 0) {
    return sendError(res, 502, "heimdall_upstream_error", `heimdall exit ${result.exitCode}`, result.stderr);
  }

  let raw;
  try {
    raw = JSON.parse(result.stdout);
  } catch {
    return sendError(res, 502, "heimdall_invalid_output", "heimdall did not return JSON", result.stdout.slice(0, 500));
  }

  const slots = normalizeDumpSlots(raw);
  if (slots === null) {
    return sendError(res, 502, "heimdall_invalid_output", "unexpected dump shape");
  }

  const response = {
    address: normalizedAddress,
    chainId,
    blockNumber: typeof blockInput === "number" ? blockInput : 0,
    slots,
    heimdallVersion,
    cacheHit: false,
    generatedAt: Date.now(),
  };
  if (cacheKey) resultCache.set(cacheKey, response);
  sendOk(res, response);
}

export async function handleHeimdall(url, body, res) {
  if (url === "/heimdall/version") {
    await handleVersion(res);
    return true;
  }
  if (url === "/heimdall/decompile") {
    await handleDecompile(body, res);
    return true;
  }
  if (url === "/heimdall/dump") {
    await handleDump(body, res);
    return true;
  }
  return false;
}
