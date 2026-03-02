// =============================================================================
// Debug Sessions — EDB server, WebSocket, debug session management, async prep
// =============================================================================

import http from "node:http";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import WebSocket from "ws";

import {
  EDB_WS_PORT,
  EDB_BINARY_PATH,
} from "./bridge-config.mjs";

import { redactRpcUrl } from "./bridge-security.mjs";

import {
  gatedRunSimulationWithKeepAlive,
} from "./keep-alive-manager.mjs";

// =============================================================================
// EDB Server + WebSocket (legacy codepath)
// =============================================================================

/** @type {import('node:child_process').ChildProcess | null} */
let edbServerProcess = null;

/** @type {WebSocket | null} */
let edbWebSocket = null;

/**
 * @typedef {Object} DebugSession
 * @property {string} sessionId
 * @property {number} rpcPort
 * @property {number} snapshotCount
 * @property {string[]} sourceFiles
 * @property {number} createdAt
 */

/** @type {Map<string, DebugSession>} */
const debugSessions = new Map();

/**
 * Start the EDB server process if not already running
 */
export async function ensureEdbServer() {
  if (edbServerProcess && !edbServerProcess.killed) {
    if (edbWebSocket && edbWebSocket.readyState === WebSocket.OPEN) {
      return;
    }
    await connectWebSocket();
    return;
  }

  if (!existsSync(EDB_BINARY_PATH)) {
    throw new Error(
      `EDB binary not found at ${EDB_BINARY_PATH}. Build with: cargo build -p edb --manifest-path edb/Cargo.toml`,
    );
  }

  console.log(`[simulator-bridge] starting EDB server on ws://127.0.0.1:${EDB_WS_PORT}`);

  edbServerProcess = spawn(EDB_BINARY_PATH, ["server", "--ws-port", String(EDB_WS_PORT)], {
    stdio: ["ignore", "pipe", "pipe"],
  });

  edbServerProcess.stdout?.on("data", (data) => {
    console.log(`[edb-server] ${data.toString().trim()}`);
  });

  edbServerProcess.stderr?.on("data", (data) => {
    console.error(`[edb-server] ${data.toString().trim()}`);
  });

  edbServerProcess.on("error", (err) => {
    console.error("[edb-server] process error:", err);
    edbServerProcess = null;
  });

  edbServerProcess.on("close", (code) => {
    console.log(`[edb-server] process exited with code ${code}`);
    edbServerProcess = null;
    edbWebSocket = null;
  });

  await new Promise((resolve) => setTimeout(resolve, 1000));
  await connectWebSocket();
}

/**
 * Connect to EDB server via WebSocket
 */
function connectWebSocket() {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${EDB_WS_PORT}`);

    const timeout = setTimeout(() => {
      ws.close();
      reject(new Error("WebSocket connection timeout"));
    }, 5000);

    ws.on("open", () => {
      clearTimeout(timeout);
      console.log("[simulator-bridge] connected to EDB server via WebSocket");
      edbWebSocket = ws;
      resolve();
    });

    ws.on("error", (err) => {
      clearTimeout(timeout);
      console.error("[simulator-bridge] WebSocket error:", err);
      reject(err);
    });

    ws.on("close", () => {
      console.log("[simulator-bridge] WebSocket connection closed");
      edbWebSocket = null;
    });
  });
}

// =============================================================================
// Debug Session CRUD
// =============================================================================

/**
 * Start a debug session via simulator keep-alive mode.
 * @param {import('./bridge-config.mjs').SimulationSemaphore} simulationSemaphore
 * @param {Object} params
 * @returns {Promise<DebugSession>}
 */
export async function startDebugSession(simulationSemaphore, params) {
  const hasTxPayload = Boolean(params.transaction);
  const hasTxHash = Boolean(params.txHash);
  if (!hasTxPayload && !hasTxHash) {
    throw new Error("Missing required debug target: transaction or txHash");
  }

  const payload = {
    mode: hasTxHash ? "onchain" : "local",
    rpcUrl: params.rpcUrl,
    chainId: params.chainId,
    blockTag: params.blockTag || "latest",
    enableDebug: true,
    debugSessionOnly: true,
    analysisOptions: {
      quickMode: true,
      collectCallTree: true,
      collectEvents: true,
      collectStorageDiff: true,
      collectStorageDiffs: true,
      collectSnapshots: true,
    },
  };

  if (hasTxPayload) {
    payload.transaction = params.transaction;
  } else if (hasTxHash) {
    payload.txHash = params.txHash;
  }

  if (params.artifacts_inline && typeof params.artifacts_inline === "object") {
    payload.artifacts_inline = params.artifacts_inline;
  }
  if (Array.isArray(params.artifacts)) {
    payload.artifacts = params.artifacts;
  }

  console.log(
    `[simulator-bridge] starting keep-alive debug session (RPC: ${redactRpcUrl(params.rpcUrl)}, chain: ${params.chainId}, mode: ${payload.mode})`,
  );
  const { result, session } = await gatedRunSimulationWithKeepAlive(simulationSemaphore, JSON.stringify(payload));
  if (!session) {
    throw new Error("Failed to create keep-alive debug session");
  }

  return {
    sessionId: session.sessionId,
    rpcPort: session.rpcPort,
    snapshotCount: session.snapshotCount || result?.debugSession?.snapshotCount || 0,
    sourceFiles: result?.sourceFiles || {},
    createdAt: session.createdAt,
  };
}

/**
 * Make an RPC call to a debug session (legacy path)
 */
export async function debugRpcCall(sessionId, method, params = []) {
  const session = debugSessions.get(sessionId);
  if (!session) {
    throw new Error(`Debug session not found: ${sessionId}`);
  }

  const rpcRequest = {
    jsonrpc: "2.0",
    id: Date.now(),
    method,
    params,
  };

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: session.rpcPort,
        path: "/",
        method: "POST",
        headers: { "Content-Type": "application/json" },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            const response = JSON.parse(data);
            if (response.error) {
              reject(new Error(response.error.message || JSON.stringify(response.error)));
            } else {
              resolve(response.result);
            }
          } catch (err) {
            reject(new Error(`Failed to parse RPC response: ${err.message}`));
          }
        });
      },
    );
    req.on("error", reject);
    req.write(JSON.stringify(rpcRequest));
    req.end();
  });
}

/**
 * End a debug session (legacy path)
 */
export function endDebugSession(sessionId) {
  const session = debugSessions.get(sessionId);
  if (session) {
    debugSessions.delete(sessionId);
    console.log(`[simulator-bridge] debug session ended: ${sessionId}`);
  }
}

// =============================================================================
// Async Debug Preparation Infrastructure
// =============================================================================

/**
 * @typedef {Object} PrepareJob
 * @property {string} prepareId
 * @property {'queued'|'preparing'|'ready'|'failed'} status
 * @property {string|null} stage
 * @property {number} progressPct
 * @property {string|null} message
 * @property {string|null} sessionId
 * @property {number|null} snapshotCount
 * @property {Object|null} sourceFiles
 * @property {string|null} error
 * @property {Set<import('node:http').ServerResponse>} sseClients
 * @property {number} createdAt
 * @property {number|null} completedAt
 */

/** @type {Map<string, PrepareJob>} */
export const prepareJobs = new Map();
export const PREPARE_JOB_TTL_MS = 30 * 60 * 1000;
export const PREPARE_JOB_MAX = 10;

export const PREPARE_STAGE_NAMES = {
  1: "replay_and_collect_trace",
  2: "download_verified_sources",
  3: "analyze_source",
  4: "instrument_and_recompile",
  5: "capture_opcode_snapshots",
  6: "tweak_bytecode",
  7: "capture_hook_snapshots",
  8: "start_debug_rpc",
};

export const PREPARE_STAGE_LABELS = {
  1: "Replaying transaction to collect call trace...",
  2: "Downloading verified source code...",
  3: "Analyzing source code...",
  4: "Instrumenting and recompiling contracts...",
  5: "Collecting opcode-level snapshots...",
  6: "Replacing bytecode with instrumented versions...",
  7: "Capturing hook-level snapshots...",
  8: "Starting debug RPC server...",
};

export function broadcastPrepareEvent(prepareId, event, data) {
  const job = prepareJobs.get(prepareId);
  if (!job) return;
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of job.sseClients) {
    try {
      client.write(payload);
    } catch {
      job.sseClients.delete(client);
    }
  }
}

export function pruneStalePrepareSessions() {
  const now = Date.now();
  for (const [id, job] of prepareJobs) {
    if (job.completedAt && (now - job.completedAt) > PREPARE_JOB_TTL_MS) {
      prepareJobs.delete(id);
    }
  }
  if (prepareJobs.size > PREPARE_JOB_MAX) {
    const sorted = Array.from(prepareJobs.entries()).sort(
      (a, b) => a[1].createdAt - b[1].createdAt,
    );
    while (prepareJobs.size > PREPARE_JOB_MAX && sorted.length > 0) {
      const [id] = sorted.shift();
      prepareJobs.delete(id);
    }
  }
}

/**
 * Run async debug preparation in the background
 * Spawns edb-simulator and streams progress via SSE
 * @param {import('./bridge-config.mjs').SimulationSemaphore} simulationSemaphore
 * @param {string} prepareId
 * @param {Object} params
 */
export async function runAsyncDebugPrep(simulationSemaphore, prepareId, params) {
  const job = prepareJobs.get(prepareId);
  if (!job) return;

  job.status = "preparing";
  job.message = "Starting debug preparation...";
  broadcastPrepareEvent(prepareId, "stage", {
    stage: "queued",
    progressPct: 0,
    message: job.message,
  });

  const payload = {
    mode: params.txHash ? "onchain" : "local",
    rpcUrl: params.rpcUrl,
    chainId: params.chainId,
    blockTag: params.blockTag || "latest",
    enableDebug: true,
    debugSessionOnly: true,
    analysisOptions: {
      quickMode: true,
      collectCallTree: true,
      collectEvents: true,
      collectStorageDiff: true,
      collectStorageDiffs: true,
      collectSnapshots: true,
    },
  };

  if (params.transaction) payload.transaction = params.transaction;
  if (params.txHash) payload.txHash = params.txHash;
  if (params.artifacts_inline) payload.artifacts_inline = params.artifacts_inline;
  if (Array.isArray(params.artifacts)) payload.artifacts = params.artifacts;

  console.log(
    `[simulator-bridge] async debug prep starting: ${prepareId} (RPC: ${redactRpcUrl(params.rpcUrl)}, chain: ${params.chainId})`,
  );

  try {
    const { result, session } = await gatedRunSimulationWithKeepAlive(
      simulationSemaphore,
      JSON.stringify(payload),
      {
        onProgress: (msg) => {
          const step = msg.current_step;
          const total = msg.total_steps || 8;
          const stageName = PREPARE_STAGE_NAMES[step] || `step_${step}`;
          const stageLabel = PREPARE_STAGE_LABELS[step] || msg.message;
          const pct = Math.round((step / total) * 100);

          job.stage = stageName;
          job.progressPct = pct;
          job.message = stageLabel;

          broadcastPrepareEvent(prepareId, "stage", {
            stage: stageName,
            progressPct: pct,
            message: stageLabel,
            currentStep: step,
            totalSteps: total,
          });
        },
      },
    );

    if (session) {
      job.status = "ready";
      job.sessionId = session.sessionId;
      job.snapshotCount = session.snapshotCount || 0;
      job.sourceFiles = result?.sourceFiles || {};
      job.progressPct = 100;
      job.stage = "ready";
      job.message = "Debug session ready";
      job.completedAt = Date.now();

      console.log(
        `[simulator-bridge] async debug prep ready: ${prepareId} → session ${session.sessionId}`,
      );

      broadcastPrepareEvent(prepareId, "ready", {
        sessionId: session.sessionId,
        snapshotCount: job.snapshotCount,
        sourceFiles: job.sourceFiles,
      });
    } else {
      throw new Error("Failed to create debug session — no keep-alive session returned");
    }
  } catch (err) {
    job.status = "failed";
    job.error = err.message || "Unknown error during debug preparation";
    job.completedAt = Date.now();
    console.error(`[simulator-bridge] async debug prep failed: ${prepareId}:`, err.message);

    broadcastPrepareEvent(prepareId, "failed", { error: job.error });
  }

  for (const client of job.sseClients) {
    try {
      client.end();
    } catch {}
  }
  job.sseClients.clear();
}
