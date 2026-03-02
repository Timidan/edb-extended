// =============================================================================
// Simulator Bridge — HTTP Server Entry Point
//
// This is the main entry point for the simulator bridge. It imports all
// functionality from split modules and wires up the HTTP server and
// route handlers with graceful shutdown.
// =============================================================================

import http from "node:http";
import { freemem, totalmem } from "node:os";

import {
  PORT,
  SIMULATOR_BINARY_PATH,
  SIMULATION_QUEUE_TIMEOUT_MS,
  MAX_CONCURRENT_SIMULATIONS,
  SIMULATION_QUEUE_MAX,
  MEMORY_PRESSURE_THRESHOLD_MB,
  MEMORY_PRESSURE_HARD_LIMIT_MB,
  KEEP_ALIVE_MAX_SESSIONS,
  KEEP_ALIVE_IDLE_TTL_MS,
  KEEP_ALIVE_SWEEP_INTERVAL_MS,
  TRACE_LITE_TRANSPORT_ENABLED,
  SimulationCapacityError,
  SimulationSemaphore,
  validateBinaryExists,
} from "./bridge-config.mjs";

import { redactRpcUrl } from "./bridge-security.mjs";
import { sendJson } from "./http-compression.mjs";

import {
  traceDetailStore,
  getTraceDetailEntryBytes,
  decodeTraceDetailPayload,
  pruneTraceDetailStore,
} from "./trace-detail-store.mjs";

import { extractStorageLayoutFromArtifact } from "./artifact-compactor.mjs";

import {
  parseSimulationResult,
  applyLiteTraceTransport,
} from "./trace-processing.mjs";

import {
  readBody,
  abortSignalFromReq,
  runSimulation,
} from "./simulation-runner.mjs";

import {
  keepAliveSessions,
  keepAliveSweepTimer,
  checkMemoryPressure,
  endKeepAliveSession,
  cleanupStaleKeepAliveProcesses,
  runSimulationWithKeepAlive,
  makeKeepAliveRpcCall,
} from "./keep-alive-manager.mjs";

import {
  startDebugSession,
  prepareJobs,
  pruneStalePrepareSessions,
  runAsyncDebugPrep,
} from "./debug-sessions.mjs";

// =============================================================================
// Startup Validation
// =============================================================================

validateBinaryExists();

const simulationSemaphore = new SimulationSemaphore(
  MAX_CONCURRENT_SIMULATIONS,
  SIMULATION_QUEUE_MAX,
  SIMULATION_QUEUE_TIMEOUT_MS,
);

// =============================================================================
// Helper: 503 Capacity Error Response
// =============================================================================

function send503(res, err) {
  const retryAfterSec = Math.ceil(SIMULATION_QUEUE_TIMEOUT_MS / 1000);
  res.writeHead(503, {
    "Content-Type": "application/json",
    "Retry-After": String(retryAfterSec),
  });
  res.end(JSON.stringify({
    success: false,
    error: err.message,
    code: err.code,
    retry: true,
    capacity: {
      active: simulationSemaphore.activeCount,
      queued: simulationSemaphore.queueLength,
      maxConcurrent: simulationSemaphore.maxConcurrent,
      maxQueue: simulationSemaphore.maxQueueSize,
    },
  }));
}

// =============================================================================
// HTTP Server
// =============================================================================

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  if (req.headers["access-control-request-private-network"] === "true") {
    res.setHeader("Access-Control-Allow-Private-Network", "true");
  }

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = req.url?.split("?")[0];

  // Health check
  if (req.method === "GET" && url === "/health") {
    pruneTraceDetailStore();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      status: "ok",
      edbServerRunning: false,
      activeSessions: keepAliveSessions.size,
      traceDetailHandles: traceDetailStore.size,
      traceDetailBytes: Array.from(traceDetailStore.values()).reduce(
        (sum, entry) => sum + getTraceDetailEntryBytes(entry),
        0,
      ),
      concurrency: {
        activeSimulations: simulationSemaphore.activeCount,
        queuedRequests: simulationSemaphore.queueLength,
        maxConcurrent: simulationSemaphore.maxConcurrent,
        maxQueue: simulationSemaphore.maxQueueSize,
        queueTimeoutMs: SIMULATION_QUEUE_TIMEOUT_MS,
      },
      memory: {
        totalMB: Math.round(totalmem() / (1024 * 1024)),
        freeMB: Math.round(freemem() / (1024 * 1024)),
        pressureThresholdMB: MEMORY_PRESSURE_THRESHOLD_MB,
        hardLimitMB: MEMORY_PRESSURE_HARD_LIMIT_MB,
      },
    }));
    return;
  }

  // =========================================================================
  // GET endpoints for debug preparation SSE and polling
  // =========================================================================
  if (req.method === "GET") {
    const sseMatch = url?.match(/^\/debug\/prepare\/([^/]+)\/events$/);
    if (sseMatch) {
      const prepareId = sseMatch[1];
      const job = prepareJobs.get(prepareId);
      if (!job) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "prepare_job_not_found" }));
        return;
      }

      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Access-Control-Allow-Origin": "*",
      });

      if (job.status === "ready") {
        res.write(`event: ready\ndata: ${JSON.stringify({
          sessionId: job.sessionId,
          snapshotCount: job.snapshotCount,
          sourceFiles: job.sourceFiles,
        })}\n\n`);
        res.end();
        return;
      }
      if (job.status === "failed") {
        res.write(`event: failed\ndata: ${JSON.stringify({ error: job.error })}\n\n`);
        res.end();
        return;
      }

      res.write(`event: stage\ndata: ${JSON.stringify({
        stage: job.stage || "queued",
        progressPct: job.progressPct || 0,
        message: job.message || "Waiting...",
      })}\n\n`);

      job.sseClients.add(res);
      req.on("close", () => {
        job.sseClients.delete(res);
      });
      return;
    }

    const pollMatch = url?.match(/^\/debug\/prepare\/([^/]+)$/);
    if (pollMatch) {
      const prepareId = pollMatch[1];
      const job = prepareJobs.get(prepareId);
      if (!job) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "prepare_job_not_found" }));
        return;
      }

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        prepareId: job.prepareId,
        status: job.status,
        stage: job.stage,
        progressPct: job.progressPct,
        message: job.message,
        sessionId: job.sessionId,
        snapshotCount: job.snapshotCount,
        sourceFiles: job.sourceFiles,
        error: job.error,
      }));
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
    return;
  }

  if (req.method !== "POST") {
    res.writeHead(405, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "method_not_allowed" }));
    return;
  }

  try {
    const body = await readBody(req);

    switch (url) {
      // =========================================================================
      // Simulation Endpoint
      // =========================================================================
      case "/simulate": {
        const { rpcUrl, transaction, txHash, mode, enableDebug } = body;
        const payload = JSON.stringify(body);
        const enableLiteTraceTransport =
          TRACE_LITE_TRANSPORT_ENABLED && enableDebug === false;

        let release;
        try {
          release = await simulationSemaphore.acquire(abortSignalFromReq(req));
        } catch (capacityErr) {
          if (capacityErr instanceof SimulationCapacityError) {
            send503(res, capacityErr);
            break;
          }
          throw capacityErr;
        }

        try {
          const memErr = checkMemoryPressure();
          if (memErr) {
            release();
            send503(res, memErr);
            break;
          }

          const useKeepAlive = rpcUrl && (transaction || (mode === "onchain" && txHash)) && enableDebug !== false;
          if (useKeepAlive) {
            try {
              console.log("[simulator-bridge] running simulation with keep-alive for debugging");
              const { result, session } = await runSimulationWithKeepAlive(payload);

              if (session) {
                result.debugSession = {
                  sessionId: session.sessionId,
                  rpcPort: session.rpcPort,
                  snapshotCount: session.snapshotCount,
                };
              }

              if (result.renderedTrace && typeof result.renderedTrace === "object") {
                const rt = result.renderedTrace;
                if (Array.isArray(rt.rows) && rt.rows.length > 0) {
                  result.traceSchemaVersion = 3;
                  const rawTrace = result.rawTrace;
                  if (rawTrace && typeof rawTrace === "object") {
                    for (const field of ["snapshots", "sources", "opcodeTrace"]) {
                      if (rawTrace[field]) delete rawTrace[field];
                      if (rawTrace.inner && typeof rawTrace.inner === "object" && rawTrace.inner[field]) delete rawTrace.inner[field];
                    }
                    if (rawTrace.artifacts && typeof rawTrace.artifacts === "object") {
                      for (const [addr, artifact] of Object.entries(rawTrace.artifacts)) {
                        if (artifact && typeof artifact === "object") {
                          const cName = artifact.meta?.ContractName || artifact.meta?.Name || null;
                          const storageLayout = extractStorageLayoutFromArtifact(artifact, cName);
                          rawTrace.artifacts[addr] = {
                            ...(artifact.meta ? { meta: artifact.meta } : {}),
                            ...(storageLayout ? { storageLayout } : {}),
                          };
                        }
                      }
                    }
                  }
                  console.log(`[simulator-bridge] keep-alive V3 rendered trace: ${rt.rows.length} rows`);
                }
              }

              const responsePayload = enableLiteTraceTransport ? applyLiteTraceTransport(result) : result;
              sendJson(res, req, 200, responsePayload);
            } catch (err) {
              console.error("[simulator-bridge] keep-alive simulation failed:", err);

              const isOutputTooLarge = err.message?.includes('too large') ||
                                        err.message?.includes('ERR_STRING_TOO_LONG') ||
                                        err.message?.includes('string longer than');
              if (isOutputTooLarge) {
                console.error("[simulator-bridge] trace output exceeds Node.js string limit, cannot proceed");
                res.writeHead(413, { "Content-Type": "application/json" });
                res.end(JSON.stringify({
                  success: false,
                  error: "Transaction trace is too large to process. This transaction has too many opcodes (likely a complex DeFi transaction). Try simulating a simpler transaction.",
                  details: err.message,
                }));
                break;
              }

              console.log("[simulator-bridge] falling back to regular simulation");
              const result = await runSimulation(payload);
              let responsePayload = parseSimulationResult(result);
              if (enableLiteTraceTransport) {
                responsePayload = applyLiteTraceTransport(responsePayload);
              }
              sendJson(res, req, 200, responsePayload);
            }
          } else {
            try {
              const result = await runSimulation(payload);
              let responsePayload = parseSimulationResult(result);
              if (enableLiteTraceTransport) {
                responsePayload = applyLiteTraceTransport(responsePayload);
              }
              sendJson(res, req, 200, responsePayload);
            } catch (err) {
              console.error("[simulator-bridge] simulation failed:", err);
              const isOutputTooLarge = err.message?.includes('too large') ||
                                        err.message?.includes('ERR_STRING_TOO_LONG') ||
                                        err.message?.includes('string longer than');
              if (isOutputTooLarge) {
                res.writeHead(413, { "Content-Type": "application/json" });
                res.end(JSON.stringify({
                  success: false,
                  error: "Transaction trace is too large to process. This transaction has too many opcodes (likely a complex DeFi transaction). Try simulating a simpler transaction.",
                  details: err.message,
                }));
              } else {
                res.writeHead(500, { "Content-Type": "application/json" });
                res.end(JSON.stringify({
                  success: false,
                  error: err.message || "Simulation failed",
                }));
              }
            }
          }
        } finally {
          release();
        }
        break;
      }

      // =========================================================================
      // Trace Detail Endpoint
      // =========================================================================
      case "/trace/detail": {
        const { id } = body || {};
        if (!id || typeof id !== "string") {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Missing required field: id" }));
          return;
        }

        pruneTraceDetailStore();
        const detailEntry = traceDetailStore.get(id);
        if (!detailEntry) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "trace_detail_not_found" }));
          return;
        }
        let decodedFields;
        try {
          decodedFields = decodeTraceDetailPayload(detailEntry);
        } catch (error) {
          console.error("[simulator-bridge] failed to decode trace detail payload:", error);
          traceDetailStore.delete(id);
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "trace_detail_decode_failed" }));
          return;
        }

        sendJson(res, req, 200, {
          id: detailEntry.id,
          fields: detailEntry.fields,
          expiresAt: detailEntry.expiresAt,
          rawTrace: decodedFields,
        });
        break;
      }

      // =========================================================================
      // Debug Endpoints
      // =========================================================================

      case "/debug/prepare": {
        const { rpcUrl, chainId, blockTag, transaction, txHash, artifacts, artifacts_inline } =
          body;

        if (!rpcUrl || !chainId || (!transaction && !txHash)) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              error: "Missing required fields: rpcUrl, chainId, and (transaction or txHash)",
            }),
          );
          return;
        }

        pruneStalePrepareSessions();

        const prepareId = `prep-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
        const job = {
          prepareId,
          status: "queued",
          stage: null,
          progressPct: 0,
          message: "Queued for debug preparation",
          sessionId: null,
          snapshotCount: null,
          sourceFiles: null,
          error: null,
          sseClients: new Set(),
          createdAt: Date.now(),
          completedAt: null,
        };
        prepareJobs.set(prepareId, job);

        console.log(
          `[simulator-bridge] debug prepare job created: ${prepareId}`,
        );

        runAsyncDebugPrep(simulationSemaphore, prepareId, {
          rpcUrl,
          chainId,
          blockTag,
          transaction,
          txHash,
          artifacts,
          artifacts_inline,
        }).catch((err) => {
          console.error(`[simulator-bridge] uncaught error in debug prep ${prepareId}:`, err);
        });

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ prepareId }));
        break;
      }

      case "/debug/start": {
        const { rpcUrl, chainId, blockTag, transaction, txHash, artifacts, artifacts_inline } =
          body;

        if (!rpcUrl || !chainId || (!transaction && !txHash)) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              error: "Missing required fields: rpcUrl, chainId, and (transaction or txHash)",
            }),
          );
          return;
        }

        const session = await startDebugSession(simulationSemaphore, {
          rpcUrl,
          chainId,
          blockTag,
          transaction,
          txHash,
          artifacts,
          artifacts_inline,
        });

        sendJson(res, req, 200, {
          sessionId: session.sessionId,
          rpcPort: session.rpcPort,
          snapshotCount: session.snapshotCount,
          sourceFiles: session.sourceFiles,
        });
        break;
      }

      case "/debug/rpc": {
        const { sessionId, method, params } = body;

        if (!sessionId || !method) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Missing required fields: sessionId, method" }));
          return;
        }

        const keepAliveSession = keepAliveSessions.get(sessionId);
        if (keepAliveSession) {
          const result = await makeKeepAliveRpcCall(keepAliveSession, method, params || []);
          sendJson(res, req, 200, { result });
        } else {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: `Debug session not found: ${sessionId}` }));
        }
        break;
      }

      case "/debug/end": {
        const { sessionId } = body;

        if (!sessionId) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Missing required field: sessionId" }));
          return;
        }

        if (keepAliveSessions.has(sessionId)) {
          endKeepAliveSession(sessionId);
        }

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true }));
        break;
      }

      case "/debug/sessions": {
        const kaSessions = Array.from(keepAliveSessions.values()).map((s) => ({
          sessionId: s.sessionId,
          rpcPort: s.rpcPort,
          snapshotCount: s.snapshotCount || 0,
          rpcProvider: redactRpcUrl(s.rpcUrl),
          createdAt: s.createdAt,
          age: Date.now() - s.createdAt,
          idleMs: Date.now() - s.lastAccessedAt,
          type: "keep-alive",
        }));

        sendJson(res, req, 200, { sessions: kaSessions });
        break;
      }

      default:
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "not_found" }));
    }
  } catch (err) {
    if (err instanceof SimulationCapacityError) {
      send503(res, err);
      return;
    }
    console.error(`[simulator-bridge] error on ${url}:`, err);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "internal_error", details: String(err) }));
  }
});

// =============================================================================
// Server Startup + Graceful Shutdown
// =============================================================================

server.listen(PORT, () => {
  cleanupStaleKeepAliveProcesses();
  console.log(`[simulator-bridge] listening on http://127.0.0.1:${PORT}`);
  console.log(`[simulator-bridge] using simulator binary at ${SIMULATOR_BINARY_PATH}`);
  console.log(`[simulator-bridge] endpoints:`);
  console.log(`  POST /simulate     - Run quick simulation`);
  console.log(`  POST /trace/detail - Fetch heavy trace payload fields`);
  console.log(`  POST /debug/prepare - Start async debug preparation (returns prepareId)`);
  console.log(`  GET  /debug/prepare/:id/events - SSE stream for debug prep progress`);
  console.log(`  GET  /debug/prepare/:id - Poll debug prep status`);
  console.log(`  POST /debug/start  - Start debug session (synchronous)`);
  console.log(`  POST /debug/rpc    - Call debug RPC method`);
  console.log(`  POST /debug/end    - End debug session`);
  console.log(`  POST /debug/sessions - List active sessions`);
  console.log(`  GET  /health       - Health check`);
  console.log(`[simulator-bridge] concurrency: max=${MAX_CONCURRENT_SIMULATIONS} processes, queue=${SIMULATION_QUEUE_MAX}, queue_timeout=${SIMULATION_QUEUE_TIMEOUT_MS}ms`);
  console.log(`[simulator-bridge] memory-pressure: evict_threshold=${MEMORY_PRESSURE_THRESHOLD_MB}MB, hard_limit=${MEMORY_PRESSURE_HARD_LIMIT_MB}MB, system_total=${Math.round(totalmem() / (1024 * 1024))}MB`);
  console.log(`[simulator-bridge] keep-alive: max_sessions=${KEEP_ALIVE_MAX_SESSIONS}, idle_ttl=${KEEP_ALIVE_IDLE_TTL_MS / 1000}s, sweep_interval=${KEEP_ALIVE_SWEEP_INTERVAL_MS / 1000}s`);
});

function gracefulShutdown(signal) {
  console.log(`[simulator-bridge] shutting down (${signal})`);

  simulationSemaphore.drainAndRejectAll();

  if (keepAliveSessions.size > 0) {
    console.log(`[simulator-bridge] stopping ${keepAliveSessions.size} keep-alive session(s)`);
    for (const sessionId of keepAliveSessions.keys()) {
      endKeepAliveSession(sessionId);
    }
  }

  traceDetailStore.clear();
  clearInterval(keepAliveSweepTimer);

  server.close(() => process.exit(0));
}

process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
