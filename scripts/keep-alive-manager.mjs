// =============================================================================
// Keep-Alive Session Manager — Session CRUD, sweep, stale cleanup,
// runSimulationWithKeepAlive, makeKeepAliveRpcCall, gated wrappers
// =============================================================================

import http from "node:http";
import { spawn, execSync } from "node:child_process";
import { createWriteStream, readFileSync, unlinkSync } from "node:fs";
import { resolve as pathResolve } from "node:path";
import { tmpdir, freemem, totalmem } from "node:os";
import {
  SIMULATOR_BINARY_PATH,
  KEEP_ALIVE_IDLE_TTL_MS,
  KEEP_ALIVE_SWEEP_INTERVAL_MS,
  KEEP_ALIVE_MAX_SESSIONS,
  KEEP_ALIVE_CLEAN_STALE_ON_STARTUP,
  KEEP_ALIVE_INCREMENTAL_PARSE_MAX_BYTES,
  KEEP_ALIVE_SIM_TIMEOUT_MS,
  MEMORY_PRESSURE_THRESHOLD_MB,
  MEMORY_PRESSURE_HARD_LIMIT_MB,
  SimulationCapacityError,
} from "./bridge-config.mjs";
import { redactRpcUrl } from "./bridge-security.mjs";
import { terminatePidWithFallback, extractJsonFromOutputInternal } from "./simulation-runner.mjs";

/**
 * @typedef {Object} KeepAliveSession
 * @property {string} sessionId
 * @property {import('node:child_process').ChildProcess} process
 * @property {number} rpcPort
 * @property {string} rpcUrl
 * @property {number} createdAt
 * @property {number} lastAccessedAt
 * @property {string | undefined} tempFile
 */

/** @type {Map<string, KeepAliveSession>} */
export const keepAliveSessions = new Map();

// =============================================================================
// Memory Pressure
// =============================================================================

/**
 * Check system memory pressure and evict idle keep-alive sessions if needed.
 * Returns null if memory is available, or a SimulationCapacityError if even
 * after eviction the system is still critically low on RAM.
 * @returns {SimulationCapacityError|null}
 */
export function checkMemoryPressure() {
  const freeMemMB = freemem() / (1024 * 1024);
  const totalMemMB = totalmem() / (1024 * 1024);

  if (freeMemMB >= MEMORY_PRESSURE_THRESHOLD_MB) return null;

  // Soft pressure — evict idle keep-alive sessions oldest-first
  if (keepAliveSessions.size > 0) {
    const sessionsByIdle = Array.from(keepAliveSessions.values()).sort(
      (a, b) => a.lastAccessedAt - b.lastAccessedAt,
    );
    let evicted = 0;
    for (const session of sessionsByIdle) {
      endKeepAliveSession(session.sessionId);
      evicted++;
      const nowFree = freemem() / (1024 * 1024);
      if (nowFree >= MEMORY_PRESSURE_THRESHOLD_MB) break;
    }
    if (evicted > 0) {
      console.log(
        `[simulator-bridge] memory pressure: evicted ${evicted} idle keep-alive session(s) ` +
        `(free: ${freeMemMB.toFixed(0)}MB → ${(freemem() / (1024 * 1024)).toFixed(0)}MB / ${totalMemMB.toFixed(0)}MB total)`,
      );
    }
  }

  // Hard limit — still too low after eviction
  const freeAfterMB = freemem() / (1024 * 1024);
  if (freeAfterMB < MEMORY_PRESSURE_HARD_LIMIT_MB) {
    return new SimulationCapacityError(
      `Server memory critically low: ${freeAfterMB.toFixed(0)}MB free (need ${MEMORY_PRESSURE_HARD_LIMIT_MB}MB). ` +
      `Try again in a few seconds.`,
      "memory_pressure",
    );
  }
  return null;
}

// =============================================================================
// Session Lifecycle Helpers
// =============================================================================

export function touchKeepAliveSession(sessionId) {
  const session = keepAliveSessions.get(sessionId);
  if (!session) return;
  session.lastAccessedAt = Date.now();
}

export function enforceKeepAliveCapacity() {
  if (keepAliveSessions.size < KEEP_ALIVE_MAX_SESSIONS) return;
  const sessionsByAge = Array.from(keepAliveSessions.values()).sort(
    (a, b) => a.lastAccessedAt - b.lastAccessedAt || a.createdAt - b.createdAt,
  );
  while (keepAliveSessions.size >= KEEP_ALIVE_MAX_SESSIONS && sessionsByAge.length > 0) {
    const victim = sessionsByAge.shift();
    if (!victim) break;
    console.log(
      `[simulator-bridge] max keep-alive sessions reached (${KEEP_ALIVE_MAX_SESSIONS}), evicting oldest session ${victim.sessionId}`,
    );
    endKeepAliveSession(victim.sessionId);
  }
}

/**
 * End a keep-alive session by killing the simulator process
 * @param {string} sessionId
 */
export function endKeepAliveSession(sessionId) {
  const session = keepAliveSessions.get(sessionId);
  if (session) {
    const pid = session.process?.pid;
    if (pid && !session.process.killed) {
      terminatePidWithFallback(pid, `keep-alive session ${sessionId}`);
    }
    if (session.tempFile) {
      try { unlinkSync(session.tempFile); } catch {}
    }
    keepAliveSessions.delete(sessionId);
    console.log(`[simulator-bridge] keep-alive session ended: ${sessionId}`);
  }
}

export function sweepIdleKeepAliveSessions() {
  const now = Date.now();
  for (const session of keepAliveSessions.values()) {
    const idleMs = now - session.lastAccessedAt;
    if (idleMs > KEEP_ALIVE_IDLE_TTL_MS) {
      console.log(
        `[simulator-bridge] keep-alive session idle timeout: ${session.sessionId} (idle ${(idleMs / 1000).toFixed(0)}s)`,
      );
      endKeepAliveSession(session.sessionId);
    }
  }
}

/** @type {ReturnType<typeof setInterval>} */
export const keepAliveSweepTimer = setInterval(sweepIdleKeepAliveSessions, KEEP_ALIVE_SWEEP_INTERVAL_MS);
if (typeof keepAliveSweepTimer?.unref === "function") {
  keepAliveSweepTimer.unref();
}

export function cleanupStaleKeepAliveProcesses() {
  if (!KEEP_ALIVE_CLEAN_STALE_ON_STARTUP) return;
  try {
    const psOutput = execSync("ps -eo pid,args --no-headers", {
      stdio: ["ignore", "pipe", "ignore"],
      encoding: "utf8",
    });
    let terminated = 0;
    for (const rawLine of psOutput.split("\n")) {
      const line = rawLine.trim();
      if (!line) continue;
      const firstSpace = line.indexOf(" ");
      if (firstSpace === -1) continue;

      const pid = Number(line.slice(0, firstSpace).trim());
      if (!Number.isInteger(pid) || pid <= 1 || pid === process.pid) continue;
      const args = line.slice(firstSpace + 1);
      if (!args.includes(SIMULATOR_BINARY_PATH) || !args.includes("--keep-alive")) continue;

      terminatePidWithFallback(pid, "stale keep-alive");
      terminated += 1;
    }
    if (terminated > 0) {
      console.log(`[simulator-bridge] terminated ${terminated} stale keep-alive process(es) at startup`);
    }
  } catch (error) {
    console.warn("[simulator-bridge] failed to scan stale keep-alive processes:", error);
  }
}

// =============================================================================
// Stderr Parsing (progress lines from edb-simulator)
// =============================================================================

function looksLikeKeepAliveSimulationResult(result) {
  return Boolean(result && typeof result === "object");
}

/**
 * Parse stderr chunk from edb-simulator, extracting __EDB_PROGRESS__ lines.
 * @param {Buffer} chunk
 * @param {((msg: {message: string, current_step?: number, total_steps?: number}) => void)|null} onProgress
 */
function logKeepAliveStderrChunk(chunk, onProgress) {
  const text = chunk.toString("utf8");
  if (!text) return;
  const MAX_LINE_CHARS = 500;
  const PROGRESS_PREFIX = "__EDB_PROGRESS__:";
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  for (const line of lines) {
    if (line.startsWith(PROGRESS_PREFIX)) {
      try {
        const json = JSON.parse(line.slice(PROGRESS_PREFIX.length));
        if (onProgress && json && json.message) {
          onProgress(json);
        }
      } catch {
        console.log(`[edb-simulator] ${line}`);
      }
      continue;
    }

    if (line.length <= MAX_LINE_CHARS) {
      console.log(`[edb-simulator] ${line}`);
      continue;
    }
    const omitted = line.length - MAX_LINE_CHARS;
    console.log(
      `[edb-simulator] ${line.slice(0, MAX_LINE_CHARS)}... [truncated ${omitted} chars]`,
    );
  }
}

// =============================================================================
// Keep-Alive Simulation Runner
// =============================================================================

/**
 * Run simulation with --keep-alive flag for debugging
 * Returns the simulation result and keeps the RPC server alive
 * Uses file-based streaming to handle very large trace outputs
 * @param {string} payload - JSON payload for simulation
 * @param {{onProgress?: (msg: {message: string, current_step?: number, total_steps?: number}) => void}} [options]
 * @returns {Promise<{result: Object, session: KeepAliveSession | null}>}
 */
export function runSimulationWithKeepAlive(payload, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(SIMULATOR_BINARY_PATH, ["--keep-alive"], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    const tempFile = pathResolve(tmpdir(), `edb-keep-alive-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
    const writeStream = createWriteStream(tempFile);
    let writeStreamClosed = false;
    let totalBytes = 0;
    let jsonParsed = false;
    let createdSessionId = null;
    let settled = false;
    let fileParseTimer = null;
    let idleParseTimer = null;
    let fileParseModeEnabled = false;
    let recentBuffer = Buffer.alloc(0);
    const MAX_INCREMENTAL_SIZE = KEEP_ALIVE_INCREMENTAL_PARSE_MAX_BYTES;
    const IDLE_PARSE_DELAY_MS = 750;
    const timeoutMs = Math.max(1000, KEEP_ALIVE_SIM_TIMEOUT_MS);

    const clearFileParseTimer = () => {
      if (fileParseTimer) {
        clearInterval(fileParseTimer);
        fileParseTimer = null;
      }
    };

    const clearIdleParseTimer = () => {
      if (idleParseTimer) {
        clearTimeout(idleParseTimer);
        idleParseTimer = null;
      }
    };

    const closeWriteStream = (onClosed) => {
      if (writeStreamClosed) {
        if (typeof onClosed === "function") onClosed();
        return;
      }
      writeStreamClosed = true;
      writeStream.end(() => {
        if (typeof onClosed === "function") onClosed();
      });
    };

    const settleResolve = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutHandle);
      clearFileParseTimer();
      clearIdleParseTimer();
      resolve(value);
    };

    const settleReject = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutHandle);
      clearFileParseTimer();
      clearIdleParseTimer();
      reject(error);
    };

    const resolveParsedKeepAliveResult = (result) => {
      if (settled || jsonParsed || !looksLikeKeepAliveSimulationResult(result)) {
        return false;
      }

      jsonParsed = true;
      recentBuffer = Buffer.alloc(0);
      clearFileParseTimer();

      let session = null;
      if (result.debugSession) {
        enforceKeepAliveCapacity();
        const sessionId = `keep-alive-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
        createdSessionId = sessionId;
        session = {
          sessionId,
          process: child,
          rpcPort: result.debugSession.rpcPort,
          rpcUrl: result.debugSession.rpcUrl,
          snapshotCount: result.debugSession.snapshotCount || 0,
          createdAt: Date.now(),
          lastAccessedAt: Date.now(),
          tempFile,
        };
        keepAliveSessions.set(sessionId, session);
        console.log(
          `[simulator-bridge] keep-alive session created: ${sessionId} on port ${session.rpcPort} with ${session.snapshotCount} snapshots (RPC: ${redactRpcUrl(session.rpcUrl)})`,
        );
      } else {
        closeWriteStream(() => { try { unlinkSync(tempFile); } catch {} });
      }

      settleResolve({ result, session });
      return true;
    };

    const tryParseFromTempFile = () => {
      if (settled || jsonParsed) return;
      try {
        const stdout = readFileSync(tempFile, "utf8");
        const jsonStr = extractJsonFromOutputInternal(stdout, { silentFailures: true });
        const result = JSON.parse(jsonStr);
        resolveParsedKeepAliveResult(result);
      } catch (error) {
        if (error?.code === "ERR_STRING_TOO_LONG") {
          settleReject(
            new Error(
              `Trace output too large to parse incrementally (${(totalBytes / 1024 / 1024).toFixed(0)} MB).`,
            ),
          );
        }
      }
    };

    const scheduleIdleParse = () => {
      if (settled || jsonParsed) return;
      clearIdleParseTimer();
      idleParseTimer = setTimeout(() => {
        idleParseTimer = null;
        tryParseFromTempFile();
      }, IDLE_PARSE_DELAY_MS);
      if (typeof idleParseTimer?.unref === "function") {
        idleParseTimer.unref();
      }
    };

    const timeoutHandle = setTimeout(() => {
      const pid = child.pid;
      if (Number.isInteger(pid) && pid > 1) {
        terminatePidWithFallback(pid, `keep-alive simulation timeout (${timeoutMs}ms)`);
      }
      closeWriteStream(() => {
        try { unlinkSync(tempFile); } catch {}
      });
      settleReject(new Error(`Keep-alive simulation timed out after ${Math.round(timeoutMs / 1000)}s`));
    }, timeoutMs);
    if (typeof timeoutHandle?.unref === "function") {
      timeoutHandle.unref();
    }

    child.stdout.on("data", (chunk) => {
      if (settled || writeStreamClosed || writeStream.destroyed || !writeStream.writable) {
        return;
      }
      totalBytes += chunk.length;
      writeStream.write(chunk);

      if (!jsonParsed && totalBytes < MAX_INCREMENTAL_SIZE) {
        recentBuffer = Buffer.concat([recentBuffer, chunk]);
        try {
          const stdout = recentBuffer.toString("utf8");
          const jsonStr = extractJsonFromOutputInternal(stdout, { silentFailures: true });
          const result = JSON.parse(jsonStr);
          resolveParsedKeepAliveResult(result);
        } catch {
          // Not complete JSON yet
        }
      } else if (!jsonParsed && totalBytes >= MAX_INCREMENTAL_SIZE) {
        recentBuffer = Buffer.alloc(0);
        if (!fileParseModeEnabled) {
          fileParseModeEnabled = true;
          console.log(
            `[simulator-bridge] output exceeds ${MAX_INCREMENTAL_SIZE / 1024 / 1024}MB, switching to periodic file parse mode`,
          );
          fileParseTimer = setInterval(tryParseFromTempFile, 1500);
          if (typeof fileParseTimer?.unref === "function") {
            fileParseTimer.unref();
          }
        }
      }

      scheduleIdleParse();
    });

    child.stderr.on("data", (chunk) => {
      logKeepAliveStderrChunk(chunk, options.onProgress || null);
    });

    child.on("error", (err) => {
      if (!jsonParsed && !settled) {
        clearIdleParseTimer();
        closeWriteStream();
        try { unlinkSync(tempFile); } catch {}
        settleReject(err);
      }
    });

    child.on("close", (code, signal) => {
      clearFileParseTimer();
      clearIdleParseTimer();
      if (createdSessionId && keepAliveSessions.has(createdSessionId)) {
        keepAliveSessions.delete(createdSessionId);
        try { unlinkSync(tempFile); } catch {}
        console.log(
          `[simulator-bridge] keep-alive process exited for session ${createdSessionId} (code=${code}, signal=${signal ?? "none"})`,
        );
      }
      if (settled) {
        return;
      }
      if (!jsonParsed) {
        closeWriteStream(() => {
          const closeReason = signal
            ? `signal ${signal}`
            : code === null || typeof code === "undefined"
              ? "unknown close reason"
              : `code ${code}`;

          try {
            console.log(
              `[simulator-bridge] keep-alive close before incremental parse; reading output file (${(totalBytes / 1024 / 1024).toFixed(2)} MB), reason=${closeReason}`,
            );
            const stdout = readFileSync(tempFile, "utf8");
            const jsonStr = extractJsonFromOutputInternal(stdout, { silentFailures: true });
            const result = JSON.parse(jsonStr);
            try { unlinkSync(tempFile); } catch {}

            if (resolveParsedKeepAliveResult(result)) {
              return;
            }
            settleResolve({ result, session: null });
          } catch (e) {
            try { unlinkSync(tempFile); } catch {}
            if (e?.code === "ERR_STRING_TOO_LONG") {
              settleReject(
                new Error(
                  `Trace output too large (${(totalBytes / 1024 / 1024).toFixed(0)} MB). This transaction has too many opcodes to display. Consider using a simpler transaction.`,
                ),
              );
            } else if ((code === 0 || code === null || typeof code === "undefined") && !signal) {
              settleReject(new Error(`Failed to parse simulator output: ${e.message}`));
            } else {
              settleReject(
                new Error(
                  `simulator exited (${closeReason}) before keep-alive JSON was parsed: ${e.message}`,
                ),
              );
            }
          }
        });
      }
    });

    child.stdin.write(payload);
    child.stdin.end();
  });
}

// =============================================================================
// Gated Wrappers (semaphore-acquiring)
// =============================================================================

/**
 * Acquire a semaphore slot, run runSimulationWithKeepAlive, release on completion.
 * @param {import('./bridge-config.mjs').SimulationSemaphore} simulationSemaphore
 * @param {string} payload
 * @param {Object} [options]
 * @param {AbortSignal} [signal]
 * @returns {Promise<{result: Object, session: KeepAliveSession | null}>}
 */
export async function gatedRunSimulationWithKeepAlive(simulationSemaphore, payload, options = {}, signal) {
  const release = await simulationSemaphore.acquire(signal);
  try {
    const memErr = checkMemoryPressure();
    if (memErr) { release(); throw memErr; }
    return await runSimulationWithKeepAlive(payload, options);
  } finally {
    release();
  }
}

/**
 * Make an RPC call to a keep-alive session's RPC server
 * @param {KeepAliveSession} session
 * @param {string} method
 * @param {any[]} params
 * @returns {Promise<any>}
 */
export function makeKeepAliveRpcCall(session, method, params = []) {
  touchKeepAliveSession(session.sessionId);
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
        headers: {
          "Content-Type": "application/json",
        },
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

    req.on("error", (err) => {
      reject(new Error(`RPC call failed: ${err.message}`));
    });

    req.write(JSON.stringify(rpcRequest));
    req.end();
  });
}
