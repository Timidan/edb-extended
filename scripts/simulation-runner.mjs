// =============================================================================
// Simulation Runner — Standard (non-keep-alive) simulation + shared utilities
// =============================================================================

import { spawn } from "node:child_process";
import { createWriteStream, readFileSync, unlinkSync } from "node:fs";
import { resolve as pathResolve } from "node:path";
import { tmpdir } from "node:os";
import {
  SIMULATOR_BINARY_PATH,
  SIMULATION_TIMEOUT_MS,
} from "./bridge-config.mjs";

// =============================================================================
// Shared Utilities
// =============================================================================

/**
 * Read the full body of an HTTP request as parsed JSON.
 * @param {import('node:http').IncomingMessage} req
 * @returns {Promise<any>}
 */
export function readBody(req) {
  return new Promise((resolveBody, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      try {
        const buffer = Buffer.concat(chunks).toString("utf8");
        resolveBody(buffer ? JSON.parse(buffer) : {});
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

/**
 * Parse JSON from simulator output (handles log lines before JSON)
 * @param {string} stdout - Raw simulator output
 * @returns {string} - Extracted JSON string
 */
export function extractJsonFromOutput(stdout) {
  return extractJsonFromOutputInternal(stdout, { silentFailures: false });
}

/**
 * Parse JSON from simulator output with optional silent failure logging.
 * @param {string} stdout
 * @param {{ silentFailures?: boolean }} [options]
 * @returns {string}
 */
export function extractJsonFromOutputInternal(stdout, options = {}) {
  const silentFailures = options?.silentFailures === true;
  const trimmed = stdout.trim();
  if (!trimmed) {
    return "{}";
  }

  // EDB outputs debug INFO logs before the JSON response.
  // The JSON is a complete object starting with "{" at the root level.
  const lines = trimmed.split("\n");
  let jsonStartIndex = -1;
  let accumulatedLength = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) {
      accumulatedLength += lines[i].length + 1;
      continue;
    }
    if (
      /^\d{4}-\d{2}-\d{2}T/.test(line) ||
      /^(INFO|WARN|ERROR|DEBUG|TRACE)\s/.test(line) ||
      /^\[.*\]/.test(line)
    ) {
      accumulatedLength += lines[i].length + 1;
      continue;
    }
    if (line.startsWith("{")) {
      jsonStartIndex = accumulatedLength;
      break;
    }
    accumulatedLength += lines[i].length + 1;
  }

  if (jsonStartIndex !== -1) {
    const jsonCandidate = trimmed.slice(jsonStartIndex).trim();
    try {
      JSON.parse(jsonCandidate);
      return jsonCandidate;
    } catch (parseError) {
      let depth = 0;
      let jsonEndIndex = -1;
      for (let i = 0; i < jsonCandidate.length; i++) {
        if (jsonCandidate[i] === "{") depth++;
        else if (jsonCandidate[i] === "}") {
          depth--;
          if (depth === 0) {
            jsonEndIndex = i + 1;
            break;
          }
        }
      }
      if (jsonEndIndex !== -1) {
        const extracted = jsonCandidate.slice(0, jsonEndIndex);
        try {
          JSON.parse(extracted);
          return extracted;
        } catch {
          if (!silentFailures) {
            console.warn("[simulator-bridge] failed to parse extracted JSON, returning raw output");
          }
        }
      }
    }
  }

  // Fallback: try parsing the whole trimmed output
  try {
    JSON.parse(trimmed);
    return trimmed;
  } catch {
    if (!silentFailures) {
      console.warn("[simulator-bridge] failed to parse simulator stdout as JSON, returning raw output");
    }
  }

  return trimmed;
}

/**
 * Terminate a process with SIGTERM, falling back to SIGKILL if unresponsive.
 * @param {number} pid
 * @param {string} label
 */
export function terminatePidWithFallback(pid, label) {
  if (!Number.isInteger(pid) || pid <= 1 || pid === process.pid) return;
  try {
    process.kill(pid, "SIGTERM");
  } catch (error) {
    console.warn(`[simulator-bridge] failed to terminate ${label} pid=${pid}:`, error);
    return;
  }

  const killTimer = setTimeout(() => {
    try {
      process.kill(pid, 0);
    } catch {
      return;
    }
    try {
      process.kill(pid, "SIGKILL");
      console.log(`[simulator-bridge] force-killed unresponsive ${label} pid=${pid}`);
    } catch (error) {
      console.warn(`[simulator-bridge] failed to force-kill ${label} pid=${pid}:`, error);
    }
  }, 1200);
  if (typeof killTimer?.unref === "function") {
    killTimer.unref();
  }
}

/**
 * Create an AbortSignal that fires when the HTTP request closes (client disconnect).
 * @param {import('node:http').IncomingMessage} req
 * @returns {AbortSignal}
 */
export function abortSignalFromReq(req) {
  const ac = new AbortController();
  req.on("close", () => { if (!req.complete) ac.abort(); });
  return ac.signal;
}

// =============================================================================
// Standard Simulation (non-keep-alive)
// =============================================================================

/**
 * Standard simulation without keep-alive (process exits after completion)
 * Uses file-based streaming to handle very large trace outputs that exceed Node.js string limits
 * @param {string} payload - JSON payload
 * @returns {Promise<string>}
 */
export function runSimulation(payload) {
  return new Promise((resolveResult, reject) => {
    const tempFile = pathResolve(tmpdir(), `edb-sim-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
    const writeStream = createWriteStream(tempFile);
    let writeStreamClosed = false;

    const child = spawn(SIMULATOR_BINARY_PATH, {
      stdio: ["pipe", "pipe", "inherit"],
    });

    let totalBytes = 0;
    let settled = false;
    const timeoutMs = Math.max(1000, SIMULATION_TIMEOUT_MS);

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
      resolveResult(value);
    };

    const settleReject = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutHandle);
      reject(error);
    };

    const timeoutHandle = setTimeout(() => {
      const pid = child.pid;
      if (Number.isInteger(pid) && pid > 1) {
        terminatePidWithFallback(pid, `simulation timeout (${timeoutMs}ms)`);
      }
      closeWriteStream(() => {
        try { unlinkSync(tempFile); } catch {}
      });
      settleReject(new Error(`Simulation timed out after ${Math.round(timeoutMs / 1000)}s`));
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
    });

    child.on("error", (err) => {
      if (settled) return;
      closeWriteStream();
      try { unlinkSync(tempFile); } catch {}
      settleReject(err);
    });

    child.on("close", (code, signal) => {
      if (settled) return;
      writeStream.end(() => {
        if (code === 0) {
          try {
            console.log(`[simulator-bridge] reading output file (${(totalBytes / 1024 / 1024).toFixed(2)} MB)`);
            const stdout = readFileSync(tempFile, "utf8");
            unlinkSync(tempFile);
            settleResolve(extractJsonFromOutput(stdout));
          } catch (readErr) {
            console.error(`[simulator-bridge] failed to read full output: ${readErr.message}`);
            try { unlinkSync(tempFile); } catch {}

            if (readErr.code === 'ERR_STRING_TOO_LONG' || readErr.message?.includes('string longer than')) {
              settleReject(new Error(`Trace output too large (${(totalBytes / 1024 / 1024).toFixed(0)} MB). This transaction has too many opcodes to process. Try a simpler transaction.`));
            } else {
              settleReject(new Error(`Failed to read simulator output: ${readErr.message}`));
            }
          }
        } else {
          try { unlinkSync(tempFile); } catch {}
          const errMsg = signal
            ? `simulator killed by signal ${signal}`
            : `simulator exited with code ${code}`;
          console.error(`[simulator-bridge] ${errMsg}`);
          settleReject(new Error(errMsg));
        }
      });
    });

    child.stdin.write(payload);
    child.stdin.end();
  });
}
