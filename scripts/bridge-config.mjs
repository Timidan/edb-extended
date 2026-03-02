// =============================================================================
// Bridge Configuration — Constants, Environment Variables, Concurrency
// =============================================================================

import { resolve as pathResolve } from "node:path";
import { existsSync } from "node:fs";
import { totalmem, freemem } from "node:os";

export const PORT = Number(process.env.SIMULATOR_BRIDGE_PORT ?? 5789);
export const EDB_WS_PORT = Number(process.env.EDB_WS_PORT ?? 9001);
export const TRACE_DETAIL_TTL_MS = Number(process.env.TRACE_DETAIL_TTL_MS ?? 30 * 60 * 1000);
export const TRACE_DETAIL_MAX_ENTRIES = Number(process.env.TRACE_DETAIL_MAX_ENTRIES ?? 64);
export const TRACE_DETAIL_MAX_TOTAL_BYTES = Number(
  process.env.TRACE_DETAIL_MAX_TOTAL_BYTES ?? 128 * 1024 * 1024,
);
export const TRACE_DETAIL_GZIP_MIN_BYTES = Number(
  process.env.TRACE_DETAIL_GZIP_MIN_BYTES ?? 128 * 1024,
);
export const TRACE_STRIP_OPCODE_LINES = process.env.TRACE_DETAIL_STRIP_OPCODE_LINES === "true";
export const TRACE_DETAIL_STRIP_OPCODE_TRACE = process.env.TRACE_DETAIL_STRIP_OPCODE_TRACE !== "false";
export const TRACE_DETAIL_COMPACT_ARTIFACTS = process.env.TRACE_DETAIL_COMPACT_ARTIFACTS !== "false";
export const TRACE_V2_BRIDGE_JS_FALLBACK = process.env.SIM_TRACE_V2_BRIDGE_JS_FALLBACK === "true";
export const TRACE_LITE_TRANSPORT_ENABLED =
  process.env.SIM_TRACE_V2_LITE_TRANSPORT !== "false";
export const KEEP_ALIVE_IDLE_TTL_MS = Number(process.env.KEEP_ALIVE_IDLE_TTL_MS ?? 3 * 60 * 1000);
export const KEEP_ALIVE_SWEEP_INTERVAL_MS = Number(
  process.env.KEEP_ALIVE_SWEEP_INTERVAL_MS ?? 15 * 1000,
);
export const KEEP_ALIVE_MAX_SESSIONS = Math.max(1, Number(process.env.KEEP_ALIVE_MAX_SESSIONS ?? 3));
export const KEEP_ALIVE_CLEAN_STALE_ON_STARTUP =
  process.env.KEEP_ALIVE_CLEAN_STALE_ON_STARTUP !== "false";
export const KEEP_ALIVE_INCREMENTAL_PARSE_MAX_BYTES = Number(
  process.env.KEEP_ALIVE_INCREMENTAL_PARSE_MAX_BYTES ?? 16 * 1024 * 1024,
);
export const KEEP_ALIVE_SIM_TIMEOUT_MS = Number(
  process.env.KEEP_ALIVE_SIM_TIMEOUT_MS ?? 5 * 60 * 1000,
);
export const SIMULATION_TIMEOUT_MS = Number(process.env.SIMULATION_TIMEOUT_MS ?? 5 * 60 * 1000);

// Concurrency limiting — caps total edb-simulator child processes
export const MAX_CONCURRENT_SIMULATIONS = Math.max(1, Number(process.env.MAX_CONCURRENT_SIMULATIONS ?? 6));
export const SIMULATION_QUEUE_MAX = Math.max(0, Number(process.env.SIMULATION_QUEUE_MAX ?? 40));
export const SIMULATION_QUEUE_TIMEOUT_MS = Math.max(1000, Number(process.env.SIMULATION_QUEUE_TIMEOUT_MS ?? 45_000));

// Memory-pressure eviction — evict idle keep-alive sessions when free RAM is low
export const MEMORY_PRESSURE_THRESHOLD_MB = Number(process.env.MEMORY_PRESSURE_THRESHOLD_MB ?? 1500);
export const MEMORY_PRESSURE_HARD_LIMIT_MB = Number(process.env.MEMORY_PRESSURE_HARD_LIMIT_MB ?? 500);

// Snapshots are kept in rawTrace for the legacy 3-phase FE decode to
// produce rich trace data (function args, internal calls, source maps,
// events).  V2 lite enrichment is disabled until Stage 2 (Rust EDB)
// produces fully-rich rows.  Only strip artifacts/sources/opcodeLines.
export const TRACE_HEAVY_FIELDS = TRACE_STRIP_OPCODE_LINES
  ? ["artifacts", "sources", "opcodeLines"]
  : ["artifacts", "sources"];
export const SIMULATOR_BUILD_PROFILE = process.env.SIMULATOR_BUILD_PROFILE === "debug" ? "debug" : "release";

// Path to edb-simulator binary (for quick simulations)
export const SIMULATOR_BINARY_PATH =
  process.env.SIMULATOR_BINARY ??
  pathResolve(
    process.cwd(),
    "edb",
    "target",
    SIMULATOR_BUILD_PROFILE,
    process.platform === "win32" ? "edb-simulator.exe" : "edb-simulator",
  );

// Path to edb binary (for debug server)
export const EDB_BINARY_PATH =
  process.env.EDB_BINARY ??
  pathResolve(
    process.cwd(),
    "edb",
    "target",
    SIMULATOR_BUILD_PROFILE,
    process.platform === "win32" ? "edb.exe" : "edb",
  );

export function validateBinaryExists() {
  if (!existsSync(SIMULATOR_BINARY_PATH)) {
    console.error(
      `[simulator-bridge] expected simulator binary at ${SIMULATOR_BINARY_PATH}. Build it with:\n  cargo build -p edb-simulator --manifest-path edb/Cargo.toml`,
    );
    process.exit(1);
  }
}

// =============================================================================
// Concurrency: SimulationCapacityError + SimulationSemaphore
// =============================================================================

export class SimulationCapacityError extends Error {
  /** @param {string} message @param {"queue_full"|"queue_timeout"|"shutting_down"|"aborted"|"memory_pressure"} code */
  constructor(message, code) {
    super(message);
    this.name = "SimulationCapacityError";
    this.code = code;
  }
}

export class SimulationSemaphore {
  /**
   * @param {number} maxConcurrent
   * @param {number} maxQueueSize
   * @param {number} queueTimeoutMs
   */
  constructor(maxConcurrent, maxQueueSize, queueTimeoutMs) {
    this._maxConcurrent = maxConcurrent;
    this._maxQueueSize = maxQueueSize;
    this._queueTimeoutMs = queueTimeoutMs;
    this._activeCount = 0;
    /** @type {Array<{ resolve: Function, reject: Function, timer: ReturnType<typeof setTimeout>|null, onAbort: Function|null }>} */
    this._queue = [];
  }

  get activeCount() { return this._activeCount; }
  get queueLength() { return this._queue.length; }
  get maxConcurrent() { return this._maxConcurrent; }
  get maxQueueSize() { return this._maxQueueSize; }

  /**
   * Acquire a simulation slot. Resolves with an idempotent release function.
   * @param {AbortSignal} [signal] - If aborted while queued, rejects and frees queue spot.
   * @returns {Promise<() => void>}
   */
  acquire(signal) {
    // Already aborted
    if (signal?.aborted) {
      return Promise.reject(
        new SimulationCapacityError("Client disconnected before simulation started.", "aborted"),
      );
    }

    // Fast path: slot available
    if (this._activeCount < this._maxConcurrent) {
      this._activeCount++;
      return Promise.resolve(this._createRelease());
    }

    // Queue full
    if (this._queue.length >= this._maxQueueSize) {
      return Promise.reject(
        new SimulationCapacityError(
          `Server at capacity: ${this._activeCount} simulation(s) running, ${this._queue.length} queued. Try again later.`,
          "queue_full",
        ),
      );
    }

    // Enqueue with timeout
    return new Promise((resolve, reject) => {
      const entry = { resolve, reject, timer: null, onAbort: null };

      const removeEntry = () => {
        const idx = this._queue.indexOf(entry);
        if (idx !== -1) this._queue.splice(idx, 1);
        if (entry.timer) { clearTimeout(entry.timer); entry.timer = null; }
        if (entry.onAbort && signal) {
          signal.removeEventListener("abort", entry.onAbort);
          entry.onAbort = null;
        }
      };

      entry.timer = setTimeout(() => {
        removeEntry();
        reject(
          new SimulationCapacityError(
            `Simulation queue timeout: waited ${Math.round(this._queueTimeoutMs / 1000)}s but no slot became available. ${this._activeCount} simulation(s) still running.`,
            "queue_timeout",
          ),
        );
      }, this._queueTimeoutMs);
      if (typeof entry.timer?.unref === "function") entry.timer.unref();

      // Abort signal support — cancel if client disconnects while queued
      if (signal) {
        entry.onAbort = () => {
          removeEntry();
          reject(
            new SimulationCapacityError("Client disconnected while waiting in queue.", "aborted"),
          );
        };
        signal.addEventListener("abort", entry.onAbort, { once: true });
      }

      this._queue.push(entry);
    });
  }

  /** @returns {() => void} Idempotent release function */
  _createRelease() {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this._activeCount--;
      this._drain();
    };
  }

  _drain() {
    while (this._queue.length > 0 && this._activeCount < this._maxConcurrent) {
      const entry = this._queue.shift();
      if (!entry) break;
      if (entry.timer) { clearTimeout(entry.timer); entry.timer = null; }
      if (entry.onAbort) {
        entry.onAbort = null;
      }
      this._activeCount++;
      entry.resolve(this._createRelease());
    }
  }

  /** Reject all queued requests (shutdown). */
  drainAndRejectAll() {
    while (this._queue.length > 0) {
      const entry = this._queue.shift();
      if (!entry) break;
      if (entry.timer) { clearTimeout(entry.timer); entry.timer = null; }
      entry.reject(
        new SimulationCapacityError("Bridge is shutting down. Please retry.", "shutting_down"),
      );
    }
  }
}
