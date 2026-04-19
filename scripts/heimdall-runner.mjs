// scripts/heimdall-runner.mjs
//
// Spawn a heimdall (or arbitrary) subprocess with a hard timeout and return
// captured stdout/stderr. Throws classified errors so callers can map them to
// HTTP responses.

import { spawn } from "node:child_process";

export class HeimdallRunError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {{ stderr?: string, exitCode?: number }} [extra]
   */
  constructor(code, message, { stderr, exitCode } = {}) {
    super(message);
    this.name = "HeimdallRunError";
    this.code = code;
    this.stderr = stderr;
    this.exitCode = exitCode;
  }
}

export function runHeimdallSubprocess({ bin, args = [], timeoutMs, stdin }) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(bin, args, { stdio: ["pipe", "pipe", "pipe"] });
    } catch (err) {
      return reject(new HeimdallRunError("HEIMDALL_NOT_INSTALLED", err.message));
    }

    const stdoutChunks = [];
    const stderrChunks = [];
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { child.kill("SIGKILL"); } catch { /* already dead */ }
      reject(new HeimdallRunError("HEIMDALL_TIMEOUT", `heimdall exceeded ${timeoutMs}ms`));
    }, timeoutMs);

    child.stdout.on("data", (c) => stdoutChunks.push(c));
    child.stderr.on("data", (c) => stderrChunks.push(c));

    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const code = err.code === "ENOENT" ? "HEIMDALL_NOT_INSTALLED" : "HEIMDALL_SPAWN_FAILED";
      reject(new HeimdallRunError(code, err.message));
    });

    child.on("close", (exitCode) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        exitCode: exitCode ?? -1,
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        stderr: Buffer.concat(stderrChunks).toString("utf8"),
      });
    });

    if (stdin !== undefined) {
      child.stdin.write(stdin);
    }
    child.stdin.end();
  });
}
