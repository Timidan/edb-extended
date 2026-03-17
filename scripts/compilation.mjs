// edb/scripts/compilation.mjs
//
// Bridge endpoints for compiling Solidity via local toolchain.
// Detects Foundry/Hardhat/solc and executes compilation.

import { execSync, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

function detectToolchain(projectRoot) {
  if (existsSync(join(projectRoot, 'foundry.toml'))) {
    try {
      execSync('which forge', { stdio: 'ignore' });
      return { detected: 'foundry', version: execSync('forge --version', { encoding: 'utf-8' }).trim() };
    } catch { /* forge not installed */ }
  }

  if (
    existsSync(join(projectRoot, 'hardhat.config.ts')) ||
    existsSync(join(projectRoot, 'hardhat.config.js'))
  ) {
    return { detected: 'hardhat', version: 'detected' };
  }

  try {
    execSync('which solc', { stdio: 'ignore' });
    return { detected: 'solc', version: execSync('solc --version', { encoding: 'utf-8' }).trim() };
  } catch { /* solc not installed */ }

  return { detected: 'none', version: null };
}

function compileWithFoundry(projectRoot) {
  const result = spawnSync('forge', ['build', '--format-json'], {
    cwd: projectRoot,
    encoding: 'utf-8',
    timeout: 120_000,
  });

  if (result.status !== 0) {
    return { ok: false, errors: [result.stderr || result.stdout], warnings: [] };
  }

  try {
    const output = JSON.parse(result.stdout);
    return { ok: true, contracts: output, errors: [], warnings: [] };
  } catch {
    return { ok: true, contracts: {}, errors: [], warnings: [result.stderr] };
  }
}

function compileWithHardhat(projectRoot) {
  const result = spawnSync('npx', ['hardhat', 'compile'], {
    cwd: projectRoot,
    encoding: 'utf-8',
    timeout: 120_000,
  });

  if (result.status !== 0) {
    return { ok: false, errors: [result.stderr || result.stdout], warnings: [] };
  }

  return { ok: true, contracts: {}, errors: [], warnings: [] };
}

export function handleCompilation(url, body, res) {
  switch (url) {
    case '/compile/toolchain': {
      const { projectRoot } = body;
      if (!projectRoot) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'projectRoot is required' }));
        return true;
      }
      const result = detectToolchain(projectRoot);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, ...result }));
      return true;
    }

    case '/compile': {
      const { projectRoot, toolchain } = body;
      if (!projectRoot) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'projectRoot is required' }));
        return true;
      }

      let result;
      if (toolchain === 'foundry') {
        result = compileWithFoundry(projectRoot);
      } else if (toolchain === 'hardhat') {
        result = compileWithHardhat(projectRoot);
      } else {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: `Unsupported toolchain: ${toolchain}. Use browser solc-js fallback.` }));
        return true;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
      return true;
    }

    default:
      return false;
  }
}
