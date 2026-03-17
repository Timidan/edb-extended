// edb/scripts/node-manager.mjs
//
// Manages spawning/killing local dev chain processes from the bridge.

import { spawn } from 'node:child_process';
import { execSync } from 'node:child_process';

let spawnedProcess = null;
let spawnedNodeType = null;
let spawnedRpcUrl = null;

// Heartbeat: track last client ping. Kill orphaned process after 30s of silence.
let lastClientPing = Date.now();
const ORPHAN_TIMEOUT_MS = 30_000;
let orphanCheckTimer = null;

function startOrphanCheck() {
  stopOrphanCheck();
  orphanCheckTimer = setInterval(() => {
    if (spawnedProcess && Date.now() - lastClientPing > ORPHAN_TIMEOUT_MS) {
      console.log('[node-manager] Client heartbeat lost — killing orphaned node process');
      killSpawnedNode();
    }
  }, 10_000);
}

function stopOrphanCheck() {
  if (orphanCheckTimer) {
    clearInterval(orphanCheckTimer);
    orphanCheckTimer = null;
  }
}

function isCommandAvailable(cmd) {
  try {
    execSync(`which ${cmd}`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function killSpawnedNode() {
  if (spawnedProcess) {
    try {
      process.kill(-spawnedProcess.pid, 'SIGTERM');
    } catch {
      try { spawnedProcess.kill('SIGTERM'); } catch { /* already dead */ }
    }
    spawnedProcess = null;
    spawnedNodeType = null;
    spawnedRpcUrl = null;
    stopOrphanCheck();
  }
}

export async function handleNodeManager(url, body, res) {
  switch (url) {
    case '/node/spawn': {
      if (spawnedProcess) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'A node is already running. Kill it first.' }));
        return true;
      }

      const { type = 'anvil', config = {} } = body;
      const port = config.port || 8545;

      let cmd, args;
      if (type === 'anvil') {
        if (!isCommandAvailable('anvil')) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'anvil not found on PATH. Install Foundry.' }));
          return true;
        }
        cmd = 'anvil';
        args = ['--port', String(port)];
        if (config.forkUrl) args.push('--fork-url', config.forkUrl);
        if (config.forkBlockNumber) args.push('--fork-block-number', String(config.forkBlockNumber));
        if (config.chainId) args.push('--chain-id', String(config.chainId));
        if (config.accountCount) args.push('--accounts', String(config.accountCount));
        if (config.balance) args.push('--balance', config.balance);
      } else if (type === 'hardhat') {
        cmd = 'npx';
        args = ['hardhat', 'node', '--port', String(port)];
        if (config.forkUrl) args.push('--fork', config.forkUrl);
      } else {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: `Unsupported node type: ${type}` }));
        return true;
      }

      try {
        spawnedProcess = spawn(cmd, args, {
          detached: true,
          stdio: ['ignore', 'pipe', 'pipe'],
        });
        spawnedNodeType = type;
        spawnedRpcUrl = `http://localhost:${port}`;

        let startupOutput = '';
        await new Promise((resolve, reject) => {
          const timeout = setTimeout(() => resolve(undefined), 5000);

          spawnedProcess.stdout.on('data', (data) => {
            startupOutput += data.toString();
            if (startupOutput.includes('Listening on') || startupOutput.includes('Started HTTP')) {
              clearTimeout(timeout);
              resolve(undefined);
            }
          });

          spawnedProcess.stderr.on('data', (data) => {
            startupOutput += data.toString();
          });

          spawnedProcess.on('error', (err) => {
            clearTimeout(timeout);
            reject(err);
          });

          spawnedProcess.on('exit', (code) => {
            if (code !== null && code !== 0) {
              clearTimeout(timeout);
              reject(new Error(`Node process exited with code ${code}`));
            }
          });
        });

        startOrphanCheck();

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          ok: true,
          type: spawnedNodeType,
          rpcUrl: spawnedRpcUrl,
          pid: spawnedProcess.pid,
        }));
      } catch (err) {
        killSpawnedNode();
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: err.message }));
      }
      return true;
    }

    case '/node/kill': {
      killSpawnedNode();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return true;
    }

    case '/node/status': {
      lastClientPing = Date.now();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        running: spawnedProcess !== null,
        type: spawnedNodeType,
        rpcUrl: spawnedRpcUrl,
        pid: spawnedProcess?.pid ?? null,
      }));
      return true;
    }

    default:
      return false;
  }
}

// Cleanup on bridge shutdown
process.on('exit', killSpawnedNode);
process.on('SIGTERM', killSpawnedNode);
process.on('SIGINT', killSpawnedNode);
