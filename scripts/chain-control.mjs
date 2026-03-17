// edb/scripts/chain-control.mjs
//
// Bridge endpoints that proxy chain control RPC calls to the connected local node.
// The browser talks to the bridge; the bridge talks to the local node.
// This avoids CORS issues entirely.

/**
 * State: the currently connected local node URL.
 * Set via POST /chain/connect, cleared via POST /chain/disconnect.
 */
let connectedNodeUrl = null;

async function rpcCall(method, params = []) {
  if (!connectedNodeUrl) {
    throw new Error('No local node connected. Call POST /chain/connect first.');
  }
  const res = await fetch(connectedNodeUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: Date.now(), method, params }),
  });
  const json = await res.json();
  if (json.error) {
    throw new Error(`RPC error (${method}): ${json.error.message ?? JSON.stringify(json.error)}`);
  }
  return json.result;
}

/**
 * Route handler for chain control endpoints.
 * Returns true if the request was handled, false otherwise.
 */
export async function handleChainControl(url, body, res) {
  switch (url) {
    case '/chain/connect': {
      connectedNodeUrl = body.rpcUrl;
      try {
        const chainId = await rpcCall('eth_chainId');
        const blockNumber = await rpcCall('eth_blockNumber');
        const clientVersion = await rpcCall('web3_clientVersion');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, chainId, blockNumber, clientVersion }));
      } catch (err) {
        connectedNodeUrl = null;
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: err.message }));
      }
      return true;
    }

    case '/chain/disconnect': {
      connectedNodeUrl = null;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return true;
    }

    case '/chain/rpc': {
      try {
        const result = await rpcCall(body.method, body.params || []);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, result }));
      } catch (err) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: err.message }));
      }
      return true;
    }

    case '/chain/snapshot': {
      try {
        const id = await rpcCall('evm_snapshot');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, id }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: err.message }));
      }
      return true;
    }

    case '/chain/revert': {
      try {
        await rpcCall('evm_revert', [body.id]);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: err.message }));
      }
      return true;
    }

    case '/chain/mine': {
      try {
        await rpcCall(body.method || 'evm_mine', body.params || []);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: err.message }));
      }
      return true;
    }

    default:
      return false;
  }
}

export function getConnectedNodeUrl() {
  return connectedNodeUrl;
}
