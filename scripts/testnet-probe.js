#!/usr/bin/env node

const API_KEY =
  process.env.API_KEY ||
  process.env.VITE_API_KEY ||
  "";

const testnetDefinitions = [
  {
    id: 11155111,
    name: "Ethereum Sepolia",
    rpcUrl: API_KEY
      ? `https://eth-sepolia.g.alchemy.com/v2/${API_KEY}`
      : "https://rpc.sepolia.ethpandaops.io",
  },
  {
    id: 17000,
    name: "Holesky",
    rpcUrl: "https://ethereum-holesky.publicnode.com",
  },
  {
    id: 80002,
    name: "Polygon Amoy",
    rpcUrl: "https://rpc-amoy.polygon.technology",
  },
  {
    id: 421614,
    name: "Arbitrum Sepolia",
    rpcUrl: "https://sepolia-rollup.arbitrum.io/rpc",
  },
  {
    id: 11155420,
    name: "Optimism Sepolia",
    rpcUrl: "https://sepolia.optimism.io",
  },
  {
    id: 84532,
    name: "Base Sepolia",
    rpcUrl: API_KEY
      ? `https://base-sepolia.g.alchemy.com/v2/${API_KEY}`
      : "https://sepolia.base.org",
  },
  {
    id: 4202,
    name: "Lisk Sepolia",
    rpcUrl: "https://rpc.sepolia-api.lisk.com",
  },
  {
    id: 97,
    name: "BNB Testnet",
    rpcUrl: "https://bsc-testnet.public.blastapi.io",
  },
];

async function probeNetwork({ id, name, rpcUrl }) {
  const start = Date.now();
  try {
    const response = await fetch(rpcUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "eth_blockNumber",
        params: [],
        id: 1,
      }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    if (payload.error) {
      throw new Error(payload.error.message || JSON.stringify(payload.error));
    }

    const blockNumber = payload.result
      ? Number.parseInt(payload.result, 16)
      : NaN;
    const latency = Date.now() - start;
    return {
      id,
      name,
      rpcUrl,
      blockNumber,
      latencyMs: latency,
      status: "ok",
    };
  } catch (error) {
    return {
      id,
      name,
      rpcUrl,
      error: (error?.message || error)?.toString?.() || String(error),
      status: "error",
    };
  }
}

async function main() {
  const results = [];
  for (const definition of testnetDefinitions) {
    const result = await probeNetwork(definition);
    results.push(result);
  }

  const failures = results.filter((r) => r.status !== "ok");

  console.log("Testnet probe results:\n");
  for (const result of results) {
    if (result.status === "ok") {
      console.log(
        `${result.name} (${result.id}) => block #${result.blockNumber} [${result.latencyMs}ms]`
      );
    } else {
      console.log(
        `${result.name} (${result.id}) => FAILED (${result.error})`
      );
    }
  }

  if (failures.length) {
    console.error("\nOne or more testnet RPCs failed");
    process.exit(1);
  }

  process.exit(0);
}

main().catch((error) => {
  console.error("Unexpected probe error", error);
  process.exit(1);
});
