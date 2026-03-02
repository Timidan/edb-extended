// =============================================================================
// Artifact Compaction — ABI extraction, bytecode, sources, storage layout
// =============================================================================

export function normalizeAbiValue(value) {
  if (!value) return null;
  if (Array.isArray(value)) return value;
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : null;
    } catch {
      return null;
    }
  }
  return null;
}

export function extractCompactSourcesMap(artifact, referencedFiles) {
  if (!artifact || typeof artifact !== "object") return null;
  const sourceContainer =
    artifact?.input?.sources ||
    artifact?.sources ||
    (typeof artifact?.meta?.SourceCode === "object" ? artifact.meta.SourceCode.sources : null);
  if (!sourceContainer || typeof sourceContainer !== "object") return null;

  const includeAll = !referencedFiles || referencedFiles.size === 0;
  const compactSources = {};
  for (const [path, value] of Object.entries(sourceContainer)) {
    if (!includeAll) {
      const basename = path.split("/").pop() || path;
      if (!referencedFiles.has(path) && !referencedFiles.has(basename)) {
        continue;
      }
    }
    if (typeof value === "string") {
      compactSources[path] = { content: value };
      continue;
    }
    if (value && typeof value === "object" && typeof value.content === "string") {
      compactSources[path] = { content: value.content };
    }
  }

  if (Object.keys(compactSources).length > 0) {
    return compactSources;
  }

  if (includeAll) {
    return null;
  }

  // If file hints were too strict, fall back to all available sources.
  return extractCompactSourcesMap(artifact, null);
}

export function pickArtifactAbi(artifact) {
  if (!artifact || typeof artifact !== "object") return null;

  const directAbi =
    normalizeAbiValue(artifact?.output?.abi) ||
    normalizeAbiValue(artifact?.abi) ||
    normalizeAbiValue(artifact?.meta?.ABI);
  if (directAbi) return directAbi;

  const outputContracts = artifact?.output?.contracts;
  if (!outputContracts || typeof outputContracts !== "object") {
    return null;
  }

  for (const contractsByName of Object.values(outputContracts)) {
    if (!contractsByName || typeof contractsByName !== "object") continue;
    for (const contractInfo of Object.values(contractsByName)) {
      if (!contractInfo || typeof contractInfo !== "object") continue;
      const candidate = normalizeAbiValue(contractInfo.abi);
      if (candidate) return candidate;
    }
  }

  return null;
}

export function pickArtifactRuntimeBytecode(artifact) {
  if (!artifact || typeof artifact !== "object") return null;

  const directRuntime =
    typeof artifact?.deployedBytecode?.object === "string"
      ? artifact.deployedBytecode.object
      : typeof artifact?.deployedBytecode === "string"
        ? artifact.deployedBytecode
        : null;
  if (directRuntime && directRuntime.length > 2) return directRuntime;

  if (typeof artifact?.meta?.Bytecode === "string" && artifact.meta.Bytecode.length > 2) {
    return artifact.meta.Bytecode;
  }

  const outputContracts = artifact?.output?.contracts;
  if (!outputContracts || typeof outputContracts !== "object") return null;

  const preferredName =
    typeof artifact?.meta?.ContractName === "string" && artifact.meta.ContractName.length > 0
      ? artifact.meta.ContractName
      : null;

  let fallbackRuntime = null;
  for (const contractsByName of Object.values(outputContracts)) {
    if (!contractsByName || typeof contractsByName !== "object") continue;
    for (const [contractName, contractInfo] of Object.entries(contractsByName)) {
      if (!contractInfo || typeof contractInfo !== "object") continue;
      const runtimeObj = contractInfo?.evm?.deployedBytecode?.object;
      if (typeof runtimeObj !== "string" || runtimeObj.length <= 2) continue;
      if (preferredName && contractName === preferredName) {
        return runtimeObj;
      }
      if (!fallbackRuntime) {
        fallbackRuntime = runtimeObj;
      }
    }
  }

  return fallbackRuntime;
}

export function buildCompactOutputSources(artifact) {
  const outputSources = artifact?.output?.sources;
  if (!outputSources || typeof outputSources !== "object") return null;

  const compactSources = {};
  for (const [path, sourceInfo] of Object.entries(outputSources)) {
    if (!sourceInfo || typeof sourceInfo !== "object") continue;
    const id = sourceInfo.id;
    if (typeof id !== "number" || !Number.isFinite(id)) continue;
    compactSources[path] = { id };
  }

  return Object.keys(compactSources).length > 0 ? compactSources : null;
}

export function buildCompactOutputContracts(artifact) {
  const outputContracts = artifact?.output?.contracts;
  if (!outputContracts || typeof outputContracts !== "object") return null;

  const compactContracts = {};

  for (const [filePath, contractsByName] of Object.entries(outputContracts)) {
    if (!contractsByName || typeof contractsByName !== "object") continue;
    const compactByName = {};

    for (const [contractName, contractInfo] of Object.entries(contractsByName)) {
      if (!contractInfo || typeof contractInfo !== "object") continue;
      const evm = contractInfo?.evm;
      if (!evm || typeof evm !== "object") continue;

      const deployedBytecode = evm.deployedBytecode || {};
      const creationBytecode = evm.bytecode || {};

      const runtimeObject =
        typeof deployedBytecode.object === "string" ? deployedBytecode.object : null;
      const runtimeSourceMap =
        typeof evm.deployedSourceMap === "string"
          ? evm.deployedSourceMap
          : typeof evm.deployed_source_map === "string"
            ? evm.deployed_source_map
            : typeof deployedBytecode.sourceMap === "string"
              ? deployedBytecode.sourceMap
              : typeof deployedBytecode.source_map === "string"
                ? deployedBytecode.source_map
                : null;

      const creationObject =
        typeof creationBytecode.object === "string" ? creationBytecode.object : null;
      const creationSourceMap =
        typeof evm.sourceMap === "string"
          ? evm.sourceMap
          : typeof evm.source_map === "string"
            ? evm.source_map
            : typeof creationBytecode.sourceMap === "string"
              ? creationBytecode.sourceMap
              : typeof creationBytecode.source_map === "string"
                ? creationBytecode.source_map
                : null;

      const compactEvm = {};
      if (runtimeObject || runtimeSourceMap) {
        compactEvm.deployedBytecode = {};
        if (runtimeObject) compactEvm.deployedBytecode.object = runtimeObject;
        if (runtimeSourceMap) compactEvm.deployedBytecode.sourceMap = runtimeSourceMap;
      }
      if (creationObject || creationSourceMap) {
        compactEvm.bytecode = {};
        if (creationObject) compactEvm.bytecode.object = creationObject;
        if (creationSourceMap) compactEvm.bytecode.sourceMap = creationSourceMap;
      }
      if (runtimeSourceMap) {
        compactEvm.deployedSourceMap = runtimeSourceMap;
      }

      if (Object.keys(compactEvm).length === 0) continue;
      const compactContract = { evm: compactEvm };
      // Preserve storageLayout — tiny metadata used by State tab for decoded variable names
      const sl = contractInfo.storageLayout || contractInfo.storage_layout;
      if (sl && typeof sl === "object" && Array.isArray(sl.storage)) {
        compactContract.storageLayout = sl;
      }
      compactByName[contractName] = compactContract;
    }

    if (Object.keys(compactByName).length > 0) {
      compactContracts[filePath] = compactByName;
    }
  }

  return Object.keys(compactContracts).length > 0 ? compactContracts : null;
}

export function collectOpcodeFileHints(opcodeLines) {
  const hints = new Map();
  if (!opcodeLines || typeof opcodeLines !== "object") return hints;
  for (const [key, value] of Object.entries(opcodeLines)) {
    if (key.endsWith("_filtered") || !Array.isArray(value)) continue;
    const addr = key.toLowerCase();
    const files = hints.get(addr) || new Set();
    for (const row of value) {
      if (!row || typeof row !== "object") continue;
      if (typeof row.file !== "string" || !row.file.length) continue;
      files.add(row.file);
      files.add(row.file.split("/").pop() || row.file);
    }
    hints.set(addr, files);
  }
  return hints;
}

/**
 * Extract storage layout from an artifact.
 * Prefers the contract matching `contractName` when provided (multi-contract outputs).
 * Returns null if none found.  The layout is a ~few-KB object:
 *   { storage: [...], types: {...} }
 */
export function extractStorageLayoutFromArtifact(artifact, contractName) {
  if (!artifact || typeof artifact !== "object") return null;

  // Direct top-level field (some EDB versions / already-extracted)
  const topLevel = artifact.storageLayout || artifact.storage_layout;
  if (topLevel && typeof topLevel === "object" && Array.isArray(topLevel.storage)) {
    return topLevel;
  }

  // Standard JSON output: output.contracts[file][name].storageLayout
  const outputContracts = artifact?.output?.contracts;
  if (outputContracts && typeof outputContracts === "object") {
    // First pass: try to match by contractName (most accurate)
    if (contractName) {
      for (const fileContracts of Object.values(outputContracts)) {
        if (!fileContracts || typeof fileContracts !== "object") continue;
        const targetContract = fileContracts[contractName];
        if (targetContract && typeof targetContract === "object") {
          const sl = targetContract.storageLayout || targetContract.storage_layout;
          if (sl && typeof sl === "object" && Array.isArray(sl.storage)) {
            return sl;
          }
        }
      }
    }
    // Second pass: fallback to first contract with valid layout
    let fallback = null;
    for (const fileContracts of Object.values(outputContracts)) {
      if (!fileContracts || typeof fileContracts !== "object") continue;
      for (const contract of Object.values(fileContracts)) {
        if (!contract || typeof contract !== "object") continue;
        const sl = contract.storageLayout || contract.storage_layout;
        if (sl && typeof sl === "object" && Array.isArray(sl.storage)) {
          if (!fallback) fallback = sl;
        }
      }
    }
    if (fallback) return fallback;
  }

  return null;
}

export function buildCompactArtifactMap(artifacts, opcodeLines) {
  if (!artifacts || typeof artifacts !== "object") return null;
  const fileHintsByAddress = collectOpcodeFileHints(opcodeLines);
  const compactArtifacts = {};

  for (const [addr, artifact] of Object.entries(artifacts)) {
    if (!artifact || typeof artifact !== "object") continue;
    const addrLower = addr.toLowerCase();
    const referencedFiles = fileHintsByAddress.get(addrLower) || null;
    const compactSources = extractCompactSourcesMap(artifact, referencedFiles);
    const abi = pickArtifactAbi(artifact);
    const runtimeBytecode = pickArtifactRuntimeBytecode(artifact);
    const compactOutputSources = buildCompactOutputSources(artifact);
    const compactOutputContracts = buildCompactOutputContracts(artifact);

    const compactArtifact = {};
    if (compactSources) {
      compactArtifact.input = { sources: compactSources };
    }
    if (runtimeBytecode) {
      compactArtifact.deployedBytecode = { object: runtimeBytecode };
    }
    if (abi || compactOutputSources || compactOutputContracts) {
      compactArtifact.output = {};
      if (abi) {
        compactArtifact.output.abi = abi;
      }
      if (compactOutputSources) {
        compactArtifact.output.sources = compactOutputSources;
      }
      if (compactOutputContracts) {
        compactArtifact.output.contracts = compactOutputContracts;
      }
    }
    if (artifact.missingSettings === true) {
      compactArtifact.missingSettings = true;
    }
    if (typeof artifact?.meta?.ContractName === "string") {
      compactArtifact.meta = {
        ContractName: artifact.meta.ContractName,
        ...(runtimeBytecode ? { Bytecode: runtimeBytecode } : {}),
      };
    } else if (runtimeBytecode) {
      compactArtifact.meta = { Bytecode: runtimeBytecode };
    }

    // Preserve storageLayout at top level — tiny metadata used by State tab for
    // decoded variable names.  Prefer contract-name-aware extraction.
    const contractName = artifact?.meta?.ContractName || artifact?.meta?.Name || null;
    const sl = extractStorageLayoutFromArtifact(artifact, contractName);
    if (sl) {
      compactArtifact.storageLayout = sl;
    }
    if (Object.keys(compactArtifact).length > 0) {
      compactArtifacts[addrLower] = compactArtifact;
    } else {
      compactArtifacts[addrLower] = artifact;
    }
  }

  return Object.keys(compactArtifacts).length > 0 ? compactArtifacts : null;
}
