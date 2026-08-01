import { readFileSync } from "node:fs";
import { freemem, totalmem } from "node:os";

const CGROUP_MEMORY_SOURCES = [
  {
    source: "cgroup-v2",
    limitPath: "/sys/fs/cgroup/memory.max",
    currentPath: "/sys/fs/cgroup/memory.current",
  },
  {
    source: "cgroup-v1",
    limitPath: "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    currentPath: "/sys/fs/cgroup/memory/memory.usage_in_bytes",
  },
];

function parseFiniteBytes(value) {
  const bytes = Number(String(value).trim());
  return Number.isSafeInteger(bytes) && bytes >= 0 ? bytes : null;
}

/**
 * Report the memory available to this process. A finite container limit takes
 * precedence over host-level values so admission control matches Docker's cap.
 */
export function readMemorySnapshot({
  readFile = readFileSync,
  hostFree = freemem,
  hostTotal = totalmem,
} = {}) {
  for (const candidate of CGROUP_MEMORY_SOURCES) {
    try {
      const rawLimit = String(readFile(candidate.limitPath, "utf8")).trim();
      if (rawLimit === "max") continue;

      const limitBytes = parseFiniteBytes(rawLimit);
      const currentBytes = parseFiniteBytes(readFile(candidate.currentPath, "utf8"));
      if (limitBytes === null || currentBytes === null) continue;

      return {
        freeBytes: Math.max(0, limitBytes - currentBytes),
        totalBytes: limitBytes,
        source: candidate.source,
      };
    } catch {
      // This cgroup layout is unavailable; try the next layout or host values.
    }
  }

  return {
    freeBytes: hostFree(),
    totalBytes: hostTotal(),
    source: "host",
  };
}
