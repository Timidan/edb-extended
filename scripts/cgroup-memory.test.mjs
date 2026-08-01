import assert from "node:assert/strict";
import test from "node:test";

import { readMemorySnapshot } from "./cgroup-memory.mjs";

function reader(files) {
  return (path) => {
    if (!(path in files)) throw new Error(`missing ${path}`);
    return files[path];
  };
}

test("uses a finite cgroup v2 limit", () => {
  const snapshot = readMemorySnapshot({
    readFile: reader({
      "/sys/fs/cgroup/memory.max": "4294967296\n",
      "/sys/fs/cgroup/memory.current": "1073741824\n",
    }),
  });
  assert.deepEqual(snapshot, {
    freeBytes: 3221225472,
    totalBytes: 4294967296,
    source: "cgroup-v2",
  });
});

test("falls through to a finite cgroup v1 limit", () => {
  const snapshot = readMemorySnapshot({
    readFile: reader({
      "/sys/fs/cgroup/memory.max": "max\n",
      "/sys/fs/cgroup/memory/memory.limit_in_bytes": "2147483648\n",
      "/sys/fs/cgroup/memory/memory.usage_in_bytes": "536870912\n",
    }),
  });
  assert.equal(snapshot.source, "cgroup-v1");
  assert.equal(snapshot.totalBytes, 2147483648);
  assert.equal(snapshot.freeBytes, 1610612736);
});

test("falls back to host values for unavailable or unlimited cgroups", () => {
  const snapshot = readMemorySnapshot({
    readFile: reader({
      "/sys/fs/cgroup/memory.max": "max\n",
      "/sys/fs/cgroup/memory/memory.limit_in_bytes": "9223372036854771712\n",
      "/sys/fs/cgroup/memory/memory.usage_in_bytes": "1\n",
    }),
    hostFree: () => 300,
    hostTotal: () => 400,
  });
  assert.deepEqual(snapshot, { freeBytes: 300, totalBytes: 400, source: "host" });
});

test("clamps cgroup availability at zero", () => {
  const snapshot = readMemorySnapshot({
    readFile: reader({
      "/sys/fs/cgroup/memory.max": "100\n",
      "/sys/fs/cgroup/memory.current": "125\n",
    }),
  });
  assert.equal(snapshot.freeBytes, 0);
  assert.equal(snapshot.totalBytes, 100);
});

test("falls back to host values for malformed cgroup data", () => {
  const snapshot = readMemorySnapshot({
    readFile: reader({
      "/sys/fs/cgroup/memory.max": "invalid\n",
      "/sys/fs/cgroup/memory.current": "25\n",
    }),
    hostFree: () => 500,
    hostTotal: () => 600,
  });
  assert.deepEqual(snapshot, { freeBytes: 500, totalBytes: 600, source: "host" });
});
