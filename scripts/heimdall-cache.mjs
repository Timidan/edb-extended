// scripts/heimdall-cache.mjs
//
// Simple LRU cache with TTL eviction. Keys are strings; values are arbitrary.
// Map preserves insertion order; reads promote via delete+reinsert. Expired
// entries are lazily purged on read.

export function createLruCache({ maxEntries, ttlMs }) {
  if (!Number.isFinite(maxEntries) || maxEntries <= 0) {
    throw new Error("createLruCache: maxEntries must be positive");
  }
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new Error("createLruCache: ttlMs must be positive");
  }

  const entries = new Map();
  const isExpired = (entry) => Date.now() - entry.storedAt > ttlMs;

  function purgeExpired() {
    for (const [key, entry] of entries) {
      if (isExpired(entry)) entries.delete(key);
    }
  }

  function evictIfOverCapacity() {
    while (entries.size > maxEntries) {
      const oldestKey = entries.keys().next().value;
      if (oldestKey === undefined) break;
      entries.delete(oldestKey);
    }
  }

  return {
    get(key) {
      const entry = entries.get(key);
      if (!entry) return undefined;
      if (isExpired(entry)) {
        entries.delete(key);
        return undefined;
      }
      entries.delete(key);
      entries.set(key, entry);
      return entry.value;
    },
    set(key, value) {
      if (entries.has(key)) entries.delete(key);
      entries.set(key, { value, storedAt: Date.now() });
      evictIfOverCapacity();
    },
    size() {
      purgeExpired();
      return entries.size;
    },
    clear() {
      entries.clear();
    },
  };
}
