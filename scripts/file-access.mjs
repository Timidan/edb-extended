// edb/scripts/file-access.mjs
//
// Bridge endpoints for reading/writing project files.
// Security: path sandboxing, session token, localhost-only.

import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, relative, extname } from 'node:path';
import { randomUUID } from 'node:crypto';

let projectRoot = null;
let sessionToken = null;

const ALLOWED_WRITE_EXTENSIONS = new Set(['.sol', '.json', '.toml', '.js', '.ts', '.md']);

function isPathSafe(filePath) {
  if (!projectRoot) return false;
  const resolved = resolve(filePath);
  const rel = relative(projectRoot, resolved);
  return !rel.startsWith('..') && resolved.startsWith(projectRoot);
}

function buildTree(dirPath, depth = 0, maxDepth = 5) {
  if (depth > maxDepth) return [];
  const entries = [];
  for (const entry of readdirSync(dirPath, { withFileTypes: true })) {
    if (entry.name.startsWith('.') && entry.isDirectory()) continue;
    if (['node_modules', 'cache', 'out', 'artifacts', 'dist', '.git'].includes(entry.name)) continue;

    const fullPath = join(dirPath, entry.name);
    if (entry.isDirectory()) {
      entries.push({
        name: entry.name,
        type: 'directory',
        path: fullPath,
        children: buildTree(fullPath, depth + 1, maxDepth),
      });
    } else {
      entries.push({
        name: entry.name,
        type: 'file',
        path: fullPath,
        size: statSync(fullPath).size,
      });
    }
  }
  return entries;
}

export function handleFileAccess(url, body, req, res) {
  // Validate session token (except for /files/open which creates it)
  if (url !== '/files/open' && sessionToken) {
    const tokenHeader = req.headers['x-workspace-token'];
    if (tokenHeader !== sessionToken) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Invalid workspace token' }));
      return true;
    }
  }

  switch (url) {
    case '/files/open': {
      const { path: dirPath } = body;
      if (!dirPath) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'path is required' }));
        return true;
      }
      try {
        projectRoot = resolve(dirPath);
        sessionToken = randomUUID();
        const tree = buildTree(projectRoot);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, token: sessionToken, tree, projectRoot }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: err.message }));
      }
      return true;
    }

    case '/files/read': {
      const filePath = body.path;
      if (!filePath || !isPathSafe(filePath)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'Invalid or unsafe path' }));
        return true;
      }
      try {
        const content = readFileSync(resolve(filePath), 'utf-8');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, content }));
      } catch (err) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: err.message }));
      }
      return true;
    }

    case '/files/write': {
      const { path: filePath, content } = body;
      if (!filePath || !isPathSafe(filePath)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'Invalid or unsafe path' }));
        return true;
      }
      const ext = extname(filePath);
      if (!ALLOWED_WRITE_EXTENSIONS.has(ext)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: `Write not allowed for extension: ${ext}` }));
        return true;
      }
      try {
        writeFileSync(resolve(filePath), content, 'utf-8');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: err.message }));
      }
      return true;
    }

    case '/files/close': {
      projectRoot = null;
      sessionToken = null;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return true;
    }

    default:
      return false;
  }
}
