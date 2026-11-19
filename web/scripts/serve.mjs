#!/usr/bin/env node
// Development/test static server for a built web client, with the security
// headers a production deployment must also send (see docs/web/security.md).
//   node web/scripts/serve.mjs DIR [--port 8080] [--host 127.0.0.1]
import { createReadStream, readFileSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';
import { parseArgs } from 'node:util';

const { values, positionals } = parseArgs({ allowPositionals: true, options: {
  port: { type: 'string', default: '8080' }, host: { type: 'string', default: '127.0.0.1' } } });
const root = resolve(positionals[0] ?? 'dist');
const config = JSON.parse(readFileSync(join(root, 'web-config.json'), 'utf8'));
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.happ': 'application/octet-stream',
  '.webmanifest': 'application/manifest+json', '.txt': 'text/plain; charset=utf-8' };
const wsOf = u => u.replace(/^http/, 'ws');
export const CSP = [
  "default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self' data:", "font-src 'self'",
  `connect-src 'self' ${config.gateway_url} ${wsOf(config.gateway_url)} ${config.media_adapter_url}`,
  "worker-src 'self'", "manifest-src 'self'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'", "object-src 'none'",
].join('; ');

createServer((req, res) => {
  const path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  const file = normalize(join(root, path === '/' ? 'index.html' : path));
  if (!file.startsWith(root) || req.method !== 'GET') { res.writeHead(404).end(); return; }
  let st;
  try { st = statSync(file); } catch { res.writeHead(404).end(); return; }
  if (!st.isFile()) { res.writeHead(404).end(); return; }
  res.writeHead(200, {
    'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream', 'Content-Length': st.size,
    'Content-Security-Policy': CSP, 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cache-Control': path.endsWith('.json') || path === '/' ? 'no-store' : 'no-cache',
  });
  createReadStream(file).pipe(res);
}).listen(Number(values.port), values.host, () => console.log(JSON.stringify({ serving: root, url: `http://${values.host}:${values.port}` })));
