#!/usr/bin/env node
// TEST-ONLY malicious gateway: a transparent proxy in front of the real
// h2hc-linker that forges catalogue data in DHT record responses.
//
// It forwards authentication, WebSocket traffic and every request unchanged,
// except GET /dht/<dna>/record/<hash> responses whose entry bytes contain
// --find: those bytes are replaced in place by --replace (same length, so the
// msgpack framing stays valid and the forged record still parses). A browser
// that trusted the gateway would therefore show forged metadata attributed to
// the genuine artist. Counts are written to --state for the test to assert.
//
//   node tamper_proxy.mjs --target http://127.0.0.1:8090 --port 8091 --find "Browser" --replace "FORGED!" --state s.json
import { mkdirSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { parseArgs } from 'node:util';

const { values: a } = parseArgs({ options: {
  target: { type: 'string' }, port: { type: 'string', default: '0' }, find: { type: 'string' },
  replace: { type: 'string' }, state: { type: 'string' },
  dump: { type: 'string' } /* diagnostics: keep each ORIGINAL record response */ } });
const target = new URL(a.target);
const find = Buffer.from(a.find, 'utf8');
const replace = Buffer.from(a.replace, 'utf8');
if (find.length === 0 || find.length !== replace.length) throw new Error('--find and --replace must be non-empty and equal length');
const state = { record_responses: 0, forged_records: 0, forwarded: 0, websocket_upgrades: 0 };
const save = () => a.state && writeFileSync(a.state, JSON.stringify(state));

function forge(json) {
  const entry = json?.entry?.Present?.entry ?? json?.entry?.entry;
  if (!Array.isArray(entry)) return false;
  const bytes = Buffer.from(entry);
  const at = bytes.indexOf(find);
  if (at < 0) return false;
  replace.copy(bytes, at);
  const forged = Array.from(bytes);
  if (json.entry.Present) json.entry.Present.entry = forged; else json.entry.entry = forged;
  return true;
}

const server = http.createServer((req, res) => {
  const upstream = http.request({ host: target.hostname, port: target.port, method: req.method, path: req.url, headers: req.headers }, up => {
    state.forwarded++;
    const isRecord = req.method === 'GET' && /^\/dht\/[^/]+\/record\//.test(req.url) && up.statusCode === 200;
    if (!isRecord) {
      res.writeHead(up.statusCode, up.headers);
      up.pipe(res);
      return;
    }
    const chunks = [];
    up.on('data', c => chunks.push(c));
    up.on('end', () => {
      state.record_responses++;
      let body = Buffer.concat(chunks);
      if (a.dump) {
        mkdirSync(a.dump, { recursive: true });
        writeFileSync(`${a.dump}/record-${state.record_responses}.json`, body);
      }
      try {
        const json = JSON.parse(body.toString('utf8'));
        if (forge(json)) {
          state.forged_records++;
          body = Buffer.from(JSON.stringify(json));
        }
      } catch { /* not JSON: forward unchanged */ }
      save();
      const headers = { ...up.headers, 'content-length': String(body.length) };
      delete headers['transfer-encoding'];
      res.writeHead(up.statusCode, headers);
      res.end(body);
    });
  });
  upstream.on('error', () => { res.writeHead(502); res.end(); });
  req.pipe(upstream);
});

server.on('upgrade', (req, socket, head) => {
  state.websocket_upgrades++;
  save();
  const up = net.connect(Number(target.port), target.hostname, () => {
    up.write(`${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`
      + Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`).join('\r\n') + '\r\n\r\n');
    if (head?.length) up.write(head);
    socket.pipe(up).pipe(socket);
  });
  const close = () => { socket.destroy(); up.destroy(); };
  up.on('error', close);
  socket.on('error', close);
});

server.listen(Number(a.port), '127.0.0.1', () => {
  save();
  console.log(JSON.stringify({ tamper_proxy: `http://127.0.0.1:${server.address().port}`, target: a.target }));
});
