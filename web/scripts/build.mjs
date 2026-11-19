#!/usr/bin/env node
// Build the static web client into an output directory.
// Reuses the desktop Music stylesheet, fonts and icon byte-for-byte.
//
//   node web/scripts/build.mjs --out DIR --happ PATH --catalogue-dna uhC0k… --storage-dna uhC0k…
//        --gateway https://gateway.example --adapter https://media.example [--allow-lan-hosts] [--release NAME]
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { validateConfig } from '../src/config.js';

const here = dirname(fileURLToPath(import.meta.url));
const web = resolve(here, '..');
const repo = resolve(web, '..');
const { values: a } = parseArgs({ options: {
  out: { type: 'string' }, happ: { type: 'string' }, 'catalogue-dna': { type: 'string' }, 'storage-dna': { type: 'string' },
  gateway: { type: 'string' }, adapter: { type: 'string' }, 'allow-lan-hosts': { type: 'boolean', default: false },
  release: { type: 'string', default: 'development' }, 'app-id': { type: 'string', default: 'holochain-music-web' },
  origin: { type: 'string', default: 'http://localhost' },
} });
for (const k of ['out', 'happ', 'catalogue-dna', 'storage-dna', 'gateway', 'adapter']) if (!a[k]) throw new Error(`--${k} is required`);

const out = resolve(a.out);
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
cpSync(join(web, 'public'), out, { recursive: true });
cpSync(join(web, 'src'), join(out, 'src'), { recursive: true });
const ui = join(repo, 'holochain_music', 'ui');
cpSync(join(ui, 'app.css'), join(out, 'app.css'));
cpSync(join(ui, 'icon.svg'), join(out, 'icon.svg'));
cpSync(join(ui, 'fonts'), join(out, 'fonts'), { recursive: true });
const happ = readFileSync(a.happ);
writeFileSync(join(out, 'holochain_music.happ'), happ);
const config = {
  app_id: a['app-id'], happ_url: '/holochain_music.happ',
  happ_sha256: createHash('sha256').update(happ).digest('hex'),
  roles: { music_catalogue: a['catalogue-dna'], music_storage: a['storage-dna'] },
  gateway_url: a.gateway, media_adapter_url: a.adapter, allow_lan_hosts: a['allow-lan-hosts'], release: a.release,
};
validateConfig(config, { pageOrigin: a.origin });
writeFileSync(join(out, 'web-config.json'), JSON.stringify(config, null, 2));
console.log(JSON.stringify({ out, happ_sha256: config.happ_sha256, roles: config.roles }));
