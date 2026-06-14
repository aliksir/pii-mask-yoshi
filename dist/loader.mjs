import { readFileSync } from 'node:fs';
import { createDecipheriv } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { MaskStore } from '../src/store.mjs';

const _require = createRequire(import.meta.url);
const __dir = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dir, '..');

// key (embedded at build time)
const _k = Buffer.from([0x20,0x5d,0x12,0xfb,0x2a,0x2c,0xc0,0x73,0x86,0xb2,0x68,0xcf,0x46,0x68,0xc1,0xe7,0xd4,0xda,0xb1,0x93,0x42,0x9e,0x5f,0x4d,0x90,0xbf,0x3e,0xc3,0x55,0x20,0xa4,0xf9]);

// decrypt
const _enc = JSON.parse(readFileSync(join(__dir, 'core.enc'), 'utf8'));
const _iv = Buffer.from(_enc.iv, 'base64');
const _tag = Buffer.from(_enc.tag, 'base64');
const _ct = Buffer.from(_enc.ct, 'base64');
const _d = createDecipheriv('aes-256-gcm', _k, _iv);
_d.setAuthTag(_tag);
const _src = Buffer.concat([_d.update(_ct), _d.final()]).toString('utf8');

// execute factory
const _fn = new Function('require', 'ROOT', 'MaskStore', _src);
const _core = _fn(_require, ROOT, MaskStore);

export const { maskText, unmaskText, getStore } = _core;
export const { loadPatterns } = _core;
