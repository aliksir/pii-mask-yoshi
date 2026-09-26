import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';

const ALG = 'aes-256-gcm';
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const KEY_FILE = join(homedir(), '.pii-mask-yoshi', '.key');

export function resolveKey() {
  const envKey = process.env.PII_MASK_ENCRYPT_KEY;
  if (envKey) {
    const buf = Buffer.from(envKey, 'base64');
    if (buf.length === KEY_LEN) return buf;
  }
  if (existsSync(KEY_FILE)) {
    const raw = readFileSync(KEY_FILE, 'utf8').trim();
    const buf = Buffer.from(raw, 'base64');
    if (buf.length === KEY_LEN) return buf;
  }
  return null;
}

export function generateKey() {
  const key = randomBytes(KEY_LEN);
  const dir = dirname(KEY_FILE);
  mkdirSync(dir, { recursive: true });
  writeFileSync(KEY_FILE, key.toString('base64') + '\n', { encoding: 'utf8', mode: 0o600 });
  return key;
}

export function encrypt(plaintext, key) {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALG, key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    v: 1,
    alg: ALG,
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ct: enc.toString('base64'),
  });
}

export function decrypt(json, key) {
  const obj = typeof json === 'string' ? JSON.parse(json) : json;
  if (obj.v !== 1 || obj.alg !== ALG) throw new Error('Unsupported encryption format');
  const iv = Buffer.from(obj.iv, 'base64');
  const tag = Buffer.from(obj.tag, 'base64');
  const ct = Buffer.from(obj.ct, 'base64');
  const decipher = createDecipheriv(ALG, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

export function isEncrypted(content) {
  try {
    const obj = JSON.parse(content);
    return obj.v === 1 && obj.alg === ALG;
  } catch {
    return false;
  }
}
