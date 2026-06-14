import { writeFileSync, readFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { resolveKey, encrypt, decrypt, isEncrypted } from './crypto.mjs';

const STORE_DIR = join(homedir(), '.pii-mask-yoshi', 'maps');

const LABEL_TO_PREFIX = {};

const PREFIX_LABELS = {
  'EMAIL': 'メール',
  'TEL': '電話',
  'IPv4': 'IPv4',
  'PRIV-IPv4': '内部IPv4',
  'IPv6': 'IPv6',
  'PATH': 'パス',
  'JWT': 'JWT',
  'APIKEY': 'APIキー',
  'SECRET': '秘匿値',
  'PASSWD': 'PW',
  'CARD': 'カード',
  'MYNUM': 'マイナンバー',
  'BANK': '口座',
  'PASSPORT': 'パスポート',
  'CORPNUM': '法人番号',
  'ADDR': '住所',
  'PERSON': '人名',
  'CUSTOMER': '顧客名',
  'NAME': '名前',
  'AMOUNT': '金額',
  'DATE': '日付',
  'ZAIRYU': '在留カード',
  'PENSION': '年金番号',
  'LICENSE': '免許番号',
  'URL': 'URL',
  'CRYPTO': '暗号通貨',
  'IBAN': 'IBAN',
  'JUMINCODE': '住民票コード',
};

for (const [k, v] of Object.entries(PREFIX_LABELS)) LABEL_TO_PREFIX[v] = k;

function counterToLabel(n) {
  let label = '';
  while (n > 0) {
    n--;
    label = String.fromCharCode(65 + (n % 26)) + label;
    n = Math.floor(n / 26);
  }
  return label;
}

export class MaskStore {
  constructor() {
    this.tokenToOriginal = new Map();
    this.originalToToken = new Map();
    this.counters = {};
    this.sessionId = `session-${Date.now()}`;
    this.findings = [];
  }

  addFinding(file, line, category, token) {
    this.findings.push({ file, line, category, token });
  }

  getFindings() {
    return this.findings;
  }

  getOrCreate(original, prefix) {
    const key = `${prefix}::${original}`;
    if (this.originalToToken.has(key)) {
      return this.originalToToken.get(key);
    }
    if (!this.counters[prefix]) this.counters[prefix] = 0;
    this.counters[prefix]++;
    const label = PREFIX_LABELS[prefix] || prefix;
    const token = `[${label}${counterToLabel(this.counters[prefix])}]`;
    this.tokenToOriginal.set(token, original);
    this.originalToToken.set(key, token);
    return token;
  }

  unmask(text) {
    let result = text;
    for (const [token, original] of this.tokenToOriginal) {
      result = result.replaceAll(token, original);
    }
    return result;
  }

  stats() {
    const byCategory = {};
    for (const [prefix, count] of Object.entries(this.counters)) {
      const label = PREFIX_LABELS[prefix] || prefix;
      byCategory[label] = count;
    }
    return {
      totalMasked: this.tokenToOriginal.size,
      byCategory,
      sessionId: this.sessionId,
      mapFile: this.getMapPath(),
    };
  }

  save() {
    mkdirSync(STORE_DIR, { recursive: true });
    const data = {};
    for (const [token, original] of this.tokenToOriginal) {
      data[token] = original;
    }
    const path = this.getMapPath();
    const json = JSON.stringify(data, null, 2);
    const key = resolveKey();
    writeFileSync(path, key ? encrypt(json, key) : json, 'utf8');
    return path;
  }

  load(sessionId) {
    if (!/^session-\d+$/.test(sessionId)) return false;
    const path = join(STORE_DIR, `${sessionId}.json`);
    if (!existsSync(path)) return false;
    const raw = readFileSync(path, 'utf8');
    let data;
    if (isEncrypted(raw)) {
      const key = resolveKey();
      if (!key) throw new Error('Encrypted map found but no decryption key available');
      data = JSON.parse(decrypt(raw, key));
    } else {
      data = JSON.parse(raw);
    }
    for (const [token, original] of Object.entries(data)) {
      this.tokenToOriginal.set(token, original);
      const inner = token.slice(1, -1);
      let prefix;
      const oldMatch = inner.match(/^([A-Z][\w-]*)-\d+$/);
      if (oldMatch) {
        prefix = oldMatch[1];
      } else {
        const alphaMatch = inner.match(/[A-Z]+$/);
        const label = alphaMatch ? inner.slice(0, -alphaMatch[0].length) : inner;
        prefix = LABEL_TO_PREFIX[label] || label;
      }
      this.originalToToken.set(`${prefix}::${original}`, token);
    }
    return true;
  }

  getMapPath() {
    return join(STORE_DIR, `${this.sessionId}.json`);
  }

  clear() {
    this.tokenToOriginal.clear();
    this.originalToToken.clear();
    this.counters = {};
    this.findings.length = 0;
  }
}
