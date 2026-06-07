import { writeFileSync, readFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const STORE_DIR = join(homedir(), '.pii-mask-yoshi', 'maps');

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
    const token = `[${prefix}-${String(this.counters[prefix]).padStart(3, '0')}]`;
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
    for (const [token] of this.tokenToOriginal) {
      const prefix = token.replace(/^\[/, '').replace(/-\d+\]$/, '');
      byCategory[prefix] = (byCategory[prefix] || 0) + 1;
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
    writeFileSync(path, JSON.stringify(data, null, 2), 'utf8');
    return path;
  }

  load(sessionId) {
    if (!/^session-\d+$/.test(sessionId)) return false;
    const path = join(STORE_DIR, `${sessionId}.json`);
    if (!existsSync(path)) return false;
    const data = JSON.parse(readFileSync(path, 'utf8'));
    for (const [token, original] of Object.entries(data)) {
      this.tokenToOriginal.set(token, original);
      const prefix = token.replace(/^\[/, '').replace(/-\d+\]$/, '');
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
  }
}
