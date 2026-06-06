import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const NEKO_NOT_YOSHI_DIR = join(process.env.NEKO_NOT_YOSHI_DIR || 'C:/work/neko-not-yoshi');

const BUILTIN_PATTERNS = [
  { id: 'email', category: 'pii', regex: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}', maskPrefix: 'EMAIL' },
  { id: 'phone-jp', category: 'pii', regex: '0\\d{1,4}-\\d{1,4}-\\d{4}', maskPrefix: 'TEL' },
  { id: 'ipv4', category: 'network', regex: '(?:\\d{1,3}\\.){3}\\d{1,3}', maskPrefix: 'IPv4' },
  { id: 'ipv6', category: 'network', regex: '(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}', maskPrefix: 'IPv6' },
  { id: 'local-path-home', category: 'pii', regex: "[A-Za-z]:[\\\\/]Users[\\\\/][^\\s\"'`,)]+", maskPrefix: 'PATH' },
];

const EXTRA_PATTERNS = [
  { id: 'jwt-token', category: 'credential', regex: 'eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.?[A-Za-z0-9_-]*', maskPrefix: 'JWT' },
  { id: 'api-key-openai', category: 'credential', regex: 'sk-[a-zA-Z0-9]{20,}', maskPrefix: 'APIKEY' },
  { id: 'api-key-github', category: 'credential', regex: 'ghp_[a-zA-Z0-9]{36,}', maskPrefix: 'APIKEY' },
  { id: 'api-key-aws', category: 'credential', regex: 'AKIA[A-Z0-9]{16}', maskPrefix: 'APIKEY' },
  { id: 'api-key-anthropic', category: 'credential', regex: 'sk-ant-[a-zA-Z0-9-]{20,}', maskPrefix: 'APIKEY' },
  { id: 'aws-secret-key', category: 'credential', regex: '(?:(?:aws)?_?secret_?(?:access)?_?key|SecretAccessKey|Secret)\\s*[:=]\\s*[A-Za-z0-9/+=]{40}', maskPrefix: 'SECRET' },
  { id: 'azure-account-key', category: 'credential', regex: 'AccountKey=[A-Za-z0-9/+=]{20,}', maskPrefix: 'SECRET' },
  { id: 'password-kv-slash', category: 'credential', regex: '(?:管理者|admin\\b|root\\b|user\\b)\\s*/\\s*\\S+', maskPrefix: 'PASSWD' },
  { id: 'password-kv-en', category: 'credential', regex: '(?:password|passwd|secret|token)\\s*[:=]\\s*\\S+', maskPrefix: 'PASSWD' },
  { id: 'password-kv-ja', category: 'credential', regex: '(?:パスワード|パス|密码|秘密鍵)\\s*[:=：]\\s*\\S+', maskPrefix: 'PASSWD' },
  { id: 'credit-card', category: 'financial', regex: '\\b(?:\\d{4}[-\\s]?){3}\\d{4}\\b', maskPrefix: 'CARD' },
  { id: 'my-number', category: 'pii', regex: '\\b\\d{4}\\s?\\d{4}\\s?\\d{4}\\b', maskPrefix: 'MYNUM' },
  { id: 'bank-account', category: 'financial', regex: '(?:口座番号|口座)\\s*[:=：]?\\s*\\d{7,8}', maskPrefix: 'BANK' },
  { id: 'bank-account-type', category: 'financial', regex: '(?:普通|当座)\\s*\\d{7,8}', maskPrefix: 'BANK' },
  { id: 'passport-jp', category: 'pii', regex: '\\b[A-Z]{2}\\d{7}\\b', maskPrefix: 'PASSPORT' },
  { id: 'corporate-number', category: 'pii', regex: '(?:法人番号\\s*[:：]?\\s*|T)\\d{13}', maskPrefix: 'CORPNUM' },
  { id: 'jp-address', category: 'pii', regex: '(?:東京都|北海道|(?:大阪|京都)府|.{2,3}県)(?:[\\u4E00-\\u9FFF\\u3040-\\u309F\\u30A0-\\u30FF0-9０-９]{1,4}[\\u5E02\\u533A\\u753A\\u6751\\u90E1])[\\u4E00-\\u9FFF\\u3040-\\u309F\\u30A0-\\u30FF0-9０-９\\-]{1,20}', maskPrefix: 'ADDR' },
  { id: 'jp-person-name', category: 'pii', regex: '[\\u3400-\\u9FFF]{2,4}[\\s\\u3000]+[\\u3400-\\u9FFF]{1,4}', maskPrefix: 'PERSON' },
  { id: 'jp-person-name-list', category: 'pii', regex: '[\\u3400-\\u9FFF]{1,4}(?:[、,][\\u3400-\\u9FFF]{1,4}){2,}', maskPrefix: 'PERSON' },
];

const CATEGORY_TO_PREFIX = {
  email: 'EMAIL',
  'phone-jp': 'TEL',
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  'local-path-home': 'PATH',
  'local-path-work': 'PATH',
};

function classifyIPv4(ip) {
  const o = ip.split('.').map((n) => Number(n));
  if (o.length !== 4 || o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return 'invalid';
  if (o[0] === 10) return 'private';
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return 'private';
  if (o[0] === 192 && o[1] === 168) return 'private';
  if (o[0] === 127) return 'private';
  if (o[0] === 0 || o[0] === 255) return 'private';
  if (o[0] === 169 && o[1] === 254) return 'private';
  return 'global';
}

function looksLikeIPv6(s) {
  if (s.includes('::')) return true;
  const g = s.split(':');
  if (g.length < 6) return false;
  return g.some((x) => x.length >= 3 || /[a-fA-F]/.test(x));
}

const GEO_SUFFIXES = /[都道府県市区町村郡]$/;

function validateJpName(matched) {
  const parts = matched.trim().split(/[\s　]+/);
  if (parts.length !== 2) return null;
  if (GEO_SUFFIXES.test(parts[0]) && GEO_SUFFIXES.test(parts[1])) return null;
  return 'PERSON';
}

function luhnCheck(num) {
  const digits = num.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function compileBasePattern(p) {
  return {
    id: p.id,
    category: p.category,
    regex: new RegExp(p.regex, 'g'),
    maskPrefix: CATEGORY_TO_PREFIX[p.id] || p.maskPrefix || p.category.toUpperCase(),
    validator: p.id === 'ipv4' ? (m) => {
      const cls = classifyIPv4(m);
      if (cls === 'invalid') return null;
      return cls === 'private' ? 'PRIV-IPv4' : 'IPv4';
    } : p.id === 'ipv6' ? (m) => looksLikeIPv6(m) ? 'IPv6' : null : null,
  };
}

export function loadPatterns() {
  const compiled = [];

  const pubPath = join(NEKO_NOT_YOSHI_DIR, 'ngwords.public.json');
  if (existsSync(pubPath)) {
    const pub = JSON.parse(readFileSync(pubPath, 'utf8'));
    for (const p of pub.patterns || []) {
      try { compiled.push(compileBasePattern(p)); } catch { /* skip */ }
    }
  } else {
    for (const p of BUILTIN_PATTERNS) {
      try { compiled.push(compileBasePattern(p)); } catch { /* skip */ }
    }
  }

  const privPath = join(NEKO_NOT_YOSHI_DIR, 'ngwords.private.json');
  if (existsSync(privPath)) {
    const priv = JSON.parse(readFileSync(privPath, 'utf8'));
    for (const w of priv.words || []) {
      if (!w.value || w.value.startsWith('<')) continue;
      const escaped = w.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const isAscii = /^[\x00-\x7F]+$/.test(w.value);
      const pattern = isAscii ? `\\b${escaped}\\b` : escaped;
      compiled.push({
        id: `private:${w.value.slice(0, 8)}`,
        category: w.category || 'customer',
        regex: new RegExp(pattern, 'g'),
        maskPrefix: w.category === 'customer' ? 'CUSTOMER' : 'NAME',
        isPrivateWord: true,
      });
    }
  }

  for (const p of EXTRA_PATTERNS) {
    try {
      compiled.push({
        id: p.id,
        category: p.category,
        regex: new RegExp(p.regex, 'g'),
        maskPrefix: p.maskPrefix,
        validator: p.id === 'credit-card' ? (m) => luhnCheck(m) ? 'CARD' : null
          : p.id === 'jp-person-name' ? (m) => validateJpName(m) : null,
      });
    } catch { /* skip */ }
  }

  return compiled;
}
