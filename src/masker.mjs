import { loadPatterns } from './patterns.mjs';
import { MaskStore } from './store.mjs';

let patterns = null;
const store = new MaskStore();

const ANTI_CONTEXT = /(?:例[)）]|サンプルデータ|テストデータ|テスト用|ダミー|\bdummy\b|\bexample\b|\bsample\s+data\b)/i;
const emailDomainRe = /[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
const ANTI_CONTEXT_IDS = new Set([
  'jp-person-name', 'jp-person-name-nospace', 'jp-person-name-list',
  'jp-person-name-honorific', 'jp-label-name',
  'jp-furigana-name', 'jp-katakana-name', 'jp-name-nakaguro',
  'jp-person-name-fullspace',
]);

function ensurePatterns() {
  if (!patterns) patterns = loadPatterns();
  return patterns;
}

function getLineNumber(text, charIndex) {
  let line = 1;
  for (let i = 0; i < charIndex && i < text.length; i++) {
    if (text[i] === '\n') line++;
  }
  return line;
}

export function maskText(text, filePath = null, options = {}) {
  const pats = ensurePatterns();
  let result = text;
  const replacements = [];

  for (const p of pats) {
    p.regex.lastIndex = 0;
    let m;
    while ((m = p.regex.exec(result)) !== null) {
      const matched = m[0];

      let prefix = p.maskPrefix;
      let confidence = p.defaultConfidence ?? 1.0;
      if (p.validator) {
        const v = p.validator(matched, { text: result, start: m.index, end: m.index + matched.length });
        if (v === null) {
          if (m.index === p.regex.lastIndex) p.regex.lastIndex++;
          continue;
        }
        prefix = v.label;
        confidence = v.confidence;
      }

      replacements.push({
        start: m.index,
        end: m.index + matched.length,
        original: matched,
        prefix,
        category: p.category,
        patternId: p.id,
        confidence,
      });

      if (m.index === p.regex.lastIndex) p.regex.lastIndex++;
    }
  }

  replacements.sort((a, b) => b.start - a.start);

  const seen = new Set();
  const deduped = [];
  for (const r of replacements) {
    const key = `${r.start}:${r.end}`;
    if (seen.has(key)) continue;
    let overlap = false;
    for (const d of deduped) {
      if (r.start < d.end && r.end > d.start) { overlap = true; break; }
    }
    if (overlap) continue;
    seen.add(key);
    deduped.push(r);
  }

  deduped.sort((a, b) => b.start - a.start);

  const EMAIL_DOMAIN_SAFE_RANGES = [];
  emailDomainRe.lastIndex = 0;
  let edm;
  while ((edm = emailDomainRe.exec(result)) !== null) {
    if (/example/i.test(edm[1])) {
      const domainStart = edm.index + edm[0].indexOf('@') + 1;
      EMAIL_DOMAIN_SAFE_RANGES.push([domainStart, edm.index + edm[0].length]);
    }
  }

  function isInEmailDomainSafeRange(pos) {
    return EMAIL_DOMAIN_SAFE_RANGES.some(([s, e]) => pos >= s && pos < e);
  }

  const filtered = deduped.filter(r => {
    if (!ANTI_CONTEXT_IDS.has(r.patternId)) return true;
    const ws = Math.max(0, r.start - 15);
    const we = Math.min(result.length, r.end + 15);
    const window = result.slice(ws, we);
    if (!ANTI_CONTEXT.test(window)) return true;
    // email ドメイン内の "example" が ANTI_CONTEXT を誤発動させている場合は除外しない（FN-34対応）
    // window 内の "example" が safe range に完全に含まれるか確認
    const exampleMatch = /\bexample\b/i.exec(window);
    if (exampleMatch) {
      const absolutePos = ws + exampleMatch.index;
      if (isInEmailDomainSafeRange(absolutePos)) return true;
    }
    return false;
  });

  const minConf = options.min_confidence ?? 0.0;
  const final = minConf > 0 ? filtered.filter(r => r.confidence >= minConf) : filtered;

  let masked = result;
  for (const r of final) {
    const token = store.getOrCreate(r.original, r.prefix);
    masked = masked.slice(0, r.start) + token + masked.slice(r.end);
    if (filePath) {
      store.addFinding(filePath, getLineNumber(text, r.start), r.category, token, r.confidence);
    }
  }

  store.save();
  return masked;
}

export function unmaskText(text) {
  return store.unmask(text);
}

export function getStore() {
  return store;
}
