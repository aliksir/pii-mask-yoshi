import { maskText, unmaskText, getStore } from '../src/masker.mjs';
import { readFileSync, writeFileSync } from 'node:fs';

const inputFile = process.argv[2];
if (!inputFile) { console.error('Usage: node fuzz-runner.mjs <input.json>'); process.exit(1); }

const cases = JSON.parse(readFileSync(inputFile, 'utf8'));
const results = [];

for (const c of cases) {
  getStore().clear();
  const masked = maskText(c.text);
  const restored = unmaskText(masked);
  const roundTrip = restored === c.text;
  const store = getStore();
  const items = [...store.tokenToOriginal.entries()].map(([token, orig]) => ({
    token, orig, len: orig.length,
  }));

  const fps = items.filter(i => {
    if (i.token.startsWith('[人名')) {
      if (/[\n\r]/.test(i.orig)) return true;
      if (/[部課室局所省庁]/.test(i.orig)) return true;
      if (i.orig.length > 12) return true;
    }
    if (i.token.startsWith('[住所')) {
      if (i.orig.length > 30) return true;
      if (/[。、！？\n]/.test(i.orig)) return true;
    }
    return false;
  });

  results.push({
    name: c.name,
    charCount: c.text.length,
    roundTrip,
    maskedCount: items.length,
    items,
    suspectedFP: fps,
  });
}

const summary = {
  total: results.length,
  totalChars: results.reduce((s, r) => s + r.charCount, 0),
  roundTripPass: results.filter(r => r.roundTrip).length,
  totalMasked: results.reduce((s, r) => s + r.maskedCount, 0),
  totalSuspectedFP: results.reduce((s, r) => s + r.suspectedFP.length, 0),
  failures: results.filter(r => !r.roundTrip).map(r => r.name),
  fpDetails: results.filter(r => r.suspectedFP.length > 0).map(r => ({
    name: r.name,
    fps: r.suspectedFP,
  })),
  allMasked: results.filter(r => r.maskedCount > 0).map(r => ({
    name: r.name,
    items: r.items,
  })),
};

const outputFile = inputFile.replace('.json', '-results.json');
writeFileSync(outputFile, JSON.stringify(summary, null, 2), 'utf8');
console.log(JSON.stringify(summary));
