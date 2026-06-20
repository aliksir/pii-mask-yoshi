import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

const wasmModule = require(join(__dirname, '..', 'rust', 'pkg', 'pii_engine.js'));

export function findMatches(input) {
  const json = wasmModule.find_matches(input);
  return JSON.parse(json);
}
