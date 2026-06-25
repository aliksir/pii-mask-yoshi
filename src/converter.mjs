import { execFileSync } from 'node:child_process';

export const BINARY_EXTENSIONS = new Set([
  '.xlsx', '.xls', '.docx', '.pptx', '.pdf',
  '.odt', '.ods', '.odp', '.rtf',
]);

export function convertWithMarkitdown(filePath) {
  try {
    return execFileSync('python', ['-m', 'markitdown', filePath], {
      encoding: 'utf8',
      timeout: 30000,
      maxBuffer: 10 * 1024 * 1024,
    });
  } catch {
    return null;
  }
}
