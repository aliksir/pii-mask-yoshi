import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { BINARY_EXTENSIONS, convertWithMarkitdown } from '../src/converter.mjs';

describe('BINARY_EXTENSIONS', () => {
  it('should include office and PDF extensions', () => {
    for (const ext of ['.xlsx', '.xls', '.docx', '.pptx', '.pdf']) {
      assert.ok(BINARY_EXTENSIONS.has(ext), `${ext} should be recognized`);
    }
  });

  it('should include ODF extensions', () => {
    for (const ext of ['.odt', '.ods', '.odp']) {
      assert.ok(BINARY_EXTENSIONS.has(ext), `${ext} should be recognized`);
    }
  });

  it('should not include text file extensions', () => {
    for (const ext of ['.txt', '.md', '.json', '.csv', '.mjs', '.html']) {
      assert.ok(!BINARY_EXTENSIONS.has(ext), `${ext} should NOT be recognized`);
    }
  });
});

describe('convertWithMarkitdown', () => {
  it('should return null for non-existent file', () => {
    const result = convertWithMarkitdown('C:/nonexistent/fake-file.xlsx');
    assert.equal(result, null);
  });

  it('should convert xlsx file when markitdown is available', () => {
    const testFile = process.env.PII_TEST_XLSX;
    if (!testFile) {
      // no test file specified — skip
      return;
    }
    const result = convertWithMarkitdown(testFile);
    if (result === null) {
      // markitdown not installed — skip gracefully
      return;
    }
    assert.ok(result.length > 0, 'converted output should not be empty');
  });
});
