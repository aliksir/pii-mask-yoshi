import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { encrypt, decrypt, isEncrypted, resolveKey, generateKey } from '../src/crypto.mjs';
import { randomBytes } from 'node:crypto';
import { existsSync, unlinkSync, readFileSync, writeFileSync as fsWriteSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const KEY_FILE = join(homedir(), '.pii-mask-yoshi', '.key');
const TEST_KEY = randomBytes(32);

describe('crypto', () => {
  describe('encrypt/decrypt round-trip', () => {
    it('should encrypt and decrypt to original', () => {
      const plain = '{"[PERSON-001]":"John Doe","[IP-001]":"10.0.0.1"}';
      const encrypted = encrypt(plain, TEST_KEY);
      const decrypted = decrypt(encrypted, TEST_KEY);
      assert.equal(decrypted, plain);
    });

    it('should produce different ciphertext each time (random IV)', () => {
      const plain = 'test data';
      const a = encrypt(plain, TEST_KEY);
      const b = encrypt(plain, TEST_KEY);
      assert.notEqual(a, b);
    });

    it('should handle empty object', () => {
      const plain = '{}';
      const encrypted = encrypt(plain, TEST_KEY);
      assert.equal(decrypt(encrypted, TEST_KEY), plain);
    });

    it('should handle large data', () => {
      const plain = JSON.stringify(Object.fromEntries(
        Array.from({ length: 1000 }, (_, i) => [`[TOKEN-${i}]`, `value-${i}`])
      ));
      const encrypted = encrypt(plain, TEST_KEY);
      assert.equal(decrypt(encrypted, TEST_KEY), plain);
    });
  });

  describe('wrong key', () => {
    it('should throw on wrong key', () => {
      const plain = 'secret data';
      const encrypted = encrypt(plain, TEST_KEY);
      const wrongKey = randomBytes(32);
      assert.throws(() => decrypt(encrypted, wrongKey));
    });
  });

  describe('tampered data', () => {
    it('should throw on tampered ciphertext', () => {
      const plain = 'secret data';
      const encrypted = encrypt(plain, TEST_KEY);
      const obj = JSON.parse(encrypted);
      const ct = Buffer.from(obj.ct, 'base64');
      ct[0] ^= 0xff;
      obj.ct = ct.toString('base64');
      assert.throws(() => decrypt(JSON.stringify(obj), TEST_KEY));
    });
  });

  describe('isEncrypted', () => {
    it('should detect encrypted content', () => {
      const encrypted = encrypt('test', TEST_KEY);
      assert.equal(isEncrypted(encrypted), true);
    });

    it('should not detect plain JSON', () => {
      assert.equal(isEncrypted('{"key":"value"}'), false);
    });

    it('should not detect invalid JSON', () => {
      assert.equal(isEncrypted('not json'), false);
    });
  });

  describe('generateKey', () => {
    let hadKey = false;
    let origKey = null;

    before(() => {
      if (existsSync(KEY_FILE)) {
        hadKey = true;
        origKey = readFileSync(KEY_FILE, 'utf8');
      }
    });

    after(() => {
      if (hadKey) {
        fsWriteSync(KEY_FILE, origKey, 'utf8');
      } else if (existsSync(KEY_FILE)) {
        unlinkSync(KEY_FILE);
      }
    });

    it('should generate a valid key file', () => {
      const key = generateKey();
      assert.equal(key.length, 32);
      assert.ok(existsSync(KEY_FILE));
      const stored = Buffer.from(readFileSync(KEY_FILE, 'utf8').trim(), 'base64');
      assert.equal(stored.length, 32);
    });
  });
});
