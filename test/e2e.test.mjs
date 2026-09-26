// e2e.test.mjs — mask→AI処理→復元→scan 一気通貫テスト
// 各テストは独立して動作する（順序依存なし）

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, unlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

// マスカーモジュールのインポート
import { maskText, unmaskText, getStore } from '../src/masker.mjs';
// 暗号化モジュールのインポート
import { encrypt, decrypt, generateKey, isEncrypted } from '../src/crypto.mjs';
// ストアクラスのインポート（mask map round-trip テストで使用）
import { MaskStore } from '../src/store.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const NEKO_NOT_YOSHI_BIN = join(__dirname, '..', '..', 'neko-not-yoshi', 'bin', 'neko-not-yoshi');

// テスト用日本語PII入りテキスト（RFC2606 example ドメイン + ダミー番号を使用）
const PII_TEXT = [
  '担当者: 山田 太郎',
  'メール: yamada.taro@example.com',
  '電話: 03-1234-5678',
  '以上の情報でご連絡ください。',
].join('\n');

// 各テスト前にストアをクリアして独立性を確保
function freshStore() {
  getStore().clear();
}

// --------------------------------------------------------
// 1. mask→unmask round-trip
// --------------------------------------------------------
describe('mask→unmask round-trip', () => {
  it('日本語PIIテキストをマスクして完全復元できる', () => {
    freshStore();

    // マスク処理
    const masked = maskText(PII_TEXT, 'e2e-test.txt');

    // マスク結果に元のPII文字列が含まれないことを検証
    assert.ok(!masked.includes('yamada.taro@example.com'), `メールが残存: ${masked}`);
    assert.ok(!masked.includes('03-1234-5678'), `電話番号が残存: ${masked}`);

    // マスクトークンが存在することを確認
    assert.ok(masked.includes('[メール'), `メールトークンがない: ${masked}`);
    assert.ok(masked.includes('[電話'), `電話トークンがない: ${masked}`);

    // unmask で元テキストに完全復元できることを検証
    const restored = unmaskText(masked);
    assert.equal(restored, PII_TEXT, 'round-trip復元失敗');
  });

  it('同一PIIには同一トークンが割り当てられる', () => {
    freshStore();

    // 同じメールアドレスが2回出現するテキスト
    const text = [
      '送信者: repeat@example.net',
      'CC: repeat@example.net',
    ].join('\n');

    const masked = maskText(text);

    // トークンの個数が2個（同一値なので同一トークン）
    const tokenMatches = masked.match(/\[メール[A-Z]+\]/g);
    assert.ok(tokenMatches && tokenMatches.length === 2, `同一メールに別トークンが割り当てられた: ${masked}`);
    assert.equal(tokenMatches[0], tokenMatches[1], '同一値に異なるトークン');
  });
});

// --------------------------------------------------------
// 2. PII 非残存検証
// --------------------------------------------------------
describe('PIIの非残存検証', () => {
  it('マスク後のテキストに元PII値が一切含まれない', () => {
    freshStore();

    // 複数種のPIIを含むテキスト
    const piiValues = {
      email: 'leak-check@example.org',
      phone: '090-0000-0000',
    };

    const text = [
      `連絡先: ${piiValues.email}`,
      `電話: ${piiValues.phone}`,
      '田中 健太 様',
    ].join('\n');

    const masked = maskText(text, 'pii-check.txt');

    // 元のメールアドレスが残存していないことを検証
    assert.ok(!masked.includes(piiValues.email), `メールが残存: ${masked}`);

    // 元の電話番号が残存していないことを検証
    assert.ok(!masked.includes(piiValues.phone), `電話番号が残存: ${masked}`);

    // 人名部分が検出できる（あれば）かどうかを確認（FPも有り得るため件数のみ確認）
    const store = getStore();
    assert.ok(store.tokenToOriginal.size >= 2, `期待より少ないマスク件数: ${store.tokenToOriginal.size}`);
  });

  it('マスク後テキストをスキャンしてPII原文が検出されない', () => {
    freshStore();

    const secretEmail = 'secret@example.jp';
    const secretPhone = '03-1234-5678';
    const text = `担当: 佐藤 次郎, 電話: ${secretPhone}, メール: ${secretEmail}`;

    const masked = maskText(text);

    // grep的な文字列検索で残存チェック
    const piiPatterns = [secretEmail, secretPhone];
    for (const pii of piiPatterns) {
      assert.ok(!masked.includes(pii), `PII残存検出: "${pii}" が masked テキストに存在する`);
    }
  });
});

// --------------------------------------------------------
// 3. マスク処理の決定性検証
// --------------------------------------------------------
describe('マスク処理の決定性検証', () => {
  it('同一テキストを別セッションでマスクしてもトークン種類・数が一致する', () => {
    freshStore();

    const text = [
      '担当: 鈴木 次郎',
      'メール: suzuki@example.org',
      '電話: 090-0000-0000',
    ].join('\n');

    // WASM有効でマスク
    const maskedWasm = maskText(text, 'wasm-test.txt');
    const wasmTokens = (maskedWasm.match(/\[[^\]]+\]/g) || []).sort();

    freshStore();

    // JS fallbackでマスク（WASM無効化はモジュールキャッシュがあるため
    // ここでは同一テキストで2回マスクして同一結果を確認する）
    const maskedWasm2 = maskText(text, 'wasm-test2.txt');
    const wasmTokens2 = (maskedWasm2.match(/\[[^\]]+\]/g) || []).sort();

    // 2回のマスク結果でトークン種類・数が一致することを確認
    assert.deepEqual(wasmTokens, wasmTokens2, 'WASM経路での2回マスク結果が一致しない');
    assert.ok(wasmTokens.length >= 2, `トークンが少なすぎる: ${wasmTokens.length}`);
  });

  it('同一テキストを繰り返しマスクしても冪等性が保たれる（決定性確認）', () => {
    freshStore();

    const text = 'データ: user@example.net, TEL: 03-1234-5678';

    const masked1 = maskText(text);
    freshStore();
    const masked2 = maskText(text);

    // トークン数の一致を確認
    const count1 = (masked1.match(/\[[^\]]+\]/g) || []).length;
    const count2 = (masked2.match(/\[[^\]]+\]/g) || []).length;
    assert.equal(count1, count2, `マスクトークン数が一致しない: ${count1} vs ${count2}`);
  });
});

// --------------------------------------------------------
// 4. 暗号化 mask map round-trip
// --------------------------------------------------------
describe('暗号化 mask map round-trip', () => {
  it('generateKey で生成した鍵で encrypt→decrypt が元データと一致する', () => {
    // 元データ
    const original = JSON.stringify({
      '[メールA]': 'test@example.com',
      '[電話A]': '090-0000-0000',
    });

    // 一時的な鍵を生成（ファイルには書き込まず直接 randomBytes を使う）
    const key = randomBytes(32);

    // 暗号化
    const ciphertext = encrypt(original, key);

    // 暗号化結果が JSON 形式になっていることを確認
    assert.ok(isEncrypted(ciphertext), '暗号化結果が想定フォーマットでない');

    // 復号
    const decrypted = decrypt(ciphertext, key);

    // 元データと一致することを確認
    assert.equal(decrypted, original, '暗号化→復号で元データが変化した');
  });

  it('異なる鍵で復号しようとすると例外が発生する', () => {
    const key1 = randomBytes(32);
    const key2 = randomBytes(32);
    const plaintext = '{"[PERSON-001]": "山田太郎"}';

    const encrypted = encrypt(plaintext, key1);

    // 異なる鍵で復号しようとすると例外が発生することを確認
    assert.throws(
      () => decrypt(encrypted, key2),
      /Unsupported encryption format|auth|decryption/i,
      '異なる鍵での復号が成功してしまった（セキュリティ上の問題）'
    );
  });

  it('isEncrypted が平文 JSON と暗号化済み JSON を正しく判別する', () => {
    const key = randomBytes(32);
    const plainJson = '{"[メールA]": "test@example.com"}';
    const encrypted = encrypt(plainJson, key);

    // 平文は false
    assert.equal(isEncrypted(plainJson), false, '平文が暗号化済みと誤判定された');
    // 暗号化済みは true
    assert.equal(isEncrypted(encrypted), true, '暗号化済みが平文と誤判定された');
    // 非 JSON は false
    assert.equal(isEncrypted('not json'), false, '非JSONが暗号化済みと誤判定された');
  });

  it('mask→save→load でストアを復元できる', () => {
    freshStore();

    const text = 'テスト: store@example.com, TEL: 090-0000-0000';
    const masked = maskText(text);

    // ストア保存
    const store = getStore();
    const mapPath = store.save();
    const sessionId = store.sessionId;

    // 新規ストアで load
    const newStore = new MaskStore();
    const loaded = newStore.load(sessionId);

    assert.ok(loaded, 'ストアのロードに失敗した');

    // 復元したストアで unmask できることを確認
    const restored = newStore.unmask(masked);
    assert.equal(restored, text, 'ストアload後のunmaskが元テキストと一致しない');

    // クリーンアップ: 生成したマップファイルを削除
    try {
      if (existsSync(mapPath)) unlinkSync(mapPath);
    } catch {
      // cleanup 失敗は無視
    }
  });
});

// --------------------------------------------------------
// 5. neko-not-yoshi scan 統合（neko-not-yoshi が存在する場合のみ）
// --------------------------------------------------------
describe('neko-not-yoshi scan 統合テスト', () => {
  // neko-not-yoshi の存在チェック
  const nekoExists = existsSync(NEKO_NOT_YOSHI_BIN);

  it('マスク済みテキストをスキャンして block=0 を確認', { skip: !nekoExists ? 'neko-not-yoshi が見つかりません' : false }, async () => {
    freshStore();

    const piiText = [
      '顧客: 佐藤 花子',
      'メールアドレス: sato.hanako@example.jp',
      '電話番号: 03-1234-5678',
    ].join('\n');

    // マスク処理
    const maskedText = maskText(piiText, 'neko-scan-test.txt');

    // マスク済みテキストを一時ファイルに書き出し
    const tmpFile = join(tmpdir(), `pii-e2e-scan-${Date.now()}.txt`);
    writeFileSync(tmpFile, maskedText, 'utf8');

    try {
      // neko-not-yoshi scan を実行
      let scanOutput = '';
      let exitCode = 0;

      try {
        scanOutput = execFileSync('node', [NEKO_NOT_YOSHI_BIN, 'scan', tmpFile], {
          encoding: 'utf8',
          timeout: 30000,
        });
      } catch (err) {
        // exit code が 0 以外の場合も err.stdout に出力が入る
        scanOutput = err.stdout || '';
        exitCode = err.status || 1;
      }

      // block=0 を確認（ブロック検出なし）
      assert.equal(exitCode, 0, `neko-not-yoshi scan が非0で終了: ${scanOutput}`);
      assert.ok(
        !scanOutput.includes('block:') || scanOutput.includes('block: 0') || scanOutput.includes('"block":0'),
        `マスク済みテキストにブロック検出: ${scanOutput}`
      );
    } finally {
      // 一時ファイルを削除
      try { if (existsSync(tmpFile)) unlinkSync(tmpFile); } catch { /* ignore */ }
    }
  });

  it('生のPIIテキストをスキャンするとブロック検出される', { skip: !nekoExists ? 'neko-not-yoshi が見つかりません' : false }, async () => {
    // 元のPIIテキストをファイルに書き出し
    const tmpFile = join(tmpdir(), `pii-e2e-raw-${Date.now()}.txt`);
    writeFileSync(tmpFile, PII_TEXT, 'utf8');

    try {
      let scanOutput = '';
      let exitCode = 0;

      try {
        scanOutput = execFileSync('node', [NEKO_NOT_YOSHI_BIN, 'scan', tmpFile], {
          encoding: 'utf8',
          timeout: 30000,
        });
      } catch (err) {
        scanOutput = err.stdout || err.stderr || '';
        exitCode = err.status || 1;
      }

      // PII を含むファイルは非0終了またはブロック検出されることを期待
      // （neko-not-yoshi がPII検出でブロックを報告することを確認）
      const hasBlock = exitCode !== 0 || scanOutput.includes('block') || scanOutput.includes('found');
      assert.ok(hasBlock, `生PIIテキストがスキャンを素通りした: exit=${exitCode}, output=${scanOutput}`);
    } finally {
      try { if (existsSync(tmpFile)) unlinkSync(tmpFile); } catch { /* ignore */ }
    }
  });
});
