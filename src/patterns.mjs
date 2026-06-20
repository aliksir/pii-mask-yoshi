import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

import { homedir } from 'node:os';
// XOR難読化パターンデータ（encode-js-patterns.mjs で生成）
import { XOR_KEY, BUILTIN, EXTRA, SURNAMES, HONORIFICS } from './encoded-data.mjs';

const NEKO_NOT_YOSHI_DIR = process.env.NEKO_NOT_YOSHI_DIR || join(homedir(), 'neko-not-yoshi');

// XOR + base64 デコード関数
const _K = Buffer.from(XOR_KEY, 'base64');
const _d = (b) => { const buf = Buffer.from(b, 'base64'); for (let i = 0; i < buf.length; i++) buf[i] ^= _K[i % _K.length]; return buf.toString('utf8'); };

// 難読化済みパターンを実行時にデコード
const BUILTIN_PATTERNS = BUILTIN.map(p => ({ ...p, regex: _d(p.regex) }));

const JP_SURNAMES_TOP200 = _d(SURNAMES);
const JP_HONORIFICS = _d(HONORIFICS);
const JP_SURNAME_RE = new RegExp(`^(?:${JP_SURNAMES_TOP200})`);
const JP_SURNAME_EXACT_RE = new RegExp(`^(?:${JP_SURNAMES_TOP200})$`);
const JP_HONORIFIC_SUFFIX_RE = new RegExp('(?:' + JP_HONORIFICS + ')$');

// 難読化済みEXTRAパターンをデコード（テンプレートリテラルは展開済み）
const EXTRA_PATTERNS = EXTRA.map(p => ({ ...p, regex: _d(p.regex) }));

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
const NOSPACE_EXCLUDE = /(?:様|氏|殿|社|部|課|係|長|官|局|室|員|棟|号|館|駅|港|橋|寺|院|神|塚|山|川|池|田|畑|工業|電気|商店|物産|建設|製作|通信|銀行|保険|証券|不動産|新聞|食品|薬品|産業|科学|商事|運送|倉庫|鉄道|放送|出版|印刷|繊維|化学|金属|機械|電子|光学|医療|福祉|教育|大学|学院|中学|小学|幼稚|高校|学園|病院|薬局|農園|牧場|酒造|醸造|水産|漁業|林業|鉱業|興業|観光|旅館|飯店|食堂|書店|薬店|花店|教授|先生|委員|議員|知事|市長|大臣|弁護士|医師|博士|商会|組合|漁協|農協|学校|幼園)$/;

// 第2パートが一般動詞・操作名で終わる場合は人名ではない
const NON_NAME_ENDINGS = /(?:処理|管理|対応|追加|追記|変更|削除|設定|確認|報告|実装|作成|修正|更新|登録|解除|承認|完了|開始|終了|検討|導入|移行|構築|改善|改修|分析|統計|集計|検証|試験|測定|調査|連絡|相談|方法|情報|一覧|研究|発表|委員|議員|学会|研究科|職員|業務|工事|工務|建設|開発|運用|担当|責任|担当者|制度|規程|規則|通達|規約|基準|連携|支店|支社|支局|銀行)$/;

// 第1パートが機関名・役職名で終わる場合は人名ではない（surnameIsExact時は除外しない）
const INSTITUTIONAL_FIRST = /(?:銀行|支店|支社|支局|工場|締役|社長|部長|課長|係長|主任|室長|局長|所長|院長|取締|担当|幹事|監事|理事|顧問|連携|事業|会計|会社|法人|事務)$/;

// 第1パートが一般的な概念語の場合は人名ではない
const COMMON_FIRST_WORDS = new Set([
  '情報', '品質', '機能', '技術', '基本', '詳細', '概要', '要件', '仕様',
  '画面', '帳票', '一覧', '明細', '予算', '実績', '計画', '目標', '成果',
  '評価', '審査', '監査', '環境', '設備', '資材', '資産', '在庫', '受注',
  '発注', '請求', '支払', '売上', '原価', '利益', '費用', '経費', '給与',
  '処理', '学会', '発表', '分類', '研究', '参加', '申込', '講演', '登壇',
  '基調', '登壇者', '会場', '幕張', '配信', '管理', '戦略', '未来', '号館',
  '行委', '者連', '執行', '株式', '合同', '工務', '専務', '総務', '省庁',
  '政策', '局長', '究部', '部門', '大学', '学研', '東京',
]);

// 人名として出現しにくい第2パートの語（組織・役職・概念語）
const NON_NAME_SECOND_WORDS = new Set([
  '部長', '課長', '係長', '室長', '主任', '工事', '事業', '代表', '関係',
  '支援', '一式', '以降', '以前', '以外', '以上', '以下',
  '申請', '通知', '開催', '開幕', '実行', '研報',
  '研究科', '学部', '事務局',
]);

// 法人格・組織形態語（第1パートとして人名ではない）
const LEGAL_ENTITY_WORDS = /^(?:株式会社|有限会社|合同会社|合資会社|一般社団|公益社団|特定非営利|独立行政|国立研究|都立|県立|市立|区立)/;

function validateJpName(matched) {
  if (/[\n\r]/.test(matched)) return null;
  const parts = matched.trim().split(/[ \t　]+/);
  if (parts.length !== 2) return null;
  const normalizedSurname = parts[0].normalize('NFKC');
  const surnameIsKnown = JP_SURNAME_RE.test(normalizedSurname);
  const surnameIsExact = JP_SURNAME_EXACT_RE.test(normalizedSurname);
  if (!surnameIsExact && GEO_SUFFIXES.test(parts[0]) && GEO_SUFFIXES.test(parts[1])) return null;
  if (COMMON_FIRST_WORDS.has(parts[0])) return null;
  if (COMMON_FIRST_WORDS.has(parts[1])) return null;
  if (NON_NAME_ENDINGS.test(parts[0])) return null;
  if (NON_NAME_ENDINGS.test(parts[1])) return null;
  if (NON_NAME_SECOND_WORDS.has(parts[1])) return null;
  if (!surnameIsExact && INSTITUTIONAL_FIRST.test(parts[0])) return null;
  if (!surnameIsKnown && /[部課室係局所省庁院]$/.test(parts[0])) return null;
  if (!surnameIsKnown && /[部課室係局所省庁院]$/.test(parts[1])) return null;
  if (LEGAL_ENTITY_WORDS.test(parts[0])) return null;
  if (!surnameIsExact && (/^[万億兆百千円]/.test(parts[0]) || /^[万億兆百千][万億兆百千円0-9０-９]/.test(parts[1]))) return null;
  if (/^(?:相当|以上|以下|未満|超過|程度|前後|水準|規模)/.test(parts[1])) return null;
  return 'PERSON';
}

const NOSPACE_CONTAINS = /(?:工業|電気|商店|物産|建設|製作|通信|銀行|保険|証券|不動産|新聞|食品|薬品|産業|商事|運送|倉庫|鉄道|放送|出版|印刷|医療|福祉|教育|病院|観光|酒造|水産|漁業|部長|課長|社長|会長|取締|締役|役副|副社|委員|教授|先生|議員|大臣|知事|市長|弁護|医師|博士|主任|係長|局長|室長)/;

function validateJpNameNospace(matched, ctx) {
  if (matched.length < 3 || matched.length > 6) return null;
  if (GEO_SUFFIXES.test(matched)) return null;
  if (NOSPACE_EXCLUDE.test(matched)) return null;
  const normalized = matched.normalize('NFKC');
  const afterSurname = normalized.replace(JP_SURNAME_RE, '');
  if (NOSPACE_CONTAINS.test(afterSurname)) return null;
  if (ctx) {
    const after = ctx.text.slice(ctx.end, ctx.end + 4);
    if (/^(?:は|が|を|に|で|の|へ|から|まで|として|という)/.test(after)) return 'PERSON';
  }
  const surname = normalized.match(JP_SURNAME_RE)?.[0];
  if (surname && surname.length === 1) return null;
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

function validateMyNumber(matched) {
  const digits = matched.replace(/\s/g, '');
  if (digits.length !== 12) return null;
  // マイナンバーチェックデジット: Q[n] * P[n] の合計 mod 11
  const q = digits.split('').map(Number);
  const p = [6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
  let sum = 0;
  for (let i = 0; i < 11; i++) sum += q[i] * p[i];
  const remainder = sum % 11;
  const checkDigit = remainder <= 1 ? 0 : 11 - remainder;
  if (q[11] !== checkDigit) return null;
  return 'MYNUM';
}

const NON_NAME_WORDS = new Set([
  '東京', '大阪', '名古屋', '福岡', '札幌', '横浜', '神戸', '京都', '広島', '仙台',
  '横浜市', '川崎市', '千葉市', '浜松市', '堺市', '新潟市', '静岡市', '岡山市',
  '営業', '技術', '管理', '総務', '経理', '人事', '企画', '開発', '設計', '製造',
  '生産', '物流', '販売', '購買', '調達', '検査', '保守', '運用', '広報', '法務',
  '会計', '財務', '監査', '品質', '安全', '環境', '情報', '研究', '教育', '福利',
  '氏名', '住所', '電話', '番号', '口座', '金額', '日付', '名前', '年齢', '性別',
  '売上高', '売上', '利益', '時価', '従業', '工業', '商業', '観光', '農業', '漁業',
  '鹿児島', '営業利益', '時価総額', '従業員数', '純利益', '経常利益',
  // 組織・機関（FP追加分）
  '吉田本町', '東京基礎', '処理学会', '情報学', '学会', '研究報告', '発表一覧',
  '業務一式', '保守業務', '会計課長', '室契約班', '参加申込',
]);

function validateJpNameList(matched) {
  const items = matched.split(/[、,]/);
  if (items.some(item => item.length < 2)) return null;
  const longItems = items.filter(item => item.length > 4);
  if (longItems.length > items.length / 2) return null;
  const nonNameCount = items.filter(item => NON_NAME_WORDS.has(item)).length;
  if (nonNameCount >= items.length / 2) return null;
  const instSuffix = /[藩城寺宮院塔閣橋川山湖池港駅線路号丁市区町村郡県府都道社軍職制令地]/;
  const instCount = items.filter(item => {
    const parts = item.split(/[\s　]/);
    if (parts.length >= 2 && JP_SURNAME_RE.test(parts[0])) return false;
    return instSuffix.test(item.slice(-1));
  }).length;
  if (instCount >= items.length / 2) return null;
  return 'PERSON';
}

// D2: 敬称トリガー validator
const GENERIC_HONORIFIC = /^(?:お客様|皆様|各位|関係者各位|担当者様|ご担当者様|受講者様|利用者様|保護者様)/;

function validateHonorific(matched) {
  if (GENERIC_HONORIFIC.test(matched)) return null;
  // 敬称部分を除去して漢字部分のみ取得
  const suffix = matched.match(JP_HONORIFIC_SUFFIX_RE)?.[0];
  const name = suffix ? matched.slice(0, -suffix.length) : matched;
  if (name.length < 2) return null;
  if (NOSPACE_CONTAINS.test(name)) return null;
  if (GEO_SUFFIXES.test(name)) return null;
  if (suffix === '様' && !JP_SURNAME_RE.test(name)) return null;
  return 'PERSON';
}

function validateSpacedHonorific(matched) {
  if (GENERIC_HONORIFIC.test(matched)) return null;
  const parts = matched.trim().split(/[ \t　]+/);
  if (parts.length !== 2) return null;
  const name = parts[0];
  const honorific = parts[1];
  if (name.length < 1) return null;
  if (name.length === 1 && !/^(?:氏|様|殿)$/.test(honorific)) return null;
  if (NOSPACE_CONTAINS.test(name)) return null;
  if (GEO_SUFFIXES.test(name)) return null;
  if (INSTITUTIONAL_FIRST.test(name)) return null;
  if (NON_NAME_ENDINGS.test(name)) return null;
  if (COMMON_FIRST_WORDS.has(name)) return null;
  if (LEGAL_ENTITY_WORDS.test(name)) return null;
  return 'PERSON';
}

// D8: contextContains ヘルパー
function contextContains(ctx, keywords) {
  if (!ctx) return false;
  const s = Math.max(0, ctx.start - 30);
  const e = Math.min(ctx.text.length, ctx.end + 30);
  const range = ctx.text.slice(s, e);
  return keywords.some(k => range.includes(k));
}

// D8: IBAN mod97 バリデーション
function validateIBAN(iban) {
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  const numeric = rearranged.replace(/[A-Z]/g, ch => (ch.charCodeAt(0) - 55).toString());
  let remainder = '';
  for (const ch of numeric) {
    remainder = String(Number(remainder + ch) % 97);
  }
  return Number(remainder) === 1;
}

function compileBasePattern(p) {
  return {
    id: p.id,
    category: p.category,
    regex: new RegExp(p.regex, 'g' + (p.flags || '')),
    maskPrefix: CATEGORY_TO_PREFIX[p.id] || p.maskPrefix || p.category.toUpperCase(),
    validator: p.id === 'ipv4' ? (m) => {
      const cls = classifyIPv4(m);
      if (cls === 'invalid') return null;
      return { label: cls === 'private' ? 'PRIV-IPv4' : 'IPv4', confidence: 1.0 };
    } : p.id === 'ipv6' ? (m) => looksLikeIPv6(m) ? { label: 'IPv6', confidence: 1.0 } : null : null,
  };
}

// 組織・役職語を含むマッチを除外する jp-company-name バリデーター
const COMPANY_EXCLUDE_PATTERNS = /(?:部長|課長|室長|係長|主任|担当|局長|事務|役員|委員|取締役|議員|教授|先生|弁護士|医師|博士|知事|市長|大臣)/;

function validateCompanyName(matched) {
  // 組織内役職語を含む場合は除外
  if (COMPANY_EXCLUDE_PATTERNS.test(matched)) return null;
  return 'COMPANY';
}

// jp-person-name の金額コンテキスト validator（FP-44対応）
function validateJpPersonNameWithCtx(matched, ctx) {
  const r = validateJpName(matched);
  if (!r) return null;
  // 直前に数字・金額単位がある場合は除外（「万円 相当」パターン）
  if (ctx) {
    const before = ctx.text.slice(Math.max(0, ctx.start - 10), ctx.start);
    if (/\d[,，]?\d*[万億兆百千円]\s*$/.test(before)) return null;
  }
  return { label: r, confidence: 0.9 };
}

const KATAKANA_COMMON = /^(?:アプリ|システム|サービス|ネットワーク|データ|プラン|コース|センター|タワー|ビル|ホール|スタジオ|チーム|グループ|ブランド|イベント|メッセ|プロジェクト|ロジェクト|エンジン|モデル|フレーム|ドライバ|ドライブ|テスト|サンプル|ダミー|クラウド|ポータル|フェーズ|フォーム|ツール|パート|マネージャー|リーダー|メンバー|エリア|フロア|スペース|コスト|リスク|タスク)$/;

function validateKatakanaName(matched) {
  const parts = matched.trim().split(/[ \t　]+/);
  if (parts.some(p => KATAKANA_COMMON.test(p))) return null;
  return 'PERSON';
}

// 中黒区切りで人名ではない語の末尾パターン
const NAKAGURO_NON_NAME_ENDS = /(?:事項|関係|情報|業務|管理|制度|処理|対応|設定|確認|報告|学会|研究|委員|工事|一式|担当|方針|規程|手順|基準|種別|番号|分類|内訳|附則|通達|連携|統合|システム|その他|等|他|費)$/;

function validateNakaguro(matched) {
  // 一般語や機関名の可能性があるパターンを除外
  const parts = matched.split('・');
  // 地名接尾辞を含む場合は除外
  if (parts.some(p => GEO_SUFFIXES.test(p))) return null;
  // NON_NAME_WORDS に含まれる場合は除外
  if (parts.some(p => NON_NAME_WORDS.has(p))) return null;
  // 業務・事項・関係等の概念語で終わる場合は除外
  if (parts.some(p => NAKAGURO_NON_NAME_ENDS.test(p))) return null;
  // 3文字以上の各パートが概念語的な場合は除外（人名は通常1-2文字の固有パート）
  const longConceptParts = parts.filter(p => p.length >= 3 && NON_NAME_ENDINGS.test(p));
  if (longConceptParts.length > 0) return null;
  return 'PERSON';
}

// jp-label-name: 部門名・役職名を除外
function validateLabelName(matched) {
  // 「広報部」「営業課」等の部門名は除外
  if (/[部課室係局庁院]$/.test(matched)) return null;
  // 「株式会社」等の法人格語は除外
  if (LEGAL_ENTITY_WORDS.test(matched)) return null;
  if (NON_NAME_WORDS.has(matched)) return null;
  if (matched.length < 2) return null;
  return 'PERSON';
}

const VALIDATORS = {
  'credit-card': (m) => luhnCheck(m) ? { label: 'CARD', confidence: 1.0 } : null,
  'my-number': (m) => { const r = validateMyNumber(m); return r ? { label: r, confidence: 1.0 } : null; },
  'jp-person-name': (m, ctx) => validateJpPersonNameWithCtx(m, ctx),
  'jp-person-name-hira': (m, ctx) => validateJpPersonNameWithCtx(m, ctx),
  'jp-person-name-nospace': (m, ctx) => { const r = validateJpNameNospace(m, ctx); return r ? { label: r, confidence: 0.7 } : null; },
  'jp-person-name-list': (m) => { const r = validateJpNameList(m); return r ? { label: r, confidence: 0.5 } : null; },
  'jp-person-name-honorific': (m) => { const r = validateHonorific(m); return r ? { label: r, confidence: 0.8 } : null; },
  'jp-person-name-spaced-honorific': (m) => { const r = validateSpacedHonorific(m); return r ? { label: r, confidence: 0.75 } : null; },
  'basic-pension': (m, ctx) => contextContains(ctx, ['年金', '基礎年金番号']) ? { label: 'PENSION', confidence: 0.7 } : null,
  'driver-license': (m, ctx) => contextContains(ctx, ['免許', '免許証番号', '運転免許']) ? { label: 'LICENSE', confidence: 0.5 } : null,
  'iban': (m) => validateIBAN(m) ? { label: 'IBAN', confidence: 1.0 } : null,
  'jumin-code': (m, ctx) => contextContains(ctx, ['住民票コード', '住民票']) ? { label: 'JUMINCODE', confidence: 0.5 } : null,
  'jp-company-name': (m) => { const r = validateCompanyName(m); return r ? { label: r, confidence: 0.8 } : null; },
  'jp-katakana-name': (m) => { const r = validateKatakanaName(m); return r ? { label: r, confidence: 0.7 } : null; },
  'jp-name-nakaguro': (m) => { const r = validateNakaguro(m); return r ? { label: r, confidence: 0.7 } : null; },
  'jp-label-name': (m) => { const r = validateLabelName(m); return r ? { label: r, confidence: 0.9 } : null; },
};

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

  const businessEnabled = process.env.PII_MASK_BUSINESS === '1';

  for (const p of EXTRA_PATTERNS) {
    if (p.category === 'business' && !businessEnabled) continue;
    try {
      compiled.push({
        id: p.id,
        category: p.category,
        regex: new RegExp(p.regex, 'g' + (p.flags || '')),
        maskPrefix: p.maskPrefix,
        validator: VALIDATORS[p.id] || null,
        ...(p.defaultConfidence != null && { defaultConfidence: p.defaultConfidence }),
      });
    } catch { /* skip */ }
  }

  return compiled;
}
