/**
 * Поиск ФИО без NLP-моделей: словарь имён/фамилий (pymorphy3) + правила по расположению слов.
 * Что ловится: «Иванов Иван», «Иванов Иван Иванович», «Иван Иванович», падежные формы
 * («Иванову Петру»), инициалы («И. И. Иванов», «Иванов И.И.»), ФИО заглавными и (строго)
 * строчными, латиница после метки контакта, одиночные имя/фамилия после слов-признаков
 * («менеджер Алексей», «позвони Петрову»).
 * Что не ловится (хуже Python/Natasha): одиночная фамилия без слова-признака, незнакомые
 * иностранные фамилии без инициалов, ФИО в именах файлов.
 */
import { foldWord, isAllowedWord } from './allowlist';
import { ci, ciAny } from './regex-utils';
import {
  STRENGTH_HEURISTIC,
  STRENGTH_STRONG,
  analyzeWord,
  isStopWord,
  type PersonToken,
} from './person-words';
import type { DetectedSpan } from './types';

const TOKEN_RE = /[А-ЯЁ]\.|[А-Яа-яЁё]+(?:-[А-Яа-яЁё]+)*/g;
const GAP_SPACES_RE = /^[ \t ]+$/;
const GAP_SPACES_OPT_RE = /^[ \t ]*$/;
const GLUE_BEFORE_RE = /[A-Za-z0-9_@]/;
const GLUE_AFTER_RE = /[A-Za-z0-9_@]/;
const MAX_INITIALS = 2;
const MIN_GENERIC_SURNAME_LEN = 3;
const CONTEXT_WINDOW = 48;
const EXCLUDE_WINDOW = 24;

/*
 * Слова-признаки перед одиночным именем/фамилией: должность, роль, подпись, обращение,
 * глагол связи. Без признака одиночное слово не маскируется: названия городов (Чехов,
 * Королёв), брендов и улиц совпадают с фамилиями.
 */
const ROLE_CUES =
  '(?:менеджер|директор|руководител|бухгалтер|специалист|ответственн|представител|консультант|' +
  'оператор|продавец|куратор|закупщик|снабженец|начальник|заведующ|логист|инженер|технолог|' +
  'секретар|администратор|владел|основател|учредител|собственник|заказчик|поставщик|' +
  'исполнител|подписант|подпис|контакт|фио|ф\\.и\\.о|фамили|имя|отчеств|гендиректор|эксперт|' +
  'заместител|помощник|мастер|прораб|водител|кладовщик|получател|отправител|плательщик|' +
  'покупател|клиент|ип|предприниматель|врач|юрист|бухгалтер)[а-яё]*';
const VERB_CUES =
  '(?:позвони|позвоните|звони|звоните|звонил|звонила|позвонил|позвонила|связаться с|свяжись с|' +
  'свяжитесь с|обращайтесь к|обратиться к|обращаться к|передай|передайте|передать|скажи|' +
  'скажите|спроси|спросите|спросить|согласуй|согласуйте|написал|написала|ответил|ответила|' +
  'сообщил|сообщила|просил|просила|прислал|прислала|отправил|отправила|подготовил|' +
  'подготовила|уточни|уточните|пишите|ждем|ждём|письмо от|звонок от|заявка от|' +
  'заказ от|ответ от|для|согласуй с|согласуйте с|спроси у|спросите у|договорись с|' +
  'договоритесь с|были|присутствовали|участвовали|подписал|подписала|подписали|' +
  '(?:сказал|сказала|сообщил|сообщила|ответил|ответила|написал|написала|говорил|говорила)' +
  '[,]?[ \\t]+что)';
const GREETING_CUES =
  '(?:здравствуйте|здравствуй|привет|добрый день|добрый вечер|доброе утро|уважаемый|' +
  'уважаемая|дорогой|дорогая|с уважением|искренне ваш|ваш)';
const CUE_RE = new RegExp(
  `(?:^|[^А-Яа-яЁёA-Za-z])(?:${ROLE_CUES}|${VERB_CUES}|${GREETING_CUES})` +
    '[ \\t\\u00A0]*[:,\\-—–«"(]?[ \\t\\u00A0]*$',
  'i',
);
/** Историческая личность в названии (школа имени Ивана Петрова) или улица — не ПДн. */
const EXCLUDE_BEFORE_RE = new RegExp(
  `(?:^|[^А-Яа-яЁёA-Za-z])(?:имени|им|памяти|в честь|${ciAny([
    'ул', 'улица', 'улице', 'улицу', 'пр-т', 'проспект', 'проспекте', 'пер', 'переулок',
    'площадь', 'площади', 'пл', 'наб', 'набережная', 'бульвар', 'б-р', 'шоссе', 'аллея',
    'проезд', 'тупик',
  ])})\\.?[ \\t\\u00A0]*$`,
  'i',
);
/** Продолжение списка: «, Козлов» или « и Козлов» сразу после найденного ФИО. */
const AFTER_INITIALS_GAP_RE = /^\.[ \t\u00A0]+$/;
const LIST_GAP_RE = /^[ \t ]*(?:,|и)[ \t ]+$/;

/** Лишнее для фамилии «общее» слово при двух инициалах. */
function isGenericSurname(token: PersonToken): boolean {
  return (
    (token.shape === 'cap' || token.shape === 'upper') &&
    token.name === 0 &&
    !token.patr &&
    token.text.length >= MIN_GENERIC_SURNAME_LEN &&
    !isStopWord(foldWord(token.text))
  );
}

/** Сочетание силы фамилии и имени, достаточное для ФИО из двух слов. */
function pairOk(surn: number, name: number): boolean {
  if (surn === 0 || name === 0) return false;
  if (surn === STRENGTH_STRONG) return true;
  return name === STRENGTH_STRONG;
}

interface Match {
  /** Сколько токенов занято. */
  count: number;
}

class PersonScanner {
  private readonly tokens: PersonToken[] = [];
  private readonly spans: DetectedSpan[] = [];
  private readonly isAllowed: (word: string) => boolean;

  constructor(
    private readonly text: string,
    stems: readonly string[],
  ) {
    this.isAllowed = (word: string): boolean => isAllowedWord(word, stems);
    const allowed = this.isAllowed;
    for (const m of text.matchAll(TOKEN_RE)) {
      const start = m.index ?? 0;
      const word = m[0];
      const before = start > 0 ? text.charAt(start - 1) : '';
      const after = text.charAt(start + word.length);
      const glued = GLUE_BEFORE_RE.test(before) || GLUE_AFTER_RE.test(after);
      const token = analyzeWord(word, start, allowed);
      this.tokens.push(glued ? { ...token, shape: 'mixed', surn: 0, name: 0, patr: false } : token);
    }
  }

  /** Все найденные ФИО. */
  scan(): DetectedSpan[] {
    this.scanUpperAndCap();
    this.scanStandalone();
    this.scanLower();
    this.scanLowerInitials();
    this.spans.sort((a, b) => a.start - b.start);
    return this.spans;
  }

  private tok(i: number): PersonToken | undefined {
    return this.tokens[i];
  }

  /** Токены `i` и `i+1` стоят рядом (разделены пробелами; инициалы допускают пустой зазор). */
  private adjacent(i: number): boolean {
    const a = this.tok(i);
    const b = this.tok(i + 1);
    if (a === undefined || b === undefined) return false;
    const gap = this.text.slice(a.end, b.start);
    if (a.shape === 'initial') {
      if (!GAP_SPACES_OPT_RE.test(gap)) return false;
    } else if (b.shape === 'initial') {
      if (!GAP_SPACES_OPT_RE.test(gap)) return false;
    } else {
      if (!GAP_SPACES_RE.test(gap)) return false;
      if (a.shape !== b.shape) return false;
    }
    return true;
  }

  private add(first: number, count: number, trimDot = false): void {
    const a = this.tok(first);
    const b = this.tok(first + count - 1);
    if (a === undefined || b === undefined) return;
    // Конечная точка инициала остаётся снаружи (она же бывает точкой предложения)
    const end = trimDot && b.shape === 'initial' ? b.end - 1 : b.end;
    if (EXCLUDE_BEFORE_RE.test(this.text.slice(Math.max(0, a.start - EXCLUDE_WINDOW), a.start))) {
      return;
    }
    this.spans.push({ start: a.start, end, kind: 'person', text: this.text.slice(a.start, end) });
  }

  /** Фамилия + инициалы, инициалы + фамилия, словарные сочетания слов. */
  private scanUpperAndCap(): void {
    let i = 0;
    while (i < this.tokens.length) {
      const m = this.matchAt(i);
      if (m === null) {
        i += 1;
        continue;
      }
      i += m.count;
    }
  }

  private isWord(t: PersonToken | undefined): t is PersonToken {
    return t !== undefined && (t.shape === 'cap' || t.shape === 'upper');
  }

  /** Число идущих подряд инициалов с позиции `i` (не больше двух). */
  private initialsRun(i: number): number {
    let n = 0;
    while (n < MAX_INITIALS && this.tok(i + n)?.shape === 'initial') {
      if (n > 0 && !this.adjacent(i + n - 1)) break;
      n += 1;
    }
    return n;
  }

  private matchAt(i: number): Match | null {
    const t0 = this.tok(i);
    if (t0 === undefined) return null;
    if (t0.shape === 'initial') return this.matchInitialsFirst(i);
    if (!this.isWord(t0)) return null;
    const t1 = this.adjacent(i) ? this.tok(i + 1) : undefined;
    const t2 = t1 !== undefined && this.adjacent(i + 1) ? this.tok(i + 2) : undefined;
    // Фамилия + инициалы
    if (t1?.shape === 'initial') {
      const n = this.initialsRun(i + 1);
      const ok = n >= MAX_INITIALS
        ? t0.surn > 0 || isGenericSurname(t0)
        : t0.surn >= STRENGTH_HEURISTIC;
      if (ok) {
        this.add(i, 1 + n, true);
        return { count: 1 + n };
      }
      return null;
    }
    if (!this.isWord(t1)) return null;
    // Фамилия Имя Отчество
    if (this.isWord(t2) && t2.patr && t0.surn > 0 && t1.name > 0) {
      this.add(i, 3);
      return { count: 3 };
    }
    // Имя Отчество Фамилия
    if (this.isWord(t2) && t1.patr && t0.name > 0 && t2.surn > 0) {
      this.add(i, 3);
      return { count: 3 };
    }
    // Имя Отчество
    if (t1.patr && t0.name > 0) {
      this.add(i, 2);
      return { count: 2 };
    }
    // Фамилия Имя / Имя Фамилия
    const surnName = pairOk(t0.surn, t1.name) &&
      !(t0.surn === STRENGTH_HEURISTIC && t1.name < STRENGTH_STRONG);
    const nameSurn = pairOk(t1.surn, t0.name) &&
      !(t1.surn === STRENGTH_HEURISTIC && t0.name < STRENGTH_STRONG);
    if (surnName || nameSurn) {
      this.add(i, 2);
      return { count: 2 };
    }
    return null;
  }

  private matchInitialsFirst(i: number): Match | null {
    const n = this.initialsRun(i);
    const word = this.tok(i + n);
    if (n === 0 || !this.isWord(word) || !this.adjacent(i + n - 1)) return null;
    const ok = n >= MAX_INITIALS
      ? word.surn > 0 || isGenericSurname(word)
      : word.surn >= STRENGTH_HEURISTIC;
    if (!ok) return null;
    this.add(i, n + 1);
    return { count: n + 1 };
  }

  /** Одиночное сильное имя/фамилия после слова-признака или рядом с найденным ФИО. */
  private scanStandalone(): void {
    const covered = (t: PersonToken): boolean =>
      this.spans.some((s) => t.start < s.end && t.end > s.start);
    this.tokens.forEach((t, i) => {
      if (!this.isWord(t) || covered(t)) return;
      const strong = t.surn === STRENGTH_STRONG || t.name === STRENGTH_STRONG;
      if (!strong) return;
      const before = this.text.slice(Math.max(0, t.start - CONTEXT_WINDOW), t.start);
      let cued = CUE_RE.test(before);
      if (!cued) cued = this.followsPerson(t);
      if (!cued) return;
      this.add(i, 1);
    });
  }

  /** Токен идёт сразу за найденным ФИО или через «,»/«и» (список людей). */
  private followsPerson(t: PersonToken): boolean {
    if (t.surn !== STRENGTH_STRONG) return false;
    const prev = this.spans.find((s) => s.end <= t.start && t.start - s.end <= 4);
    if (prev === undefined) return false;
    const gap = this.text.slice(prev.end, t.start);
    // После инициалов точка осталась снаружи находки
    return GAP_SPACES_RE.test(gap) || LIST_GAP_RE.test(gap) || AFTER_INITIALS_GAP_RE.test(gap);
  }

  /** «иванов и.и.»: строчная сильная фамилия и два строчных инициала. */
  private scanLowerInitials(): void {
    const re = /(?<![А-Яа-яЁё])([а-яё]{3,})[ \t\u00A0]+([а-яё]\.[ \t]?[а-яё])\./g;
    for (const m of this.text.matchAll(re)) {
      const word = m[1] ?? '';
      const start = m.index ?? 0;
      const token = analyzeWord(word, start, (w) => this.isAllowed(w));
      if (token.surn !== STRENGTH_STRONG || token.name !== 0) continue;
      const end = start + m[0].length - 1;
      this.spans.push({ start, end, kind: 'person', text: this.text.slice(start, end) });
    }
  }

  /** Строчные ФИО: только строгие сочетания из сильных словарных слов. */
  private scanLower(): void {
    for (let i = 0; i + 1 < this.tokens.length; i += 1) {
      const a = this.tok(i);
      const b = this.tok(i + 1);
      if (a?.shape !== 'lower' || b?.shape !== 'lower' || !this.adjacent(i)) continue;
      const c = this.adjacent(i + 1) ? this.tok(i + 2) : undefined;
      const abs = (t: PersonToken): boolean =>
        t.surn === STRENGTH_STRONG && t.name === 0;
      const nbs = (t: PersonToken): boolean =>
        t.name === STRENGTH_STRONG && t.surn === 0;
      let count = 0;
      if (b.patr && a.name === STRENGTH_STRONG) count = c?.shape === 'lower' && abs(c) ? 3 : 2;
      else if (c?.shape === 'lower' && c.patr && abs(a) && nbs(b)) count = 3;
      else if ((abs(a) && nbs(b)) || (nbs(a) && abs(b))) count = 2;
      if (count > 0) {
        this.add(i, count);
        i += count - 1;
      }
    }
  }
}

/*
 * Латинское ФИО («Li Wei», «John Smith») — только сразу после метки контакта: без метки
 * имя не отличить от названия товара или компании (как в Python).
 */
const LATIN_LABEL = `(?<![A-Za-z])(?:${ciAny(['contact', 'attn', 'attention', 'manager',
  'representative', 'regards', 'sincerely', 'signed'])}|${ci('contact')}[ \\t]+${ci('person')}|` +
  `${ci('sales')}[ \\t]+${ci('manager')}|${ci('best')}[ \\t]+${ci('regards')}|` +
  `${ci('kind')}[ \\t]+${ci('regards')})`;
const LATIN_NAME_RE = new RegExp(
  `${LATIN_LABEL}[ \\t]*[:,\\-]?[ \\t\\r\\n]{0,3}` +
    '(?<name>[A-Z][a-z]{1,19}(?:[ \\t]+[A-Z][a-z]{1,19}){1,2})(?![A-Za-z])',
  'gd',
);
const LATIN_WORD_RE = /[A-Z][a-z]+/g;
const LATIN_MIN_WORDS = 2;
const LATIN_MIN_REPEAT_LEN = 3;
const LATIN_NOT_NAME = new Set(
  ('accounts accounting payable receivable department dept office team support sales service ' +
    'services customer customers head general company co ltd llc inc limited group trading ' +
    'logistics procurement purchasing purchase export import management finance legal hr ' +
    'technical engineering production quality warehouse shipping supply regards thanks thank ' +
    'dear hello hi best kind please us today information details sheet').split(' '),
);

/** Латинские ФИО после метки контакта и их повторы в тексте. */
function findLatinNames(text: string): DetectedSpan[] {
  const found: DetectedSpan[] = [];
  const names: string[][] = [];
  for (const m of text.matchAll(LATIN_NAME_RE)) {
    const range = m.indices?.groups?.['name'];
    if (range === undefined) continue;
    const words: string[] = [];
    let end = range[0];
    for (const w of text.slice(range[0], range[1]).matchAll(LATIN_WORD_RE)) {
      if (LATIN_NOT_NAME.has(w[0].toLowerCase())) break;
      end = range[0] + (w.index ?? 0) + w[0].length;
      words.push(w[0]);
    }
    if (words.length < LATIN_MIN_WORDS) continue;
    found.push({ start: range[0], end, kind: 'person', text: text.slice(range[0], end) });
    names.push(words);
  }
  if (names.length === 0) return found;
  const forms = new Set<string>();
  for (const words of names) {
    forms.add(words.map(escapeRe).join('[ \\t]+'));
    for (const w of words) if (w.length >= LATIN_MIN_REPEAT_LEN) forms.add(escapeRe(w));
  }
  const alt = [...forms].sort((a, b) => b.length - a.length).join('|');
  const repeat = new RegExp(`(?<![A-Za-z0-9_])(?:${alt})(?![A-Za-z0-9_])`, 'g');
  for (const m of text.matchAll(repeat)) {
    const start = m.index ?? 0;
    found.push({ start, end: start + m[0].length, kind: 'person', text: m[0] });
  }
  return found;
}

function escapeRe(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Убирает пересечения: при совпадении начала остаётся более длинная находка. */
export function dropOverlaps(spans: DetectedSpan[]): DetectedSpan[] {
  const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
  const result: DetectedSpan[] = [];
  for (const span of sorted) {
    const last = result[result.length - 1];
    if (last !== undefined && span.start < last.end) {
      if (span.end > last.end && span.start === last.start) result[result.length - 1] = span;
      continue;
    }
    result.push(span);
  }
  return result;
}

/**
 * Ищет ФИО в тексте.
 *
 * @param text Исходный текст.
 * @param allowedStems Основы белого списка (нормализованные).
 * @param latinNames Искать ли латинские ФИО после метки контакта.
 */
export function findPersons(
  text: string,
  allowedStems: readonly string[],
  latinNames: boolean,
): DetectedSpan[] {
  const found = new PersonScanner(text, allowedStems).scan();
  if (latinNames) found.push(...findLatinNames(text));
  return dropOverlaps(found);
}
