/**
 * Латинские ФИО без метки контакта: «Ivan Petrov», «Sidorova Elena», «Ivan Petrovich Sidorov»
 * (перенос `find_latin_name_spans` из `python/labops_pii/latin_names.py`; данные — из Python,
 * см. tools/gen_ts_latin_names.py).
 *
 * Нужно имя из словаря рядом со словом, похожим на фамилию, отчество или имя. Слова-стопы
 * (должности, технологии, приветствия) имя не продолжают: «Product Manager Anna» даёт только
 * «Anna» без пары, а «Visual Studio» не ловится вовсе.
 */
import {
  LATIN_FIRST_NAMES,
  LATIN_LOWER,
  LATIN_MAX_WORDS,
  LATIN_MIN_PATRONYMIC_LEN,
  LATIN_MIN_SURNAME_LEN,
  LATIN_MIN_UNKNOWN_SURNAME_LEN,
  LATIN_NOT_NAME_WORDS,
  LATIN_PATRONYMIC_SUFFIXES,
  LATIN_SURNAME_SUFFIXES,
  LATIN_UPPER,
} from './dictionary/latin-names-data';
import type { DetectedSpan } from './types';

/** Вид слова в латинском ФИО. */
type LatinKind = 'first' | 'patr' | 'surn' | 'other' | 'stop';

const FIRST_NAMES: ReadonlySet<string> = new Set(LATIN_FIRST_NAMES);
const NOT_NAME_WORDS: ReadonlySet<string> = new Set(LATIN_NOT_NAME_WORDS);
const LETTERS = LATIN_UPPER + LATIN_LOWER;
const TITLE_WORD = `[${LATIN_UPPER}][${LATIN_LOWER}]{2,19}`;
/** Слово: «Ivan», «IVAN», «Jean-Pierre»; слева и справа не буква/цифра/знак пути или адреса. */
const WORD =
  `(?<![${LETTERS}0-9_@./\\\\:+-])` +
  `(?:${TITLE_WORD}(?:-${TITLE_WORD})?|[${LATIN_UPPER}]{3,20})` +
  `(?![${LETTERS}0-9_@/\\\\-])`;
/** Цепочка слов через пробелы: окна по 2-3 слова перебираются внутри неё. */
const RUN_RE = new RegExp(`${WORD}(?:[ \\t]{1,3}${WORD})+`, 'g');
const WORD_RE = new RegExp(WORD, 'g');
/** После пары «Слово Имя» строчное слово: английская фраза («Yesterday Anna went»). */
const LOWER_WORD_AHEAD_RE = /^[ \t]+[a-z]{2,}/;

const VALID_PAIRS: ReadonlySet<string> = new Set([
  'first first', 'first patr', 'first surn', 'first other', 'surn first', 'patr surn',
  'surn patr', 'other first',
]);
const VALID_TRIPLES: ReadonlySet<string> = new Set([
  'surn first patr', 'first patr surn', 'first patr other', 'first first surn',
  'surn first first',
]);

/** Слово цепочки с позицией. */
interface LatinWord {
  start: number;
  end: number;
  text: string;
}

/** Вид латинского слова: имя, отчество, фамилия по суффиксу, «чужое» слово или стоп. */
function latinWordKind(word: string): LatinKind {
  const low = word.toLowerCase();
  if (NOT_NAME_WORDS.has(low)) return 'stop';
  if (low.split('-').some((part) => FIRST_NAMES.has(part))) return 'first';
  const endsWithAny = (suffixes: readonly string[]): boolean =>
    suffixes.some((suffix) => low.endsWith(suffix));
  if (low.length >= LATIN_MIN_PATRONYMIC_LEN && endsWithAny(LATIN_PATRONYMIC_SUFFIXES)) {
    return 'patr';
  }
  if (low.length >= LATIN_MIN_SURNAME_LEN && endsWithAny(LATIN_SURNAME_SUFFIXES)) return 'surn';
  return 'other';
}

/**
 * Подходит ли набор видов подряд идущих слов под латинское ФИО. Пара «неизвестное слово + имя»
 * строже: слово не короче LATIN_MIN_UNKNOWN_SURNAME_LEN и дальше не идёт строчное слово.
 */
function validWindow(
  kinds: readonly LatinKind[],
  text: string,
  words: readonly LatinWord[],
): boolean {
  const key = kinds.join(' ');
  if (kinds.length === 3) return VALID_TRIPLES.has(key);
  if (!VALID_PAIRS.has(key)) return false;
  if (key === 'other first') {
    const first = words[0];
    const last = words[words.length - 1];
    if (first === undefined || last === undefined) return false;
    return (
      first.text.length >= LATIN_MIN_UNKNOWN_SURNAME_LEN &&
      !LOWER_WORD_AHEAD_RE.test(text.slice(last.end))
    );
  }
  return true;
}

/** Размер окна, которое начинается со слова `index`, или 0. */
function matchedSize(
  text: string,
  words: readonly LatinWord[],
  kinds: readonly LatinKind[],
  index: number,
): number {
  for (let size = Math.min(LATIN_MAX_WORDS, words.length - index); size > 1; size -= 1) {
    const windowKinds = kinds.slice(index, index + size);
    // «Слово Имя Фамилия»: пара «Слово Имя» уступает «Имя Фамилия» со следующего слова
    const next = kinds[index + size];
    if (windowKinds.join(' ') === 'other first' && next !== undefined && next !== 'stop') continue;
    if (validWindow(windowKinds, text, words.slice(index, index + size))) return size;
  }
  return 0;
}

/**
 * Латинские ФИО по словарю имён.
 *
 * @param text Исходный текст.
 * @returns Непересекающиеся находки по порядку.
 */
export function findLatinDictionaryNames(text: string): DetectedSpan[] {
  const spans: DetectedSpan[] = [];
  for (const run of text.matchAll(RUN_RE)) {
    const base = run.index ?? 0;
    const words: LatinWord[] = [...run[0].matchAll(WORD_RE)].map((m) => ({
      start: base + (m.index ?? 0),
      end: base + (m.index ?? 0) + m[0].length,
      text: m[0],
    }));
    // Регистр одной записи един: «IVAN PETROV» или «Ivan Petrov», но не смесь
    if (new Set(words.map((w) => w.text === w.text.toUpperCase())).size > 1) continue;
    const kinds = words.map((w) => latinWordKind(w.text));
    let index = 0;
    while (index < words.length) {
      const size = matchedSize(text, words, kinds, index);
      const first = words[index];
      const last = words[index + size - 1];
      if (size > 0 && first !== undefined && last !== undefined) {
        spans.push({
          start: first.start,
          end: last.end,
          kind: 'person',
          text: text.slice(first.start, last.end),
        });
        index += size;
      } else {
        index += 1;
      }
    }
  }
  return spans;
}
