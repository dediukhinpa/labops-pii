/**
 * Поиск слова в словаре имён и фамилий (данные сгенерированы из pymorphy3, см.
 * `tools/gen_ts_name_dictionary.py`). Слово разбирается как «основа + окончание» и
 * сверяется с парадигмой; так воспроизводятся словарные формы pymorphy без NLP-зависимостей.
 */
import {
  NAME_PARADIGMS,
  NAME_STEMS_STRONG,
  NAME_STEMS_WEAK,
  NAME_WEAK_FORMS,
} from './dictionary/name-dictionary-data';

/** Битовые роли формы (те же значения, что в генераторе). */
export const ROLE_SURNAME = 1;
export const ROLE_NAME = 2;

/** Результат поиска слова в словаре. */
export interface WordLookup {
  /** Слово может быть фамилией. */
  surname: boolean;
  /** Слово может быть именем. */
  name: boolean;
  /** «Слабое» слово: чаще обычное слово (Вера, Роман, Машина). Одно ФИО не доказывает. */
  weak: boolean;
}

interface StemEntry {
  paradigm: number;
  weak: boolean;
}

interface DictionaryIndex {
  /** Окончание -> роли, по номеру парадигмы. */
  paradigms: Array<Map<string, number>>;
  /** Основа -> парадигмы, в которых она встречается. */
  stems: Map<string, StemEntry[]>;
  weakForms: Set<string>;
  maxEndingLength: number;
}

const ENTRY_SEPARATOR = ',';
const ROLE_SEPARATOR = ':';
const STEM_SEPARATOR = ' ';
/** Знак пустой основы в данных (парадигмы на одно слово). */
const EMPTY_STEM = '∅';
/** Размер кэша результатов; при переполнении очищается целиком (дёшево и без утечек). */
const LOOKUP_CACHE_MAX = 20000;

let cachedIndex: DictionaryIndex | undefined;
const lookupCache = new Map<string, WordLookup | null>();

/** Разбор строки парадигмы «окончание:роль,окончание:роль». */
function parseParadigm(line: string): Map<string, number> {
  const forms = new Map<string, number>();
  for (const item of line.split(ENTRY_SEPARATOR)) {
    const cut = item.lastIndexOf(ROLE_SEPARATOR);
    if (cut < 0) continue;
    forms.set(item.slice(0, cut), Number(item.slice(cut + 1)));
  }
  return forms;
}

/** Строит индекс при первом обращении (около 22 тыс. основ, десятки миллисекунд). */
function buildIndex(): DictionaryIndex {
  const paradigms = NAME_PARADIGMS.map(parseParadigm);
  const stems = new Map<string, StemEntry[]>();
  const add = (lines: readonly string[], weak: boolean): void => {
    lines.forEach((line, paradigm) => {
      for (const stem of line.split(STEM_SEPARATOR)) {
        const key = stem === EMPTY_STEM ? '' : stem;
        if (stem === '') continue;
        const list = stems.get(key);
        if (list === undefined) stems.set(key, [{ paradigm, weak }]);
        else list.push({ paradigm, weak });
      }
    });
  };
  add(NAME_STEMS_STRONG, false);
  add(NAME_STEMS_WEAK, true);
  let maxEndingLength = 0;
  for (const forms of paradigms) {
    for (const ending of forms.keys()) maxEndingLength = Math.max(maxEndingLength, ending.length);
  }
  return { paradigms, stems, weakForms: new Set(NAME_WEAK_FORMS), maxEndingLength };
}

/** Словарь без кэша результатов. */
function lookupUncached(low: string): WordLookup | null {
  cachedIndex ??= buildIndex();
  const index = cachedIndex;
  let roles = 0;
  let strong = false;
  const firstSplit = Math.max(0, low.length - index.maxEndingLength);
  for (let cut = firstSplit; cut <= low.length; cut += 1) {
    const entries = index.stems.get(low.slice(0, cut));
    if (entries === undefined) continue;
    const ending = low.slice(cut);
    for (const entry of entries) {
      const role = index.paradigms[entry.paradigm]?.get(ending);
      if (role === undefined) continue;
      roles |= role;
      if (!entry.weak) strong = true;
    }
  }
  if (roles === 0) return null;
  const weak = !strong || index.weakForms.has(low);
  return { surname: (roles & ROLE_SURNAME) !== 0, name: (roles & ROLE_NAME) !== 0, weak };
}

/**
 * Ищет слово в словаре имён и фамилий.
 *
 * @param low Слово в нижнем регистре, «ё» заменена на «е».
 * @returns Роли слова или `null`, если слова нет в словаре (единственное число).
 */
export function lookupName(low: string): WordLookup | null {
  const cached = lookupCache.get(low);
  if (cached !== undefined) return cached;
  const result = lookupUncached(low);
  if (lookupCache.size >= LOOKUP_CACHE_MAX) lookupCache.clear();
  lookupCache.set(low, result);
  return result;
}
