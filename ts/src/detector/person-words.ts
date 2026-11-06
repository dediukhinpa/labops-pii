/**
 * Разбор отдельного слова как части ФИО: фамилия, имя, отчество, инициал.
 * Сила признака: 3 — слово из словаря и обычно именно имя/фамилия; 2 — эвристика по суффиксу
 * (слова нет в словаре); 1 — слабое слово (чаще обычное: Вера, Роман, Мельник); 0 — нет.
 */
import { foldWord } from './allowlist';
import { lookupName } from './name-dictionary';

export const STRENGTH_NONE = 0;
export const STRENGTH_WEAK = 1;
export const STRENGTH_HEURISTIC = 2;
export const STRENGTH_STRONG = 3;

/** Регистровая форма слова. */
export type WordShape = 'cap' | 'upper' | 'lower' | 'initial' | 'mixed';

/** Слово текста с разбором ролей. */
export interface PersonToken {
  start: number;
  end: number;
  text: string;
  shape: WordShape;
  /** Сила признака «фамилия». */
  surn: number;
  /** Сила признака «имя». */
  name: number;
  /** Отчество (по суффиксу). */
  patr: boolean;
}

/** Слова, которые не бывают частью ФИО: роли, подписи полей, реквизиты. */
const STOP_WORDS: ReadonlySet<string> = new Set(
  (
    'инн огрнип огрн кпп окпо бик тел ооо ао пао зао оао нао ип гост ту адрес почта телефон ' +
    'счет заказчик поставщик покупатель продавец исполнитель подрядчик клиент контрагент ' +
    'плательщик получатель отправитель директор руководитель бухгалтер менеджер ' +
    'предприниматель представитель подписант ответственный согласовано утверждаю ' +
    'главный генеральный исполнительный заместитель начальник специалист сайт цена ' +
    'каталог контакты главная корзина доставка оплата'
  ).split(' '),
);

/** Обычные слова, похожие на фамилию по суффиксу (-ина, -ова): эвристика их пропускает. */
const COMMON_LOOKALIKES: ReadonlySet<string> = new Set(
  (
    'картина машина корзина резина витрина кабина лавина пластина дрова слова острова ' +
    'сорта бревна полотна ' +
    'гардина медина нова перина лучина осина ' +
    'мужской женской'
  ).split(' '),
);

/** Основы, от которых «-евич/-евна» — не отчество (царевич, королевна). */
const NOT_PATRONYMIC_STEMS: ReadonlySet<string> = new Set(['цар', 'корол', 'княж', 'коро']);

const PATRONYMIC_MALE_RE = /^([а-я]+?)(?:ович|евич|ьич)(?:а|у|ем|е)?$/;
const PATRONYMIC_FEMALE_RE = /^([а-я]+?)(?:овн|евн|ьичн|иничн)(?:а|ы|е|у|ой|ою)$/;
/** «Никитична», «Лукична»: без «ин»/«ь» перед суффиксом только для этих основ. */
const PATRONYMIC_PLAIN_RE = /^(?:никит|лук|фом|савв)(?:ич(?:а|у|ем|е)?|ичн(?:а|ы|е|у|ой|ою))$/;
const MIN_SURNAME_STEM = 3;
const SURNAME_SUFFIX_RE =
  /^[а-я]{3,}(?:ов|ев|ин|ын)(?:а|у|ым|ом|ем|е|ой|ою|ы|ых|ыми)?$/;
const SURNAME_ADJ_RE = /^[а-я]{2,}(?:ск|цк)(?:ий|ого|ому|им|ом|ая|ой|ую|ое|ие|их)$/;

/** Форма слова по регистру (дефисные слова — по всем частям). */
export function shapeOf(word: string): WordShape {
  const parts = word.split('-');
  if (parts.every((p) => /^[А-ЯЁ][а-яё]+$/.test(p))) return 'cap';
  if (parts.every((p) => /^[А-ЯЁ]{2,}$/.test(p))) return 'upper';
  if (parts.every((p) => /^[а-яё]+$/.test(p))) return 'lower';
  return 'mixed';
}

/** Слово — отчество по суффиксу (нижний регистр, «ё» как «е»). */
export function isPatronymic(low: string): boolean {
  if (PATRONYMIC_PLAIN_RE.test(low)) return true;
  const male = PATRONYMIC_MALE_RE.exec(low);
  if (male !== null) return !NOT_PATRONYMIC_STEMS.has(male[1] ?? '');
  const female = PATRONYMIC_FEMALE_RE.exec(low);
  return female !== null && !NOT_PATRONYMIC_STEMS.has(female[1] ?? '');
}

/** Слово из списка стоп-слов (роли и подписи полей). */
export function isStopWord(low: string): boolean {
  return STOP_WORDS.has(low);
}

interface PartRoles {
  surn: number;
  name: number;
  patr: boolean;
}

/** Роли одной части слова (без дефиса). */
function partRoles(low: string): PartRoles {
  if (STOP_WORDS.has(low)) return { surn: STRENGTH_NONE, name: STRENGTH_NONE, patr: false };
  if (isPatronymic(low)) return { surn: STRENGTH_NONE, name: STRENGTH_NONE, patr: true };
  const hit = lookupName(low);
  let surn = STRENGTH_NONE;
  if (hit?.surname === true) surn = hit.weak ? STRENGTH_WEAK : STRENGTH_STRONG;
  else if (hit === null && !COMMON_LOOKALIKES.has(low)) {
    const looksLikeSurname =
      low.length >= MIN_SURNAME_STEM + 2 &&
      (SURNAME_SUFFIX_RE.test(low) || SURNAME_ADJ_RE.test(low));
    if (looksLikeSurname) surn = STRENGTH_HEURISTIC;
  }
  let name = STRENGTH_NONE;
  if (hit?.name === true) name = hit.weak ? STRENGTH_WEAK : STRENGTH_STRONG;
  return { surn, name, patr: false };
}

/**
 * Разбирает слово текста.
 *
 * @param text Слово как в тексте (кириллица, возможно с дефисом) или инициал «И.».
 * @param start Начало слова в тексте.
 * @param isAllowed Проверка слова по белому списку.
 */
export function analyzeWord(
  text: string,
  start: number,
  isAllowed: (word: string) => boolean,
): PersonToken {
  const end = start + text.length;
  if (/^[А-ЯЁ]\.$/.test(text)) {
    return { start, end, text, shape: 'initial', surn: 0, name: 0, patr: false };
  }
  const shape = shapeOf(text);
  const none: PersonToken = { start, end, text, shape, surn: 0, name: 0, patr: false };
  if (shape === 'mixed' || isAllowed(text)) return none;
  const parts = foldWord(text).split('-');
  const roles = parts.map(partRoles);
  const first = roles[0];
  if (first === undefined) return none;
  if (parts.length === 1) return { ...none, ...first };
  return {
    ...none,
    surn: Math.min(...roles.map((r) => r.surn)),
    name: Math.min(...roles.map((r) => r.name)),
  };
}
