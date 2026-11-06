/**
 * Шаблоны адреса уровня дома: улица + номер дома (+ корпус, квартира, индекс). Порт
 * `ADDRESS_STREET_HOUSE_RE` из `python/labops_pii/pii_patterns.py`; поведение то же.
 * Город без улицы адресом не считается и остаётся открытым (нужен шорт-листу поставщиков).
 *
 * Регулярные выражения собираются из тех же частей, что и в Python. Встроенные флаги `(?i:)`
 * в JS-движках поддерживаются не везде, поэтому регистр раскрывается явно (`ci`).
 */
import { ci, ciAny, ciOpt } from './regex-utils';

/** Ограничения на число повторов (как в Python-шаблонах: время поиска линейно). */
const INDEX_DIGITS = 6;
const INDEX_WINDOW_BEFORE = 160;
const MAX_NAME_EXTRA_WORDS = 2;

const LETTER_RU = 'А-Яа-яЁё';
// Слово названия улицы: «Ленина», «Красной», «Санкт-Петербургская», «ЛЕНИНА»
const ADDR_WORD = '[А-ЯЁ][А-ЯЁа-яё]+(?:-[А-ЯЁа-яё]+)*';
// Слова, с которых название улицы не начинается: «Серия 5», «Заказ 12», «Партия 7» — не адрес
const NAME_STOP_WORDS: readonly string[] = [
  'заказ', 'заказа', 'серия', 'серии', 'партия', 'партии', 'позиция', 'позиции', 'артикул',
  'номер', 'код', 'тип', 'модель', 'размер', 'лот', 'этап', 'пункт', 'раздел', 'статья',
  'приложение', 'договор', 'счет', 'счёт', 'накладная', 'спецификация', 'заявка', 'тираж',
  'цех', 'склад', 'офис', 'корпус', 'строение', 'литера', 'квартира', 'этаж', 'комната',
  'помещение', 'версия', 'вариант', 'группа', 'класс', 'уровень', 'сорт', 'марка', 'формат',
  'цена', 'итого', 'всего', 'страница', 'лист',
];
const NAME_GUARD = `(?!${ciAny(NAME_STOP_WORDS)}(?![${LETTER_RU}]))`;
const ORDINAL_PREFIX = '\\d{1,3}-(?:я|й|е|го|ая|ой|ья|ий)[ \\t]+';
// Название: «Ленина», «Красной Армии», «1-я Тверская», «8 Марта», «50 лет Октября»
const ADDR_NAME =
  `(?:${ORDINAL_PREFIX}|\\d{1,3}[ \\t]+(?:${ci('лет')}[ \\t]+)?)?` +
  `${NAME_GUARD}${ADDR_WORD}(?:[ \\t]+${ADDR_WORD}){0,${MAX_NAME_EXTRA_WORDS}}`;
// Название перед ключевым словом («Ленина ул., д. 5», «1-я Тверская ул., 5»)
const ADDR_NAME_POSTFIX =
  `(?:${ORDINAL_PREFIX})?${NAME_GUARD}${ADDR_WORD}(?:[ \\t]+${ADDR_WORD})?`;

// Ключевое слово улицы: полные формы в падежах и сокращения. Короткие сокращения, которые
// бывают и другими словами («пр.» — примечание), требуют точку.
const DESIG_FULL: readonly string[] = [
  'улица', 'улице', 'улицу', 'улицы', 'проспект', 'проспекта', 'проспекте', 'проспекту',
  'переулок', 'переулка', 'переулке', 'переулку', 'бульвар', 'бульвара', 'бульваре', 'бульвару',
  'набережная', 'набережной', 'набережную', 'шоссе', 'площадь', 'площади', 'проезд', 'проезда',
  'проезде', 'проезду', 'тупик', 'тупика', 'тупике', 'тупику', 'аллея', 'аллеи', 'аллее',
  'аллею',
];
const DESIG_ABBR_OPTIONAL_DOT: readonly string[] = [
  'ул', 'пр-кт', 'пр-т', 'пер', 'б-р', 'бул', 'пр-д',
];
const DESIG_ABBR_REQUIRED_DOT: readonly string[] = ['наб', 'пл', 'ш', 'пр', 'просп'];
const ADDR_DESIG =
  `(?:${ciAny(DESIG_FULL)}|${ciAny(DESIG_ABBR_OPTIONAL_DOT)}\\.?|` +
  `${ciAny(DESIG_ABBR_REQUIRED_DOT)}\\.)(?![а-яё])`;

const ADDR_LEFT = `(?<![${LETTER_RU}A-Za-z0-9-])`;
// Номер дома: «5», «5а», «12-14» (после нормализации «12/14» тоже с дефисом)
const ADDR_HOUSE = `\\d{1,4}(?:-\\d{1,4})?[А-Яа-я]?(?![${LETTER_RU}A-Za-z0-9])`;
// Пометка дома: «д.», «дом», «влд.», «№»
const ADDR_MARK =
  `(?:${ciAny(['дом', 'д', 'владение', 'влд', 'вл'])}\\.?[ \\t]*(?:№[ \\t]*)?|№[ \\t]*)`;
// Корпус, строение, литера, квартира, офис, этаж: «, кв. 12», «корп. 2», «стр. 1», «лит. А»
const SUFFIX_WORDS = [
  ciOpt('корп', 'ус'), ciOpt('стр', 'оение'), ciOpt('лит', 'ера'), ciOpt('кв', 'артира'),
  ciOpt('оф', 'ис'), ciOpt('пом', 'ещение'), ciOpt('комн', 'ата'), ciOpt('эт', 'аж'),
].join('|');
const ADDR_SUFFIX =
  `(?:[ \\t]*(?:,[ \\t]*)?(?:(?:${SUFFIX_WORDS})\\.?|${ciAny(['к', 'с'])}(?:\\.|(?=\\d)))` +
  `[ \\t]*(?:№[ \\t]*)?(?:\\d{1,4}[А-Яа-я]?|[А-Я])(?![${LETTER_RU}A-Za-z0-9]))`;
const MAX_SUFFIXES = 4;
const ADDR_SUFFIXES = `${ADDR_SUFFIX}{0,${MAX_SUFFIXES}}`;
const ADDR_SEP = '[ \\t]*(?:,[ \\t]*)?';
// Дом с пометкой не должен быть количеством: «д. 5 мм», «д. 5 шт»
const UNIT_WORDS: readonly string[] = [
  'шт', 'штук', 'мм', 'см', 'кг', 'мкм', 'вт', 'квт', 'руб', 'рублей', 'коробок', 'упаковок',
];
const ADDR_UNIT_AFTER = `(?![ \\t]*(?:${ciAny(UNIT_WORDS)}|%)(?![а-яё]))`;
// Дом без пометки («Ленина 5») обязан закончиться знаком, концом строки или квартирой
const ADDR_END = '(?=[ \\t]*(?:$|[\\n\\r]|\\.(?!\\d)|[,;:)!?»"\'\\-](?!\\d)))';
const ADDR_TAIL_INDEX = `(?:[ \\t]*,[ \\t]*\\d{${INDEX_DIGITS}}(?!\\d))?`;
const ADDR_HOUSE_PART =
  `(?:${ADDR_MARK}${ADDR_HOUSE}${ADDR_SUFFIXES}${ADDR_UNIT_AFTER}` +
  `|${ADDR_HOUSE}${ADDR_SUFFIXES}${ADDR_END})${ADDR_TAIL_INDEX}`;

const MAX_ADDRESS_WORD_TAIL = 6;
const MAX_ADDRESS_FILLER_WORDS = 2;
// Контекст, после которого допустим адрес без ключевого слова улицы («Ленина 5»): город
// перед запятой («г. Москва, Ленина 5») или слово «адрес» («по адресу: Ленина 5»)
const ADDR_CONTEXT =
  `(?:${ADDR_LEFT}${ciAny(['город', 'г'])}\\.?[ \\t]*${ADDR_WORD}(?:[ \\t]+${ADDR_WORD})?` +
  `[ \\t]*,[ \\t]*|(?<![${LETTER_RU}])${ci('адрес')}[${LETTER_RU}A-Za-z0-9_]` +
  `{0,${MAX_ADDRESS_WORD_TAIL}}(?:[ \\t]+[а-яё]{2,15}){0,${MAX_ADDRESS_FILLER_WORDS}}` +
  `(?:[ \\t]*[:\\-])?[ \\t]*)`;

/** Группы основного шаблона в порядке проверки. */
const ADDRESS_GROUPS = ['pre', 'post', 'house_first', 'bare'] as const;

/** Основной шаблон «улица + дом» (флаг `g`; создаётся заново на каждый прогон). */
function streetHouseRegExp(): RegExp {
  return new RegExp(
    // 1) ключевое слово перед названием: «ул. Ленина, д. 5, кв. 12»
    `${ADDR_LEFT}(?<pre>${ADDR_DESIG}[ \\t]*${ADDR_NAME}${ADDR_SEP}${ADDR_HOUSE_PART})` +
      // 2) название перед ключевым словом: «Ленина ул., д. 5»
      `|${ADDR_LEFT}(?<post>${ADDR_NAME_POSTFIX}[ \\t]+${ADDR_DESIG}${ADDR_SEP}` +
      `${ADDR_HOUSE_PART})` +
      // 3) дом раньше улицы: «дом 5 по улице Ленина», «д. 5, ул. Ленина»
      `|${ADDR_LEFT}(?<house_first>${ciAny(['дом', 'д'])}\\.?[ \\t]*(?:№[ \\t]*)?${ADDR_HOUSE}` +
      `${ADDR_SUFFIXES}${ADDR_SEP}(?:${ciAny(['по', 'на'])}[ \\t]+)?${ADDR_DESIG}[ \\t]*` +
      `${ADDR_NAME})` +
      // 4) без ключевого слова, но в адресном контексте: «г. Москва, Ленина 5»
      `|${ADDR_CONTEXT}(?<bare>${ADDR_NAME}${ADDR_SEP}${ADDR_HOUSE_PART})`,
    'gd',
  );
}

// Индекс слева от адреса: «119019, ул. Арбат, д. 1» или «119019, г. Москва, ул. Арбат, 1».
// Между индексом и адресом допустимы до трёх сегментов без цифр (город, область).
const MAX_INDEX_GAP_SEGMENTS = 3;
const MAX_INDEX_GAP_SEGMENT_LEN = 40;
const INDEX_BEFORE_RE = new RegExp(
  `(?<![\\d.,\\-])(?<idx>\\d{${INDEX_DIGITS}})(?!\\d)(?<gap>[ \\t]*(?:,[ \\t]*)?` +
    `(?:[^\\n,;\\d]{1,${MAX_INDEX_GAP_SEGMENT_LEN}},[ \\t]*){0,${MAX_INDEX_GAP_SEGMENTS}})$`,
);
const DIGIT_RE = /\d/;

/** Диапазон адреса. `street` — это «улица + дом»; индекс, отделённый городом, — отдельно. */
export interface AddressPart {
  start: number;
  end: number;
  street: boolean;
}

/** Диапазоны «улица + дом» в нормализованном тексте (без индекса слева). */
function streetHouseMatches(norm: string): Array<[number, number]> {
  // Любая форма адреса содержит номер дома: текст без цифр пропускаем дешёвым поиском
  if (!DIGIT_RE.test(norm)) return [];
  const spans: Array<[number, number]> = [];
  for (const match of norm.matchAll(streetHouseRegExp())) {
    const groups = match.indices?.groups;
    if (groups === undefined) continue;
    for (const name of ADDRESS_GROUPS) {
      const range = groups[name];
      if (range === undefined) continue;
      // Контекст («г. Москва, » перед bare) остаётся слева от диапазона группы
      spans.push([range[0], range[1]]);
      break;
    }
  }
  return spans;
}

/**
 * Диапазоны адреса в нормализованном тексте: «улица + дом» (с индексом вплотную слева) и
 * индекс, отделённый от улицы городом (город остаётся открытым).
 */
export function findAddressParts(norm: string): AddressPart[] {
  const parts: AddressPart[] = [];
  for (const [start, end] of streetHouseMatches(norm)) {
    const windowStart = Math.max(0, start - INDEX_WINDOW_BEFORE);
    const index = INDEX_BEFORE_RE.exec(norm.slice(windowStart, start));
    const groups = index?.groups;
    if (index === null || groups === undefined) {
      parts.push({ start, end, street: true });
      continue;
    }
    const idx = groups['idx'] ?? '';
    const gap = groups['gap'] ?? '';
    const idxStart = windowStart + index.index;
    if (gap.replace(/[ \t,]/g, '') === '') {
      // индекс вплотную к улице («119019, ул. Арбат, 1») входит в адрес
      parts.push({ start: idxStart, end, street: true });
    } else {
      // город между индексом и улицей: город остаётся открытым, индекс — отдельный диапазон
      parts.push({ start: idxStart, end: idxStart + idx.length, street: false });
      parts.push({ start, end, street: true });
    }
  }
  return parts;
}
