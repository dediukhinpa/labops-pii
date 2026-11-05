/**
 * Детектор ФИО и адресов для TS-проектов (без сети и внешних NLP-зависимостей).
 * Синхронный и чистый: подходит для очистки текста страниц прямо в процессе.
 */
import { findAddresses } from './addresses';
import { normalizeStems } from './allowlist';
import { findPersons } from './persons';
import { DETECTOR_PROFILES, DEFAULT_PROFILE_NAME } from './profiles';
import {
  DetectorOptionsSchema,
  DetectorTextSchema,
  type DetectedSpan,
  type DetectorOptions,
} from './types';

export { findAddresses } from './addresses';
export { DETECTOR_PROFILES } from './profiles';
export type { DetectorProfile } from './profiles';
export {
  DetectorOptionsSchema,
  PROFILE_NAMES,
  type DetectedKind,
  type DetectedSpan,
  type DetectorOptions,
  type ProfileName,
} from './types';

interface ResolvedOptions {
  maskAddresses: boolean;
  stems: readonly string[];
  latinNames: boolean;
}

function resolve(options: DetectorOptions | undefined): ResolvedOptions {
  const parsed = DetectorOptionsSchema.parse(options ?? {});
  const profile = DETECTOR_PROFILES[parsed.profile ?? DEFAULT_PROFILE_NAME];
  return {
    maskAddresses: parsed.maskAddresses ?? profile.maskAddresses,
    stems: normalizeStems([...profile.allowedWords, ...(parsed.allowedWords ?? [])]),
    latinNames: parsed.latinNames ?? true,
  };
}

/**
 * Находит ФИО в тексте.
 *
 * @param text Исходный текст.
 * @param options Профиль, белый список, латиница.
 * @returns Непересекающиеся находки по возрастанию позиции.
 * @throws ZodError Если вход не строка или настройки неверны (вызывающий код должен не
 *   пропускать текст дальше, fail closed).
 */
export function detectPersons(text: string, options?: DetectorOptions): DetectedSpan[] {
  const input = DetectorTextSchema.parse(text);
  const opts = resolve(options);
  return findPersons(input, opts.stems, opts.latinNames);
}

/**
 * Находит адреса уровня дома (улица + дом), независимо от флага профиля.
 *
 * @param text Исходный текст.
 */
export function detectAddresses(text: string): DetectedSpan[] {
  return findAddresses(DetectorTextSchema.parse(text));
}

/**
 * Находит ФИО и адреса вместе. Адрес сильнее ФИО: название улицы по фамилии
 * («ул. Ленина, д. 5») остаётся одним адресом, а не ФИО внутри адреса. Адреса ищутся,
 * только если их маскирует профиль (или `maskAddresses: true`).
 *
 * @param text Исходный текст.
 * @param options Профиль и белый список.
 * @returns Непересекающиеся находки по возрастанию позиции.
 */
export function detectNamesAndAddresses(
  text: string,
  options?: DetectorOptions,
): DetectedSpan[] {
  const input = DetectorTextSchema.parse(text);
  const opts = resolve(options);
  const addresses = opts.maskAddresses ? findAddresses(input) : [];
  const persons = findPersons(input, opts.stems, opts.latinNames).filter(
    (p) => !addresses.some((a) => p.start < a.end && p.end > a.start),
  );
  return [...addresses, ...persons].sort((a, b) => a.start - b.start);
}

/**
 * Заменяет находки в тексте метками.
 *
 * @param text Исходный текст.
 * @param spans Непересекающиеся находки (результат детектора).
 * @param mark Функция метки по виду данных.
 */
export function replaceSpans(
  text: string,
  spans: readonly DetectedSpan[],
  mark: (span: DetectedSpan) => string,
): string {
  let result = '';
  let cursor = 0;
  for (const span of [...spans].sort((a, b) => a.start - b.start)) {
    if (span.start < cursor) continue;
    result += text.slice(cursor, span.start) + mark(span);
    cursor = span.end;
  }
  return result + text.slice(cursor);
}
