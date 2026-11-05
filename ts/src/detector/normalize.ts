/**
 * Нормализация текста перед поиском адресов (аналог `normalize_text` из
 * `python/labops_pii/pii_patterns.py`): длина строки не меняется никогда, поэтому позиции
 * находок в копии совпадают с позициями исходного текста.
 */

/** Тире и дефисы всех видов, косые черты — всё становится «-». */
const DASH_LIKE_RE = /[­‐-―⁃−﹘﹣－⁄∕／/]/g;
/** Невидимые символы нулевой ширины и BOM — становятся пробелом (не склеивают цифры). */
const INVISIBLE_RE = /[​‌‍⁠﻿]/g;
/** Любой не-ASCII символ (одна UTF-16-единица). */
const NON_ASCII_RE = /[^\x00-\x7F]/g;
const DECIMAL_DIGIT_RE = /\p{Nd}/u;
/** Длина самого длинного подряд идущего блока десятичных цифр в Unicode (математические). */
const MAX_DIGIT_RUN = 50;
const DIGITS_PER_BLOCK = 10;

/** Значение десятичной цифры любой системы счисления (0–9) по коду символа. */
function digitValue(codePoint: number): number {
  let start = codePoint;
  while (
    codePoint - start < MAX_DIGIT_RUN &&
    start > 0 &&
    DECIMAL_DIGIT_RE.test(String.fromCodePoint(start - 1))
  ) {
    start -= 1;
  }
  return (codePoint - start) % DIGITS_PER_BLOCK;
}

/** Образ одного не-ASCII символа: цифра -> ASCII, NFKC только если результат один знак. */
function foldChar(char: string): string {
  if (DECIMAL_DIGIT_RE.test(char)) return String(digitValue(char.charCodeAt(0)));
  const folded = char.normalize('NFKC');
  return folded.length === 1 ? folded : char;
}

/**
 * Приводит текст к виду для поиска адресов; длина результата равна длине входа.
 *
 * Цифры любых систем счисления -> ASCII, NFKC посимвольно (NBSP -> пробел), все виды тире и
 * «/» -> «-», невидимые символы -> пробел. Символы вне BMP остаются как есть: замена на один
 * знак сдвинула бы позиции (для номеров домов они не нужны).
 */
export function normalizeText(text: string): string {
  const dashed = text.replace(DASH_LIKE_RE, '-').replace(INVISIBLE_RE, ' ');
  return dashed.replace(NON_ASCII_RE, (char) => {
    // Явные правила выше сильнее общих: тире и невидимые уже заменены
    return foldChar(char);
  });
}
