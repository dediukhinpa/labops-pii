/**
 * Белый список слов, которые не ПДн (названия продуктов и т.п.). Слово задаётся
 * основой (пример: «вектрик»); допустимы любые падежные формы: основа плюс до трёх букв окончания.
 * Совпадать должно слово целиком, как в `python/labops_pii/allowlist.py`.
 */

/** Сколько букв окончания допустимо после основы. */
const ALLOWED_ENDING_MAX = 3;

/** Нормализация для сравнения: нижний регистр, «ё» как «е». */
export function foldWord(word: string): string {
  return word.toLowerCase().replace(/ё/g, 'е');
}

/** Основы белого списка в нормальной форме (пустые отбрасываются, повторы убираются). */
export function normalizeStems(stems: readonly string[]): readonly string[] {
  const folded = stems.map((stem) => foldWord(stem.trim())).filter((stem) => stem.length > 0);
  return [...new Set(folded)];
}

/** Слово из белого списка (основа + падежное окончание). */
export function isAllowedWord(word: string, stems: readonly string[]): boolean {
  const low = foldWord(word);
  return stems.some(
    (stem) => low.startsWith(stem) && low.length - stem.length <= ALLOWED_ENDING_MAX,
  );
}
