/**
 * Помощники сборки регулярных выражений без встроенных флагов `(?i:)`: они поддерживаются
 * не всеми JS-движками, поэтому регистр раскрывается в классы символов.
 */

/** Буква в обоих регистрах: «у» -> «[уУ]». Остальные символы без изменений. */
function ciChar(char: string): string {
  const lower = char.toLowerCase();
  const upper = char.toUpperCase();
  return lower === upper ? char : `[${lower}${upper}]`;
}

/** Слово без учёта регистра. */
export function ci(word: string): string {
  return [...word].map(ciChar).join('');
}

/** Альтернатива из слов без учёта регистра; длинные формы первыми. */
export function ciAny(words: readonly string[]): string {
  const sorted = [...words].sort((a, b) => b.length - a.length);
  return `(?:${sorted.map(ci).join('|')})`;
}

/** Слово с необязательным продолжением: ciOpt('корп', 'ус') — «корп» или «корпус». */
export function ciOpt(stem: string, rest: string): string {
  return `${ci(stem)}(?:${ci(rest)})?`;
}
