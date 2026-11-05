import {
  BATCH_ITEM_COST_CHARS,
  BATCH_MAX_ITEMS,
  MAX_TEXT_CHARS,
  SPLIT_SEARCH_MIN_SHARE,
} from './constants';

const HIGH_SURROGATE_MIN = 0xd800;
const HIGH_SURROGATE_MAX = 0xdbff;

/**
 * Режет длинный текст на части не длиннее `max` без потерь (склейка частей = исходный текст).
 * Граница - последний перевод строки в окне, иначе последний пробел, иначе жёсткий разрез
 * (не посреди суррогатной пары). Разделитель остаётся в конце левой части.
 */
export function splitText(text: string, max: number = MAX_TEXT_CHARS): string[] {
  if (text.length <= max) return [text];
  const pieces: string[] = [];
  let start = 0;
  const floor = Math.floor(max * SPLIT_SEARCH_MIN_SHARE);
  while (text.length - start > max) {
    const window = text.slice(start, start + max);
    let cut = window.lastIndexOf('\n');
    if (cut < floor) cut = window.lastIndexOf(' ');
    let end = cut < floor ? max : cut + 1;
    const last = text.charCodeAt(start + end - 1);
    if (end === max && last >= HIGH_SURROGATE_MIN && last <= HIGH_SURROGATE_MAX) end -= 1;
    pieces.push(text.slice(start, start + end));
    start += end;
  }
  pieces.push(text.slice(start));
  return pieces;
}

/**
 * Делит тексты на пачки: не больше {@link BATCH_MAX_ITEMS} текстов, сумма длин с поправкой
 * {@link BATCH_ITEM_COST_CHARS} на каждый текст после первого не больше `MAX_TEXT_CHARS`.
 */
export function chunkBatches(texts: readonly string[]): string[][] {
  const chunks: string[][] = [];
  let current: string[] = [];
  let cost = 0;
  for (const text of texts) {
    const full =
      current.length >= BATCH_MAX_ITEMS
      || cost + BATCH_ITEM_COST_CHARS + text.length > MAX_TEXT_CHARS;
    if (current.length > 0 && full) {
      chunks.push(current);
      current = [];
      cost = 0;
    }
    cost += text.length + (current.length === 0 ? 0 : BATCH_ITEM_COST_CHARS);
    current.push(text);
  }
  if (current.length > 0) chunks.push(current);
  return chunks;
}

/** Выполнить задачи с ограничением параллельности; результаты в порядке входа. */
export async function mapLimited<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i] as T);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}
