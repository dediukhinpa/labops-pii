import { findAddressParts } from './address-patterns';
import { normalizeText } from './normalize';
import type { DetectedSpan } from './types';

/**
 * Ищет адреса уровня дома: «улица + дом (+ корпус, квартира, индекс)». Город без улицы —
 * не ПДн и остаётся открытым. Поиск идёт в нормализованной копии той же длины, поэтому
 * границы относятся к исходному тексту.
 *
 * @param text Исходный текст.
 * @returns Непересекающиеся находки, отсортированные по позиции.
 */
export function findAddresses(text: string): DetectedSpan[] {
  const parts = findAddressParts(normalizeText(text));
  return parts
    .map((part) => ({
      start: part.start,
      end: part.end,
      kind: 'address' as const,
      text: text.slice(part.start, part.end),
    }))
    .sort((a, b) => a.start - b.start);
}
