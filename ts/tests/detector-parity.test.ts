import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { detectAddresses, detectPersons } from '../src/index';

/** Один текст корпуса с эталонными спанами Python-детектора. */
interface ParityItem {
  source: string;
  text: string;
  person: Array<[number, number]>;
  address: Array<[number, number]>;
}

function loadItems(): ParityItem[] {
  const path = join(import.meta.dir, 'fixtures', 'detector_parity.json');
  const raw: unknown = JSON.parse(readFileSync(path, 'utf8'));
  if (typeof raw !== 'object' || raw === null || !('items' in raw) || !Array.isArray(raw.items)) {
    throw new Error('detector_parity.json: нет items');
  }
  return raw.items as ParityItem[];
}

/** Источники, где ФИО есть: полнота считается по спанам Python. */
const POSITIVE_SOURCES = new Set([
  'names_positive', 'recall_easy', 'recall_hard', 'caps_pii', 'page_positive',
]);
/** Источники без ФИО: любая находка — ложное срабатывание. */
const NEGATIVE_SOURCES = new Set([
  'page_negative', 'caps_clean', 'address_negative', 'address_clean',
]);

/*
 * Пороги измерены 05.11.2026 на этом корпусе (см. вывод теста). Паритета с Natasha нет и быть
 * не может (нейросеть против словаря), поэтому фиксируем запас, а не равенство:
 * падение полноты или рост ложных срабатываний при правке правил станет виден.
 * Измерено: полнота ФИО 1.00 (115/115), ложных 1 из 49 (Natasha-детектор Python на тех же текстах: 10 из 49),
 * адреса: точное совпадение границ 42/42, лишних 0.
 */
const MIN_PERSON_RECALL = 0.95;
const MAX_FALSE_POSITIVE_RATE = 0.05;
const MIN_ADDRESS_EXACT_RATE = 0.97;
const MAX_ADDRESS_EXTRA = 0;

const items = loadItems();

function overlaps(a: [number, number], start: number, end: number): boolean {
  return start < a[1] && end > a[0];
}

describe('паритет с Python-детектором на корпусе', () => {
  test('полнота ФИО по спанам Python (по перекрытию)', () => {
    let total = 0;
    let hit = 0;
    const missed: string[] = [];
    for (const item of items.filter((i) => POSITIVE_SOURCES.has(i.source))) {
      const found = detectPersons(item.text, { profile: 'pragmatika' });
      for (const span of item.person) {
        total += 1;
        if (found.some((f) => overlaps(span, f.start, f.end))) hit += 1;
        else missed.push(`${item.text.slice(span[0], span[1])} <= ${item.text}`);
      }
    }
    console.log(`[замер] полнота ФИО: ${hit}/${total}; пропуски: ${JSON.stringify(missed)}`);
    expect(total).toBeGreaterThan(100);
    expect(hit / total).toBeGreaterThanOrEqual(MIN_PERSON_RECALL);
  });

  test('ложные срабатывания ФИО на текстах без ФИО', () => {
    const negatives = items.filter((i) => NEGATIVE_SOURCES.has(i.source));
    const wrong = negatives.filter(
      (i) => detectPersons(i.text, { profile: 'pragmatika' }).length > 0,
    );
    console.log(`[замер] ложных ФИО: ${wrong.length} из ${negatives.length}`);
    expect(wrong.length / negatives.length).toBeLessThanOrEqual(MAX_FALSE_POSITIVE_RATE);
  });

  test('адреса: границы совпадают с Python, лишних нет', () => {
    let total = 0;
    let exact = 0;
    let extra = 0;
    for (const item of items) {
      const found = detectAddresses(item.text);
      for (const [start, end] of item.address) {
        total += 1;
        if (found.some((f) => f.start === start && f.end === end)) exact += 1;
      }
      extra += found.filter(
        (f) => !item.address.some(([s, e]) => s === f.start && e === f.end),
      ).length;
    }
    console.log(`[замер] адреса: точно ${exact}/${total}, лишних ${extra}`);
    expect(exact / total).toBeGreaterThanOrEqual(MIN_ADDRESS_EXACT_RATE);
    expect(extra).toBeLessThanOrEqual(MAX_ADDRESS_EXTRA);
  });
});
