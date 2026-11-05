import { describe, expect, test } from 'bun:test';
import { BATCH_MAX_ITEMS, MAX_TEXT_CHARS } from '../src/constants';
import { BoundedCache, BootTracker } from '../src/mask-cache';
import { chunkBatches, splitText } from '../src/text-split';
import { TokenBoundaryBuffer } from '../src/token-boundary-buffer';
import { parseSse } from '../src/sse';

describe('деление текста', () => {
  test('склейка частей равна исходному, части в пределе', () => {
    const text = `${'слово '.repeat(40_000)}\n${'x'.repeat(150_000)}`;
    const parts = splitText(text);
    expect(parts.join('')).toBe(text);
    expect(parts.every((p) => p.length <= MAX_TEXT_CHARS)).toBe(true);
  });
  test('пачки: не больше 100 текстов и предел длины с поправкой', () => {
    const many = chunkBatches(Array.from({ length: 250 }, () => 'a'));
    expect(many.map((c) => c.length)).toEqual([BATCH_MAX_ITEMS, BATCH_MAX_ITEMS, 50]);
    const big = chunkBatches(['x'.repeat(40_000), 'y'.repeat(40_000)]);
    expect(big.length).toBe(2);
  });
});

describe('буфер границы токена', () => {
  test('токен с меткой разрезан на «|»', () => {
    const b = new TokenBoundaryBuffer();
    expect(b.push('Привет [PERSON_1')).toBe('Привет ');
    expect(b.push('|')).toBe('');
    expect(b.holdsTokenStart).toBe(true);
    expect(b.push('da')).toBe('');
    expect(b.push('tv] ок')).toBe('[PERSON_1|datv] ок');
  });
  test('хвост, не похожий на токен, отдаётся сразу; начало токена ждёт', () => {
    const b = new TokenBoundaryBuffer();
    expect(b.push('массив [i')).toBe('массив [i');
    expect(b.hasPending).toBe(false);
    expect(b.push('x [1')).toBe('x [1');
    expect(b.push('y [')).toBe('y ');
    expect(b.holdsTokenStart).toBe(true);
    expect(b.flush()).toBe('[');
  });
  test('длиннее 32 символов - обычный текст', () => {
    const b = new TokenBoundaryBuffer();
    expect(b.push(`[${'A'.repeat(40)}`)).toBe(`[${'A'.repeat(40)}`);
  });
});

describe('кэш и boot_id', () => {
  test('бюджет вытесняет давние записи', () => {
    const c = new BoundedCache(200);
    c.set('a', 'x'.repeat(100));
    c.set('b', 'y'.repeat(100));
    expect(c.get('a')).toBeUndefined();
    expect(c.get('b')).toBeDefined();
  });
  test('health не чаще окна, смена boot_id сбрасывает', async () => {
    let boot = 'one';
    let calls = 0;
    let resets = 0;
    let t = 0;
    const svc = { health: async () => { calls++; return boot; } } as never;
    const tr = new BootTracker(svc, () => resets++, () => t, 5_000);
    await tr.current();
    await tr.current();
    expect(calls).toBe(1);
    boot = 'two';
    t = 6_000;
    expect(await tr.current()).toBe('two');
    expect(resets).toBe(1);
  });
});

describe('SSE', () => {
  test('разбор событий, разрезанных по байтам', async () => {
    const enc = new TextEncoder().encode('event: a\ndata: {"x":1}\n\nevent: b\ndata: 2\n\n');
    const body = new ReadableStream<Uint8Array>({
      start(c) { c.enqueue(enc.slice(0, 7)); c.enqueue(enc.slice(7)); c.close(); },
    });
    const out = [];
    for await (const e of parseSse(body)) out.push(e);
    expect(out).toEqual([{ event: 'a', data: '{"x":1}' }, { event: 'b', data: '2' }]);
  });
});
