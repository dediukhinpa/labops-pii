import { describe, expect, test } from 'bun:test';

import {
  Restorer, restoreMessageJson, restoreSse, type CheckResult, type JsonObject, type Pseudonymizer,
  type SseEvent,
} from '../src/index';

const DICT: Readonly<Record<string, string>> = { '[PERSON_1]': 'Иванов', '[PHONE_1]': '+7 900' };

/** Сервис-заглушка: /restore подставляет значения из словаря. */
const service: Pseudonymizer = {
  health: async () => 'boot',
  pseudonymizeBatch: async (_t, texts) => [...texts],
  restore: async (_t, text) => Object.entries(DICT).reduce(
    (acc, [token, value]) => acc.split(token).join(value), text),
  check: async (): Promise<CheckResult> => ({ hasPii: false, types: [] }),
  deleteThread: async () => undefined,
};

async function* events(list: SseEvent[]): AsyncGenerator<SseEvent> {
  for (const e of list) yield e;
}

const delta = (index: number, text: string): SseEvent => ({
  event: 'content_block_delta',
  data: JSON.stringify({
    type: 'content_block_delta', index, delta: { type: 'text_delta', text },
  }),
});
const plain = (type: string, extra: Record<string, unknown> = {}): SseEvent => ({
  event: type, data: JSON.stringify({ type, ...extra }),
});

describe('Restorer', () => {
  test('без «]» сервис не зовётся, токены считаются', async () => {
    const r = new Restorer(service, 't');
    expect(await r.text('просто текст')).toBe('просто текст');
    expect(r.restoredTokens).toBe(0);
    // Заглушка не знает падежных меток: считаем только, что токен учтён
    expect(await r.text('звонил [PERSON_1|datv] и [PHONE_1]')).toBe(
      'звонил [PERSON_1|datv] и +7 900');
    expect(r.restoredTokens).toBe(2);
  });

  test('память восстановлений получает пары только при изменении', async () => {
    const pairs: string[][] = [];
    const r = new Restorer(service, 't', (a, b) => pairs.push([a, b]));
    const holder = { input: { q: '[PERSON_1]', other: 'без токенов ]' } };
    await r.leaves(holder);
    expect(holder.input.q).toBe('Иванов');
    expect(pairs).toEqual([['Иванов', '[PERSON_1]']]);
  });
});

describe('restoreMessageJson', () => {
  test('text и tool_use восстанавливаются, thinking не трогается', async () => {
    const body: JsonObject = {
      content: [
        { type: 'text', text: 'Привет, [PERSON_1]' },
        { type: 'tool_use', input: { name: '[PERSON_1]' } },
        { type: 'thinking', thinking: '[PERSON_1]' },
      ],
    };
    const out = await restoreMessageJson(body, new Restorer(service, 't'));
    expect(out.content).toEqual([
      { type: 'text', text: 'Привет, Иванов' },
      { type: 'tool_use', input: { name: 'Иванов' } },
      { type: 'thinking', thinking: '[PERSON_1]' },
    ]);
  });
});

describe('restoreSse', () => {
  const collect = async (list: SseEvent[]): Promise<{ text: string; types: string[] }> => {
    let text = '';
    const types: string[] = [];
    for await (const e of restoreSse(events(list), new Restorer(service, 't'))) {
      const j = JSON.parse(e.data) as { type: string; delta?: { text?: string } };
      types.push(j.type);
      text += j.delta?.text ?? '';
    }
    return { text, types };
  };

  test('токен, разорванный между чанками, восстанавливается целиком', async () => {
    const { text, types } = await collect([
      plain('content_block_start', { index: 0, content_block: { type: 'text', text: '' } }),
      delta(0, 'Звонил [PERS'),
      delta(0, 'ON_1] вчера.'),
      plain('content_block_stop', { index: 0 }),
    ]);
    expect(text).toBe('Звонил Иванов вчера.');
    expect(text).not.toContain('[');
    expect(types[types.length - 1]).toBe('content_block_stop');
  });

  test('сбой восстановления - событие error и конец потока', async () => {
    const broken: Pseudonymizer = { ...service, restore: async () => { throw new Error('x'); } };
    const out: string[] = [];
    const list = [
      plain('content_block_start', { index: 0, content_block: { type: 'text', text: '' } }),
      delta(0, 'вот [PERSON_1].'),
      plain('content_block_stop', { index: 0 }),
    ];
    for await (const e of restoreSse(events(list), new Restorer(broken, 't'))) out.push(e.data);
    expect(out[out.length - 1]).toContain('"type":"error"');
    expect(out.join('')).not.toContain('PERSON_1]."');
  });
});
