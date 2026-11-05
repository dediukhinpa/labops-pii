import { afterEach, describe, expect, test } from 'bun:test';

import { HttpPseudonymizer, PseudonymizerError } from '../src/index';

/** Запись запроса к фейковому сервису. */
interface Hit {
  readonly method: string;
  readonly path: string;
  readonly auth: string | null;
  readonly body: unknown;
}

const TOKEN = 'test-token';
const TIMEOUT_MS = 500;
const HANG_MS = 3_000;
const HTTP_ERROR = 500;

/** Запущенный фейковый сервис и клиенты к нему. */
interface Started {
  readonly client: HttpPseudonymizer;
  readonly hits: Hit[];
  readonly clientWith: (caseLabels: boolean) => HttpPseudonymizer;
}

let server: ReturnType<typeof Bun.serve> | undefined;

afterEach(() => { server?.stop(true); server = undefined; });

/** Поднять фейковый сервис: ответ задаёт обработчик. */
function start(handler: (hit: Hit) => Response | Promise<Response>): Started {
  const hits: Hit[] = [];
  server = Bun.serve({
    port: 0,
    hostname: '127.0.0.1',
    async fetch(req): Promise<Response> {
      const text = await req.text();
      const hit: Hit = {
        method: req.method,
        path: new URL(req.url).pathname,
        auth: req.headers.get('authorization'),
        body: text === '' ? undefined : (JSON.parse(text) as unknown),
      };
      hits.push(hit);
      return handler(hit);
    },
  });
  const baseUrl = `http://127.0.0.1:${server.port}`;
  const make = (caseLabels?: boolean): HttpPseudonymizer => new HttpPseudonymizer({
    baseUrl, token: TOKEN, timeoutMs: TIMEOUT_MS,
    ...(caseLabels === undefined ? {} : { caseLabels }),
  });
  return { client: make(), hits, clientWith: make };
}

const json = (data: unknown): Response => Response.json(data);

describe('HttpPseudonymizer', () => {
  test('health без авторизации возвращает boot_id', async () => {
    const { client, hits } = start(() => json({ boot_id: 'b1' }));
    expect(await client.health()).toBe('b1');
    expect(hits[0]?.auth).toBeNull();
  });

  test('пачка: Bearer, thread_id, без case_labels по умолчанию', async () => {
    const { client, hits } = start(() => json({ items: [{ text: 'A' }, { text: 'B' }] }));
    expect(await client.pseudonymizeBatch('t', ['a', 'b'])).toEqual(['A', 'B']);
    expect(hits[0]?.auth).toBe(`Bearer ${TOKEN}`);
    expect(hits[0]?.body).toEqual({ thread_id: 't', texts: ['a', 'b'] });
  });

  test('case_labels: true добавляет поле в тело', async () => {
    const { clientWith, hits } = start(() => json({ items: [{ text: 'A' }] }));
    await clientWith(true).pseudonymizeBatch('t', ['a']);
    expect(hits[0]?.body).toEqual({ thread_id: 't', texts: ['a'], case_labels: true });
  });

  test('число ответов не равно числу текстов - batch_size_mismatch', async () => {
    const { client } = start(() => json({ items: [] }));
    await expect(client.pseudonymizeBatch('t', ['a'])).rejects.toMatchObject({
      code: 'batch_size_mismatch',
    });
  });

  test('restore, check и deleteThread', async () => {
    const { client, hits } = start((h) => {
      if (h.path === '/restore') return json({ text: 'Иванов' });
      if (h.path === '/check') return json({ has_pii: true, types: ['PERSON'] });
      return new Response(null, { status: 204 });
    });
    expect(await client.restore('t', '[PERSON_1]')).toBe('Иванов');
    expect(await client.check('x', 't')).toEqual({ hasPii: true, types: ['PERSON'] });
    await client.deleteThread('a/b');
    expect(hits.map((h) => `${h.method} ${h.path}`)).toEqual([
      'POST /restore', 'POST /check', 'DELETE /threads/a%2Fb',
    ]);
  });

  test('не 2xx - http_<код>, неверный ответ - invalid_response', async () => {
    const bad = start(() => new Response('x', { status: HTTP_ERROR }));
    await expect(bad.client.restore('t', 'x')).rejects.toMatchObject({ code: 'http_500' });
    server?.stop(true);
    const wrong = start(() => json({ nope: 1 }));
    await expect(wrong.client.restore('t', 'x')).rejects.toBeInstanceOf(PseudonymizerError);
    await expect(wrong.client.health()).rejects.toMatchObject({ code: 'invalid_response' });
  });

  test('таймаут и недоступность - fail closed', async () => {
    const slow = start(async () => {
      await new Promise((r) => setTimeout(r, HANG_MS));
      return json({ boot_id: 'b' });
    });
    await expect(slow.client.health()).rejects.toMatchObject({ code: 'timeout' });
    server?.stop(true);
    const dead = new HttpPseudonymizer({
      baseUrl: 'http://127.0.0.1:1', token: TOKEN, timeoutMs: TIMEOUT_MS,
    });
    await expect(dead.health()).rejects.toMatchObject({ code: 'unreachable' });
  });
});
