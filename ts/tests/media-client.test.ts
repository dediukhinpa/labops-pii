import { afterEach, describe, expect, test } from 'bun:test';

import { HttpMediaMasker } from '../src/index';

const TOKEN = 'test-token';
const TIMEOUT_MS = 500;
const IMAGE_B64 = 'aGVsbG8=';

/** Тело, которое получил фейковый media-masker. */
let lastBody: unknown;
let server: ReturnType<typeof Bun.serve> | undefined;

afterEach(() => { server?.stop(true); server = undefined; lastBody = undefined; });

/** Фейковый media-masker: запоминает тело запроса и отвечает `reply`. */
function client(reply: unknown, originalIfClean?: boolean): HttpMediaMasker {
  server = Bun.serve({
    port: 0,
    hostname: '127.0.0.1',
    async fetch(req): Promise<Response> {
      lastBody = JSON.parse(await req.text()) as unknown;
      return Response.json(reply);
    },
  });
  return new HttpMediaMasker({
    baseUrl: `http://127.0.0.1:${server.port}`,
    token: TOKEN,
    timeoutMs: TIMEOUT_MS,
    ...(originalIfClean === undefined ? {} : { originalIfClean }),
  });
}

const IMAGE_REPLY = {
  media_type: 'image/png',
  data: IMAGE_B64,
  recognized: { text: 'текст', codes: [], hidden_text: false },
};

describe('HttpMediaMasker: режим «оригинал, если чисто»', () => {
  test('по умолчанию поля нет: запрос прежний', async () => {
    const r = await client(IMAGE_REPLY).maskImage('image/png', IMAGE_B64);
    expect(lastBody).toEqual({ media_type: 'image/png', data: IMAGE_B64 });
    expect(r.recognized.text).toBe('текст');
  });

  test('false: поля нет', async () => {
    await client(IMAGE_REPLY, false).maskImage('image/png', IMAGE_B64);
    expect(lastBody).toEqual({ media_type: 'image/png', data: IMAGE_B64 });
  });

  test('true: original_if_clean уходит в запросе картинки', async () => {
    await client(IMAGE_REPLY, true).maskImage('image/png', IMAGE_B64);
    expect(lastBody).toEqual({
      media_type: 'image/png', data: IMAGE_B64, original_if_clean: true,
    });
  });

  test('true не добавляет поле в запрос PDF', async () => {
    await client({ kind: 'text', pages: [] }, true).extractDocument(IMAGE_B64);
    expect(lastBody).toEqual({ media_type: 'application/pdf', data: IMAGE_B64 });
  });
});

describe('HttpMediaMasker: типы находок для запроса разрешения', () => {
  test('pii_kinds, лица и коды складываются в piiKinds без мусора', async () => {
    const reply = { ...IMAGE_REPLY,
      stats: { pii_kinds: ['PHONE', 'bad value 79161234567', 'PERSON'], faces: 2, codes: 1 } };
    const r = await client(reply).maskImage('image/png', IMAGE_B64);
    expect(r.piiKinds).toEqual(['FACE', 'PERSON', 'PHONE', 'QR_CODE']);
  });

  test('старый сервис без stats: типов нет', async () => {
    const r = await client(IMAGE_REPLY).maskImage('image/png', IMAGE_B64);
    expect(r.piiKinds).toEqual([]);
  });

  test('PDF: типы со страниц', async () => {
    const reply = { kind: 'images', pages: [], stats: { pii_kinds: ['INN'] } };
    const r = await client(reply).extractDocument(IMAGE_B64);
    expect(r.piiKinds).toEqual(['INN']);
  });
});
