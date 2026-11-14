import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import {
  existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CONSENT_TTL_MS, consentOfferText } from '../src/constants';
import type { JsonObject } from '../src/json-leaves';
import type { Logger, LogFields } from '../src/log';
import { MediaProcessor } from '../src/media';
import type { ExtractedDocument, MaskedImage, MediaMasker } from '../src/media-client';
import { NOTHING_RECOGNIZED } from '../src/media-client';
import { FileConsentGate, mediaFingerprint, mediaIdOf } from '../src/media-consent';
import { RequestWalker } from '../src/request-walker';

// Синтетика: «картинка» - произвольные байты, настоящих ПДн нет
const ORIGINAL = Buffer.from('synthetic-original-image-bytes').toString('base64');
const MASKED = Buffer.from('synthetic-masked-image-bytes').toString('base64');
const OTHER = Buffer.from('another-file-bytes').toString('base64');
const AGENT = 'agent-a';
const T0 = Date.parse('2026-11-14T12:00:00.000Z');

class FakeMedia implements MediaMasker {
  calls = 0;
  constructor(private readonly kinds: readonly string[]) {}

  async maskImage(mediaType: string): Promise<MaskedImage> {
    this.calls++;
    return { mediaType, data: MASKED, recognized: NOTHING_RECOGNIZED, piiKinds: this.kinds };
  }

  async extractDocument(): Promise<ExtractedDocument> {
    this.calls++;
    return {
      pages: [{ text: 'page text', image: null }],
      piiKinds: this.kinds,
    };
  }
}

class MemoryLogger implements Logger {
  readonly events: { event: string; fields: LogFields | undefined }[] = [];
  log(event: string, fields?: LogFields): void {
    this.events.push({ event, fields });
  }
}

let dir: string;
let clock: number;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'consent-'));
  clock = T0;
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function gate(agentId = AGENT): FileConsentGate {
  return new FileConsentGate({ dir, agentId, now: () => clock });
}

/** Записать разрешение так, как это делает канал мессенджера. */
function approve(sha256: string, over: Record<string, unknown> = {}): void {
  const record = {
    sha256, agent: AGENT, kinds: ['PHONE'], approved_by: 1,
    approved_at: new Date(T0).toISOString(),
    expires_at: new Date(T0 + CONSENT_TTL_MS).toISOString(),
    ...over,
  };
  writeFileSync(join(dir, `${sha256}.json`), JSON.stringify(record));
}

function imageBody(data = ORIGINAL): JsonObject {
  const block = { type: 'image', source: { type: 'base64', media_type: 'image/png', data } };
  return { messages: [{ role: 'user', content: [block] }] };
}

function blocks(body: JsonObject): JsonObject[] {
  const messages = body.messages as JsonObject[];
  return (messages[0] as JsonObject).content as JsonObject[];
}

async function walk(body: JsonObject, media: MediaProcessor): Promise<RequestWalker> {
  const walker = new RequestWalker('mask', media);
  await walker.walk(body);
  return walker;
}

describe('FileConsentGate: проверка разрешения', () => {
  const sha = mediaFingerprint(ORIGINAL);

  test('нет файла - нет разрешения', () => {
    expect(gate().approved(sha)).toBeUndefined();
  });

  test('действующее разрешение находится по отпечатку', () => {
    approve(sha);
    const found = gate().approved(sha);
    expect(found?.sha256).toBe(sha);
    expect(found?.mediaId).toBe(mediaIdOf(sha));
    expect(found?.kinds).toEqual(['PHONE']);
  });

  test('просроченное разрешение не действует', () => {
    approve(sha);
    clock = T0 + CONSENT_TTL_MS + 1;
    expect(gate().approved(sha)).toBeUndefined();
  });

  test('растянутый expires_at не продлевает срок сверх TTL от approved_at', () => {
    approve(sha, { expires_at: new Date(T0 + 24 * 60 * 60 * 1000).toISOString() });
    clock = T0 + CONSENT_TTL_MS + 1;
    expect(gate().approved(sha)).toBeUndefined();
  });

  test('разрешение другого агента не действует', () => {
    approve(sha, { agent: 'agent-b' });
    expect(gate().approved(sha)).toBeUndefined();
  });

  test('отпечаток внутри файла не совпал с именем', () => {
    approve(sha, { sha256: mediaFingerprint(OTHER) });
    expect(gate().approved(sha)).toBeUndefined();
  });

  test('битый JSON и неполная запись - нет разрешения', () => {
    writeFileSync(join(dir, `${sha}.json`), '{oops');
    expect(gate().approved(sha)).toBeUndefined();
    writeFileSync(join(dir, `${sha}.json`), JSON.stringify({ sha256: sha }));
    expect(gate().approved(sha)).toBeUndefined();
  });

  test('approved_at из далёкого будущего отклоняется', () => {
    approve(sha, { approved_at: new Date(T0 + 3_600_000).toISOString(),
      expires_at: new Date(T0 + 3_600_000 + CONSENT_TTL_MS).toISOString() });
    expect(gate().approved(sha)).toBeUndefined();
  });

  test('предложение: файл 600, повтор не перезаписывает, типы очищаются', () => {
    const id = gate().offer(sha, ['PHONE', 'bad kind', 'PERSON', 'PHONE']);
    expect(id).toBe(mediaIdOf(sha));
    const file = join(dir, 'offers', `${id}.json`);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    const saved = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
    expect(saved.sha256).toBe(sha);
    expect(saved.kinds).toEqual(['PERSON', 'PHONE']);
    expect(saved.agent).toBe(AGENT);
    expect(readdirSync(join(dir, 'offers'))).toEqual([`${id}.json`]);
  });
});

describe('вложение: оригинал только по разрешению', () => {
  const sha = mediaFingerprint(ORIGINAL);

  test('разрешения нет: закрашенный блок и текст про запрос разрешения', async () => {
    const fake = new FakeMedia(['PHONE', 'PERSON']);
    const body = imageBody();
    const walker = await walk(body, new MediaProcessor(fake, { consent: gate() }));
    const out = blocks(body);
    expect((out[0] as JsonObject).source).toMatchObject({ data: MASKED });
    const id = mediaIdOf(sha);
    expect(out[1]).toEqual({ type: 'text', text: consentOfferText(id, ['PERSON', 'PHONE']) });
    expect(walker.consentOriginals).toBe(0);
    expect(existsSync(join(dir, 'offers', `${id}.json`))).toBe(true);
    // Значений ПДн и самого файла в тексте для модели нет
    expect(JSON.stringify(out[1])).not.toContain(ORIGINAL);
  });

  test('текст про разрешение не попадает в листья (не маскируется как обычный текст)', async () => {
    const body = imageBody();
    const walker = await walk(body, new MediaProcessor(new FakeMedia(['PHONE']), { consent: gate() }));
    expect(walker.leaves).toHaveLength(0);
  });

  test('разрешение есть: оригинал уходит как есть, media-masker не вызывается, событие в журнале', async () => {
    approve(sha);
    const fake = new FakeMedia(['PHONE']);
    const logger = new MemoryLogger();
    const body = imageBody();
    const walker = await walk(body, new MediaProcessor(fake, { consent: gate(), logger }));
    const out = blocks(body);
    expect(out).toHaveLength(1);
    expect((out[0] as JsonObject).source).toMatchObject({ data: ORIGINAL });
    expect(fake.calls).toBe(0);
    expect(walker.consentOriginals).toBe(1);
    expect(logger.events).toEqual([{ event: 'consent_original_sent',
      fields: { media_id: mediaIdOf(sha), pii_types: ['PHONE'] } }]);
    // В журнале нет содержимого вложения
    expect(JSON.stringify(logger.events)).not.toContain(ORIGINAL);
  });

  test('разрешение просрочено: снова закрашенная версия', async () => {
    approve(sha);
    clock = T0 + CONSENT_TTL_MS + 1;
    const fake = new FakeMedia(['PHONE']);
    const body = imageBody();
    const walker = await walk(body, new MediaProcessor(fake, { consent: gate() }));
    expect((blocks(body)[0] as JsonObject).source).toMatchObject({ data: MASKED });
    expect(walker.consentOriginals).toBe(0);
    expect(fake.calls).toBe(1);
  });

  test('отпечаток другого файла не совпал: разрешение не действует', async () => {
    approve(mediaFingerprint(OTHER));
    const fake = new FakeMedia(['PHONE']);
    const body = imageBody();
    const walker = await walk(body, new MediaProcessor(fake, { consent: gate() }));
    expect((blocks(body)[0] as JsonObject).source).toMatchObject({ data: MASKED });
    expect(walker.consentOriginals).toBe(0);
  });

  test('разрешение на один файл не открывает второй в том же запросе', async () => {
    approve(sha);
    const first = { type: 'image', source: { type: 'base64', media_type: 'image/png', data: ORIGINAL } };
    const second = { type: 'image', source: { type: 'base64', media_type: 'image/png', data: OTHER } };
    const body: JsonObject = { messages: [{ role: 'user', content: [first, second] }] };
    const walker = await walk(body, new MediaProcessor(new FakeMedia(['PHONE']), { consent: gate() }));
    const out = blocks(body);
    expect((out[0] as JsonObject).source).toMatchObject({ data: ORIGINAL });
    expect((out[1] as JsonObject).source).toMatchObject({ data: MASKED });
    expect(walker.consentOriginals).toBe(1);
  });

  test('на вложении нет находок: текста про разрешение нет', async () => {
    const body = imageBody();
    await walk(body, new MediaProcessor(new FakeMedia([]), { consent: gate() }));
    expect(blocks(body)).toHaveLength(1);
  });

  test('без хранилища разрешений поведение прежнее: ни текста, ни файлов', async () => {
    const body = imageBody();
    await walk(body, new MediaProcessor(new FakeMedia(['PHONE'])));
    expect(blocks(body)).toHaveLength(1);
    expect(readdirSync(dir)).toEqual([]);
  });

  test('cache_control переезжает на последний добавленный блок', async () => {
    const block = { type: 'image', cache_control: { type: 'ephemeral' },
      source: { type: 'base64', media_type: 'image/png', data: ORIGINAL } };
    const body: JsonObject = { messages: [{ role: 'user', content: [block] }] };
    await walk(body, new MediaProcessor(new FakeMedia(['PHONE']), { consent: gate() }));
    const out = blocks(body);
    expect((out[0] as JsonObject).cache_control).toBeUndefined();
    expect((out[1] as JsonObject).cache_control).toEqual({ type: 'ephemeral' });
  });

  test('PDF: разрешение возвращает документ как есть, иначе страницы и текст про запрос', async () => {
    const pdf = Buffer.from('synthetic-pdf-bytes').toString('base64');
    const doc = (): JsonObject => ({ messages: [{ role: 'user', content: [
      { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: pdf } },
    ] }] });
    const sha256 = mediaFingerprint(pdf);
    const plain = doc();
    await walk(plain, new MediaProcessor(new FakeMedia(['PERSON']), { consent: gate() }));
    const plainBlocks = blocks(plain);
    expect((plainBlocks[0] as JsonObject).text).toBe('page text');
    expect(plainBlocks[plainBlocks.length - 1]).toEqual({ type: 'text',
      text: consentOfferText(mediaIdOf(sha256), ['PERSON']) });

    approve(sha256);
    const fake = new FakeMedia(['PERSON']);
    const allowed = doc();
    const walker = await walk(allowed, new MediaProcessor(fake, { consent: gate() }));
    expect((blocks(allowed)[0] as JsonObject).type).toBe('document');
    expect(fake.calls).toBe(0);
    expect(walker.consentOriginals).toBe(1);
  });
});
