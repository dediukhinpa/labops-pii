import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  RequestMasker, RequestRejectedError, Restorer, ResponsesWalker, restoreResponsesJson,
  restoreResponsesSse, SYSTEM_INSERT_TEXT, type CheckResult, type JsonObject, type Pseudonymizer,
  type SseEvent,
} from '../src/index';

/**
 * Формат OpenAI Responses (Codex CLI). Образцы в fixtures/codex-responses сняты с живого
 * трафика Codex 0.171.0 к бэкенду ChatGPT (22.11.2026); идентификаторы аккаунта вычищены,
 * «Иван Петров +7 913 555-12-34» — выдуманные данные запроса.
 */
const FIXTURES = join(import.meta.dir, 'fixtures', 'codex-responses');
const PERSON = 'Иван Петров';
const PHONE = '+7 913 555-12-34';

const realRequest = (): JsonObject =>
  JSON.parse(readFileSync(join(FIXTURES, 'real-turn-tool-result.request.json'), 'utf8')) as JsonObject;

/** Сервис-заглушка: заменяет известные значения токенами и обратно. */
class FakeService implements Pseudonymizer {
  readonly dict: Readonly<Record<string, string>> = { [PERSON]: '[PERSON_1]', [PHONE]: '[PHONE_1]' };

  async health(): Promise<string> {
    return 'boot-1';
  }

  async pseudonymizeBatch(_t: string, texts: readonly string[]): Promise<string[]> {
    return texts.map((t) => Object.entries(this.dict).reduce(
      (acc, [value, token]) => acc.split(value).join(token), t));
  }

  async restore(_t: string, text: string): Promise<string> {
    return Object.entries(this.dict).reduce(
      (acc, [value, token]) => acc.split(token).join(value), text);
  }

  async check(text: string): Promise<CheckResult> {
    const has = text.includes(PERSON) || text.includes(PHONE);
    return { hasPii: has, types: has ? ['PERSON'] : [] };
  }

  async deleteThread(): Promise<void> {
    return undefined;
  }
}

async function leavesOf(body: JsonObject): Promise<string[]> {
  const w = new ResponsesWalker('strip');
  await w.walk(body);
  return w.leaves.map((l) => l.text);
}

describe('ResponsesWalker: обход живого запроса Codex', () => {
  test('все элементы живого запроса известны, ПДн попадают в листья', async () => {
    const leaves = await leavesOf(realRequest());
    const joined = leaves.join('\n');
    // Текст пользователя, код инструмента и его вывод
    expect(joined).toContain(PERSON);
    expect(leaves.filter((t) => t.includes(PHONE)).length).toBeGreaterThanOrEqual(2);
  });

  test('определения инструментов и зашифрованное не маскируются', async () => {
    const body: JsonObject = {
      input: [
        { type: 'additional_tools', role: 'developer', tools: [{ name: PERSON }] },
        { type: 'reasoning', summary: [], encrypted_content: PERSON },
        { type: 'compaction', encrypted_content: PERSON },
      ],
    };
    expect(await leavesOf(body)).toEqual([]);
  });

  test('неизвестный элемент — отказ, а не пропуск', async () => {
    const body: JsonObject = { input: [{ type: 'brand_new_item', text: PERSON }] };
    await expect(leavesOf(body)).rejects.toBeInstanceOf(RequestRejectedError);
  });

  test('неизвестная часть содержимого — отказ', async () => {
    const body: JsonObject = {
      input: [{ type: 'message', role: 'user', content: [{ type: 'input_video', text: PERSON }] }],
    };
    await expect(leavesOf(body)).rejects.toBeInstanceOf(RequestRejectedError);
  });

  test('content объектом, а не списком — отказ', async () => {
    const body: JsonObject = {
      input: [{ type: 'message', role: 'user', content: { type: 'input_text', text: PERSON } }],
    };
    await expect(leavesOf(body)).rejects.toBeInstanceOf(RequestRejectedError);
  });

  test('картинка без media-masker по политике strip заменяется заглушкой', async () => {
    const body: JsonObject = {
      input: [{ type: 'message', role: 'user', content: [
        { type: 'input_image', image_url: 'data:image/png;base64,AAAA' },
      ] }],
    };
    const w = new ResponsesWalker('strip');
    await w.walk(body);
    expect(w.strippedAttachments).toBe(1);
    expect(JSON.stringify(body)).not.toContain('base64');
  });
});

describe('RequestMasker в формате openai-responses', () => {
  test('живой запрос уходит без ПДн, справка — после ведущих developer-сообщений', async () => {
    const masker = new RequestMasker(new FakeService(), 'strip');
    const body = realRequest();
    const leadingBefore = (body.input as JsonObject[])
      .findIndex((i) => i.role === 'user' || (i.type !== 'message' && i.type !== 'additional_tools'));
    const stats = await masker.mask(body, 'thread-1', 'openai-responses');
    const text = JSON.stringify(body);
    expect(text).not.toContain(PERSON);
    expect(text).not.toContain(PHONE);
    expect(text).toContain('[PERSON_1]');
    expect(stats.leaves).toBeGreaterThan(0);
    const input = body.input as JsonObject[];
    const note = input[leadingBefore] as JsonObject;
    expect(note.role).toBe('developer');
    expect(JSON.stringify(note)).toContain(SYSTEM_INSERT_TEXT.slice(0, 40));
  });

  test('аргументы function_call маскируются внутри JSON и собираются обратно', async () => {
    const masker = new RequestMasker(new FakeService(), 'strip');
    const body: JsonObject = {
      input: [{
        type: 'function_call', call_id: 'c1', name: 'reply',
        arguments: JSON.stringify({ chat_id: 1, text: `Звоните ${PERSON}, ${PHONE}` }),
      }],
    };
    await masker.mask(body, 't', 'openai-responses');
    const call = (body.input as JsonObject[]).find((i) => i.type === 'function_call') as JsonObject;
    expect(JSON.parse(call.arguments as string)).toEqual({
      chat_id: 1, text: 'Звоните [PERSON_1], [PHONE_1]',
    });
  });

  test('прежний формат по умолчанию не изменился', async () => {
    const masker = new RequestMasker(new FakeService(), 'strip');
    const body: JsonObject = { messages: [{ role: 'user', content: PERSON }] };
    await masker.mask(body, 't');
    expect((body.messages as JsonObject[])[0]?.content).toBe('[PERSON_1]');
    expect(Array.isArray(body.system)).toBe(true);
  });
});

/** Разбор SSE-файла образца в события. */
function sseFile(name: string): SseEvent[] {
  const raw = readFileSync(join(FIXTURES, name), 'utf8');
  return raw.split(/\r?\n\r?\n/).filter((b) => b.trim() !== '').map((block) => {
    let event: string | undefined;
    const data: string[] = [];
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith('event:')) event = line.slice(6).trimStart();
      else if (line.startsWith('data:')) data.push(line.slice(5).replace(/^ /, ''));
    }
    return event === undefined ? { data: data.join('\n') } : { event, data: data.join('\n') };
  });
}

async function* stream(list: SseEvent[]): AsyncGenerator<SseEvent> {
  for (const e of list) yield e;
}

async function run(list: SseEvent[], restorer: Restorer): Promise<JsonObject[]> {
  const out: JsonObject[] = [];
  for await (const e of restoreResponsesSse(stream(list), restorer)) {
    out.push(JSON.parse(e.data) as JsonObject);
  }
  return out;
}

/** Живой поток с ПДн, заменёнными токенами — как ответила бы модель на маскированный запрос. */
function maskedLiveStream(): SseEvent[] {
  return sseFile('real-turn-tool-call.response.sse').map((e) => ({
    ...e, data: e.data.split(PERSON).join('[PERSON_1]').split(PHONE).join('[PHONE_1]'),
  }));
}

describe('restoreResponsesSse на живом потоке Codex', () => {
  test('код инструмента приходит одной восстановленной дельтой и тем же done', async () => {
    const out = await run(maskedLiveStream(), new Restorer(new FakeService(), 't'));
    const deltas = out.filter((j) => j.type === 'response.custom_tool_call_input.delta');
    const done = out.find((j) => j.type === 'response.custom_tool_call_input.done') as JsonObject;
    expect(deltas.length).toBe(1);
    expect(deltas[0]?.delta).toBe(done.input);
    expect(done.input as string).toContain(PERSON);
    expect(JSON.stringify(out)).not.toContain('[PERSON_1]');
    expect(JSON.stringify(out)).not.toContain('[PHONE_1]');
  });

  test('без токенов поток не меняется по тексту', async () => {
    const live = sseFile('real-turn-tool-call.response.sse');
    const out = await run(live, new Restorer(new FakeService(), 't'));
    const text = (list: JsonObject[]): string => list
      .filter((j) => j.type === 'response.output_text.delta').map((j) => j.delta).join('');
    const original = live.map((e) => JSON.parse(e.data) as JsonObject);
    expect(text(out)).toBe(text(original));
    expect(out.at(-1)?.type).toBe('response.completed');
  });
});

describe('restoreResponsesSse: разрезанный токен и память восстановлений', () => {
  const ev = (type: string, extra: JsonObject): SseEvent => ({
    event: type, data: JSON.stringify({ type, ...extra }),
  });

  test('токен, разрезанный между дельтами текста, восстанавливается целиком', async () => {
    const pairs: string[][] = [];
    const restorer = new Restorer(new FakeService(), 't', (a, b) => pairs.push([a, b]));
    const base = { item_id: 'm1', output_index: 0, content_index: 0 };
    const out = await run([
      ev('response.output_text.delta', { ...base, delta: 'Звоню [PERS' }),
      ev('response.output_text.delta', { ...base, delta: 'ON_1] сейчас.' }),
      ev('response.output_text.done', { ...base, text: 'Звоню [PERSON_1] сейчас.' }),
      ev('response.output_item.done', { output_index: 0, item: {
        type: 'message', id: 'm1', role: 'assistant',
        content: [{ type: 'output_text', text: 'Звоню [PERSON_1] сейчас.' }],
      } }),
    ], restorer);
    const text = out.filter((j) => j.type === 'response.output_text.delta')
      .map((j) => j.delta).join('');
    expect(text).toBe(`Звоню ${PERSON} сейчас.`);
    expect(out.find((j) => j.type === 'response.output_text.done')?.text)
      .toBe(`Звоню ${PERSON} сейчас.`);
    const item = out.find((j) => j.type === 'response.output_item.done')?.item as JsonObject;
    expect(JSON.stringify(item)).toContain(PERSON);
    // Пара для памяти: восстановленный текст -> текст модели с токеном
    expect(pairs).toContainEqual([`Звоню ${PERSON} сейчас.`, 'Звоню [PERSON_1] сейчас.']);
  });

  test('аргументы function_call копятся и восстанавливаются по JSON', async () => {
    const restorer = new Restorer(new FakeService(), 't');
    const args = JSON.stringify({ text: 'Привет, [PERSON_1]' });
    const out = await run([
      ev('response.function_call_arguments.delta', { item_id: 'f1', output_index: 0,
        delta: args.slice(0, 15) }),
      ev('response.function_call_arguments.delta', { item_id: 'f1', output_index: 0,
        delta: args.slice(15) }),
      ev('response.function_call_arguments.done', { item_id: 'f1', output_index: 0,
        arguments: args }),
    ], restorer);
    const deltas = out.filter((j) => j.type === 'response.function_call_arguments.delta');
    expect(deltas.length).toBe(1);
    expect(JSON.parse(deltas[0]?.delta as string)).toEqual({ text: `Привет, ${PERSON}` });
    expect(out.at(-1)?.arguments).toBe(deltas[0]?.delta);
  });

  test('сбой восстановления — response.failed, токены наружу не уходят', async () => {
    const broken = new FakeService();
    broken.restore = async () => {
      throw new Error('down');
    };
    const out = await run([
      ev('response.output_text.delta', { item_id: 'm', output_index: 0, content_index: 0,
        delta: 'Это [PERSON_1].' }),
    ], new Restorer(broken, 't'));
    expect(out.at(-1)?.type).toBe('response.failed');
    expect(JSON.stringify(out)).not.toContain('[PERSON_1]');
  });

  test('нестриминговый ответ восстанавливается', async () => {
    const body: JsonObject = { output: [{ type: 'message', id: 'm', content: [
      { type: 'output_text', text: 'Это [PERSON_1]' },
    ] }] };
    await restoreResponsesJson(body, new Restorer(new FakeService(), 't'));
    expect(JSON.stringify(body)).toContain(PERSON);
  });
});
