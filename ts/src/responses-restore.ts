import { PENDING_FLUSH_MS, RESTORE_MAX_CHARS, RESTORE_WINDOW_MS } from './constants';
import { isObject, type JsonObject } from './json-leaves';
import { rememberTextBlock } from './json-restore';
import type { Restorer } from './restorer';
import type { SseEvent } from './sse';
import type { StreamOptions } from './stream-restore';
import { TokenBoundaryBuffer } from './token-boundary-buffer';

/**
 * Восстановление оригиналов в потоке ответа OpenAI Responses (Codex CLI).
 *
 * События сняты с живого трафика Codex 0.171.0 (бэкенд ChatGPT):
 * - текст ответа и сводки рассуждений идут дельтами (`response.output_text.delta`,
 *   `response.reasoning_summary_text.delta`, `response.reasoning_text.delta`): они проходят
 *   через буфер границы токена и восстанавливаются пачками по предложениям, как text_delta
 *   у Anthropic;
 * - код инструмента (`response.custom_tool_call_input.delta`) и аргументы
 *   (`response.function_call_arguments.delta`) копятся до `.done` и уходят одним
 *   восстановленным куском: токен внутри кода разрезается между дельтами (в живом потоке их
 *   было 27 на один вызов), а исполнять код с токеном нельзя;
 * - итоговые события (`*.done`, `response.content_part.done`, `response.output_item.done`,
 *   `response.completed`) получают тот же текст, что ушёл дельтами: Codex строит историю из
 *   них, и следующая маска этого текста должна совпасть с тем, что писала модель (память
 *   восстановлений).
 * Сбой восстановления — событие `response.failed` и конец потока: токены и недовосстановленный
 * текст наружу не отдаются.
 */

/** Конец предложения или строки: здесь накопленный текст можно восстанавливать. */
const SENTENCE_END = /(?:[.!?…]|\n)["»')\]]*\s*$/;
const TIMEOUT = Symbol('timeout');

/** Потоковые текстовые события: имя дельты -> имя завершения и поле индекса части. */
const TEXT_STREAMS: Readonly<Record<string, { done: string; part: string }>> = {
  'response.output_text.delta': { done: 'response.output_text.done', part: 'content_index' },
  'response.reasoning_summary_text.delta': {
    done: 'response.reasoning_summary_text.done', part: 'summary_index',
  },
  'response.reasoning_text.delta': { done: 'response.reasoning_text.done', part: 'content_index' },
};
const TEXT_DONE: ReadonlyMap<string, string> = new Map(
  Object.entries(TEXT_STREAMS).map(([delta, v]) => [v.done, delta]),
);

/** Накопительные события: дельта -> завершение и поле с полным значением. */
const HELD_STREAMS: Readonly<Record<string, { done: string; field: string }>> = {
  'response.custom_tool_call_input.delta': {
    done: 'response.custom_tool_call_input.done', field: 'input',
  },
  'response.function_call_arguments.delta': {
    done: 'response.function_call_arguments.done', field: 'arguments',
  },
};
const HELD_DONE: ReadonlyMap<string, string> = new Map(
  Object.entries(HELD_STREAMS).map(([delta, v]) => [v.done, delta]),
);

interface TextState {
  readonly buffer: TokenBoundaryBuffer;
  /** Исходное событие дельты: по нему строятся наши дельты (те же item_id/индексы). */
  readonly template: JsonObject;
  readonly eventName: string;
  held: string;
  raw: string;
  out: string;
  heldSince: number;
  tailSince: number;
}

/** Событие сбоя потока в формате Responses. */
export function responsesFailedEvent(message: string): SseEvent {
  return {
    event: 'response.failed',
    data: JSON.stringify({
      type: 'response.failed',
      response: { status: 'failed', error: { code: 'server_error', message } },
    }),
  };
}

function parseData(ev: SseEvent): JsonObject | undefined {
  try {
    const v: unknown = JSON.parse(ev.data);
    return isObject(v) ? v : undefined;
  } catch {
    return undefined;
  }
}

function eventOf(name: string, body: JsonObject): SseEvent {
  return { event: name, data: JSON.stringify(body) };
}

/** Ключ потоковой части: элемент и индекс части внутри него. */
function partKey(j: JsonObject, partField: string): string {
  const item = typeof j.item_id === 'string' ? j.item_id : `#${String(j.output_index)}`;
  return `${item}\u0000${partField}\u0000${String(j[partField] ?? 0)}`;
}

function itemKey(j: JsonObject): string {
  return typeof j.item_id === 'string' ? j.item_id : `#${String(j.output_index)}`;
}

/** Восстановить строку аргументов function_call: листья JSON, затем сборка обратно. */
async function restoreArguments(raw: string, restorer: Restorer): Promise<string> {
  if (!raw.includes(']')) return raw;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    const out = await restorer.text(raw);
    restorer.remember(out, raw);
    return out;
  }
  const holder: JsonObject = { value: parsed };
  await restorer.leaves(holder);
  return JSON.stringify(holder.value);
}

/**
 * Восстановленные значения элементов ответа, уже отданные клиенту: итоговые события получают
 * ровно их, без повторного обращения к сервису.
 */
class Restored {
  /** Ключ части текста -> восстановленный текст. */
  readonly texts = new Map<string, string>();
  /** Элемент -> восстановленный input/arguments. */
  readonly held = new Map<string, string>();
}

/** Восстановить элемент ответа (output_item.done, response.completed). */
async function restoreItem(item: JsonObject, restorer: Restorer, known: Restored): Promise<void> {
  const id = typeof item.id === 'string' ? item.id : undefined;
  const fromKnown = (field: string, index: number): string | undefined => (
    id === undefined ? undefined : known.texts.get(`${id}\u0000${field}\u0000${index}`)
  );
  const restoreParts = async (parts: unknown, field: string): Promise<void> => {
    if (!Array.isArray(parts)) return;
    for (const [i, part] of parts.entries()) {
      if (!isObject(part) || typeof part.text !== 'string') continue;
      const original = part.text;
      const out = fromKnown(field, i) ?? await restorer.text(original);
      part.text = out;
      rememberTextBlock(restorer, out, original);
    }
  };
  switch (item.type) {
    case 'message':
      await restoreParts(item.content, 'content_index');
      return;
    case 'reasoning':
      await restoreParts(item.summary, 'summary_index');
      await restoreParts(item.content, 'content_index');
      return;
    case 'custom_tool_call':
      if (typeof item.input === 'string') {
        const original = item.input;
        const out = (id === undefined ? undefined : known.held.get(id))
          ?? await restorer.text(original);
        item.input = out;
        restorer.remember(out, original);
      }
      return;
    case 'function_call':
      if (typeof item.arguments === 'string') {
        item.arguments = (id === undefined ? undefined : known.held.get(id))
          ?? await restoreArguments(item.arguments, restorer);
      }
      return;
    case 'local_shell_call':
    case 'web_search_call':
      await restorer.leaves(item.action);
      return;
    default:
      return;
  }
}

/**
 * Восстанавливает оригиналы в потоке событий ответа Responses с сохранением порядка событий.
 * Параметры и поведение таймеров — как у restoreSse.
 */
export async function* restoreResponsesSse(
  upstream: AsyncIterable<SseEvent>,
  restorer: Restorer,
  options: StreamOptions = {},
): AsyncGenerator<SseEvent> {
  const now = options.now ?? ((): number => performance.now());
  const windowMs = options.windowMs ?? RESTORE_WINDOW_MS;
  const flushMs = options.pendingFlushMs ?? PENDING_FLUSH_MS;
  const maxChars = options.maxChars ?? RESTORE_MAX_CHARS;
  const texts = new Map<string, TextState>();
  const held = new Map<string, string>();
  const known = new Restored();
  const iterator = upstream[Symbol.asyncIterator]();

  const due = (s: TextState): boolean =>
    s.held.length >= maxChars || SENTENCE_END.test(s.held) || now() - s.heldSince >= windowMs;

  const deltaEvent = (s: TextState, text: string): SseEvent =>
    eventOf(s.eventName, { ...s.template, delta: text });

  async function* emit(s: TextState, text: string, force: boolean): AsyncGenerator<SseEvent> {
    if (text !== '') {
      if (s.held === '' && !text.includes(']')) {
        s.out += text;
        yield deltaEvent(s, text);
      } else {
        if (s.held === '') s.heldSince = now();
        s.held += text;
      }
    }
    if (s.held !== '' && (force || due(s))) {
      const out = await restorer.text(s.held);
      s.held = '';
      s.out += out;
      yield deltaEvent(s, out);
    }
  }

  /** Дописать весь задержанный текст части и закрыть её (перед её .done). */
  async function* closeText(key: string): AsyncGenerator<SseEvent> {
    const s = texts.get(key);
    if (s === undefined) return;
    yield* emit(s, s.buffer.flush(), true);
    texts.delete(key);
    known.texts.set(key, s.out);
    rememberTextBlock(restorer, s.out, s.raw);
  }

  async function* flushAll(): AsyncGenerator<SseEvent> {
    for (const s of texts.values()) yield* emit(s, s.buffer.flush(), true);
  }

  const nextDeadline = (): number => {
    let at = Number.POSITIVE_INFINITY;
    for (const s of texts.values()) {
      if (s.held !== '') at = Math.min(at, s.heldSince + windowMs);
      if (s.buffer.hasPending && !s.buffer.holdsTokenStart) {
        at = Math.min(at, s.tailSince + flushMs);
      }
    }
    return at;
  };

  async function* onTimer(): AsyncGenerator<SseEvent> {
    for (const s of texts.values()) {
      const tailExpired =
        s.buffer.hasPending && !s.buffer.holdsTokenStart && now() - s.tailSince >= flushMs;
      yield* emit(s, tailExpired ? s.buffer.flush() : '', false);
      if (s.held !== '' && now() - s.heldSince >= windowMs) yield* emit(s, '', true);
    }
  }

  async function* handle(ev: SseEvent): AsyncGenerator<SseEvent> {
    const j = parseData(ev);
    const type = typeof j?.type === 'string' ? j.type : (ev.event ?? '');
    if (j === undefined) {
      yield ev;
      return;
    }
    const textStream = TEXT_STREAMS[type];
    if (textStream !== undefined && typeof j.delta === 'string') {
      const key = partKey(j, textStream.part);
      let s = texts.get(key);
      if (s === undefined) {
        const { delta: _d, ...template } = j;
        s = {
          buffer: new TokenBoundaryBuffer(), template, eventName: ev.event ?? type,
          held: '', raw: '', out: '', heldSince: 0, tailSince: 0,
        };
        texts.set(key, s);
      }
      s.raw += j.delta;
      const ready = s.buffer.push(j.delta);
      if (s.buffer.hasPending) s.tailSince = now();
      yield* emit(s, ready, false);
      return;
    }
    if (HELD_STREAMS[type] !== undefined && typeof j.delta === 'string') {
      const key = itemKey(j);
      held.set(key, (held.get(key) ?? '') + j.delta);
      return;
    }
    // Любое другое событие: сначала всё накопленное, чтобы порядок сохранился.
    const doneOf = TEXT_DONE.get(type);
    if (doneOf !== undefined) {
      const key = partKey(j, (TEXT_STREAMS[doneOf] as { part: string }).part);
      yield* closeText(key);
      yield* flushAll();
      if (typeof j.text === 'string') {
        const out = known.texts.get(key) ?? await restorer.text(j.text);
        if (!known.texts.has(key)) rememberTextBlock(restorer, out, j.text);
        known.texts.set(key, out);
        j.text = out;
      }
      yield eventOf(ev.event ?? type, j);
      return;
    }
    yield* flushAll();
    const heldOf = HELD_DONE.get(type);
    if (heldOf !== undefined) {
      const spec = HELD_STREAMS[heldOf] as { done: string; field: string };
      const key = itemKey(j);
      const raw = typeof j[spec.field] === 'string' ? j[spec.field] as string
        : (held.get(key) ?? '');
      held.delete(key);
      let out: string;
      if (spec.field === 'arguments') {
        out = await restoreArguments(raw, restorer);
      } else {
        out = await restorer.text(raw);
        restorer.remember(out, raw);
      }
      known.held.set(key, out);
      // Одна дельта со всем восстановленным значением, затем завершение с ним же.
      const { [spec.field]: _f, ...rest } = j;
      yield eventOf(heldOf, { ...rest, type: heldOf, delta: out });
      yield eventOf(ev.event ?? type, { ...j, [spec.field]: out });
      return;
    }
    if (type === 'response.content_part.done' && isObject(j.part)
      && typeof j.part.text === 'string') {
      const key = partKey(j, 'content_index');
      const original = j.part.text;
      j.part.text = known.texts.get(key) ?? await restorer.text(original);
      yield eventOf(ev.event ?? type, j);
      return;
    }
    if ((type === 'response.output_item.done' || type === 'response.output_item.added')
      && isObject(j.item)) {
      await restoreItem(j.item, restorer, known);
      yield eventOf(ev.event ?? type, j);
      return;
    }
    if (type === 'response.completed' && isObject(j.response)
      && Array.isArray(j.response.output)) {
      for (const item of j.response.output) {
        if (isObject(item)) await restoreItem(item, restorer, known);
      }
      yield eventOf(ev.event ?? type, j);
      return;
    }
    yield ev;
  }

  let pending: Promise<IteratorResult<SseEvent>> | undefined;
  try {
    for (;;) {
      pending ??= iterator.next();
      const deadline = nextDeadline();
      let result: IteratorResult<SseEvent> | typeof TIMEOUT;
      if (Number.isFinite(deadline)) {
        let timer: ReturnType<typeof setTimeout> | undefined;
        const sleep = new Promise<typeof TIMEOUT>((resolve) => {
          timer = setTimeout(() => resolve(TIMEOUT), Math.max(0, deadline - now()));
        });
        result = await Promise.race([pending, sleep]);
        clearTimeout(timer);
      } else {
        result = await pending;
      }
      if (result === TIMEOUT) {
        yield* onTimer();
        continue;
      }
      pending = undefined;
      if (result.done === true) break;
      yield* handle(result.value);
    }
    yield* flushAll();
  } catch (e) {
    // Любой сбой (восстановления, разбора, upstream): текст не отдаём, поток обрываем.
    const code = e instanceof Error ? e.name : 'unknown';
    yield responsesFailedEvent(`Поток прерван (${code}): восстановление данных не выполнено.`);
  } finally {
    pending?.catch(() => undefined);
    void iterator.return?.()?.catch(() => undefined);
  }
}

/** Восстановить нестриминговый ответ Responses (объект response с output[]). */
export async function restoreResponsesJson(
  body: JsonObject,
  restorer: Restorer,
): Promise<JsonObject> {
  const output = body.output;
  if (!Array.isArray(output)) return body;
  const known = new Restored();
  for (const item of output) if (isObject(item)) await restoreItem(item, restorer, known);
  return body;
}
