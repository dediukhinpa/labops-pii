import { PENDING_FLUSH_MS, RESTORE_MAX_CHARS, RESTORE_WINDOW_MS } from './constants';
import { errorBody } from './errors';
import { isObject, type JsonObject } from './json-leaves';
import { rememberTextBlock } from './json-restore';
import type { Restorer } from './restorer';
import type { SseEvent } from './sse';
import { TokenBoundaryBuffer } from './token-boundary-buffer';

/** Конец предложения или строки: здесь накопленный текст можно восстанавливать. */
const SENTENCE_END = /(?:[.!?…]|\n)["»')\]]*\s*$/;
const TIMEOUT = Symbol('timeout');

/** Параметры восстановления потока (в тестах подменяются часы). */
export interface StreamOptions {
  readonly now?: () => number;
  readonly windowMs?: number;
  readonly pendingFlushMs?: number;
  readonly maxChars?: number;
}

interface TextState {
  readonly buffer: TokenBoundaryBuffer;
  held: string;
  /** Текст блока как прислала модель. */
  raw: string;
  /** Текст блока как отдан клиенту. */
  out: string;
  heldSince: number;
  tailSince: number;
}

/** Событие ошибки потока в формате API. */
export function streamErrorEvent(message: string): SseEvent {
  return { event: 'error', data: JSON.stringify(errorBody('api_error', message)) };
}

function textDelta(index: number, text: string): SseEvent {
  return {
    event: 'content_block_delta',
    data: JSON.stringify({
      type: 'content_block_delta',
      index,
      delta: { type: 'text_delta', text },
    }),
  };
}

function jsonDelta(index: number, json: string): SseEvent {
  return {
    event: 'content_block_delta',
    data: JSON.stringify({
      type: 'content_block_delta',
      index,
      delta: { type: 'input_json_delta', partial_json: json },
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

/**
 * Восстанавливает оригиналы в потоке событий ответа модели с сохранением порядка событий.
 * text_delta проходит через буфер границы токена и копилку (восстановление пачками);
 * input_json_delta копится до content_block_stop и уходит одним куском после восстановления;
 * thinking, signature и прочее идёт как есть. Ошибка восстановления - событие error и конец
 * потока: токены и недовосстановленный текст наружу не отдаются.
 */
export async function* restoreSse(
  upstream: AsyncIterable<SseEvent>,
  restorer: Restorer,
  options: StreamOptions = {},
): AsyncGenerator<SseEvent> {
  const now = options.now ?? ((): number => performance.now());
  const windowMs = options.windowMs ?? RESTORE_WINDOW_MS;
  const flushMs = options.pendingFlushMs ?? PENDING_FLUSH_MS;
  const maxChars = options.maxChars ?? RESTORE_MAX_CHARS;
  const texts = new Map<number, TextState>();
  const tools = new Map<number, string>();
  const iterator = upstream[Symbol.asyncIterator]();

  const due = (s: TextState): boolean =>
    s.held.length >= maxChars || SENTENCE_END.test(s.held) || now() - s.heldSince >= windowMs;

  /** Положить готовый текст блока; отдать восстановленное, если пора или `force`. */
  async function* emit(index: number, s: TextState, text: string, force: boolean) {
    if (text !== '') {
      if (s.held === '' && !text.includes(']')) {
        s.out += text;
        yield textDelta(index, text);
      } else {
        if (s.held === '') s.heldSince = now();
        s.held += text;
      }
    }
    if (s.held !== '' && (force || due(s))) {
      const out = await restorer.text(s.held);
      s.held = '';
      s.out += out;
      yield textDelta(index, out);
    }
  }

  async function* flushAll(): AsyncGenerator<SseEvent> {
    for (const [index, s] of texts) yield* emit(index, s, s.buffer.flush(), true);
  }

  /** Ближайший срок таймера, мс от now (Infinity - таймер не нужен). */
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
    for (const [index, s] of texts) {
      const tailExpired =
        s.buffer.hasPending && !s.buffer.holdsTokenStart && now() - s.tailSince >= flushMs;
      yield* emit(index, s, tailExpired ? s.buffer.flush() : '', false);
      if (s.held !== '' && now() - s.heldSince >= windowMs) yield* emit(index, s, '', true);
    }
  }

  async function* handle(ev: SseEvent): AsyncGenerator<SseEvent> {
    const j = parseData(ev);
    const type = j?.type;
    const index = typeof j?.index === 'number' ? j.index : -1;
    if (type === 'ping') {
      yield ev;
      return;
    }
    const delta = j !== undefined && isObject(j.delta) ? j.delta : undefined;
    if (type === 'content_block_delta' && delta?.type === 'text_delta'
      && typeof delta.text === 'string') {
      const s = texts.get(index);
      if (s !== undefined) {
        s.raw += delta.text;
        const ready = s.buffer.push(delta.text);
        if (s.buffer.hasPending) s.tailSince = now();
        yield* emit(index, s, ready, false);
        return;
      }
    }
    if (type === 'content_block_delta' && delta?.type === 'input_json_delta'
      && typeof delta.partial_json === 'string') {
      tools.set(index, (tools.get(index) ?? '') + delta.partial_json);
      return;
    }
    // Любое другое событие: сначала всё накопленное, чтобы порядок сохранился.
    yield* flushAll();
    if (type === 'content_block_start' && isObject(j?.content_block)) {
      const cb = j.content_block;
      if (cb.type === 'text') {
        texts.set(index, {
          buffer: new TokenBoundaryBuffer(), held: '', raw: '', out: '', heldSince: 0, tailSince: 0,
        });
      } else if (typeof cb.type === 'string' && cb.type.endsWith('tool_use')) {
        tools.set(index, '');
      }
    } else if (type === 'content_block_stop') {
      // Блок закрыт целиком (оборванный поток сюда не доходит): пара идёт в память.
      const closed = texts.get(index);
      if (closed !== undefined) rememberTextBlock(restorer, closed.out, closed.raw);
      texts.delete(index);
      const json = tools.get(index);
      if (json !== undefined) {
        tools.delete(index);
        const input: unknown = json.trim() === '' ? {} : JSON.parse(json);
        const holder = { input };
        await restorer.leaves(holder);
        yield jsonDelta(index, JSON.stringify(holder.input));
      }
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
    // Любой сбой (восстановления, разбора, upstream): текст не отдаём, поток обрываем ошибкой.
    const code = e instanceof Error ? e.name : 'unknown';
    yield streamErrorEvent(`Поток прерван (${code}): восстановление данных не выполнено.`);
  } finally {
    pending?.catch(() => undefined);
    void iterator.return?.()?.catch(() => undefined);
  }
}
