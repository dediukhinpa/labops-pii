/** Событие SSE: имя (необязательно) и данные. */
export interface SseEvent {
  readonly event?: string;
  readonly data: string;
}

const EVENT_SEPARATOR = /\r?\n\r?\n/;

/** Разбор потока байтов в события SSE (по пустой строке). */
export async function* parseSse(body: ReadableStream<Uint8Array>): AsyncGenerator<SseEvent> {
  const decoder = new TextDecoder();
  let buf = '';
  const reader = body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      for (;;) {
        const m = EVENT_SEPARATOR.exec(buf);
        if (m === null) break;
        const ev = parseBlock(buf.slice(0, m.index));
        buf = buf.slice(m.index + m[0].length);
        if (ev !== undefined) yield ev;
      }
    }
    buf += decoder.decode();
    const tail = parseBlock(buf);
    if (tail !== undefined) yield tail;
  } finally {
    await reader.cancel().catch(() => undefined);
  }
}

function parseBlock(block: string): SseEvent | undefined {
  let event: string | undefined;
  const data: string[] = [];
  for (const line of block.split(/\r?\n/)) {
    if (line.startsWith('event:')) event = line.slice(6).trimStart();
    else if (line.startsWith('data:')) data.push(line.slice(5).replace(/^ /, ''));
  }
  if (event === undefined && data.length === 0) return undefined;
  return event === undefined ? { data: data.join('\n') } : { event, data: data.join('\n') };
}

/** Сериализация события SSE. */
export function formatSse(ev: SseEvent): string {
  const head = ev.event === undefined ? '' : `event: ${ev.event}\n`;
  return `${head}${ev.data.split('\n').map((l) => `data: ${l}`).join('\n')}\n\n`;
}
