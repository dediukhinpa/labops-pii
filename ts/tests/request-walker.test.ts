import { describe, expect, test } from 'bun:test';
import { RequestRejectedError } from '../src/errors';
import { RequestWalker } from '../src/request-walker';
import type { JsonObject } from '../src/json-leaves';

const PII = 'Клиент Иванов Иван, тел. +7 916 123-45-67';

async function leaves(body: JsonObject): Promise<string[]> {
  const walker = new RequestWalker('strip');
  await walker.walk(body);
  return walker.leaves.map((leaf) => leaf.text);
}

describe('обход тела: неизвестная форма отклоняется, а не пропускается', () => {
  test('system-объект', async () => {
    const body = { system: { type: 'text', text: PII }, messages: [] };
    await expect(leaves(body)).rejects.toBeInstanceOf(RequestRejectedError);
  });

  test('content-объект в сообщении', async () => {
    const body = { messages: [{ role: 'user', content: { type: 'text', text: PII } }] };
    await expect(leaves(body)).rejects.toBeInstanceOf(RequestRejectedError);
  });

  test('строка вместо блока в списке', async () => {
    const body = { messages: [{ role: 'user', content: [PII] }] };
    await expect(leaves(body)).rejects.toBeInstanceOf(RequestRejectedError);
  });

  test('content-объект внутри tool_result', async () => {
    const block = { type: 'tool_result', tool_use_id: 't', content: { text: PII } };
    const body = { messages: [{ role: 'user', content: [block] }] };
    await expect(leaves(body)).rejects.toBeInstanceOf(RequestRejectedError);
  });

  test('обычные формы по-прежнему собираются', async () => {
    const body = {
      system: [{ type: 'text', text: 'sys' }],
      messages: [{ role: 'user', content: PII }, { role: 'assistant', content: [] }],
    };
    expect(await leaves(body)).toEqual(['sys', PII]);
  });
});
