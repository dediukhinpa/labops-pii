import { describe, expect, test } from 'bun:test';
import { RequestMasker, THREAD_EPOCHS_MAX, THREAD_IDLE_RESET_MS } from '../src/masker';
import type { CheckResult, Pseudonymizer } from '../src/pseudonymizer-client';

/** Сервис с таблицей по треду: нумерация с 1, тред можно удалить (как ретенция сервера). */
class FakeService implements Pseudonymizer {
  readonly threads = new Map<string, Map<string, string>>();
  calls = 0;

  async health(): Promise<string> {
    return 'boot-1';
  }

  async pseudonymizeBatch(threadId: string, texts: readonly string[]): Promise<string[]> {
    this.calls += texts.length;
    const table = this.threads.get(threadId) ?? new Map<string, string>();
    this.threads.set(threadId, table);
    return texts.map((text) => {
      const known = table.get(text);
      if (known !== undefined) return known;
      const token = `[PERSON_${table.size + 1}]`;
      table.set(text, token);
      return token;
    });
  }

  async restore(_threadId: string, text: string): Promise<string> {
    return text;
  }

  async check(): Promise<CheckResult> {
    return { hasPii: false, types: [] };
  }

  async deleteThread(threadId: string): Promise<void> {
    this.threads.delete(threadId);
  }
}

function body(...texts: string[]): { messages: { role: string; content: string }[] } {
  return { messages: texts.map((content) => ({ role: 'user', content })) };
}

async function masked(masker: RequestMasker, ...texts: string[]): Promise<string[]> {
  const b = body(...texts);
  await masker.mask(b, 't1');
  return b.messages.map((m) => m.content);
}

describe('кэш маскирования после удаления треда на сервере', () => {
  test('после долгого простоя кэш треда не используется', async () => {
    const service = new FakeService();
    let clock = 0;
    const masker = new RequestMasker(service, 'strip', false, undefined, { now: () => clock });
    expect(await masked(masker, 'Иванов')).toEqual(['[PERSON_1]']);
    // Сервис удалил тред по сроку хранения; boot_id прежний
    service.threads.delete('t1');
    clock += THREAD_IDLE_RESET_MS + 1;
    // «Иванов» замаскирован заново той же таблицей, что и «Петров»: разные люди - разные токены
    const [ivanov, petrov] = await masked(masker, 'Иванов', 'Петров');
    expect(ivanov).not.toEqual(petrov);
  });

  test('forgetThread сбрасывает кэш сразу', async () => {
    const service = new FakeService();
    const masker = new RequestMasker(service, 'strip');
    await masked(masker, 'Иванов');
    await service.deleteThread('t1');
    masker.forgetThread('t1');
    const [ivanov, petrov] = await masked(masker, 'Иванов', 'Петров');
    expect(ivanov).not.toEqual(petrov);
  });

  test('в пределах простоя кэш работает', async () => {
    const service = new FakeService();
    let clock = 0;
    const masker = new RequestMasker(service, 'strip', false, undefined, { now: () => clock });
    await masked(masker, 'Иванов');
    const before = service.calls;
    clock += THREAD_IDLE_RESET_MS - 1;
    await masked(masker, 'Иванов');
    expect(service.calls).toBe(before);
  });
});

describe('поколения кэша при вытеснении записи треда', () => {
  test('после forgetThread и вытеснения старые маски треда недоступны', async () => {
    const service = new FakeService();
    const masker = new RequestMasker(service, 'strip');
    await masked(masker, 'Иванов');
    await service.deleteThread('t1');
    masker.forgetThread('t1');
    // Вытесняем запись t1 из таблицы поколений
    for (let i = 0; i <= THREAD_EPOCHS_MAX; i++) masker.forgetThread(`other-${i}`);
    const [ivanov, petrov] = await masked(masker, 'Иванов', 'Петров');
    expect(ivanov).not.toEqual(petrov);
  });
});
