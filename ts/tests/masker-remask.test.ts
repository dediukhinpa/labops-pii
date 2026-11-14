import { describe, expect, test } from 'bun:test';
import { PII_HIDDEN_TEXT, REMASK_MAX_PASSES } from '../src/constants';
import { PseudonymizerError, RequestRejectedError } from '../src/errors';
import type { Logger, LogFields } from '../src/log';
import { RequestMasker } from '../src/masker';
import type { CheckResult, Pseudonymizer } from '../src/pseudonymizer-client';

/** Вымышленный остаток ПДн: /check считает его ФИО, дозаливка заменяет на «[PERSON_9]». */
const RESIDUE = 'ОСТАТОК';

/** Подмена сервиса: маска ничего не меняет, /check видит RESIDUE, дозаливка его убирает. */
class FakeService implements Pseudonymizer {
  checkCalls = 0;
  remaskCalls = 0;
  /** Сколько дозаливок оставляют остаток (для проверки второго прохода и заглушки). */
  stubbornPasses = 0;
  remaskError: PseudonymizerError | undefined;
  withRemask = true;

  async health(): Promise<string> {
    return 'boot-1';
  }

  async pseudonymizeBatch(_t: string, texts: readonly string[]): Promise<string[]> {
    return [...texts];
  }

  async restore(_t: string, text: string): Promise<string> {
    return text;
  }

  async check(text: string): Promise<CheckResult> {
    this.checkCalls++;
    return text.includes(RESIDUE)
      ? { hasPii: true, types: ['PERSON'] }
      : { hasPii: false, types: [] };
  }

  async deleteThread(): Promise<void> {}

  remaskBatch = async (_t: string, texts: readonly string[]): Promise<string[]> => {
    this.remaskCalls++;
    if (this.remaskError !== undefined) throw this.remaskError;
    const stubborn = this.remaskCalls <= this.stubbornPasses;
    return texts.map((t) => (stubborn ? t : t.split(RESIDUE).join('[PERSON_9]')));
  };
}

function body(...texts: string[]): { messages: { role: string; content: string }[] } {
  return { messages: texts.map((content) => ({ role: 'user', content })) };
}

describe('остаток ПДн после маски: дозамаскирование вместо отказа', () => {
  test('второй проход закрывает остаток, запрос не отклоняется', async () => {
    const service = new FakeService();
    const masker = new RequestMasker(service, 'strip');
    const b = body(`письмо ${RESIDUE} кандидату`, 'чистый лист');
    const stats = await masker.mask(b, 't1');
    expect(b.messages.map((m) => m.content)).toEqual([
      'письмо [PERSON_9] кандидату',
      'чистый лист',
    ]);
    expect(stats.remaskedLeaves).toBe(1);
    expect(stats.hiddenLeaves).toBe(0);
  });

  test('итог запоминается: на следующем запросе нет ни дозаливки, ни /check', async () => {
    const service = new FakeService();
    const masker = new RequestMasker(service, 'strip');
    await masker.mask(body(`карточка ${RESIDUE}`), 't1');
    const remask = service.remaskCalls;
    const checks = service.checkCalls;
    const b = body(`карточка ${RESIDUE}`);
    const stats = await masker.mask(b, 't1');
    expect(b.messages[0]?.content).toBe('карточка [PERSON_9]');
    expect(service.remaskCalls).toBe(remask);
    expect(service.checkCalls).toBe(checks);
    expect(stats.remaskedLeaves).toBe(0);
    expect(stats.cacheHits).toBe(1);
  });

  test('остаток после первого прохода закрывается вторым', async () => {
    const service = new FakeService();
    service.stubbornPasses = REMASK_MAX_PASSES - 1;
    const masker = new RequestMasker(service, 'strip');
    const b = body(`лист ${RESIDUE}`);
    const stats = await masker.mask(b, 't1');
    expect(b.messages[0]?.content).toBe('лист [PERSON_9]');
    expect(service.remaskCalls).toBe(REMASK_MAX_PASSES);
    expect(stats.remaskedLeaves).toBe(1);
  });

  test('остаток не уходит за REMASK_MAX_PASSES проходов: лист скрыт заглушкой', async () => {
    const service = new FakeService();
    service.stubbornPasses = 99;
    const events: { event: string; fields?: LogFields | undefined }[] = [];
    const logger: Logger = { log: (event, fields) => void events.push({ event, fields }) };
    const masker = new RequestMasker(service, 'strip', false, undefined, { logger });
    const b = body(`лист ${RESIDUE}`, 'чистый лист');
    const stats = await masker.mask(b, 't1');
    expect(b.messages.map((m) => m.content)).toEqual([PII_HIDDEN_TEXT, 'чистый лист']);
    expect(service.remaskCalls).toBe(REMASK_MAX_PASSES);
    expect(stats.hiddenLeaves).toBe(1);
    // Журнал: счётчики и виды, без текста листа
    expect(events).toHaveLength(1);
    expect(JSON.stringify(events)).not.toContain(RESIDUE);
    expect(events[0]?.fields?.hidden_leaves).toBe(1);
    expect(events[0]?.fields?.pii_types).toEqual(['PERSON']);
    // Следующий запрос: заглушка из кэша, сервис не зовётся
    const calls = service.remaskCalls;
    const again = body(`лист ${RESIDUE}`);
    await masker.mask(again, 't1');
    expect(again.messages[0]?.content).toBe(PII_HIDDEN_TEXT);
    expect(service.remaskCalls).toBe(calls);
  });

  test('сервис без дозаливки (подмена или старая версия): заглушка, не отказ', async () => {
    const service = new FakeService();
    service.remaskBatch = undefined as never;
    const masker = new RequestMasker(service, 'strip');
    const b = body(`лист ${RESIDUE}`);
    await masker.mask(b, 't1');
    expect(b.messages[0]?.content).toBe(PII_HIDDEN_TEXT);
  });

  test('сервис отвечает 404 на /remask_batch (старая версия): заглушка', async () => {
    const service = new FakeService();
    service.remaskError = new PseudonymizerError('http_404');
    const masker = new RequestMasker(service, 'strip');
    const b = body(`лист ${RESIDUE}`);
    await masker.mask(b, 't1');
    expect(b.messages[0]?.content).toBe(PII_HIDDEN_TEXT);
  });

  test('технический сбой дозаливки по-прежнему fail closed', async () => {
    const service = new FakeService();
    service.remaskError = new PseudonymizerError('timeout');
    const masker = new RequestMasker(service, 'strip');
    await expect(masker.mask(body(`лист ${RESIDUE}`), 't1')).rejects.toBeInstanceOf(
      PseudonymizerError,
    );
  });

  test('onResidualPii: reject возвращает прежний отказ 422', async () => {
    const service = new FakeService();
    const masker = new RequestMasker(service, 'strip', false, undefined, {
      onResidualPii: 'reject',
    });
    const err = await masker.mask(body(`лист ${RESIDUE}`), 't1').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RequestRejectedError);
    expect((err as RequestRejectedError).code).toBe('pii_after_mask');
    expect(service.remaskCalls).toBe(0);
  });

  test('длинный лист режется на части, остаток в любой части закрыт', async () => {
    const service = new FakeService();
    const masker = new RequestMasker(service, 'strip');
    const filler = 'слово '.repeat(30_000);
    const b = body(`${filler}${RESIDUE} ${filler}`);
    await masker.mask(b, 't1');
    const out = b.messages[0]?.content as string;
    expect(out).toContain('[PERSON_9]');
    expect(out).not.toContain(RESIDUE);
    expect(out.length).toBe(filler.length * 2 + ' [PERSON_9]'.length);
  });

  test('вложенный JSON tool_result: остаток в листе закрыт, соседние листья целы', async () => {
    const service = new FakeService();
    const masker = new RequestMasker(service, 'strip');
    const b = {
      messages: [{
        role: 'user',
        content: [{
          type: 'tool_result',
          tool_use_id: 'x',
          content: [{ type: 'text', text: `{"name":"${RESIDUE}"}` }, { type: 'text', text: 'ok' }],
        }],
      }],
    };
    await masker.mask(b as never, 't1');
    const inner = (b.messages[0]?.content[0] as { content: { text: string }[] }).content;
    expect(inner.map((x) => x.text)).toEqual(['{"name":"[PERSON_9]"}', 'ok']);
  });
});

describe('враждебные тела: время растёт линейно', () => {
  /** Время одного прогона масок на листе заданной длины с остатком в конце. */
  async function timed(size: number): Promise<number> {
    const service = new FakeService();
    const masker = new RequestMasker(service, 'strip');
    const text = `${'а'.repeat(size)} ${RESIDUE}`;
    const started = performance.now();
    await masker.mask(body(text), `t-${size}`);
    return performance.now() - started;
  }

  test('длинный повтор без пробелов и большой JSON не дают квадрата', async () => {
    await timed(10_000); // прогрев
    const small = await timed(400_000);
    const large = await timed(1_600_000);
    // 4x по длине: линейный рост даёт около 4x; квадратичный дал бы около 16x
    expect(large).toBeLessThan(Math.max(small * 8, 2_000));
  });

  test('JSON из сотен тысяч листьев маскируется без квадрата', async () => {
    const service = new FakeService();
    const masker = new RequestMasker(service, 'strip');
    const leaves = Array.from({ length: 20_000 }, (_, i) => `значение ${i} ${RESIDUE}`);
    const started = performance.now();
    const b = body(...leaves);
    await masker.mask(b, 't1');
    expect(performance.now() - started).toBeLessThan(5_000);
    expect(b.messages.every((m) => !m.content.includes(RESIDUE))).toBe(true);
  });
});
