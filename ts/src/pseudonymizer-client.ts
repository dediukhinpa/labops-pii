import { z } from 'zod';
import { PseudonymizerError } from './errors';

const healthSchema = z.object({ boot_id: z.string().min(1) });
const batchSchema = z.object({ items: z.array(z.object({ text: z.string() })) });
const restoreSchema = z.object({ text: z.string() });
const checkSchema = z.object({ has_pii: z.boolean(), types: z.array(z.string()) });

/** Результат /check. */
export interface CheckResult {
  readonly hasPii: boolean;
  readonly types: readonly string[];
}

/** Что нужно прокси от сервиса псевдонимизации (в тестах подменяется). */
export interface Pseudonymizer {
  health(): Promise<string>;
  pseudonymizeBatch(threadId: string, texts: readonly string[]): Promise<string[]>;
  restore(threadId: string, text: string): Promise<string>;
  check(text: string, threadId?: string): Promise<CheckResult>;
  /**
   * Второй проход по уже замаскированным текстам (маршрут /remask_batch, с 1.1.0): новые токены
   * той же нумерации и из той же таблицы треда. Необязателен: сервис или подмена без него
   * дают скрытие листа целиком (см. RequestMasker).
   */
  remaskBatch?(threadId: string, texts: readonly string[]): Promise<string[]>;
  deleteThread(threadId: string): Promise<void>;
}

/** Настройки HTTP-клиента сервиса. */
export interface ClientOptions {
  readonly baseUrl: string;
  readonly token: string;
  readonly timeoutMs: number;
  /** Слать `case_labels: true` в /pseudonymize_batch; false - поле не отправляется вовсе. */
  readonly caseLabels?: boolean;
}

/** HTTP-клиент сервиса. Любой сбой (сеть, таймаут, не 2xx, неверный ответ) - PseudonymizerError. */
export class HttpPseudonymizer implements Pseudonymizer {
  constructor(private readonly options: ClientOptions) {}

  async health(): Promise<string> {
    const data = await this.call('GET', '/health', undefined, false);
    return parseWith(healthSchema, data).boot_id;
  }

  async pseudonymizeBatch(threadId: string, texts: readonly string[]): Promise<string[]> {
    // Без флага тело такое же, как у старого сервиса: поле case_labels не добавляется.
    const body = this.options.caseLabels === true
      ? { thread_id: threadId, texts, case_labels: true }
      : { thread_id: threadId, texts };
    const data = await this.call('POST', '/pseudonymize_batch', body);
    const items = parseWith(batchSchema, data).items;
    if (items.length !== texts.length) throw new PseudonymizerError('batch_size_mismatch');
    return items.map((i) => i.text);
  }

  async remaskBatch(threadId: string, texts: readonly string[]): Promise<string[]> {
    const body = this.options.caseLabels === true
      ? { thread_id: threadId, texts, case_labels: true }
      : { thread_id: threadId, texts };
    const items = parseWith(batchSchema, await this.call('POST', '/remask_batch', body)).items;
    if (items.length !== texts.length) throw new PseudonymizerError('batch_size_mismatch');
    return items.map((i) => i.text);
  }

  async restore(threadId: string, text: string): Promise<string> {
    const data = await this.call('POST', '/restore', { thread_id: threadId, text });
    return parseWith(restoreSchema, data).text;
  }

  async check(text: string, threadId?: string): Promise<CheckResult> {
    const body = threadId === undefined ? { text } : { text, thread_id: threadId };
    const r = parseWith(checkSchema, await this.call('POST', '/check', body));
    return { hasPii: r.has_pii, types: r.types };
  }

  async deleteThread(threadId: string): Promise<void> {
    await this.call('DELETE', `/threads/${encodeURIComponent(threadId)}`, undefined, true, true);
  }

  private async call(
    method: string,
    path: string,
    body?: unknown,
    auth = true,
    noContent = false,
  ): Promise<unknown> {
    const headers: Record<string, string> = {};
    if (auth) headers.authorization = `Bearer ${this.options.token}`;
    if (body !== undefined) headers['content-type'] = 'application/json';
    let res: Response;
    try {
      res = await fetch(`${this.options.baseUrl}${path}`, {
        method,
        headers,
        body: body === undefined ? null : JSON.stringify(body),
        signal: AbortSignal.timeout(this.options.timeoutMs),
      });
    } catch (e) {
      const timeout = e instanceof Error && e.name === 'TimeoutError';
      throw new PseudonymizerError(timeout ? 'timeout' : 'unreachable');
    }
    if (!res.ok) {
      await res.body?.cancel().catch(() => undefined);
      throw new PseudonymizerError(`http_${res.status}`);
    }
    if (noContent) {
      await res.body?.cancel().catch(() => undefined);
      return undefined;
    }
    try {
      return (await res.json()) as unknown;
    } catch {
      throw new PseudonymizerError('invalid_json');
    }
  }
}

function parseWith<T>(schema: z.ZodType<T>, data: unknown): T {
  const r = schema.safeParse(data);
  if (!r.success) throw new PseudonymizerError('invalid_response');
  return r.data;
}
