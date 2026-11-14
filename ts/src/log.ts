import { createHash } from 'node:crypto';
import { SESSION_HASH_CHARS } from './constants';

/** Поля записи журнала: только коды и счётчики, никаких текстов. */
export interface LogFields {
  readonly route?: string;
  readonly status?: number;
  readonly duration_ms?: number;
  readonly code?: string;
  readonly session?: string;
  readonly masked_leaves?: number;
  readonly cache_hits?: number;
  readonly remembered_leaves?: number;
  readonly forgotten_leaves?: number;
  /** Листьев, дозамаскированных вторым проходом после находки /check. */
  readonly remasked_leaves?: number;
  /** Листьев, скрытых заглушкой: ПДн остались и после второго прохода. */
  readonly hidden_leaves?: number;
  readonly masked_attachments?: number;
  /** Скрытые пометкой вложения: причина (закрытый список) -> число. Без значений ПДн. */
  readonly blocked_attachments?: Readonly<Record<string, number>>;
  readonly restored_tokens?: number;
  readonly pii_types?: readonly string[];
  readonly count?: number;
}

/** Приёмник журнала (в тестах подменяется). */
export interface Logger {
  log(event: string, fields?: LogFields): void;
}

/** Журнал-пустышка. */
export const nullLogger: Logger = { log(): void {} };

/** Короткий отпечаток session id для журнала (сам id не пишется). */
export function sessionFingerprint(sessionId: string): string {
  return createHash('sha256').update(sessionId).digest('hex').slice(0, SESSION_HASH_CHARS);
}
