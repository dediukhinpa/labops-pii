import { MAX_PENDING_TOKEN_CHARS } from './constants';

/** Начало токена `[ТИП_номер|метка]`: `[`, затем необязательно буквы, `_`, цифры, `|`, метка. */
const TOKEN_PREFIX = /^\[(?:[A-Z]+(?:_\d*(?:\|[a-z]{0,4})?)?)?$/;

/**
 * Буфер границы токена для потокового восстановления.
 *
 * Токен `[PERSON_1|datv]` может прийти разрезанным между событиями. Обычный текст отдаётся
 * сразу, задерживается только хвост от последней `[`, который ещё может стать токеном.
 */
export class TokenBoundaryBuffer {
  private pending = '';

  /** Есть ли задержанный хвост (нужен таймер). */
  get hasPending(): boolean {
    return this.pending !== '';
  }

  /** Хвост похож на начало токена: по таймеру его отдавать нельзя. */
  get holdsTokenStart(): boolean {
    return this.pending !== '' && TOKEN_PREFIX.test(this.pending);
  }

  /** Добавить кусок; вернуть текст, который уже можно обрабатывать. */
  push(delta: string): string {
    const text = this.pending + delta;
    const open = text.lastIndexOf('[');
    const tail = open === -1 ? '' : text.slice(open);
    const holds =
      tail !== '' && tail.length <= MAX_PENDING_TOKEN_CHARS && TOKEN_PREFIX.test(tail);
    if (!holds) {
      this.pending = '';
      return text;
    }
    this.pending = tail;
    return text.slice(0, open);
  }

  /** Отдать хвост как есть (конец блока или таймер). */
  flush(): string {
    const text = this.pending;
    this.pending = '';
    return text;
  }
}
