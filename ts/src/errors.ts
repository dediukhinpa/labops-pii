/** Сбой сервиса псевдонимизации: запрос не отправляется наружу (fail closed). */
export class PseudonymizerError extends Error {
  constructor(readonly code: string) {
    super(`pseudonymizer: ${code}`);
    this.name = 'PseudonymizerError';
  }
}

/** Во входящем запросе найдены ПДн или недопустимое содержимое (ответ 422). */
export class RequestRejectedError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly code: string,
    readonly piiTypes: readonly string[] = [],
  ) {
    super(message);
    this.name = 'RequestRejectedError';
  }
}

/** Тело ошибки в формате API. */
export interface AnthropicErrorBody {
  readonly type: 'error';
  readonly error: { readonly type: string; readonly message: string };
}

/** Собрать тело ошибки в формате API. */
export function errorBody(type: string, message: string): AnthropicErrorBody {
  return { type: 'error', error: { type, message } };
}

/** Ответ-ошибка в формате API. */
export function errorResponse(status: number, type: string, message: string): Response {
  return new Response(JSON.stringify(errorBody(type, message)), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/**
 * Сбой или отказ media-masker по вложению. `refused` - файл обработать нельзя (запрос
 * отклоняется 422), `unavailable` - сервис недоступен или ответил неверно (503, fail closed).
 */
export class MediaMaskerError extends Error {
  constructor(
    readonly kind: 'refused' | 'unavailable',
    readonly code: string,
  ) {
    super(`media-masker: ${kind}: ${code}`);
    this.name = 'MediaMaskerError';
  }
}
