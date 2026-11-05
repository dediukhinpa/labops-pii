import {
  RECOGNIZED_BARCODE_PREFIX, RECOGNIZED_CODE_UNREAD, RECOGNIZED_HEADER, RECOGNIZED_HIDDEN_NOTE,
  RECOGNIZED_QR_PREFIX,
} from './constants';
import type { Recognized } from './media-client';

/**
 * Текст блока, который идёт модели вместе с закрашенной картинкой: распознанный локально
 * текст, содержимое QR и штрихкодов, пометка о скрытом нераспознанном тексте. Блок - обычный
 * лист запроса: ПДн в нём заменяет то же маскирование, что и в остальном тексте, а вторая
 * линия (/check) проверяет результат. Строка зависит только от содержимого картинки.
 * @returns null, если на картинке ничего не найдено (блок не нужен).
 */
export function recognizedBlockText(rec: Recognized): string | null {
  const lines: string[] = [];
  const text = rec.text.trim();
  if (text !== '') lines.push(text);
  for (const code of rec.codes) {
    const prefix = code.kind === 'barcode' ? RECOGNIZED_BARCODE_PREFIX : RECOGNIZED_QR_PREFIX;
    const content = code.text.trim();
    lines.push(`${prefix}${content === '' ? RECOGNIZED_CODE_UNREAD : content}`);
  }
  if (rec.hiddenText) lines.push(RECOGNIZED_HIDDEN_NOTE);
  if (lines.length === 0) return null;
  // Одна пометка о скрытом тексте без остального: заголовок про распознанный текст лишний
  if (text === '' && rec.codes.length === 0) return lines.join('\n');
  return [RECOGNIZED_HEADER, ...lines].join('\n');
}
