import { z } from 'zod';

/** Вид найденного фрагмента. */
export type DetectedKind = 'person' | 'address';

/** Найденный фрагмент текста: границы в UTF-16-единицах, как у `String.prototype.slice`. */
export interface DetectedSpan {
  /** Начало (включительно). */
  start: number;
  /** Конец (не включительно). */
  end: number;
  /** Вид данных. */
  kind: DetectedKind;
  /** Найденный текст (`text.slice(start, end)`). */
  text: string;
}

/**
 * Настройки детектора. Всё необязательно; профилей нет, настройку задаёт вызывающий код
 * (обычно из своего окружения: `PSEUDONYMIZER_ADDRESS_MASK`, `PII_ALLOWED_WORDS`).
 */
export interface DetectorOptions {
  /** Искать ли адреса в `detectNamesAndAddresses`; по умолчанию нет. */
  maskAddresses?: boolean | undefined;
  /** Основы слов белого списка (как PII_ALLOWED_WORDS в Python); по умолчанию пусто. */
  allowedWords?: readonly string[] | undefined;
  /** Искать латинские ФИО после метки контакта («Contact: Li Wei»); по умолчанию да. */
  latinNames?: boolean | undefined;
}

/** Схема проверки настроек во время выполнения (вход библиотеки — недоверенный). */
export const DetectorOptionsSchema = z
  .object({
    maskAddresses: z.boolean().optional(),
    allowedWords: z.array(z.string()).optional(),
    latinNames: z.boolean().optional(),
  })
  .strict();

/** Схема текста на входе: только строка. */
export const DetectorTextSchema = z.string();
