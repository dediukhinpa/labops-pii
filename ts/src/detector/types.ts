import { z } from 'zod';

/** Имена профилей настроек (как в Python-части: `labops_pii/profiles.py`). */
export const PROFILE_NAMES = ['labops', 'pragmatika', 'webapp_v2'] as const;
export type ProfileName = (typeof PROFILE_NAMES)[number];

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

/** Настройки детектора. Всё необязательно: по умолчанию профиль `labops`. */
export interface DetectorOptions {
  /** Профиль настроек; задаёт, маскируются ли адреса и какие слова в белом списке. */
  profile?: ProfileName | undefined;
  /** Перекрывает флаг профиля «маскировать адреса» для `detectPii`. */
  maskAddresses?: boolean | undefined;
  /** Дополнительные основы слов белого списка (как PII_ALLOWED_WORDS в Python). */
  allowedWords?: readonly string[] | undefined;
  /** Искать латинские ФИО после метки контакта («Contact: Li Wei»); по умолчанию да. */
  latinNames?: boolean | undefined;
}

/** Схема проверки настроек во время выполнения (вход библиотеки — недоверенный). */
export const DetectorOptionsSchema = z
  .object({
    profile: z.enum(PROFILE_NAMES).optional(),
    maskAddresses: z.boolean().optional(),
    allowedWords: z.array(z.string()).optional(),
    latinNames: z.boolean().optional(),
  })
  .strict();

/** Схема текста на входе: только строка. */
export const DetectorTextSchema = z.string();
