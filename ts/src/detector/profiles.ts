import type { ProfileName } from './types';

/** Настройки профиля, влияющие на детектор ФИО и адресов. */
export interface DetectorProfile {
  /** Имя профиля. */
  name: ProfileName;
  /** Маскировать ли адреса (улица + дом, индекс). */
  maskAddresses: boolean;
  /** Основы слов, которые не ПДн (название проекта). */
  allowedWords: readonly string[];
}

/*
 * «Прагматика» — название проекта, а не ФИО: во всех падежах не маскируется ни в одном
 * профиле (решение владельца 05.11, как ALLOWED_WORDS_DEFAULT в Python-профилях).
 */
const ALLOWED_WORDS_DEFAULT: readonly string[] = ['прагматик'];

/** Профили трёх проектов: значения `mask_addresses` совпадают с `python/labops_pii/profiles.py`. */
export const DETECTOR_PROFILES: Readonly<Record<ProfileName, DetectorProfile>> = {
  labops: { name: 'labops', maskAddresses: false, allowedWords: ALLOWED_WORDS_DEFAULT },
  pragmatika: { name: 'pragmatika', maskAddresses: true, allowedWords: ALLOWED_WORDS_DEFAULT },
  webapp_v2: { name: 'webapp_v2', maskAddresses: false, allowedWords: ALLOWED_WORDS_DEFAULT },
};

/** Профиль по умолчанию (как `DEFAULT_PROFILE` в Python). */
export const DEFAULT_PROFILE_NAME: ProfileName = 'labops';
