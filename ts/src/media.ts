import { createHash } from 'node:crypto';
import { MEDIA_CACHE_MAX_CHARS } from './constants';
import { BoundedCache } from './mask-cache';
import { MediaMaskerError } from './errors';
import type { ExtractedDocument, MaskedImage, MediaMasker } from './media-client';

/**
 * Закрытый список причин, по которым вложение не ушло к модели. Только эти метки попадают в
 * текст-заглушку, журнал и счётчики: коды сервиса и тексты ошибок наружу не идут.
 */
export type BlockReason =
  | 'not_base64' | 'unsupported_type' | 'too_large' | 'too_many_pages' | 'unreadable'
  | 'pii_remains' | 'refused_other' | 'timeout' | 'service_unavailable';

const REFUSAL_REASONS: Readonly<Record<string, BlockReason>> = {
  file_too_large: 'too_large',
  image_too_many_pixels: 'too_large',
  http_413: 'too_large',
  pdf_too_many_pages: 'too_many_pages',
  image_undecodable: 'unreadable',
  bad_base64: 'unreadable',
  empty_file: 'unreadable',
  pdf_unreadable: 'unreadable',
  unsupported_media_type: 'unsupported_type',
  pii_remains_after_masking: 'pii_remains',
};

/** Свести ошибку media-masker к метке из закрытого списка. */
export function blockReason(e: MediaMaskerError): BlockReason {
  if (e.kind === 'unavailable') return e.code === 'timeout' ? 'timeout' : 'service_unavailable';
  return REFUSAL_REASONS[e.code] ?? 'refused_other';
}

/** Метка начала записи кэша с отказом (в base64 и JSON не встречается в начале значения). */
const REFUSED_MARK = '!';

/**
 * Вложения через media-masker с кэшем результата по sha256 исходных данных.
 * Кэш нужен, чтобы история с картинками не перегонялась через OCR на каждом запросе и чтобы
 * замаскированные байты были одинаковыми (иначе ломается кэш промпта Anthropic).
 */
export class MediaProcessor {
  private readonly cache = new BoundedCache(MEDIA_CACHE_MAX_CHARS);
  /** Сколько раз результат взят из кэша (для журнала и тестов). */
  cacheHits = 0;
  /** Сколько вызовов ушло в media-masker. */
  serviceCalls = 0;

  constructor(private readonly service: MediaMasker) {}

  /** Замаскировать картинку (base64). */
  async maskImage(mediaType: string, data: string): Promise<MaskedImage> {
    const key = cacheKey('image', mediaType, data);
    const hit = this.cache.get(key);
    if (hit !== undefined) {
      this.cacheHits++;
      throwIfRefused(hit);
      return JSON.parse(hit) as MaskedImage;
    }
    this.serviceCalls++;
    const r = await this.guarded(key, () => this.service.maskImage(mediaType, data));
    // Вместе с картинкой кэшируется распознанный текст: без него каждый запрос с этой картинкой
    // в истории гонял бы её через OCR заново, а текст блока менялся бы от запроса к запросу
    this.cache.set(key, JSON.stringify(r));
    return r;
  }

  /** Разобрать PDF (base64): текстовый слой или замаскированные страницы-картинки. */
  async extractDocument(data: string): Promise<ExtractedDocument> {
    const key = cacheKey('pdf', 'application/pdf', data);
    const hit = this.cache.get(key);
    if (hit !== undefined) {
      this.cacheHits++;
      throwIfRefused(hit);
      return JSON.parse(hit) as ExtractedDocument;
    }
    this.serviceCalls++;
    const r = await this.guarded(key, () => this.service.extractDocument(data));
    this.cache.set(key, JSON.stringify(r));
    return r;
  }

  /**
   * Вызов сервиса. Отказ по самому файлу (слишком большой, не читается) детерминирован и
   * кэшируется: иначе тяжёлый файл в истории гонялся бы по сети на каждом запросе. Сбой
   * сервиса не кэшируется: после восстановления вложение должно обработаться.
   */
  private async guarded<T>(key: string, call: () => Promise<T>): Promise<T> {
    try {
      return await call();
    } catch (e) {
      if (e instanceof MediaMaskerError && e.kind === 'refused') {
        this.cache.set(key, `${REFUSED_MARK}${e.code}`);
      }
      throw e;
    }
  }
}

function cacheKey(kind: string, mediaType: string, data: string): string {
  return createHash('sha256').update(`${kind}\u0000${mediaType}\u0000${data}`).digest('hex');
}

function throwIfRefused(cached: string): void {
  if (cached.startsWith(REFUSED_MARK)) {
    throw new MediaMaskerError('refused', cached.slice(REFUSED_MARK.length));
  }
}
