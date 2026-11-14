import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync, unlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import {
  CONSENT_DIR_MODE, CONSENT_FILE_MODE, CONSENT_MEDIA_ID_PREFIX, CONSENT_MEDIA_ID_HEX_CHARS,
  CONSENT_OFFERS_DIR, CONSENT_OFFER_KEEP_MS, CONSENT_SWEEP_INTERVAL_MS, CONSENT_TTL_MS,
  CONSENT_CLOCK_SKEW_MS, CONSENT_KIND_RE, CONSENT_MAX_KINDS,
} from './constants';

/**
 * Разрешение владельца отправить ОРИГИНАЛ вложения модели (минуя media-masker).
 *
 * Поток: прокси видит вложение, на котором найдены ПДн, отдаёт модели закрашенную версию и
 * записывает «предложение» (offers/<id>.json: отпечаток и типы находок). Агент просит
 * разрешение через инструмент канала; владелец отвечает одноразовым кодом; канал пишет файл
 * `<sha256>.json`. Прокси на следующем запросе находит файл по отпечатку и отдаёт оригинал.
 *
 * Граница доверия: все процессы одного пользователя ОС, поэтому защита рассчитана на «агента
 * уговорили разрешить самому» (инструмента записи разрешения нет), а не на полный взлом
 * процесса агента: он технически может записать файл сам.
 */
export interface ApprovedConsent {
  /** Отпечаток исходных байт (sha256, hex). */
  readonly sha256: string;
  /** Короткий идентификатор вложения (как в тексте для модели). */
  readonly mediaId: string;
  /** Типы ПДн, о которых знал владелец при подтверждении. */
  readonly kinds: readonly string[];
}

/** Зависимость маскера вложений: разрешения и предложения (в тестах подменяется). */
export interface MediaConsentGate {
  /** Действующее разрешение на файл с таким отпечатком, иначе undefined (fail closed). */
  approved(sha256: string): ApprovedConsent | undefined;
  /**
   * Записать предложение «этот файл можно запросить у владельца».
   * @returns Короткий идентификатор вложения.
   */
  offer(sha256: string, kinds: readonly string[]): string;
}

/** sha256 исходных байт вложения из base64 (hex). */
export function mediaFingerprint(base64Data: string): string {
  return createHash('sha256').update(Buffer.from(base64Data, 'base64')).digest('hex');
}

/** Короткий идентификатор вложения: буква + начало отпечатка (всегда содержит букву). */
export function mediaIdOf(sha256: string): string {
  return `${CONSENT_MEDIA_ID_PREFIX}${sha256.slice(0, CONSENT_MEDIA_ID_HEX_CHARS)}`;
}

/** Только допустимые типы ПДн (метки сервиса: PHONE, PERSON, FACE...), без значений. */
export function sanitizeKinds(kinds: readonly string[]): string[] {
  const clean = kinds.filter((k) => CONSENT_KIND_RE.test(k));
  return [...new Set(clean)].sort().slice(0, CONSENT_MAX_KINDS);
}

const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);
const recordSchema = z.object({
  sha256: sha256Schema,
  agent: z.string().min(1),
  kinds: z.array(z.string()).default([]),
  approved_by: z.number().int().positive(),
  approved_at: z.string().datetime(),
  expires_at: z.string().datetime(),
});
/** Настройки файлового хранилища разрешений. */
export interface FileConsentOptions {
  /** Каталог разрешений (`~/.config/labops-pii/consent`). */
  readonly dir: string;
  /** Агент этого прокси: разрешение, выданное другому агенту, не действует. */
  readonly agentId: string;
  /** Часы (в тестах подменяются). */
  readonly now?: () => number;
  /** Срок действия разрешения с момента подтверждения, мс. */
  readonly ttlMs?: number;
}

/**
 * Хранилище на файлах. Читает разрешения, пишет только предложения; файлы разрешений создаёт
 * канал мессенджера после подтверждения владельцем.
 */
export class FileConsentGate implements MediaConsentGate {
  private readonly now: () => number;
  private readonly ttlMs: number;
  private lastSweep = 0;

  constructor(private readonly options: FileConsentOptions) {
    this.now = options.now ?? (() => Date.now());
    this.ttlMs = options.ttlMs ?? CONSENT_TTL_MS;
  }

  approved(sha256: string): ApprovedConsent | undefined {
    const file = join(this.options.dir, `${sha256}.json`);
    try {
      if (!existsSync(file)) return undefined;
      const parsed = recordSchema.safeParse(JSON.parse(readFileSync(file, 'utf8')));
      if (!parsed.success) return undefined;
      const r = parsed.data;
      const approvedAt = Date.parse(r.approved_at);
      const expiresAt = Date.parse(r.expires_at);
      const now = this.now();
      if (r.sha256 !== sha256 || r.agent !== this.options.agentId) return undefined;
      // Срок считается и от approved_at: файл с растянутым expires_at не продлевает разрешение
      if (now >= expiresAt || now >= approvedAt + this.ttlMs) return undefined;
      if (approvedAt > now + CONSENT_CLOCK_SKEW_MS) return undefined;
      return { sha256, mediaId: mediaIdOf(sha256), kinds: sanitizeKinds(r.kinds) };
    } catch {
      return undefined; // нечитаемый или битый файл: разрешения нет
    }
  }

  offer(sha256: string, kinds: readonly string[]): string {
    const id = mediaIdOf(sha256);
    const file = join(this.options.dir, CONSENT_OFFERS_DIR, `${id}.json`);
    try {
      if (!existsSync(file)) {
        ensureDir(join(this.options.dir, CONSENT_OFFERS_DIR));
        const body = {
          sha256, kinds: sanitizeKinds(kinds), agent: this.options.agentId,
          created_at: new Date(this.now()).toISOString(),
        };
        writeAtomic(file, JSON.stringify(body));
      }
      this.sweep();
    } catch {
      // Предложение не записалось: модель всё равно получит закрашенную версию, а владелец
      // не сможет подтвердить (канал не найдёт id). Запрос из-за этого не ломается.
    }
    return id;
  }

  /** Раз в час убирает старые предложения и давно истёкшие разрешения. */
  private sweep(): void {
    const now = this.now();
    if (now - this.lastSweep < CONSENT_SWEEP_INTERVAL_MS) return;
    this.lastSweep = now;
    const dirs = [join(this.options.dir, CONSENT_OFFERS_DIR), this.options.dir];
    for (const dir of dirs) {
      if (!existsSync(dir)) continue;
      for (const name of readdirSync(dir)) {
        if (!name.endsWith('.json')) continue;
        const path = join(dir, name);
        try {
          if (now - statSync(path).mtimeMs > CONSENT_OFFER_KEEP_MS) unlinkSync(path);
        } catch {
          // файл исчез или недоступен: пропускаем
        }
      }
    }
  }
}

function ensureDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: CONSENT_DIR_MODE });
  chmodSync(dir, CONSENT_DIR_MODE);
}

/** Атомарная запись: временный файл рядом, права 600, переименование. */
function writeAtomic(path: string, content: string): void {
  const tmp = `${path}.tmp-${randomBytes(6).toString('hex')}`;
  writeFileSync(tmp, content, { mode: CONSENT_FILE_MODE });
  renameSync(tmp, path);
}
