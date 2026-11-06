import type { ImagePolicy } from './image-policy';
import {
  MASK_BOOT_ATTEMPTS,
  CHECK_OVERLAP_CHARS,
  MASK_CACHE_MAX_CHARS,
  REMEMBER_CACHE_MAX_CHARS,
  MAX_TEXT_CHARS,
  STATUS_PII_FOUND,
  SERVICE_CONCURRENCY,
  SYSTEM_INSERT_TEXT,
} from './constants';
import { PseudonymizerError, RequestRejectedError } from './errors';
import { isObject, setLeaf, type JsonObject } from './json-leaves';
import { BoundedCache, BootTracker, maskCacheKey, textKey } from './mask-cache';
import type { MediaProcessor } from './media';
import type { Pseudonymizer } from './pseudonymizer-client';
import { RequestWalker } from './request-walker';
import { chunkBatches, mapLimited, splitText } from './text-split';

/**
 * Через сколько простоя треда его записи кэша и памяти восстановлений перестают использоваться.
 * Сервис удаляет тред по сроку хранения (по умолчанию 24 ч простоя) без смены boot_id и начинает
 * нумерацию заново: старая маска из кэша дала бы [PERSON_1] другому человеку. Срок короче любого
 * разумного хранения на сервере; промах кэша безопасен (сервис вернёт ту же маску, если тред жив).
 */
export const THREAD_IDLE_RESET_MS = 30 * 60 * 1000;
/** Предел числа тредов, для которых помнится поколение кэша (старые вытесняются). */
const THREAD_EPOCHS_MAX = 100_000;

/** Настройки кэша по тредам. */
export interface MaskerOptions {
  /** Простой треда, после которого его кэш не используется; по умолчанию THREAD_IDLE_RESET_MS. */
  readonly threadIdleResetMs?: number | undefined;
  /** Часы в миллисекундах (для тестов). */
  readonly now?: (() => number) | undefined;
}

/** Поколение кэша треда: новое поколение делает старые записи недостижимыми. */
interface ThreadEpoch {
  epoch: number;
  lastUsed: number;
}

/** Предел числа записей кэша «текст проверен, ПДн нет» (стоимость 0, ключ - sha256). */
const CLEAN_CACHE_MAX_ENTRIES = 200_000;
const CLEAN_COST = 1;

/** Счётчики маскирования одного запроса (без значений). */
export interface MaskStats {
  readonly leaves: number;
  readonly cacheHits: number;
  readonly strippedAttachments: number;
  /** Вложения, обработанные через media-masker. */
  readonly maskedAttachments: number;
  /** Вложения, скрытые пометкой (fail closed), по причинам из закрытого списка. */
  readonly blockedReasons: Readonly<Record<string, number>>;
  /** Листьев взято из памяти восстановлений (без обращения к сервису). */
  readonly rememberedLeaves: number;
  /** boot_id сервиса, при котором замаскирован запрос (ключ памяти восстановлений). */
  readonly bootId: string;
  /** Листьев памяти, забытых из-за находки /check и замаскированных сервисом заново. */
  readonly forgottenLeaves: number;
}

/** Лист, взятый из памяти восстановлений: ключ записи и отданный текст. */
interface RememberedLeaf {
  readonly key: string;
  readonly text: string;
}

/** Итог второй линии: тексты с находками и виды ПДн. */
interface PiiFindings {
  readonly dirty: ReadonlySet<string>;
  readonly types: ReadonlySet<string>;
}

/** Маскирует тело запроса к модели и проверяет результат второй линией (/check). */
export class RequestMasker {
  private readonly maskCache = new BoundedCache(MASK_CACHE_MAX_CHARS);
  /** Память восстановлений: восстановленная строка -> исходная строка модели. */
  private readonly rememberCache = new BoundedCache(REMEMBER_CACHE_MAX_CHARS);
  private readonly cleanCache = new BoundedCache(CLEAN_CACHE_MAX_ENTRIES * CLEAN_COST, () => 0);
  private readonly boot: BootTracker;
  private readonly epochs = new Map<string, ThreadEpoch>();
  private readonly idleResetMs: number;
  private readonly now: () => number;

  constructor(
    private readonly service: Pseudonymizer,
    private readonly imagePolicy: ImagePolicy,
    private readonly caseLabels = false,
    private readonly media?: MediaProcessor,
    options: MaskerOptions = {},
  ) {
    this.idleResetMs = options.threadIdleResetMs ?? THREAD_IDLE_RESET_MS;
    this.now = options.now ?? (() => Date.now());
    // Таблица замен сервиса потеряна: память восстановлений теряет смысл так же, как кэш.
    this.boot = new BootTracker(service, () => {
      this.maskCache.clear();
      this.rememberCache.clear();
    });
  }

  /** Размер кэша маскирования в символах (для тестов и метрик). */
  get cacheChars(): number {
    return this.maskCache.cost;
  }

  /** Размер памяти восстановлений в символах (для тестов и метрик). */
  get rememberedChars(): number {
    return this.rememberCache.cost;
  }

  /**
   * Запомнить, что восстановленная строка в истории - это ответ модели в исходном виде.
   * Ключ совпадает с ключом кэша маскирования: тред, boot_id и строка листа.
   */
  remember(threadId: string, bootId: string, restored: string, original: string): void {
    const scope = this.threadScope(threadId);
    this.rememberCache.set(maskCacheKey(scope, bootId, restored, this.caseLabels), original);
  }

  /**
   * Забыть кэш треда. Вызывать после `deleteThread` у сервиса: тред удалён, нумерация на сервере
   * начнётся заново, и прежние маски этого треда больше не годятся.
   */
  forgetThread(threadId: string): void {
    const entry = this.epochs.get(threadId);
    this.epochs.delete(threadId);
    this.epochs.set(threadId, { epoch: (entry?.epoch ?? 0) + 1, lastUsed: this.now() });
    this.trimEpochs();
  }

  /** Ключ треда для кэша с поколением; долгий простой открывает новое поколение. */
  private threadScope(threadId: string): string {
    const now = this.now();
    const entry = this.epochs.get(threadId) ?? { epoch: 0, lastUsed: now };
    if (now - entry.lastUsed > this.idleResetMs) entry.epoch += 1;
    entry.lastUsed = now;
    // Переставляем в конец: вытесняются давно не использованные треды
    this.epochs.delete(threadId);
    this.epochs.set(threadId, entry);
    this.trimEpochs();
    return entry.epoch === 0 ? threadId : `${threadId}\u0000epoch${entry.epoch}`;
  }

  private trimEpochs(): void {
    for (const key of this.epochs.keys()) {
      if (this.epochs.size <= THREAD_EPOCHS_MAX) break;
      this.epochs.delete(key);
    }
  }

  /**
   * Замаскировать тело на месте: листья, вложения, вставка в system.
   * @throws PseudonymizerError / MediaMaskerError при сбое сервисов,
   *   RequestRejectedError при ПДн после маски.
   */
  async mask(body: JsonObject, threadId: string): Promise<MaskStats> {
    const scope = this.threadScope(threadId);
    const walker = new RequestWalker(this.imagePolicy, this.media);
    await walker.walk(body);
    for (let attempt = 0; attempt < MASK_BOOT_ATTEMPTS; attempt++) {
      // boot_id сверяется до и после маскирования: если сервис перезапустился в середине,
      // кэш хранит маски старой таблицы, и [PERSON_1] из кэша и [PERSON_1] новой таблицы
      // могли бы оказаться разными людьми. Тогда кэш сброшен (onReset), маскируем заново.
      const bootId = await this.boot.current(true);
      let pass = await this.maskOnce(walker, threadId, scope, bootId);
      if ((await this.boot.current(true)) !== bootId) continue;
      let found = await this.findPii(pass.maskedTexts);
      // Свой текст модели идёт мимо сервиса, и /check может найти в нём «ФИО», которое
      // модель написала сама (название проекта и т.п.). Без отката такой лист даёт 422 на
      // каждом следующем запросе сессии: история та же. Поэтому лист забываем и маскируем
      // сервисом; если и после этого /check находит ПДн - отказ, как для любого листа.
      const stale = pass.remembered.filter((r) => found.dirty.has(r.text));
      if (stale.length > 0) {
        stale.forEach((r) => this.rememberCache.delete(r.key));
        pass = await this.maskOnce(walker, threadId, scope, bootId);
        if ((await this.boot.current(true)) !== bootId) continue;
        found = await this.findPii(pass.maskedTexts);
      }
      rejectIfFound(found.types);
      insertSystemNote(body);
      return { ...pass.stats, forgottenLeaves: stale.length };
    }
    throw new PseudonymizerError('boot_changed');
  }

  /** Один проход маскирования листьев при известном boot_id. */
  private async maskOnce(
    walker: RequestWalker,
    threadId: string,
    scope: string,
    bootId: string,
  ): Promise<{
    stats: Omit<MaskStats, 'forgottenLeaves'>;
    maskedTexts: string[];
    remembered: RememberedLeaf[];
  }> {
    const keys = walker.leaves.map(
      (l) => maskCacheKey(scope, bootId, l.text, this.caseLabels),
    );
    // Уже известные маски снимаем сразу: запись кэша может быть вытеснена новыми.
    const resolved = new Map<string, string>();
    let rememberedLeaves = 0;
    const rememberedList: RememberedLeaf[] = [];
    // Новые листья: уникальные, в порядке первого появления.
    const missing: { key: string; text: string }[] = [];
    const seen = new Set<string>();
    let cacheHits = 0;
    walker.leaves.forEach((leaf, i) => {
      const key = keys[i] as string;
      // Свой прошлый ответ модели возвращается ей как написан (с метками падежа), мимо сервиса.
      // Результат всё равно идёт во вторую линию, как и любой замаскированный лист.
      const remembered = this.rememberCache.get(key);
      const cached = remembered ?? this.maskCache.get(key);
      if (remembered !== undefined) {
        resolved.set(key, remembered);
        rememberedLeaves++;
        rememberedList.push({ key, text: remembered });
      } else if (cached !== undefined) {
        resolved.set(key, cached);
        cacheHits++;
      } else if (!seen.has(key)) {
        seen.add(key);
        missing.push({ key, text: leaf.text });
      }
    });
    for (const [key, value] of await this.pseudonymizeMissing(threadId, missing)) {
      resolved.set(key, value);
      this.maskCache.set(key, value);
    }
    const maskedTexts: string[] = [];
    walker.leaves.forEach((leaf, i) => {
      const masked = resolved.get(keys[i] as string) as string;
      setLeaf(leaf, masked);
      maskedTexts.push(masked);
    });
    return {
      stats: {
        leaves: walker.leaves.length,
        cacheHits,
        strippedAttachments: walker.strippedAttachments,
        rememberedLeaves,
        bootId,
        maskedAttachments: walker.maskedAttachments,
        blockedReasons: walker.blockedReasons,
      },
      maskedTexts,
      remembered: rememberedList,
    };
  }

  /** Маскирует новые листья строго по порядку (порядок задаёт нумерацию токенов). */
  private async pseudonymizeMissing(
    threadId: string,
    missing: readonly { key: string; text: string }[],
  ): Promise<Map<string, string>> {
    const pieces: string[] = [];
    const owners: number[] = [];
    missing.forEach((m, i) => {
      for (const piece of splitText(m.text)) {
        pieces.push(piece);
        owners.push(i);
      }
    });
    const maskedPieces: string[] = [];
    for (const chunk of chunkBatches(pieces)) {
      maskedPieces.push(...(await this.service.pseudonymizeBatch(threadId, chunk)));
    }
    const joined = missing.map(() => '');
    maskedPieces.forEach((piece, i) => {
      joined[owners[i] as number] += piece;
    });
    return new Map(missing.map((m, i) => [m.key, joined[i] as string]));
  }

  /** Вторая линия: /check каждого замаскированного листа без thread_id. */
  private async findPii(maskedTexts: readonly string[]): Promise<PiiFindings> {
    const todo = [...new Set(maskedTexts)]
      .filter((t) => this.cleanCache.get(textKey(t)) === undefined);
    const dirty = new Set<string>();
    const types = new Set<string>();
    await mapLimited(todo, SERVICE_CONCURRENCY, async (text) => {
      for (const window of checkWindows(text)) {
        const r = await this.service.check(window);
        if (r.hasPii) {
          dirty.add(text);
          r.types.forEach((t) => types.add(t));
        }
      }
      if (!dirty.has(text)) this.cleanCache.set(textKey(text), '1');
    });
    return { dirty, types };
  }
}

/** Отказ, если вторая линия нашла ПДн. */
function rejectIfFound(found: ReadonlySet<string>): void {
  if (found.size === 0) return;
  const types = [...found].sort();
  throw new RequestRejectedError(
    STATUS_PII_FOUND,
    `Запрос не отправлен: после маскирования в тексте остались персональные данные `
      + `(виды: ${types.join(', ')}).`,
    'pii_after_mask',
    types,
  );
}

/** Окна проверки длинного листа: не длиннее предела сервиса, соседние перекрываются. */
export function checkWindows(text: string): string[] {
  const step = MAX_TEXT_CHARS - CHECK_OVERLAP_CHARS;
  const windows: string[] = [];
  for (let start = 0; ; start += step) {
    windows.push(text.slice(start, start + MAX_TEXT_CHARS));
    if (start + MAX_TEXT_CHARS >= text.length) return windows;
  }
}

/**
 * Добавляет в конец system неизменную вставку про токены. Строка system превращается в
 * список блоков; cache_control у блоков списка не трогается.
 */
export function insertSystemNote(body: JsonObject): void {
  const note: JsonObject = { type: 'text', text: SYSTEM_INSERT_TEXT };
  const system = body.system;
  if (typeof system === 'string') {
    body.system = system === '' ? [note] : [{ type: 'text', text: system }, note];
  } else if (Array.isArray(system)) {
    system.push(note);
  } else if (system === undefined || system === null) {
    body.system = [note];
  } else if (isObject(system)) {
    body.system = [system, note];
  }
}
