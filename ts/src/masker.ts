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
  PII_HIDDEN_TEXT,
  REMASK_MAX_PASSES,
  UNSUPPORTED_ROUTE_CODES,
} from './constants';
import { PseudonymizerError, RequestRejectedError } from './errors';
import { isObject, setLeaf, type JsonObject } from './json-leaves';
import { nullLogger, type Logger } from './log';
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
export const THREAD_EPOCHS_MAX = 100_000;

/** Настройки кэша по тредам. */
export interface MaskerOptions {
  /** Простой треда, после которого его кэш не используется; по умолчанию THREAD_IDLE_RESET_MS. */
  readonly threadIdleResetMs?: number | undefined;
  /** Часы в миллисекундах (для тестов). */
  readonly now?: (() => number) | undefined;
  /**
   * Что делать, если после маски /check нашёл в листе ПДн: `remask` (по умолчанию) -
   * дозамаскировать, а если не вышло, скрыть лист заглушкой; запрос не отклоняется.
   * `reject` - прежнее поведение до 1.1.0 (отказ 422 `pii_after_mask`), на случай отката.
   */
  readonly onResidualPii?: 'remask' | 'reject' | undefined;
  /** Журнал событий дозамаскирования и скрытия листьев (только счётчики и виды, без текстов). */
  readonly logger?: Logger | undefined;
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
  /** Листьев, в которых /check нашёл остаток ПДн и второй проход его закрыл. */
  readonly remaskedLeaves: number;
  /** Листьев, скрытых заглушкой: остаток ПДн не ушёл и после второго прохода. */
  readonly hiddenLeaves: number;
}

/** Итог дозамаскирования одного текста: новый текст и признак «скрыт заглушкой». */
interface Fixed {
  readonly text: string;
  readonly hidden: boolean;
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
  /** Следующий номер поколения; только растёт, поэтому поколения не повторяются. */
  private nextEpoch = 0;
  private readonly idleResetMs: number;
  private readonly now: () => number;
  private readonly rejectOnResidual: boolean;
  private readonly logger: Logger;

  constructor(
    private readonly service: Pseudonymizer,
    private readonly imagePolicy: ImagePolicy,
    private readonly caseLabels = false,
    private readonly media?: MediaProcessor,
    options: MaskerOptions = {},
  ) {
    this.idleResetMs = options.threadIdleResetMs ?? THREAD_IDLE_RESET_MS;
    this.now = options.now ?? (() => Date.now());
    this.rejectOnResidual = options.onResidualPii === 'reject';
    this.logger = options.logger ?? nullLogger;
    // Заглушка чиста по построению: второй линии её проверять незачем
    this.cleanCache.set(textKey(PII_HIDDEN_TEXT), '1');
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
    this.epochs.delete(threadId);
    this.epochs.set(threadId, { epoch: this.nextEpoch++, lastUsed: this.now() });
    this.trimEpochs();
  }

  /**
   * Ключ треда для кэша с поколением; долгий простой открывает новое поколение.
   * Номер поколения берётся из общего возрастающего счётчика: если запись треда вытеснена
   * (больше THREAD_EPOCHS_MAX тредов), новое поколение не совпадёт ни с одним прежним, и
   * маски до forgetThread не станут снова доступны. Цена - промах кэша, он безопасен.
   */
  private threadScope(threadId: string): string {
    const now = this.now();
    let entry = this.epochs.get(threadId);
    if (entry === undefined || now - entry.lastUsed > this.idleResetMs) {
      entry = { epoch: this.nextEpoch++, lastUsed: now };
    }
    entry.lastUsed = now;
    // Переставляем в конец: вытесняются давно не использованные треды
    this.epochs.delete(threadId);
    this.epochs.set(threadId, entry);
    this.trimEpochs();
    return `${threadId}\u0000epoch${entry.epoch}`;
  }

  private trimEpochs(): void {
    for (const key of this.epochs.keys()) {
      if (this.epochs.size <= THREAD_EPOCHS_MAX) break;
      this.epochs.delete(key);
    }
  }

  /**
   * Замаскировать тело на месте: листья, вложения, вставка в system.
   * @throws PseudonymizerError / MediaMaskerError при сбое сервисов; RequestRejectedError при
   *   ПДн после маски только с `onResidualPii: 'reject'` (по умолчанию остаток дозамаскируется
   *   или лист скрывается заглушкой, запрос не отклоняется).
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
      // сервисом; если и после этого /check находит ПДн - дальше как с любым листом (см. ниже).
      const stale = pass.remembered.filter((r) => found.dirty.has(r.text));
      if (stale.length > 0) {
        stale.forEach((r) => this.rememberCache.delete(r.key));
        pass = await this.maskOnce(walker, threadId, scope, bootId);
        if ((await this.boot.current(true)) !== bootId) continue;
        found = await this.findPii(pass.maskedTexts);
      }
      let remasked = 0;
      let hidden = 0;
      if (found.dirty.size > 0) {
        if (this.rejectOnResidual) rejectIfFound(found.types);
        // Остаток ПДн не повод отказывать запросу: лист дозамаскируется вторым проходом, а если
        // остаток не ушёл - заменится заглушкой. Итог запоминается в кэше маски под исходным
        // листом: старый лист истории приходит в каждом следующем запросе, и без этого второй
        // проход (и /check) повторялся бы на каждом из них.
        const fixed = await this.fixDirty(threadId, found.dirty);
        if ((await this.boot.current(true)) !== bootId) continue;
        walker.leaves.forEach((leaf, i) => {
          const fix = fixed.get(pass.maskedTexts[i] as string);
          if (fix === undefined) return;
          setLeaf(leaf, fix.text);
          this.maskCache.set(pass.keys[i] as string, fix.text);
          if (fix.hidden) hidden++;
          else remasked++;
        });
        this.logger.log('pii_after_mask_fixed', {
          remasked_leaves: remasked,
          hidden_leaves: hidden,
          pii_types: [...found.types].sort(),
        });
      }
      insertSystemNote(body);
      return { ...pass.stats, forgottenLeaves: stale.length, remaskedLeaves: remasked,
        hiddenLeaves: hidden };
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
    stats: Omit<MaskStats, 'forgottenLeaves' | 'remaskedLeaves' | 'hiddenLeaves'>;
    maskedTexts: string[];
    keys: string[];
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
      keys,
      remembered: rememberedList,
    };
  }

  /** Маскирует новые листья строго по порядку (порядок задаёт нумерацию токенов). */
  private async pseudonymizeMissing(
    threadId: string,
    missing: readonly { key: string; text: string }[],
  ): Promise<Map<string, string>> {
    const joined = await this.applyByPieces(
      missing.map((m) => m.text),
      (chunk) => this.service.pseudonymizeBatch(threadId, chunk),
    );
    return new Map(missing.map((m, i) => [m.key, joined[i] as string]));
  }

  /**
   * Прогоняет тексты через пакетный вызов сервиса: длинные режутся на части, части идут
   * пачками по пределам сервиса, результат склеивается обратно по текстам (порядок сохранён).
   */
  private async applyByPieces(
    texts: readonly string[],
    call: (chunk: readonly string[]) => Promise<string[]>,
  ): Promise<string[]> {
    const pieces: string[] = [];
    const owners: number[] = [];
    texts.forEach((text, i) => {
      for (const piece of splitText(text)) {
        pieces.push(piece);
        owners.push(i);
      }
    });
    const maskedPieces: string[] = [];
    for (const chunk of chunkBatches(pieces)) {
      maskedPieces.push(...(await call(chunk)));
    }
    const joined = texts.map(() => '');
    maskedPieces.forEach((piece, i) => {
      joined[owners[i] as number] += piece;
    });
    return joined;
  }

  /**
   * Закрывает остаток ПДн в замаскированных листьях: второй проход сервиса (/remask_batch) и
   * повторный /check; кто остался грязным после REMASK_MAX_PASSES проходов (или сервис не умеет
   * дозамаскировывать, старая версия) - заменяется заглушкой. Сбой сервиса (сеть, таймаут,
   * 5xx) пробрасывается: fail closed, как у любого вызова сервиса.
   */
  private async fixDirty(
    threadId: string,
    dirty: ReadonlySet<string>,
  ): Promise<Map<string, Fixed>> {
    const fixed = new Map<string, Fixed>();
    // исходный замаскированный текст -> его текущая версия после проходов
    let pending = new Map<string, string>([...dirty].map((t) => [t, t]));
    for (let pass = 0; pass < REMASK_MAX_PASSES && pending.size > 0; pass++) {
      const originals = [...pending.keys()];
      const next = await this.remaskTexts(threadId, originals.map((o) => pending.get(o) as string));
      if (next === undefined) break;
      const check = await this.findPii(next);
      const still = new Map<string, string>();
      originals.forEach((orig, i) => {
        const text = next[i] as string;
        if (check.dirty.has(text)) still.set(orig, text);
        else fixed.set(orig, { text, hidden: false });
      });
      pending = still;
    }
    for (const orig of pending.keys()) fixed.set(orig, { text: PII_HIDDEN_TEXT, hidden: true });
    return fixed;
  }

  /** Второй проход сервиса; undefined, если у сервиса нет такого маршрута (старая версия). */
  private async remaskTexts(
    threadId: string,
    texts: readonly string[],
  ): Promise<string[] | undefined> {
    const remask = this.service.remaskBatch?.bind(this.service);
    if (remask === undefined) return undefined;
    try {
      return await this.applyByPieces(texts, (chunk) => remask(threadId, chunk));
    } catch (e) {
      if (e instanceof PseudonymizerError && UNSUPPORTED_ROUTE_CODES.includes(e.code)) {
        return undefined;
      }
      throw e;
    }
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
