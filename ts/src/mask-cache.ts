import { createHash } from 'node:crypto';
import { CACHE_KEY_CHARS, HEALTH_POLL_MS } from './constants';
import type { Pseudonymizer } from './pseudonymizer-client';

/** Кэш с бюджетом по стоимости (символы) и вытеснением самых давних записей. */
export class BoundedCache {
  private readonly map = new Map<string, string>();
  private totalCost = 0;

  constructor(
    private readonly maxCost: number,
    private readonly costOf: (value: string) => number = (v) => v.length,
  ) {}

  /** Занятый бюджет. */
  get cost(): number {
    return this.totalCost;
  }

  /** Число записей. */
  get size(): number {
    return this.map.size;
  }

  get(key: string): string | undefined {
    const value = this.map.get(key);
    if (value === undefined) return undefined;
    // Обновляем давность записи.
    this.map.delete(key);
    this.map.set(key, value);
    return value;
  }

  set(key: string, value: string): void {
    const old = this.map.get(key);
    if (old !== undefined) {
      this.totalCost -= CACHE_KEY_CHARS + this.costOf(old);
      this.map.delete(key);
    }
    const cost = CACHE_KEY_CHARS + this.costOf(value);
    if (cost > this.maxCost) return;
    this.map.set(key, value);
    this.totalCost += cost;
    for (const [k, v] of this.map) {
      if (this.totalCost <= this.maxCost) break;
      this.map.delete(k);
      this.totalCost -= CACHE_KEY_CHARS + this.costOf(v);
    }
  }

  /** Удалить запись (нет записи - ничего не делает). */
  delete(key: string): void {
    const old = this.map.get(key);
    if (old === undefined) return;
    this.totalCost -= CACHE_KEY_CHARS + this.costOf(old);
    this.map.delete(key);
  }

  clear(): void {
    this.map.clear();
    this.totalCost = 0;
  }
}

/**
 * Ключ кэша маскирования: тред, запуск сервиса, режим падежных меток и исходный лист.
 * Режим в ключе: маска с метками и без них - разные строки, смена флага не отдаёт старую.
 * При выключенных метках ключ прежний (суффикс не добавляется).
 */
export function maskCacheKey(
  threadId: string,
  bootId: string,
  text: string,
  caseLabels = false,
): string {
  const mode = caseLabels ? '\u0000case_labels' : '';
  const material = `${threadId}\u0000${bootId}${mode}\u0000${text}`;
  return createHash('sha256').update(material).digest('hex');
}

/** sha256 текста (ключ кэша «чисто» для второй линии). */
export function textKey(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

/**
 * Следит за номером запуска сервиса: /health опрашивается не чаще раза в {@link HEALTH_POLL_MS}.
 * Смена номера значит, что таблица замен потеряна: кэш маскирования сбрасывается целиком.
 */
export class BootTracker {
  private bootId: string | undefined;
  private checkedAt = Number.NEGATIVE_INFINITY;
  private inflight: Promise<string> | undefined;

  constructor(
    private readonly service: Pseudonymizer,
    private readonly onReset: () => void,
    private readonly now: () => number = () => performance.now(),
    private readonly pollMs: number = HEALTH_POLL_MS,
  ) {}

  /**
   * Актуальный boot_id (сбой /health - PseudonymizerError).
   * @param force - спросить сервис, не глядя на окно опроса.
   */
  async current(force = false): Promise<string> {
    const fresh = this.now() - this.checkedAt < this.pollMs;
    if (!force && this.bootId !== undefined && fresh) return this.bootId;
    this.inflight ??= this.refresh().finally(() => {
      this.inflight = undefined;
    });
    return this.inflight;
  }

  private async refresh(): Promise<string> {
    const id = await this.service.health();
    if (this.bootId !== undefined && this.bootId !== id) this.onReset();
    this.bootId = id;
    this.checkedAt = this.now();
    return id;
  }
}
