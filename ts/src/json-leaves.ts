/** Произвольный JSON-объект. */
export interface JsonObject {
  [key: string]: unknown;
}

/** Контейнер (объект или массив), в котором лежит строковый лист. */
export type LeafHolder = JsonObject | unknown[];

/** Строковый лист JSON: контейнер и ключ, по которым значение читается и заменяется. */
export interface Leaf {
  readonly holder: LeafHolder;
  readonly key: string | number;
  readonly text: string;
}

/** Это объект (не массив, не null)? */
export function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Записать значение в лист. */
export function setLeaf(leaf: Leaf, value: string): void {
  (leaf.holder as Record<string | number, unknown>)[leaf.key] = value;
}

/**
 * Собрать все строковые листья значения в фиксированном порядке (массивы по индексу, поля
 * объекта в порядке ключей). Ключи объектов не трогаются. Пустые строки пропускаются.
 */
export function collectStringLeaves(value: unknown, out: Leaf[] = []): Leaf[] {
  if (Array.isArray(value)) {
    value.forEach((item, i) => {
      if (typeof item === 'string') {
        if (item !== '') out.push({ holder: value, key: i, text: item });
      } else collectStringLeaves(item, out);
    });
  } else if (isObject(value)) {
    for (const key of Object.keys(value)) {
      const item = value[key];
      if (typeof item === 'string') {
        if (item !== '') out.push({ holder: value, key, text: item });
      } else collectStringLeaves(item, out);
    }
  }
  return out;
}
