import { isObject, type JsonObject } from './json-leaves';
import type { Restorer } from './restorer';

/**
 * Восстановить нестриминговый ответ: text и аргументы tool_use. Блоки thinking не трогаются.
 * @returns изменённый объект ответа.
 */
export async function restoreMessageJson(
  body: JsonObject,
  restorer: Restorer,
): Promise<JsonObject> {
  const content = body.content;
  if (!Array.isArray(content)) return body;
  for (const block of content) {
    if (!isObject(block)) continue;
    if (block.type === 'text' && typeof block.text === 'string') {
      const original: string = block.text;
      const restored = await restorer.text(original);
      block.text = restored;
      rememberTextBlock(restorer, restored, original);
    } else if (typeof block.type === 'string' && block.type.endsWith('tool_use')) {
      await restorer.leaves(block.input);
    }
  }
  return body;
}

/**
 * Запомнить целый text-блок. CLI может хранить текст блока без крайних пробелов, поэтому
 * запоминается и обрезанный вариант пары.
 */
export function rememberTextBlock(restorer: Restorer, restored: string, original: string): void {
  restorer.remember(restored, original);
  const trimmed = restored.trim();
  if (trimmed !== restored) restorer.remember(trimmed, original.trim());
}
