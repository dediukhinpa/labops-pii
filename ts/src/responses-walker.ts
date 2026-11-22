import {
  ATTACHMENT_STRIPPED_TEXT, attachmentBlockedText, STATUS_PII_FOUND,
} from './constants';
import { MediaMaskerError, RequestRejectedError } from './errors';
import type { ImagePolicy } from './image-policy';
import { collectStringLeaves, isObject, type JsonObject, type Leaf } from './json-leaves';
import { blockReason, type BlockReason, type MediaProcessor } from './media';
import { recognizedBlockText } from './media-text';

/**
 * Обход тела запроса OpenAI Responses (`POST …/responses`), как его шлёт Codex CLI.
 *
 * Формат снят с живого трафика Codex 0.171.0 и со схемы его протокола (ResponseItem):
 * история целиком лежит в `input[]` (store=false — каждый запрос несёт всю историю), системный
 * текст — сообщения роли developer, инструменты — элемент `additional_tools`.
 *
 * Правила те же, что у обхода Anthropic Messages (RequestWalker):
 * - строки, где может оказаться текст человека, собираются в листья в фиксированном порядке
 *   (порядок задаёт нумерацию токенов, менять нельзя);
 * - непрозрачное (encrypted_content, определения инструментов) проходит как есть: оно либо
 *   выработано моделью из уже замаскированного, либо не содержит ПДн;
 * - незнакомая форма — отказ, а не пропуск: иначе новый тип элемента молча отправил бы ПДн.
 */

/** Элементы без текста людей: определения инструментов, зашифрованные сводки контекста. */
const PASSTHROUGH_ITEMS: ReadonlySet<string> = new Set([
  'additional_tools',
  'compaction',
  'compaction_trigger',
  'context_compaction',
  'configuration_update',
  'item_reference',
  // Найденные инструменты: только определения, как additional_tools.
  'tool_search_output',
]);

/** Части содержимого, которые проходят как есть (зашифрованное модель отдала сама). */
const PASSTHROUGH_PARTS: ReadonlySet<string> = new Set(['encrypted_content']);

/** Текстовые части: лист — поле text. */
const TEXT_PARTS: ReadonlySet<string> = new Set([
  'input_text', 'output_text', 'text', 'reasoning_text', 'summary_text',
]);

/** Data URL картинки: `data:<тип>;base64,<данные>`. */
const DATA_URL = /^data:([^;,]+);base64,(.*)$/s;

/** Сколько частей занимает на месте обработанная часть (1 — одна, как была). */
type Consumed = number;

/** Обходит тело запроса Responses и собирает листья для маскирования (см. описание модуля). */
export class ResponsesWalker {
  readonly leaves: Leaf[] = [];
  /** Сколько вложений заменено заглушкой. */
  strippedAttachments = 0;
  /** Сколько вложений ушло как есть (политика passthrough). */
  passedAttachments = 0;
  /** Сколько вложений обработано через media-masker. */
  maskedAttachments = 0;
  /** Сколько вложений ушло оригиналом по разрешению владельца. */
  consentOriginals = 0;
  /** Вложения, замененные пометкой (fail closed): счётчик по причинам из закрытого списка. */
  readonly blockedReasons: Partial<Record<BlockReason, number>> = {};
  /** Действия после записи масок в листья (пересборка строк аргументов). */
  private readonly finishers: Array<() => void> = [];

  constructor(
    private readonly imagePolicy: ImagePolicy,
    private readonly media?: MediaProcessor,
  ) {}

  /** Обойти тело запроса: instructions, затем input по порядку. */
  async walk(body: JsonObject): Promise<void> {
    const instructions = body.instructions;
    if (typeof instructions === 'string') this.addString(body, 'instructions', instructions);
    else if (instructions !== undefined && instructions !== null) {
      throw rejectUnknown('instructions_shape');
    }
    const input = body.input;
    if (input === undefined || input === null) return;
    if (typeof input === 'string') {
      this.addString(body, 'input', input);
      return;
    }
    if (!Array.isArray(input)) throw rejectUnknown('input_shape');
    for (const item of input) {
      if (!isObject(item)) throw rejectUnknown('item_not_object');
      await this.walkItem(item);
    }
  }

  /** Вызвать после того, как листья получили маски: пересобирает строки аргументов. */
  finish(): void {
    for (const f of this.finishers) f();
  }

  private addString(holder: JsonObject | unknown[], key: string | number, text: string): void {
    if (text !== '') this.leaves.push({ holder, key, text });
  }

  private async walkItem(item: JsonObject): Promise<void> {
    // Сообщение в краткой форме Responses: {role, content} без type.
    const type = item.type ?? (typeof item.role === 'string' ? 'message' : undefined);
    if (typeof type !== 'string') throw rejectUnknown('no_type');
    if (PASSTHROUGH_ITEMS.has(type)) return;
    switch (type) {
      case 'message':
      case 'agent_message':
        await this.walkContent(item, 'content');
        return;
      case 'reasoning':
        // Сводка и текст рассуждения пишутся моделью из замаскированного, но в истории они
        // возвращаются уже восстановленными — значит, в них могут быть ПДн.
        await this.walkContent(item, 'summary');
        await this.walkContent(item, 'content');
        return;
      case 'function_call':
        this.walkArguments(item);
        return;
      case 'custom_tool_call':
        if (typeof item.input === 'string') this.addString(item, 'input', item.input);
        else throw rejectUnknown('custom_tool_call_input');
        return;
      case 'function_call_output':
      case 'custom_tool_call_output':
        await this.walkContent(item, 'output');
        return;
      case 'local_shell_call':
      case 'web_search_call':
      case 'tool_search_call':
        // Аргументы-объекты: все строковые листья (команда, запрос поиска).
        collectStringLeaves(item.action ?? item.arguments, this.leaves);
        return;
      case 'local_shell_call_output':
        await this.walkContent(item, 'output');
        return;
      case 'image_generation_call':
        // Сгенерированная картинка (result) — байты от модели; подсказка — текст.
        if (typeof item.revised_prompt === 'string') {
          this.addString(item, 'revised_prompt', item.revised_prompt);
        }
        return;
      default:
        throw rejectUnknown(type);
    }
  }

  /**
   * Аргументы function_call — JSON строкой. Маскируются строковые листья разобранного JSON,
   * затем строка собирается заново: так токен не попадёт внутрь escape-последовательности, а
   * ключи JSON останутся как были. Не JSON — маскируется строка целиком.
   */
  private walkArguments(item: JsonObject): void {
    const args = item.arguments;
    if (typeof args !== 'string') {
      if (args !== undefined && args !== null) collectStringLeaves(args, this.leaves);
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(args);
    } catch {
      this.addString(item, 'arguments', args);
      return;
    }
    if (typeof parsed === 'string') {
      this.addString(item, 'arguments', args);
      return;
    }
    const holder: JsonObject = { value: parsed };
    const before = this.leaves.length;
    collectStringLeaves(holder, this.leaves);
    if (this.leaves.length === before) return;
    // Листья пишут в разобранный объект; строка аргументов пересобирается в finish().
    this.finishers.push(() => {
      item.arguments = JSON.stringify(holder.value);
    });
  }

  /** Поле с содержимым: строка или список частей. */
  private async walkContent(holder: JsonObject, key: string): Promise<void> {
    const value = holder[key];
    if (value === undefined || value === null) return;
    if (typeof value === 'string') {
      this.addString(holder, key, value);
      return;
    }
    if (!Array.isArray(value)) throw rejectUnknown(`${key}_shape`);
    let i = 0;
    while (i < value.length) {
      const part = value[i];
      if (!isObject(part)) throw rejectUnknown('part_not_object');
      i += await this.walkPart(value, i, part);
    }
  }

  private async walkPart(parent: unknown[], index: number, part: JsonObject): Promise<Consumed> {
    const type = part.type;
    if (typeof type !== 'string') throw rejectUnknown('part_no_type');
    if (PASSTHROUGH_PARTS.has(type)) return 1;
    if (TEXT_PARTS.has(type)) {
      if (typeof part.text === 'string') this.addString(part, 'text', part.text);
      return 1;
    }
    if (type === 'refusal') {
      if (typeof part.refusal === 'string') this.addString(part, 'refusal', part.refusal);
      return 1;
    }
    if (type === 'input_image') return this.image(parent, index, part);
    if (type === 'input_audio' || type === 'input_file') return this.attachment(parent, index, part);
    throw rejectUnknown(type);
  }

  /** Картинка: base64 в data URL маскируется через media-masker, остальное — по политике. */
  private async image(parent: unknown[], index: number, part: JsonObject): Promise<Consumed> {
    if (this.imagePolicy !== 'mask' || this.media === undefined) {
      return this.attachment(parent, index, part);
    }
    const url = typeof part.image_url === 'string' ? part.image_url : undefined;
    const m = url === undefined ? null : DATA_URL.exec(url);
    if (m === null) return this.block(parent, index, 'not_base64'); // file_id, http-адрес
    const data = m[2] as string;
    try {
      // Владелец разрешил оригинал этого файла: часть уходит как есть, без media-masker
      if (this.media.originalConsent(data) !== undefined) {
        this.consentOriginals++;
        return 1;
      }
      const masked = await this.media.maskImage(m[1] as string, data);
      part.image_url = `data:${masked.mediaType};base64,${masked.data}`;
      this.maskedAttachments++;
      const notes: JsonObject[] = [];
      const text = recognizedBlockText(masked.recognized);
      if (text !== null) {
        const note: JsonObject = { type: 'input_text', text };
        notes.push(note);
        this.leaves.push({ holder: note, key: 'text', text });
      }
      // Текст про разрешение - не лист: в нём только типы ПДн и id, значений нет
      const offerText = this.media.consentNote(data, masked.piiKinds);
      if (offerText !== undefined) notes.push({ type: 'input_text', text: offerText });
      parent.splice(index + 1, 0, ...notes);
      return 1 + notes.length;
    } catch (e) {
      // Fail closed: отказ media-masker — картинка не уходит, на её месте пометка.
      if (e instanceof MediaMaskerError) return this.block(parent, index, blockReason(e));
      throw e;
    }
  }

  /** Вложение без масочного пути (звук, файл; картинка без media-masker) — по политике. */
  private attachment(parent: unknown[], index: number, _part: JsonObject): Consumed {
    if (this.imagePolicy === 'passthrough') {
      this.passedAttachments++;
      return 1;
    }
    if (this.imagePolicy === 'reject') {
      throw new RequestRejectedError(
        STATUS_PII_FOUND,
        'Вложения (изображения, PDF) нельзя отправлять модели: политика запрещает.',
        'attachment_rejected',
      );
    }
    parent[index] = { type: 'input_text', text: ATTACHMENT_STRIPPED_TEXT };
    this.strippedAttachments++;
    return 1;
  }

  /** Заменить вложение пометкой с причиной из закрытого списка. */
  private block(parent: unknown[], index: number, reason: BlockReason): Consumed {
    parent[index] = { type: 'input_text', text: attachmentBlockedText(reason) };
    this.blockedReasons[reason] = (this.blockedReasons[reason] ?? 0) + 1;
    return 1;
  }
}

/**
 * Вставка справки о токенах. Ставится сразу после ведущих сообщений developer/system, а не в
 * конец: позиция не меняется от запроса к запросу, и кэш префикса у провайдера сохраняется.
 */
export function insertResponsesNote(body: JsonObject, note: string): void {
  const item: JsonObject = {
    type: 'message', role: 'developer', content: [{ type: 'input_text', text: note }],
  };
  const input = body.input;
  if (typeof input === 'string') {
    body.input = [item, { type: 'message', role: 'user', content: [{ type: 'input_text',
      text: input }] }];
    return;
  }
  if (!Array.isArray(input)) {
    body.input = [item];
    return;
  }
  let at = 0;
  while (at < input.length && isLeadingSystem(input[at])) at++;
  input.splice(at, 0, item);
}

function isLeadingSystem(item: unknown): boolean {
  if (!isObject(item)) return false;
  if (item.type === 'additional_tools') return true;
  const isMessage = item.type === 'message' || item.type === undefined;
  return isMessage && (item.role === 'developer' || item.role === 'system');
}

function rejectUnknown(type: string): RequestRejectedError {
  return new RequestRejectedError(
    STATUS_PII_FOUND,
    'Неизвестный тип элемента в запросе: проверить на ПДн нельзя, запрос не отправлен.',
    `unknown_item_${type.slice(0, 40)}`,
  );
}
