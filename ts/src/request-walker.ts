import {
  ATTACHMENT_STRIPPED_TEXT, attachmentBlockedText, EMPTY_DOCUMENT_TEXT, PDF_MEDIA_TYPE,
  STATUS_PII_FOUND,
} from './constants';
import type { ImagePolicy } from './image-policy';
import type { Recognized } from './media-client';
import { MediaMaskerError, RequestRejectedError } from './errors';
import { recognizedBlockText } from './media-text';
import { blockReason, type BlockReason, type MediaProcessor } from './media';
import { collectStringLeaves, isObject, type JsonObject, type Leaf } from './json-leaves';

/** Блоки, которые не трогаем: подпись thinking, служебные результаты сервера. */
const PASSTHROUGH_BLOCKS: ReadonlySet<string> = new Set([
  'thinking',
  'redacted_thinking',
  'web_search_tool_result',
  'web_fetch_tool_result',
  'code_execution_tool_result',
  'compaction',
  // Определение инструмента, подгруженное по ходу сессии (сообщение роли system): то же, что
  // массив tools, который не маскируется; ПДн в описаниях инструментов не бывает.
  'tool_addition',
  // Ссылка на найденный инструмент внутри tool_result поиска инструментов: только имя
  // инструмента, ПДн нет. Живой CLI 2.1.318 шлёт её после поиска отложенных инструментов.
  'tool_reference',
]);
/** Блоки с аргументами инструмента: маскируются все строковые листья input. */
const TOOL_INPUT_BLOCKS: ReadonlySet<string> = new Set([
  'tool_use',
  'server_tool_use',
  'mcp_tool_use',
]);
/** Блоки с содержимым-результатом (строка или список блоков). */
const RESULT_BLOCKS: ReadonlySet<string> = new Set(['tool_result', 'mcp_tool_result']);

/** Сколько блоков занимает на месте обработанный блок (1 - один, как был). */
type Consumed = number;

/** Источник вложения (поле source блока image или document). */
interface AttachmentSource {
  readonly kind: string;
  readonly mediaType: string;
  readonly data: string;
}

/**
 * Обходит запрос в фиксированном порядке (system, затем messages по порядку) и собирает
 * строковые листья, которые надо маскировать. Вложения заменяются по политике: заглушка (strip),
 * отказ (reject) или маскирование через media-masker (mask). Текст из PDF становится обычными
 * text-блоками и попадает в листья там же, где стоял документ: порядок обхода определяет
 * нумерацию токенов, поэтому менять его нельзя.
 */
export class RequestWalker {
  readonly leaves: Leaf[] = [];
  /** Сколько вложений заменено заглушкой. */
  strippedAttachments = 0;
  /** Сколько вложений ушло как есть (политика passthrough). */
  passedAttachments = 0;
  /** Сколько вложений обработано через media-masker. */
  maskedAttachments = 0;
  /** Вложения, замененные пометкой (fail closed): счётчик по причинам из закрытого списка. */
  readonly blockedReasons: Partial<Record<BlockReason, number>> = {};

  constructor(
    private readonly imagePolicy: ImagePolicy,
    private readonly media?: MediaProcessor,
  ) {}

  /** Обойти тело запроса /v1/messages (или count_tokens). */
  async walk(body: JsonObject): Promise<void> {
    await this.walkField(body, 'system');
    const messages = body.messages;
    if (messages === undefined || messages === null) return;
    if (!Array.isArray(messages)) throw rejectUnknown('messages_not_list');
    for (const message of messages) {
      if (!isObject(message)) throw rejectUnknown('message_not_object');
      await this.walkField(message, 'content');
    }
  }

  /**
   * Поле с текстом: строка или список блоков. Иная форма (объект, число) отклоняется: раньше
   * она молча пропускалась, и ПДн в ней уходили модели без маскирования и без второй линии.
   */
  private async walkField(holder: JsonObject, key: string): Promise<void> {
    const value = holder[key];
    if (value === undefined || value === null) return;
    if (typeof value === 'string') this.addString(holder, key, value);
    else if (Array.isArray(value)) await this.walkBlocks(value);
    else throw rejectUnknown(`${key}_shape`);
  }

  private addString(holder: JsonObject, key: string, text: string): void {
    if (text !== '') this.leaves.push({ holder, key, text });
  }

  private async walkBlocks(blocks: unknown[]): Promise<void> {
    let i = 0;
    while (i < blocks.length) {
      const block = blocks[i];
      // Не-объект в списке блоков (строка, число) раньше пропускался вместе с его текстом
      if (!isObject(block)) throw rejectUnknown('block_not_object');
      i += await this.walkBlock(blocks, i, block);
    }
  }

  private async walkBlock(parent: unknown[], index: number, block: JsonObject): Promise<Consumed> {
    const type = block.type;
    if (typeof type !== 'string') throw rejectUnknown('no_type');
    if (PASSTHROUGH_BLOCKS.has(type)) return 1;
    if (type === 'text') {
      if (typeof block.text === 'string') this.addString(block, 'text', block.text);
    } else if (type === 'image') {
      return this.attachment(parent, index, block);
    } else if (type === 'document') {
      return this.walkDocument(parent, index, block);
    } else if (TOOL_INPUT_BLOCKS.has(type)) {
      collectStringLeaves(block.input, this.leaves);
    } else if (RESULT_BLOCKS.has(type)) {
      await this.walkContent(block);
    } else if (type === 'search_result') {
      await this.walkContent(block);
      if (typeof block.title === 'string') this.addString(block, 'title', block.title);
    } else {
      throw rejectUnknown(type);
    }
    return 1;
  }

  /** content блока: строка или список блоков. */
  private async walkContent(block: JsonObject): Promise<void> {
    await this.walkField(block, 'content');
  }

  private async walkDocument(
    parent: unknown[],
    index: number,
    block: JsonObject,
  ): Promise<Consumed> {
    const source = block.source;
    const kind = isObject(source) ? source.type : undefined;
    if (isObject(source) && kind === 'text' && typeof source.data === 'string') {
      this.addString(source, 'data', source.data);
    } else if (isObject(source) && kind === 'content') {
      await this.walkContent(source);
    } else if (this.imagePolicy !== 'passthrough') {
      return this.attachment(parent, index, block); // подписи заменены вместе с документом
    } else {
      this.passedAttachments++; // небезопасная политика: подписи документа маскируются
    }
    if (typeof block.title === 'string') this.addString(block, 'title', block.title);
    if (typeof block.context === 'string') this.addString(block, 'context', block.context);
    return 1;
  }

  /** Вложение без текста (изображение, PDF) по политике; блок может быть заменён. */
  private async attachment(
    parent: unknown[],
    index: number,
    block: JsonObject,
  ): Promise<Consumed> {
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
    if (this.imagePolicy === 'mask' && this.media !== undefined) {
      return this.maskAttachment(parent, index, block, this.media);
    }
    const stub: JsonObject = { type: 'text', text: ATTACHMENT_STRIPPED_TEXT };
    if (block.cache_control !== undefined) stub.cache_control = block.cache_control;
    parent[index] = stub;
    this.strippedAttachments++;
    return 1;
  }

  /** Вложение через media-masker: картинка закрашивается на месте, PDF становится блоками. */
  private async maskAttachment(
    parent: unknown[],
    index: number,
    block: JsonObject,
    media: MediaProcessor,
  ): Promise<Consumed> {
    const source = readSource(block.source);
    if (source === undefined || source.kind !== 'base64') {
      // url, file_id и прочее: байтов нет, проверить содержимое нельзя
      return this.block(parent, index, block, 'not_base64');
    }
    try {
      if (block.type === 'image') {
        const masked = await media.maskImage(source.mediaType, source.data);
        const src = block.source as JsonObject;
        src.media_type = masked.mediaType;
        src.data = masked.data;
        this.maskedAttachments++;
        const note = this.recognizedBlock(masked.recognized);
        if (note === undefined) return 1;
        // cache_control закрывает префикс: переносим на блок с распознанным текстом
        if (block.cache_control !== undefined) {
          note.cache_control = block.cache_control;
          delete block.cache_control;
        }
        parent.splice(index + 1, 0, note);
        this.leaves.push({ holder: note, key: 'text', text: note.text as string });
        return 2;
      }
      if (source.mediaType !== PDF_MEDIA_TYPE) return this.block(parent, index, block,
        'unsupported_type');
      const replacement = await this.pdfBlocks(block, source.data, media);
      parent.splice(index, 1, ...replacement.blocks);
      this.leaves.push(...replacement.leaves);
      this.maskedAttachments++;
      return replacement.blocks.length;
    } catch (e) {
      // Fail closed: любой отказ или сбой media-masker - вложение не уходит к модели, на его
      // месте короткая пометка. Запрос целиком не отклоняется: иначе вложение в истории
      // ломало бы каждый следующий запрос сессии.
      if (e instanceof MediaMaskerError) return this.block(parent, index, block, blockReason(e));
      throw e;
    }
  }

  /**
   * Text-блок с распознанным на картинке (текст, коды, пометка о скрытом): обычный лист, то
   * есть пройдёт то же маскирование и проверку, что и остальной текст запроса.
   */
  private recognizedBlock(rec: Recognized): JsonObject | undefined {
    const text = recognizedBlockText(rec);
    return text === null ? undefined : { type: 'text', text };
  }

  /** Заменить вложение пометкой с причиной из закрытого списка; cache_control сохраняется. */
  private block(
    parent: unknown[],
    index: number,
    block: JsonObject,
    reason: BlockReason,
  ): Consumed {
    const note: JsonObject = { type: 'text', text: attachmentBlockedText(reason) };
    if (block.cache_control !== undefined) note.cache_control = block.cache_control;
    parent[index] = note;
    this.blockedReasons[reason] = (this.blockedReasons[reason] ?? 0) + 1;
    return 1;
  }

  /** Блоки вместо PDF: text на каждую страницу с текстом, image на растровую страницу. */
  private async pdfBlocks(
    block: JsonObject,
    data: string,
    media: MediaProcessor,
  ): Promise<{ blocks: JsonObject[]; leaves: Leaf[] }> {
    const doc = await media.extractDocument(data);
    const blocks: JsonObject[] = [];
    const leaves: Leaf[] = [];
    const addText = (text: string): void => {
      if (text.trim() === '') return;
      const b: JsonObject = { type: 'text', text };
      blocks.push(b);
      leaves.push({ holder: b, key: 'text', text });
    };
    if (typeof block.title === 'string') addText(block.title);
    for (const page of doc.pages) {
      if (page.text !== null) addText(page.text);
      else if (page.image !== null) {
        blocks.push({ type: 'image', source: { type: 'base64', media_type: page.image.mediaType,
          data: page.image.data } });
        const note = this.recognizedBlock(page.image.recognized);
        if (note !== undefined) {
          blocks.push(note);
          leaves.push({ holder: note, key: 'text', text: note.text as string });
        }
      }
    }
    if (blocks.length === 0) addText(EMPTY_DOCUMENT_TEXT);
    // cache_control закрывает префикс: переносим на последний блок замены
    if (block.cache_control !== undefined) {
      (blocks[blocks.length - 1] as JsonObject).cache_control = block.cache_control;
    }
    return { blocks, leaves };
  }
}

/** Прочитать source вложения: тип, media_type и данные (строки). */
function readSource(source: unknown): AttachmentSource | undefined {
  if (!isObject(source) || typeof source.type !== 'string') return undefined;
  const mediaType = typeof source.media_type === 'string' ? source.media_type : '';
  const data = typeof source.data === 'string' ? source.data : '';
  return { kind: source.type, mediaType, data };
}

function rejectUnknown(type: string): RequestRejectedError {
  return new RequestRejectedError(
    STATUS_PII_FOUND,
    'Неизвестный тип блока в запросе: проверить на ПДн нельзя, запрос не отправлен.',
    `unknown_block_${type.slice(0, 40)}`,
  );
}
