import { describe, expect, test } from 'bun:test';

import {
  detectAddresses,
  detectNamesAndAddresses,
  detectPersons,
  replaceSpans,
  type DetectorOptions,
} from '../src/index';

// Бывший профиль pragmatika: адреса ищутся, «прагматик» в белом списке
const PRAGMATIKA: DetectorOptions = { maskAddresses: true, allowedWords: ['прагматик'] };

/** Тексты найденных ФИО. */
function persons(text: string, options: DetectorOptions = PRAGMATIKA): string[] {
  return detectPersons(text, options).map((span) => span.text);
}

describe('ФИО: явные случаи', () => {
  test.each([
    ['Иванов Иван', 'Иванов Иван'],
    ['Иванову Петру', 'Иванову Петру'],
    ['И. И. Иванов', 'И. И. Иванов'],
    ['Иванов Иван Иванович', 'Иванов Иван Иванович'],
    ['Иван Иванович', 'Иван Иванович'],
    ['Передайте Ольге Николаевне Смирновой', 'Ольге Николаевне Смирновой'],
    ['ИВАНОВ ИВАН ИВАНОВИЧ', 'ИВАНОВ ИВАН ИВАНОВИЧ'],
    ['менеджер иванов иван иванович ответил', 'иванов иван иванович'],
    ['Фёдорову Николаю Андреевичу', 'Фёдорову Николаю Андреевичу'],
    ['Contact: Li Wei', 'Li Wei'],
  ])('находит «%s»', (text, expected) => {
    expect(persons(text)).toEqual([expected]);
  });

  test('«Иванов И.И.»: конечная точка инициалов остаётся снаружи', () => {
    expect(persons('Иванов И.И.')).toEqual(['Иванов И.И']);
    expect(persons('Иванов И. И. подписал')).toEqual(['Иванов И. И']);
  });

  test('одиночное имя или фамилия — только после слова-признака', () => {
    expect(persons('Менеджер Алексей сообщит цену')).toEqual(['Алексей']);
    expect(persons('Позвони Петрову, пожалуйста')).toEqual(['Петрову']);
    expect(persons('Доставка по Королёву и Чехову')).toEqual([]);
  });

  test('список людей: вторая фамилия после «и» маскируется тоже', () => {
    expect(persons('Согласуй с Сидоровым и Козловым')).toEqual(['Сидоровым', 'Козловым']);
  });
});

describe('ФИО: не ПДн', () => {
  test.each([
    'Прагматика',
    'Прагматике и Прагматикой',
    'Войти в «Прагматику»',
    'Прагматика запускает сервис. Товар доставлен.',
    'Доставка работает. Каталог обновлён. Корзина пуста. Мастер приедет завтра.',
    'Заказ принят. Машина выехала. Картина в раме. Резина зимняя.',
    'Королевна Мария',
    'Это практична и логична',
    'Москва, Тверская улица',
    'школа имени Ивана Петрова',
    'Вера, Надежда, Любовь — наборы к 8 Марта',
    'Лада Веста и Лада Гранта',
    'Нижний Новгород, Санкт-Петербург, Ростов-на-Дону',
    'ТЕХМЕТАЛЛ СЕРВИС',
    'ВЕРА НАДЕЖДА ЛЮБОВЬ',
  ])('«%s» без находок', (text) => {
    expect(persons(text)).toEqual([]);
  });

  test('«Прагматик Иванов» белым списком не покрывается: чужое слово остаётся', () => {
    expect(persons('Прагматик Иванов, менеджер')).not.toContain('Прагматик');
  });

  test('дополнительное слово белого списка', () => {
    expect(persons('Менеджер Алексей', { ...PRAGMATIKA, allowedWords: ['алексе'] })).toEqual([]);
  });
});

describe('адреса', () => {
  test.each([
    ['ул. Ленина, д. 5, кв. 12', 'ул. Ленина, д. 5, кв. 12'],
    ['Доставка: г. Москва, ул. Ленина, д. 5, кв. 12.', 'ул. Ленина, д. 5, кв. 12'],
    ['г. Москва, Ленина 5', 'Ленина 5'],
    ['119019, ул. Арбат, д. 1', '119019, ул. Арбат, д. 1'],
    ['УЛ. ЛЕНИНА, Д. 5', 'УЛ. ЛЕНИНА, Д. 5'],
    ['пр-т Мира, д. 10, корп. 2, стр. 1', 'пр-т Мира, д. 10, корп. 2, стр. 1'],
  ])('находит адрес в «%s»', (text, expected) => {
    expect(detectAddresses(text).map((span) => span.text)).toEqual([expected]);
  });

  test.each([
    'г. Москва',
    'Склад в г. Москва, Заказ 5.',
    'д. 5 мм',
    'ул. Ленина 5 коробок',
    'Доставка на улице Ленина возможна',
    'Артикул АБ-12 д.5 по ТУ',
    'Партия 119019 отгружена',
  ])('«%s» — не адрес', (text) => {
    expect(detectAddresses(text)).toEqual([]);
  });

  test('улица по фамилии — один адрес, без ФИО внутри', () => {
    const spans = detectNamesAndAddresses('ул. Ивана Франко, д. 4', PRAGMATIKA);
    expect(spans.map((s) => [s.kind, s.text])).toEqual([['address', 'ул. Ивана Франко, д. 4']]);
  });

  test('флаг maskAddresses задаёт, ищутся ли адреса (по умолчанию да)', () => {
    const text = 'ул. Ленина, д. 5';
    expect(detectNamesAndAddresses(text)).toHaveLength(1);
    expect(detectNamesAndAddresses(text, {})).toHaveLength(1);
    expect(detectNamesAndAddresses(text, { maskAddresses: false })).toEqual([]);
    expect(detectNamesAndAddresses(text, PRAGMATIKA)).toHaveLength(1);
    expect(detectNamesAndAddresses(text, { maskAddresses: true })).toHaveLength(1);
  });

  test('цифры других систем и NBSP не сдвигают границы', () => {
    const text = 'Адрес: ул. Ленина, д. ５';
    const spans = detectAddresses(text);
    expect(spans).toHaveLength(1);
    expect(text.slice(spans[0]?.start, spans[0]?.end)).toBe('ул. Ленина, д. ５');
  });
});

describe('интерфейс', () => {
  test('replaceSpans подставляет метки', () => {
    const text = 'Менеджер Иванов Иван, ул. Ленина, д. 5.';
    const spans = detectNamesAndAddresses(text, PRAGMATIKA);
    const result = replaceSpans(text, spans, (s) => (s.kind === 'person' ? '[ФИО]' : '[адрес]'));
    expect(result).toBe('Менеджер [ФИО], [адрес].');
  });

  test('не строка на входе — ошибка (fail closed)', () => {
    expect(() => detectPersons(42 as unknown as string)).toThrow();
    expect(() => detectAddresses(null as unknown as string)).toThrow();
  });

  test('параметр profile удалён — ошибка с подсказкой, а не молчаливая подмена', () => {
    for (const profile of ['pragmatika', 'labops', 'nope']) {
      const options = { profile } as unknown as DetectorOptions;
      expect(() => detectPersons('Иванов Иван', options)).toThrow(/MIGRATION/);
      expect(() => detectNamesAndAddresses('Иванов Иван', options)).toThrow(/MIGRATION/);
    }
  });

  test('слов белого списка по умолчанию нет: исключение появляется только из параметра', () => {
    expect(persons('Менеджер Алексей', {})).not.toEqual([]);
    expect(persons('Менеджер Алексей', { allowedWords: ['алексе'] })).toEqual([]);
  });

  test('длинный текст страницы обрабатывается быстро', () => {
    const chunk = 'Цемент М500 мешок 50 кг, доставка по Красноярску. Менеджер Иванов Иван. ' +
      'Склад: ул. Мира, д. 12. ';
    const text = chunk.repeat(2000);
    const started = performance.now();
    const spans = detectNamesAndAddresses(text, PRAGMATIKA);
    const elapsedMs = performance.now() - started;
    expect(spans.length).toBeGreaterThan(3000);
    expect(elapsedMs).toBeLessThan(3000);
  });
});
