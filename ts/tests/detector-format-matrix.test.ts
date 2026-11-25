import { describe, expect, test } from 'bun:test';

import { detectPersons, replaceSpans } from '../src/index';

/*
 * Матрица записи ФИО (25.11.2026), вымышленные данные: та же, что в Python
 * (`python/tests/labops_pseudonymizer/test_person_format_matrix.py`). До переноса правил
 * Python TS-детектор оставлял открытыми 994 из 5633 кейсов: фамилии вне словаря («Головач»,
 * «Дамберг»), через дефис, «Ф, И О» через запятую, строчные ФИО, латиницу без метки.
 */

/** [фамилия, имя, отчество]: словарные, вне словаря, через дефис, несклоняемые. */
const PEOPLE: ReadonlyArray<readonly [string, string, string]> = [
  ['Иванов', 'Сергей', 'Петрович'],
  ['Петрова', 'Анна', 'Сергеевна'],
  ['Салтыков-Щедрин', 'Михаил', 'Евграфович'],
  ['Шевчук', 'Наталья', 'Олеговна'],
  ['Пехтышева', 'Юлия', 'Андреевна'],
  ['Головач', 'Дмитрий', 'Ильич'],
  ['Белых', 'Ирина', 'Павловна'],
  ['Сидоренко', 'Василий', 'Тарасович'],
  ['Новикова-Прибой', 'Мария', 'Ильинична'],
  ['Дамберг', 'Карл', 'Густавович'],
];

const CONTEXTS: readonly string[] = [
  '{x}',
  'Позвоните {x} завтра.',
  'Менеджер {x}, отдел продаж',
  'Кому: {x}\nТема: счёт',
  '«{x}»',
  '{"fio": "{x}"}',
];

/** Запись ФИО и слова, которых не должно остаться после замены находок. */
function formats(f: string, i: string, o: string): Array<[string, string[]]> {
  const fi = i.charAt(0);
  const oi = o.charAt(0);
  return [
    [`${f} ${i} ${o}`, [f, i, o]],
    [`${i} ${o} ${f}`, [f, i, o]],
    [`${f}, ${i} ${o}`, [f, i, o]],
    [`${f}  ${i}   ${o}`, [f, i, o]],
    [`${f} ${i} ${o}`.toUpperCase(), [f.toUpperCase(), i.toUpperCase(), o.toUpperCase()]],
    [`${f} ${fi}.${oi}.`, [f]],
    [`${fi}. ${oi}. ${f}`, [f]],
    [`${f} ${i}`, [f, i]],
    [`${i} ${f}`, [f, i]],
  ];
}

const CASES: Array<[string, string[]]> = PEOPLE.flatMap(([f, i, o]) =>
  formats(f, i, o).flatMap(([value, words]) =>
    CONTEXTS.map((ctx): [string, string[]] => [ctx.replace('{x}', value), words]),
  ),
);

describe('матрица записи ФИО', () => {
  test.each(CASES)('%s: ни одно слово ФИО не остаётся', (text, words) => {
    const masked = replaceSpans(text, detectPersons(text), () => '#');
    expect(words.filter((w) => masked.includes(w))).toEqual([]);
  });
});

describe('ФИО: короткие формы и латиница', () => {
  test.each([
    ['Позвоните К.Г. Дамберг завтра.', 'К.Г. Дамберг'],
    ['Белых И.', 'Белых И'],
    ['Салтыков-Щедрин М.', 'Салтыков-Щедрин М'],
    ['Согласовать с Головачом Дмитрием Ильичом.', 'Головачом Дмитрием Ильичом'],
    ['Позвоните Дмитрий Ильич Головач завтра', 'Дмитрий Ильич Головач'],
    ['головач дмитрий ильич', 'головач дмитрий ильич'],
    ['сидоренко василий тарасович', 'сидоренко василий тарасович'],
    ['ким елена николаевна', 'ким елена николаевна'],
    ['Ответственный: Sergey Ivanov', 'Sergey Ivanov'],
    ['IVANOV SERGEY', 'IVANOV SERGEY'],
    ['Contact: Hans Müller', 'Hans Müller'],
    ['Name: Łukasz Dvořák, phone', 'Łukasz Dvořák'],
    ['Mehmet Yılmaz', 'Mehmet Yılmaz'],
  ])('%s -> %s', (text, expected) => {
    expect(detectPersons(text).map((s) => s.text)).toEqual([expected]);
  });
});

describe('ФИО: роль, глагол и обычное слово рядом с «Имя Отчество» - не фамилия', () => {
  test.each([
    ['Сегодня Анна Сергеевна приедет', 'Анна Сергеевна'],
    ['Новости Дмитрий Ильич прочитал', 'Дмитрий Ильич'],
    ['Скажи Ольге Владимировне, что товар пришёл', 'Ольге Владимировне'],
    ['Сотрудник Анна Сергеевна', 'Анна Сергеевна'],
    ['Решение Анна Сергеевна приняла', 'Анна Сергеевна'],
    ['Привет Дмитрий Ильич', 'Дмитрий Ильич'],
  ])('%s -> %s', (text, expected) => {
    expect(detectPersons(text).map((s) => s.text)).toEqual([expected]);
  });

  test.each([
    'Visual Studio',
    'Product Manager',
    'Yesterday Anna went home',
    'Тягач Дмитрий',
    'Айсберг Д.',
  ])('%s: ничего', (text) => {
    expect(detectPersons(text)).toEqual([]);
  });
});
