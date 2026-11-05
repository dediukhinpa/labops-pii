import { expect, test } from 'bun:test';

import { LIB_NAME } from '../src/index';

test('barrel экспортирует имя пакета', () => {
  expect(LIB_NAME).toBe('@labops/pii');
});
