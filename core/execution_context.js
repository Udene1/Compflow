import { AsyncLocalStorage } from 'node:async_hooks';

const storage = new AsyncLocalStorage();

export function withExecutionContext(context, fn) {
  return storage.run(context, fn);
}

export function getExecutionContext() {
  return storage.getStore() || null;
}
