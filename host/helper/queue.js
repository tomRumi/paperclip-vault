// Counting semaphore and keyed mutex, both FIFO and abortable.
import { HelperError } from './errors.js';

function abortError(signal) {
  return signal?.reason instanceof HelperError
    ? signal.reason
    : new HelperError('timeout', 'operation timed out or was cancelled while queued');
}

export class Semaphore {
  #free;
  #waiters = [];

  constructor(permits) {
    if (!Number.isInteger(permits) || permits < 1) throw new RangeError('permits must be >= 1');
    this.#free = permits;
  }

  /** Resolves to a release function. Rejects if `signal` aborts while waiting. */
  acquire(signal) {
    if (signal?.aborted) return Promise.reject(abortError(signal));
    if (this.#free > 0) {
      this.#free -= 1;
      return Promise.resolve(this.#releaser());
    }
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject, signal, onAbort: null };
      waiter.onAbort = () => {
        const i = this.#waiters.indexOf(waiter);
        if (i >= 0) this.#waiters.splice(i, 1);
        reject(abortError(signal));
      };
      signal?.addEventListener('abort', waiter.onAbort, { once: true });
      this.#waiters.push(waiter);
    });
  }

  #releaser() {
    let done = false;
    return () => {
      if (done) return;
      done = true;
      const next = this.#waiters.shift();
      if (next) {
        next.signal?.removeEventListener('abort', next.onAbort);
        next.resolve(this.#releaser());
      } else {
        this.#free += 1;
      }
    };
  }
}

export class KeyedMutex {
  #locks = new Map();

  async acquire(key, signal) {
    let sem = this.#locks.get(key);
    if (!sem) {
      sem = new Semaphore(1);
      this.#locks.set(key, sem);
    }
    const release = await sem.acquire(signal);
    return () => {
      release();
    };
  }
}
