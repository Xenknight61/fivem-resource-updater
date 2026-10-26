/**
 * Typed IPC wrappers reject asynchronously for backend failures, but they throw
 * synchronously when a request fails local shape validation. A durable update
 * operation is already marked in progress at that point, so a synchronous throw
 * would escape before reconciliation runs and would leave the frontend
 * permanently blocked. Every durable invocation is started through this helper
 * so both failure shapes reconcile through the same rejected-promise path.
 */
export function startDurableInvocation<T>(invoke: () => Promise<T>): Promise<T> {
  try {
    return invoke()
  } catch (error) {
    return Promise.reject(error)
  }
}
