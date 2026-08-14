export class WorkerKitError extends Error {
  constructor(code, message, options = {}) {
    super(message, options);
    this.name = "WorkerKitError";
    this.code = code;
    this.retryable = Boolean(options.retryable);
  }
}

export function errorCode(error, fallback = "worker-kit-failed") {
  const value = error && typeof error === "object" && "code" in error
    ? String(error.code)
    : fallback;
  return /^[a-z0-9][a-z0-9._-]{0,95}$/i.test(value) ? value : fallback;
}
