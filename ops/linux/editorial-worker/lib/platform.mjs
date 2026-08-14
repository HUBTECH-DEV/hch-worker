import { WorkerKitError } from "./errors.mjs";

export function workerPlatform(value = process.platform) {
  if (value === "linux") return "linux";
  if (value === "darwin" || value === "macos") return "macos";
  throw new WorkerKitError(
    "worker-platform-unsupported",
    "This worker kit supports only Linux and macOS.",
  );
}
