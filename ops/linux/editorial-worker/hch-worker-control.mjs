#!/usr/bin/env node
import { resolve } from "node:path";
import { runWorkerCli } from "./worker.mjs";

const [action, parallelism, ...extra] = process.argv.slice(2);
const configPath = process.env.HCH_EDITORIAL_WORKER_CONFIG;
if (extra.length || typeof configPath !== "string" || !configPath.startsWith("/")) {
  process.exitCode = 2;
} else {
  const commands = new Map([
    ["start", "control-start"],
    ["pause", "control-pause"],
    ["stop", "control-stop"],
    ["set-parallelism", "control-set-parallelism"],
  ]);
  const command = commands.get(action);
  const args = command ? [command, "--config", resolve(configPath)] : [];
  if (action === "set-parallelism" && /^(?:0|[1-9]|[1-5][0-9]|6[0-4])$/.test(parallelism ?? "")) {
    args.push("--parallelism", parallelism);
  } else if (action === "set-parallelism" || parallelism !== undefined) {
    args.length = 0;
  }
  process.exitCode = args.length ? await runWorkerCli(args) : 2;
}
