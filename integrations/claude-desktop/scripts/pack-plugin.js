import { mkdirSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";

mkdirSync("dist", { recursive: true });
const output = "dist/ekubo-wallet-plugin.zip";
rmSync(output, { force: true });

const result = spawnSync(
  "zip",
  ["-q", "-r", output, ".claude-plugin", ".mcp.json", "server/index.js"],
  { stdio: "inherit" }
);
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
