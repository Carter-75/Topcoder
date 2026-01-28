import fs from "fs";
import path from "path";
import { Probot } from "probot";
import appModule = require("./index");

const getEnv = (name: string) => process.env[name] || "";

const main = async () => {
  const eventName = getEnv("GITHUB_EVENT_NAME");
  const eventPath = getEnv("GITHUB_EVENT_PATH");
  const fallbackPath = "/github/workflow/event.json";
  const resolvedPath = eventPath || (fs.existsSync(fallbackPath) ? fallbackPath : "");

  if (!resolvedPath) {
    throw new Error("Missing GitHub Actions event context.");
  }

  const fullPath = path.resolve(resolvedPath);
  const payload = JSON.parse(fs.readFileSync(fullPath, "utf-8"));
  const inferredEventName = eventName || (payload?.pull_request ? "pull_request" : payload?.ref ? "push" : "unknown");

  if (inferredEventName === "unknown") {
    throw new Error("Unable to infer GitHub Actions event name.");
  }

  const githubToken = getEnv("GITHUB_TOKEN");
  if (!githubToken) {
    throw new Error("GITHUB_TOKEN is required to run Guardrails in Actions.");
  }

  const probot = new Probot({
    githubToken,
    logLevel: (getEnv("LOG_LEVEL") as any) || "info",
  } as any);

  probot.load(appModule);

  await probot.receive({
    id: getEnv("GITHUB_RUN_ID") || "guardrails-action",
    name: inferredEventName as any,
    payload,
  } as any);
};

main().catch((error) => {
  console.error("Guardrails Action failed:", error);
  process.exit(1);
});
