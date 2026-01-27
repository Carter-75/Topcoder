import { Probot, Context } from "probot";
import fetch from "node-fetch";
import yaml from "js-yaml";

type GuardrailsConfig = {
  sector?: string;
  policy?: Record<string, string>;
};

type AnalyzeBatchResponse = {
  result: string;
  files_scanned: number;
  findings: Record<string, any>;
  policy: "advisory" | "warning" | "blocking";
  override_allowed: boolean;
};

const MAX_FILES = Number(process.env.MAX_FILES || 100);
const MAX_FILE_BYTES = Number(process.env.MAX_FILE_BYTES || 200_000);
const OVERRIDE_LABEL = process.env.OVERRIDE_LABEL || "guardrails-override";

const supportedExtensions = new Set([
  ".py",
  ".js",
  ".ts",
  ".jsx",
  ".tsx",
  ".java",
  ".go",
  ".rs",
  ".cs",
  ".cpp",
  ".c",
  ".h",
  ".hpp",
  ".html",
  ".css",
  ".scss",
  ".md",
  ".yml",
  ".yaml",
  ".json",
  ".toml",
  ".ini",
  ".sh",
  ".ps1",
]);

const isSupportedFile = (path: string) => {
  const dot = path.lastIndexOf(".");
  if (dot === -1) return false;
  return supportedExtensions.has(path.slice(dot).toLowerCase());
};

const decodeContent = (content: string, encoding?: string) => {
  if (!encoding || encoding === "base64") {
    return Buffer.from(content, "base64").toString("utf-8");
  }
  return content;
};

const fetchGuardrailsConfig = async (context: Context, owner: string, repo: string, ref: string): Promise<GuardrailsConfig> => {
  const candidates = [
    ".guardrails/config.yml",
    ".guardrails/config.yaml",
    ".guardrails/config.json",
  ];
  for (const path of candidates) {
    try {
      const res = await context.octokit.repos.getContent({ owner, repo, path, ref });
      if (Array.isArray(res.data) || !("content" in res.data)) {
        continue;
      }
      const raw = decodeContent(res.data.content, res.data.encoding);
      if (path.endsWith(".json")) {
        return JSON.parse(raw);
      }
      return (yaml.load(raw) as GuardrailsConfig) || {};
    } catch (error) {
      continue;
    }
  }
  return {};
};

const summarizeFindings = (result: AnalyzeBatchResponse) => {
  let issues = 0;
  let coding = 0;
  let license = 0;
  let sector = 0;
  let ai = 0;
  for (const file of Object.values(result.findings)) {
    issues += file.issues?.length || 0;
    coding += file.coding_issues?.length || 0;
    license += file.license_ip_issues?.length || 0;
    sector += file.sector_issues?.length || 0;
    ai += file.ai_suggestions?.length || 0;
  }
  return { issues, coding, license, sector, ai };
};

export = (app: Probot) => {
  app.on(["pull_request.opened", "pull_request.synchronize", "pull_request.reopened"], async (context: Context) => {
    const eventPayload = context.payload as any;
    const pr = eventPayload.pull_request;
    const repo = eventPayload.repository;
    const owner = repo.owner.login;
    const repoName = repo.name;
    const ref = pr.head.sha;

    const config = await fetchGuardrailsConfig(context, owner, repoName, ref);
    const sector = config.sector || "finance";

    const fileList = await context.octokit.pulls.listFiles({ owner, repo: repoName, pull_number: pr.number, per_page: 100 });
    const files = [] as Array<{ path: string; code: string }>;
    for (const file of fileList.data) {
      if (!file.filename || file.status === "removed") {
        continue;
      }
      if (!isSupportedFile(file.filename)) {
        continue;
      }
      if (files.length >= MAX_FILES) {
        break;
      }
      try {
        const contentRes = await context.octokit.repos.getContent({ owner, repo: repoName, path: file.filename, ref });
        if (Array.isArray(contentRes.data) || !("content" in contentRes.data)) {
          continue;
        }
        const raw = decodeContent(contentRes.data.content, contentRes.data.encoding);
        if (raw.length > MAX_FILE_BYTES) {
          continue;
        }
        files.push({ path: file.filename, code: raw });
      } catch (error) {
        continue;
      }
    }

    const backendUrl = process.env.BACKEND_URL || "http://localhost:8000";
    const requestPayload = {
      pr_number: pr.number,
      repo: repo.full_name,
      author: pr.user.login,
      files,
      sector,
      policy: config.policy,
      repo_path: repo.full_name,
    };

    const res = await fetch(`${backendUrl}/analyze-batch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestPayload),
    });

    const result = (await res.json()) as AnalyzeBatchResponse;
    const { issues, coding, license, sector: sectorIssues, ai } = summarizeFindings(result);
    const labels = pr.labels?.map((label: any) => label.name) || [];
    const hasOverride = labels.includes(OVERRIDE_LABEL);
    const shouldBlock = result.policy === "blocking" && !hasOverride;
    const conclusion = shouldBlock ? "failure" : result.policy === "warning" ? "neutral" : "success";

    const summaryLines = [
      `Policy: ${result.policy}${hasOverride ? " (override applied)" : ""}`,
      `Files scanned: ${result.files_scanned}`,
      `Security issues: ${issues}`,
      `Coding issues: ${coding}`,
      `License/IP issues: ${license}`,
      `Sector issues: ${sectorIssues}`,
      `AI suggestions: ${ai}`,
    ];

    await context.octokit.issues.createComment({
      owner,
      repo: repoName,
      issue_number: pr.number,
      body: `## Guardrails Report\n${summaryLines.map((line) => `- ${line}`).join("\n")}`,
    });

    await context.octokit.checks.create({
      owner,
      repo: repoName,
      name: "guardrails",
      head_sha: pr.head.sha,
      status: "completed",
      conclusion,
      output: {
        title: "Guardrails analysis",
        summary: summaryLines.join("\n"),
      },
    });
  });
};
