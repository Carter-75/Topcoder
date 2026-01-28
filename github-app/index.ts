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
  repo_license_issues?: Array<any>;
};

const MAX_FILES = Number(process.env.MAX_FILES || 100);
const MAX_FILE_BYTES = Number(process.env.MAX_FILE_BYTES || 200_000);
const OVERRIDE_LABEL = process.env.OVERRIDE_LABEL || "guardrails-override";
const REVIEW_MARKER = "<!-- guardrails-review -->";
const LICENSE_FILES = [
  "LICENSE",
  "LICENSE.txt",
  "LICENSE.md",
  "COPYING",
  "COPYING.txt",
  "NOTICE",
  "NOTICE.txt",
];

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

const detectLanguage = (path: string) => {
  const ext = path.slice(path.lastIndexOf(".") + 1).toLowerCase();
  const map: Record<string, string> = {
    py: "python",
    js: "javascript",
    ts: "typescript",
    jsx: "javascript",
    tsx: "typescript",
    java: "java",
    go: "go",
    rs: "rust",
    cs: "csharp",
    cpp: "cpp",
    c: "c",
    h: "c",
    hpp: "cpp",
    html: "html",
    css: "css",
    scss: "scss",
    md: "markdown",
    yml: "yaml",
    yaml: "yaml",
    json: "json",
    toml: "toml",
    ini: "ini",
    sh: "shell",
    ps1: "powershell",
  };
  return map[ext] || "unknown";
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

const fetchLicenseTexts = async (context: Context, owner: string, repo: string, ref: string) => {
  const texts: Array<{ path: string; content: string }> = [];
  for (const filename of LICENSE_FILES) {
    try {
      const res = await context.octokit.repos.getContent({ owner, repo, path: filename, ref });
      if (Array.isArray(res.data) || !("content" in res.data)) {
        continue;
      }
      const raw = decodeContent(res.data.content, res.data.encoding);
      if (!raw || raw.length > MAX_FILE_BYTES) {
        continue;
      }
      texts.push({ path: filename, content: raw });
    } catch (error) {
      continue;
    }
  }
  return texts;
};

const summarizeFindings = (result: AnalyzeBatchResponse) => {
  let issues = 0;
  let coding = 0;
  let license = 0;
  let sector = 0;
  let ai = 0;
  const findings = result.findings || {};
  for (const file of Object.values(findings)) {
    issues += file.issues?.length || 0;
    coding += file.coding_issues?.length || 0;
    license += file.license_ip_issues?.length || 0;
    sector += file.sector_issues?.length || 0;
    ai += file.ai_suggestions?.length || 0;
  }
  const repoLicense = result.repo_license_issues?.length || 0;
  return { issues, coding, license, sector, ai, repoLicense };
};

const collectAiHighlights = (result: AnalyzeBatchResponse, limit = 6) => {
  const highlights: Array<string> = [];
  for (const file of Object.values(result.findings)) {
    for (const suggestion of file.ai_suggestions || []) {
      const text = suggestion.message || suggestion.type || "AI suggestion";
      highlights.push(text);
      if (highlights.length >= limit) return highlights;
    }
  }
  return highlights;
};

const buildLineIndex = (code: string) => {
  const lineStarts = [0];
  for (let i = 0; i < code.length; i += 1) {
    if (code[i] === "\n") {
      lineStarts.push(i + 1);
    }
  }
  return lineStarts;
};

const offsetToLine = (lineStarts: number[], offset: number) => {
  let low = 0;
  let high = lineStarts.length - 1;
  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    if (lineStarts[mid] <= offset) {
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  return Math.max(1, high + 1);
};

const policyToLevel = (policy?: string) => {
  if (policy === "blocking") return "failure";
  if (policy === "warning") return "warning";
  return "notice";
};

const buildAnnotations = (result: AnalyzeBatchResponse, fileCode: Record<string, string>) => {
  const annotations: Array<any> = [];
  for (const [path, analysis] of Object.entries(result.findings)) {
    const code = fileCode[path];
    if (!code) continue;
    const lineIndex = buildLineIndex(code);
    const allIssues = [
      ...(analysis.issues || []),
      ...(analysis.coding_issues || []),
      ...(analysis.license_ip_issues || []),
      ...(analysis.sector_issues || []),
    ];
    for (const issue of allIssues) {
      let line = issue.line || null;
      if (!line && typeof issue.start === "number") {
        line = offsetToLine(lineIndex, issue.start);
      }
      if (!line) continue;
      const messageParts = [issue.message || issue.type];
      if (issue.suggestion) messageParts.push(`Suggestion: ${issue.suggestion}`);
      if (issue.owasp) messageParts.push(`OWASP: ${issue.owasp}`);
      if (issue.cwe) messageParts.push(`CWE: ${issue.cwe}`);
      if (issue.guideline_url) messageParts.push(`Guideline: ${issue.guideline_url}`);
      annotations.push({
        path,
        start_line: line,
        end_line: line,
        annotation_level: policyToLevel(issue.policy_level),
        title: issue.type || "guardrails",
        message: messageParts.join("\n"),
      });
    }
  }
  return annotations.slice(0, 50);
};

const buildDiffLineIndex = (patch?: string) => {
  const lines = patch?.split("\n") || [];
  const lineSet = new Set<number>();
  let rightLine = 0;
  for (const raw of lines) {
    if (raw.startsWith("@@")) {
      const match = raw.match(/\+([0-9]+)(?:,([0-9]+))?/);
      if (match) {
        rightLine = Number(match[1]);
      }
      continue;
    }
    if (raw.startsWith("+++") || raw.startsWith("---")) {
      continue;
    }
    if (raw.startsWith("+")) {
      lineSet.add(rightLine);
      rightLine += 1;
      continue;
    }
    if (raw.startsWith("-")) {
      continue;
    }
    lineSet.add(rightLine);
    rightLine += 1;
  }
  return lineSet;
};

const buildReviewComments = (
  result: AnalyzeBatchResponse,
  fileCode: Record<string, string>,
  diffLines: Record<string, Set<number>>,
  existingKeys: Set<string>,
) => {
  const comments: Array<any> = [];
  for (const [path, analysis] of Object.entries(result.findings)) {
    const code = fileCode[path];
    const allowedLines = diffLines[path];
    if (!code || !allowedLines) continue;
    const lineIndex = buildLineIndex(code);
    const allIssues = [
      ...(analysis.issues || []),
      ...(analysis.coding_issues || []),
      ...(analysis.license_ip_issues || []),
      ...(analysis.sector_issues || []),
    ];
    for (const issue of allIssues) {
      let line = issue.line || null;
      if (!line && typeof issue.start === "number") {
        line = offsetToLine(lineIndex, issue.start);
      }
      if (!line || !allowedLines.has(line)) continue;
      const messageParts = [issue.message || issue.type];
      if (issue.suggestion) messageParts.push(`Suggestion: ${issue.suggestion}`);
      if (issue.owasp) messageParts.push(`OWASP: ${issue.owasp}`);
      if (issue.cwe) messageParts.push(`CWE: ${issue.cwe}`);
      if (issue.guideline_url) messageParts.push(`Guideline: ${issue.guideline_url}`);
      const body = `${messageParts.join("\n")}\n${REVIEW_MARKER}`;
      const key = `${path}:${line}:${body}`;
      if (existingKeys.has(key)) continue;
      comments.push({
        path,
        line,
        side: "RIGHT",
        body,
      });
    }
  }
  return comments.slice(0, 50);
};

const detectCopilot = (text?: string) => {
  if (!text) return false;
  return /copilot/i.test(text) || /Co-authored-by:\s*GitHub Copilot/i.test(text);
};

export = (app: Probot) => {
  app.on(["pull_request.opened", "pull_request.synchronize", "pull_request.reopened"], async (context: Context) => {
    const eventPayload = context.payload as any;
    const pr = eventPayload.pull_request;
    const repo = eventPayload.repository;
    const owner = repo.owner.login;
    const repoName = repo.name;
    const ref = pr.head.sha;

    const checkRun = await context.octokit.checks.create({
      owner,
      repo: repoName,
      name: "guardrails",
      head_sha: pr.head.sha,
      status: "in_progress",
      output: {
        title: "Guardrails analysis",
        summary: "Scan started.",
      },
    });

    const config = await fetchGuardrailsConfig(context, owner, repoName, ref);
    const sector = config.sector || "finance";

    const fileList = await context.octokit.pulls.listFiles({ owner, repo: repoName, pull_number: pr.number, per_page: 100 });
    const files = [] as Array<{ path: string; code: string; patch?: string; language?: string }>;
    const fileCode: Record<string, string> = {};
    const diffLines: Record<string, Set<number>> = {};
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
        fileCode[file.filename] = raw;
        diffLines[file.filename] = buildDiffLineIndex(file.patch || "");
        files.push({
          path: file.filename,
          code: raw,
          patch: file.patch || "",
          language: detectLanguage(file.filename),
        });
      } catch (error) {
        continue;
      }
    }

    const commits = await context.octokit.pulls.listCommits({ owner, repo: repoName, pull_number: pr.number, per_page: 100 });
    const aiGenerated = detectCopilot(pr.title) || detectCopilot(pr.body) || commits.data.some((commit: any) => detectCopilot(commit.commit?.message));

    const backendUrl = process.env.BACKEND_URL || "http://localhost:8000";
    const backendToken = process.env.BACKEND_TOKEN || "";
    const userKey = process.env.GUARDRAILS_USER || process.env.GITHUB_ACTOR || "";
    const authHeaders: Record<string, string> = backendToken ? { Authorization: `Bearer ${backendToken}` } : {};
    if (userKey) {
      authHeaders["X-Guardrails-User"] = userKey;
    }
    const useAsync = process.env.USE_ASYNC_SCAN === "true";
    const repoLicenseTexts = await fetchLicenseTexts(context, owner, repoName, ref);
    const requestPayload = {
      pr_number: pr.number,
      repo: repo.full_name,
      author: pr.user.login,
      files,
      sector,
      policy: config.policy,
      ai_generated: aiGenerated,
      repo_path: repo.full_name,
      repo_license_texts: repoLicenseTexts,
    };
    let result: AnalyzeBatchResponse | null = null;
    if (useAsync) {
      const startRes = await fetch(`${backendUrl}/scan/async`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders },
        body: JSON.stringify(requestPayload),
      });
      if (!startRes.ok) {
        const body = await startRes.text();
        throw new Error(`Guardrails async scan failed (${startRes.status}): ${body}`);
      }
      const startData = await startRes.json();
      const jobId = startData.job_id;
      let attempts = 0;
      while (attempts < 10) {
        const statusRes = await fetch(`${backendUrl}/scan/status/${jobId}`, {
          headers: authHeaders,
        });
        if (!statusRes.ok) {
          const body = await statusRes.text();
          throw new Error(`Guardrails async status failed (${statusRes.status}): ${body}`);
        }
        const statusData = await statusRes.json();
        if (statusData.status === "completed") {
          result = statusData.result as AnalyzeBatchResponse;
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 1000));
        attempts += 1;
      }
      if (!result) {
        throw new Error("Guardrails async scan timed out");
      }
    } else {
      const res = await fetch(`${backendUrl}/analyze-batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders },
        body: JSON.stringify(requestPayload),
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(`Guardrails analyze-batch failed (${res.status}): ${body}`);
      }
      result = (await res.json()) as AnalyzeBatchResponse;
    }
    const { issues, coding, license, sector: sectorIssues, ai, repoLicense } = summarizeFindings(result);
    const labels = pr.labels?.map((label: any) => label.name) || [];
    const hasOverride = labels.includes(OVERRIDE_LABEL);
    const shouldBlock = result.policy === "blocking" && !hasOverride;
    const conclusion = shouldBlock ? "failure" : result.policy === "warning" ? "neutral" : "success";
    const annotations = buildAnnotations(result, fileCode);
    const existingReviewComments = await context.octokit.pulls.listReviewComments({
      owner,
      repo: repoName,
      pull_number: pr.number,
      per_page: 100,
    });
    const existingKeys = new Set<string>();
    for (const comment of existingReviewComments.data) {
      if (!comment.body || !comment.path || !comment.line) continue;
      if (!comment.body.includes(REVIEW_MARKER)) continue;
      existingKeys.add(`${comment.path}:${comment.line}:${comment.body}`);
    }
    const reviewComments = buildReviewComments(result, fileCode, diffLines, existingKeys);

    const summaryLines = [
      `Policy: ${result.policy}${hasOverride ? " (override applied)" : ""}`,
      `Files scanned: ${result.files_scanned}`,
      `Security issues: ${issues}`,
      `Coding issues: ${coding}`,
      `License/IP issues: ${license}`,
      `Repo license issues: ${repoLicense}`,
      `Sector issues: ${sectorIssues}`,
      `AI suggestions: ${ai}`,
    ];
    const aiHighlights = collectAiHighlights(result);

    await context.octokit.issues.createComment({
      owner,
      repo: repoName,
      issue_number: pr.number,
      body: `## Guardrails Report\n${summaryLines.map((line) => `- ${line}`).join("\n")}${
        aiHighlights.length ? `\n\n### AI review highlights\n${aiHighlights.map((item) => `- ${item}`).join("\n")}` : ""
      }`,
    });

    if (reviewComments.length > 0) {
      await context.octokit.pulls.createReview({
        owner,
        repo: repoName,
        pull_number: pr.number,
        event: "COMMENT",
        body: "Guardrails inline findings",
        comments: reviewComments,
      });
    }

    await context.octokit.checks.update({
      owner,
      repo: repoName,
      check_run_id: checkRun.data.id,
      status: "completed",
      conclusion,
      output: {
        title: "Guardrails analysis",
        summary: summaryLines.join("\n"),
        annotations,
      },
    });
  });

  app.on("push", async (context: Context) => {
    const payload = context.payload as any;
    const repo = payload.repository;
    const owner = repo.owner.login;
    const repoName = repo.name;
    const headSha = payload.after;

    const checkRun = await context.octokit.checks.create({
      owner,
      repo: repoName,
      name: "guardrails",
      head_sha: headSha,
      status: "in_progress",
      output: {
        title: "Guardrails analysis",
        summary: "Scan started.",
      },
    });

    const commit = await context.octokit.repos.getCommit({ owner, repo: repoName, ref: headSha });
    const files = [] as Array<{ path: string; code: string; patch?: string; language?: string }>;
    const fileCode: Record<string, string> = {};
    for (const file of commit.data.files || []) {
      if (!file.filename || file.status === "removed") continue;
      if (!isSupportedFile(file.filename)) continue;
      if (files.length >= MAX_FILES) break;
      try {
        const contentRes = await context.octokit.repos.getContent({ owner, repo: repoName, path: file.filename, ref: headSha });
        if (Array.isArray(contentRes.data) || !("content" in contentRes.data)) continue;
        const raw = decodeContent(contentRes.data.content, contentRes.data.encoding);
        if (raw.length > MAX_FILE_BYTES) continue;
        fileCode[file.filename] = raw;
        files.push({
          path: file.filename,
          code: raw,
          patch: file.patch || "",
          language: detectLanguage(file.filename),
        });
      } catch (error) {
        continue;
      }
    }

    const aiGenerated = payload.commits?.some((commit: any) => detectCopilot(commit.message)) || false;
    const backendUrl = process.env.BACKEND_URL || "http://localhost:8000";
    const backendToken = process.env.BACKEND_TOKEN || "";
    const userKey = process.env.GUARDRAILS_USER || process.env.GITHUB_ACTOR || "";
    const authHeaders: Record<string, string> = backendToken ? { Authorization: `Bearer ${backendToken}` } : {};
    if (userKey) {
      authHeaders["X-Guardrails-User"] = userKey;
    }
    const useAsync = process.env.USE_ASYNC_SCAN === "true";
    const repoLicenseTexts = await fetchLicenseTexts(context, owner, repoName, headSha);
    const requestPayload = {
      commit: headSha,
      repo: repo.full_name,
      files,
      sector: "finance",
      ai_generated: aiGenerated,
      repo_path: repo.full_name,
      repo_license_texts: repoLicenseTexts,
    };

    let result: AnalyzeBatchResponse | null = null;
    if (useAsync) {
      const startRes = await fetch(`${backendUrl}/scan/async`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders },
        body: JSON.stringify(requestPayload),
      });
      if (!startRes.ok) {
        const body = await startRes.text();
        throw new Error(`Guardrails async scan failed (${startRes.status}): ${body}`);
      }
      const startData = await startRes.json();
      const jobId = startData.job_id;
      let attempts = 0;
      while (attempts < 10) {
        const statusRes = await fetch(`${backendUrl}/scan/status/${jobId}`, {
          headers: authHeaders,
        });
        if (!statusRes.ok) {
          const body = await statusRes.text();
          throw new Error(`Guardrails async status failed (${statusRes.status}): ${body}`);
        }
        const statusData = await statusRes.json();
        if (statusData.status === "completed") {
          result = statusData.result as AnalyzeBatchResponse;
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 1000));
        attempts += 1;
      }
      if (!result) {
        throw new Error("Guardrails async scan timed out");
      }
    } else {
      const res = await fetch(`${backendUrl}/analyze-batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders },
        body: JSON.stringify(requestPayload),
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(`Guardrails analyze-batch failed (${res.status}): ${body}`);
      }
      result = (await res.json()) as AnalyzeBatchResponse;
    }
    const { issues, coding, license, sector: sectorIssues, ai, repoLicense } = summarizeFindings(result);
    const conclusion = result.policy === "blocking" ? "failure" : result.policy === "warning" ? "neutral" : "success";
    const annotations = buildAnnotations(result, fileCode);
    const summaryLines = [
      `Policy: ${result.policy}`,
      `Files scanned: ${result.files_scanned}`,
      `Security issues: ${issues}`,
      `Coding issues: ${coding}`,
      `License/IP issues: ${license}`,
      `Repo license issues: ${repoLicense}`,
      `Sector issues: ${sectorIssues}`,
      `AI suggestions: ${ai}`,
    ];

    await context.octokit.checks.update({
      owner,
      repo: repoName,
      check_run_id: checkRun.data.id,
      status: "completed",
      conclusion,
      output: {
        title: "Guardrails analysis",
        summary: summaryLines.join("\n"),
        annotations,
      },
    });
  });
};
