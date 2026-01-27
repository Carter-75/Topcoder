import { Probot, Context } from "probot";
import fetch from "node-fetch";

export = (app: Probot) => {
  app.on(["pull_request.opened", "pull_request.synchronize"], async (context: Context) => {
    const eventPayload = context.payload as any;
    const pr = eventPayload.pull_request;
    const repo = eventPayload.repository;
    // Collect minimal PR metadata and changed files (stub)
    const requestPayload = {
      pr_number: pr.number,
      repo: repo.full_name,
      author: pr.user.login,
      // TODO: Add changed files/diffs
      code: "// code diff or file content here",
      sector: "finance",
      repo_path: "."
    };
    // Call backend analyze endpoint (stub URL)
    const backendUrl = process.env.BACKEND_URL || "http://localhost:8000";
    const res = await fetch(`${backendUrl}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestPayload),
    });
    const result = await res.json();
    // Post a summary comment
    await context.octokit.issues.createComment({
      owner: repo.owner.login,
      repo: repo.name,
      issue_number: pr.number,
      body: `Guardrails analysis result: ${result.result}\nPolicy: ${result.policy}\nIssues: ${result.issues.length}\nCoding: ${result.coding_issues.length}\nLicense/IP: ${result.license_ip_issues.length}\nSector: ${result.sector_issues.length}`,
    });
    // Set status/check (stub)
    await context.octokit.repos.createCommitStatus({
      owner: repo.owner.login,
      repo: repo.name,
      sha: pr.head.sha,
      state: result.policy === "blocking" ? "failure" : result.policy === "warning" ? "success" : "success",
      description: `Guardrails: ${result.policy}`,
      context: "guardrails/check"
    });
  });
};
