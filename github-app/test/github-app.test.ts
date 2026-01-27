import { Probot } from "probot";
import nock from "nock";
import app from "../index";

describe("github-guardrails-app", () => {
  let probot: Probot;

  beforeEach(() => {
    probot = new Probot({
      appId: 123,
      privateKey: "test",
      secret: "test",
    });
    probot.load(app);
  });

  test("posts a comment on PR opened", async () => {
    nock("http://localhost:8000")
      .post("/analyze")
      .reply(200, { result: "analyzed" });

    const payload = require("./fixtures/pull_request.opened.json");
    const mockCreateComment = jest.fn();
    probot.octokit.issues.createComment = mockCreateComment;

    await probot.receive({ name: "pull_request", payload });
    expect(mockCreateComment).toHaveBeenCalled();
  });
});
