import { expect, test } from "@playwright/test";
import { mockApi, sampleEmail, viewerUser } from "./helpers";

test.describe("console pages", () => {
  test("overview shows feed rows and sidebar navigation", async ({ page }) => {
    await mockApi(page, {
      feed: [
        sampleEmail(),
        sampleEmail({
          id: "msg-2",
          subject: "Payroll update",
          fromAddr: "hr@example.com",
          fromName: "HR",
          verdict: "SUSPICIOUS",
          score: 52,
          threadKey: "t-hr",
        }),
      ],
    });
    await page.goto("/overview");
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    await expect(page.getByText("Q3 invoice")).toBeVisible();
    await expect(page.getByText("Payroll update")).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Pages" })).toBeVisible();
    await page.getByRole("link", { name: /Workers/ }).click();
    await expect(page).toHaveURL(/\/workers$/);
  });

  test("workers page shows job queue counts", async ({ page }) => {
    await mockApi(page, {
      feed: [
        sampleEmail({
          id: "wait-1",
          subject: "Waiting on model",
          aiSummary: "",
          aiProvider: "",
          sourceKind: "gmail",
          verdict: "MALICIOUS",
        }),
      ],
    });
    await page.goto("/workers");
    await expect(page.getByRole("heading", { name: "Workers" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Job queues" })).toBeVisible();
  });

  test("quarantine lists spool-held mail", async ({ page }) => {
    await mockApi(page, {
      feed: [
        sampleEmail({
          id: "held-1",
          subject: "Credential harvest",
          sourceKind: "spool",
          bucket: "quarantine",
          verdict: "SUSPICIOUS",
          score: 61,
          status: "held",
        }),
      ],
    });
    await page.goto("/quarantine");
    await expect(page.getByText("Credential harvest")).toBeVisible();
    await expect(page.getByRole("button", { name: /View/ })).toBeVisible();
  });

  test("mail detail renders the selected copy", async ({ page }) => {
    await mockApi(page);
    await page.goto("/mail/msg-1");
    await expect(page.getByRole("button", { name: "← Back" })).toBeVisible();
    await expect(page.getByText("Q3 invoice").first()).toBeVisible();
  });

  test("analyze is available to admins and denied to viewers", async ({ page }) => {
    await mockApi(page);
    await page.goto("/analyze");
    await expect(page.getByRole("button", { name: "Upload EML file" })).toBeVisible();

    await mockApi(page, { user: viewerUser });
    await page.goto("/analyze");
    await expect(page.getByText(/Deep analysis requires Admin or Analyst/)).toBeVisible();
  });

  test("settings is admin-only", async ({ page }) => {
    await mockApi(page);
    await page.goto("/settings");
    await expect(page.getByRole("heading", { name: "Gateway enforcement" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Email fetching" })).toBeVisible();
    await page.getByRole("link", { name: "Organization" }).click();
    await expect(page).toHaveURL(/\/settings\/organization$/);
    await expect(page.getByRole("heading", { name: "Facts the AI should keep using" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Always quarantine" })).toBeVisible();
    await page.getByRole("link", { name: "Notifications" }).click();
    await expect(page).toHaveURL(/\/settings\/notifications$/);
    await expect(page.getByRole("heading", { name: "Slack" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Email" })).toBeVisible();
    await page.getByRole("link", { name: "Users & SSO" }).click();
    await expect(page).toHaveURL(/\/settings\/users$/);
    await expect(page.getByRole("heading", { name: "JumpCloud SSO" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Create user" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Your profile" })).toBeVisible();

    await page.getByRole("link", { name: "Open profile" }).click();
    await expect(page).toHaveURL(/\/profile$/);
    await expect(page.getByRole("heading", { name: "Multi-factor authentication" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Your activity" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Password" })).toBeVisible();

    await mockApi(page, { user: viewerUser });
    await page.goto("/settings");
    await expect(page).toHaveURL(/\/overview$/);
    await page.goto("/settings/users");
    await page.goto("/settings/notifications");
    await page.goto("/settings/organization");
    await page.goto("/settings");
    await expect(page).toHaveURL(/\/overview$/);
    await page.goto("/profile");
    await expect(page).toHaveURL(/\/profile$/);
    await expect(page.getByRole("heading", { name: "Signed in as viewer" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Multi-factor authentication" })).toBeVisible();
  });

  test("audit search filters events", async ({ page }) => {
    await mockApi(page);
    await page.goto("/audit");
    await expect(page.getByText("Signed in")).toBeVisible();
    await page.getByPlaceholder("Search audit log…").fill("no-such-event");
    await expect(page.getByText(/No matching audit events/)).toBeVisible();
  });

  test("logout returns to login", async ({ page }) => {
    await mockApi(page);
    await page.goto("/overview");
    await page.getByRole("button", { name: "Log out" }).click();
    await expect(page).toHaveURL(/\/login/);
  });
});
