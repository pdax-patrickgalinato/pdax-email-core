import { expect, test } from "@playwright/test";
import { mockApi } from "./helpers";

test.describe("login", () => {
  test("signs in and lands on overview", async ({ page }) => {
    await mockApi(page);
    await page.goto("/login");
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("password1");
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL(/\/overview$/);
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  });

  test("shows an error for bad credentials", async ({ page }) => {
    await mockApi(page, { loginFail: true, user: null });
    await page.goto("/login");
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("wrongpass");
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByText("Invalid credentials")).toBeVisible();
    await expect(page).toHaveURL(/\/login/);
  });

  test("rejects open-redirect next values", async ({ page }) => {
    await mockApi(page);
    await page.goto("/login?next=https://evil.example");
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("password1");
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL(/\/overview$/);
  });

  test("sends unauthenticated visitors to login", async ({ page }) => {
    await mockApi(page, { user: null });
    await page.goto("/workers");
    await expect(page).toHaveURL(/\/login\?next=/);
  });
});
