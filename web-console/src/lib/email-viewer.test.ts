import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { bindEmailViewer, parseEml, renderEmailViewer, sanitizeEmailHtml } from "./dashboard";

const corpus = resolve(__dirname, "../../../backend/tests/fixtures/eml");

function readEml(name: string) {
  return readFileSync(resolve(corpus, name), "utf8");
}

describe("email HTML images", () => {
  it("inlines Gmail cid: images from multipart/related", () => {
    const parsed = parseEml(readEml("atiu-04082026.eml"));
    expect(parsed.html).toMatch(/cid:ii_mno7liq61/i);
    expect(parsed.cids["ii_mno7liq61"]).toMatch(/^(data:image\/jpeg;base64,|blob:)/);
    const html = sanitizeEmailHtml(parsed.html, parsed.cids);
    expect(html).not.toMatch(/cid:ii_mno7liq61/i);
    expect(html).toMatch(/src="(data:image\/jpeg;base64,|blob:)/);
  });

  it("inlines cid: images that wrap across quoted-printable lines", () => {
    const parsed = parseEml(readEml("burpsuite-proposal.eml"));
    const cid = "0.1730347420.4941052975442478724.19d2914e6ce__inline__img__src";
    expect(parsed.cids[cid]).toBeTruthy();
    const html = sanitizeEmailHtml(parsed.html, parsed.cids);
    expect(html).not.toContain("cid:" + cid);
  });

  it("keeps remote https images and resolves relative src against <base>", () => {
    const html = sanitizeEmailHtml(
      '<base href="https://cdn.example.com/camp/"><img src="hero.png"><img src="https://ok.example/a.png"><img src="http://legacy.example/b.png"><img src="//cdn.example.com/c.png">',
      {},
    );
    expect(html).toContain('src="https://cdn.example.com/camp/hero.png"');
    expect(html).toContain('src="https://ok.example/a.png"');
    expect(html).toContain('src="https://legacy.example/b.png"');
    expect(html).toContain('src="https://cdn.example.com/c.png"');
    expect(html).not.toMatch(/<base\b/i);
  });

  it("matches percent-encoded cid urls", () => {
    const html = sanitizeEmailHtml(
      '<img src="cid:ii_abc%40mail.gmail.com">',
      { "ii_abc@mail.gmail.com": "data:image/png;base64,xx" },
    );
    expect(html).toContain('src="data:image/png;base64,xx"');
  });
});

describe("detail email expand", () => {
  afterEach(() => {
    document.body.innerHTML = "";
  });

  const parsed = {
    headers: { from: "a@b.com", subject: "Invoice" },
    html: "<p>Pay this invoice now.</p>",
    plain: "Pay this invoice now.",
    attachments: [] as string[],
    cids: {},
  };

  it("keeps the body collapsed on the detail page until click", () => {
    const host = document.createElement("div");
    host.className = "detail-mail";
    host.innerHTML = renderEmailViewer(parsed, {});
    document.body.appendChild(host);
    bindEmailViewer(host);
    const viewer = host.querySelector(".email-viewer") as HTMLElement;
    expect(viewer.classList.contains("is-collapsed")).toBe(true);
    expect(host.querySelector("iframe")).toBeNull();
    expect(host.querySelector(".email-viewer-stage")?.innerHTML).toBe("");
    const peek = host.querySelector("[data-expand-mail]") as HTMLButtonElement;
    expect(peek.hidden).toBe(false);
    peek.click();
    expect(viewer.classList.contains("is-expanded")).toBe(true);
    expect(host.querySelector("iframe")).toBeTruthy();
    expect(peek.hidden).toBe(true);
  });

  it("collapses the iframe back into the snippet instead of leaving it in the page", () => {
    const host = document.createElement("div");
    host.className = "detail-mail";
    host.innerHTML = renderEmailViewer(parsed, {});
    document.body.appendChild(host);
    bindEmailViewer(host);
    (host.querySelector("[data-expand-mail]") as HTMLButtonElement).click();
    expect(host.querySelector("iframe")).toBeTruthy();
    (host.querySelector("[data-collapse-mail]") as HTMLButtonElement).click();
    expect(host.querySelector(".email-viewer")?.classList.contains("is-collapsed")).toBe(true);
    expect(host.querySelector("iframe")).toBeNull();
  });

  it("still paints immediately outside the detail page", () => {
    const host = document.createElement("div");
    host.innerHTML = renderEmailViewer(parsed, {});
    document.body.appendChild(host);
    bindEmailViewer(host);
    expect(host.querySelector(".email-viewer")?.classList.contains("is-expanded")).toBe(true);
    expect(host.querySelector("iframe")).toBeTruthy();
  });
});
