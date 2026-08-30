export async function api<T = unknown>(path: string, opts: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { ...((opts.headers as Record<string, string>) || {}) };
  if (opts.body && !(opts.body instanceof FormData) && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  const r = await fetch(path, { credentials: "same-origin", ...opts, headers });
  const isJson = (r.headers.get("content-type") || "").includes("application/json");
  const body: unknown = isJson ? await r.json().catch(() => ({})) : await r.text();
  if (!r.ok) {
    let detail: unknown = body && typeof body === "object" ? (body as { detail?: unknown }).detail : undefined;
    if (Array.isArray(detail)) {
      detail = detail.map((x: { msg?: string }) => x.msg || JSON.stringify(x)).join("; ");
    }
    throw new Error((typeof detail === "string" && detail) || r.statusText || String(r.status));
  }
  return body as T;
}
