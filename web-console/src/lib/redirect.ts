/** Same-origin relative paths only — blocks open redirects after login. */
export function safeNext(raw: string | null | undefined): string {
  if (
    raw &&
    raw.charAt(0) === "/" &&
    raw.indexOf("//") !== 0 &&
    raw.indexOf("/login") !== 0 &&
    raw.indexOf("/api") !== 0
  ) {
    return raw;
  }
  return "/overview";
}
