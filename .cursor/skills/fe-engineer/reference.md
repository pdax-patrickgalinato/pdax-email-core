# SEGS web console — reference

## Routing

`src/App.tsx` is the route table. `ConsoleLayout` loads `/api/auth/me`, then `ConsoleProvider` + `Layout`.

| Path | Page |
|------|------|
| `/login` | Login |
| `/overview` | Overview |
| `/quarantine` | Quarantine |
| `/analyze` | Analyze (parked API) |
| `/senders` | Senders |
| `/campaigns` | Campaigns |
| `/workers` | Workers (`/queue` redirects here) |
| `/audit` | Audit |
| `/settings` | Settings |
| `/settings/organization` | OrgContext |
| `/settings/notifications` | Notifications |
| `/settings/users` | UserManagement |
| `/profile` | Profile |
| `/mail/:id` | Detail |

`main.tsx` redirects `127.0.0.1` → `localhost` for passkeys.

## Legacy engine

`src/lib/dashboard.ts` (~7.4k lines, `@ts-nocheck`) is the pre-React dashboard: verdict model, Chart.js/map painters, string-HTML builders, `state` singleton, `loadFeed()`.

- Pages still import many symbols from it.
- `ConsoleContext` calls `loadFeed()` on a timer (4s while AI pending, 5s on Workers, 15s otherwise).
- Prefer extracting functions into `src/lib/<topic>.ts` with types. Do not append new painters or fetchers to `dashboard.ts`.

`state` is a mutable singleton. New React state belongs in `ConsoleContext` or local component state. Do not add more fields to `state` unless a page already depends on that pattern.

## Fetch contract

Workers write `copies`; the API should SELECT. Live mail is not re-scored on `GET /api/feed`.

Target (also `plan/efficient-api-fetches.md`):

- Overview: `GET /api/feed` only (filtered **or** unfiltered, not both).
- Detail: `GET /api/feed/item/{id}`.
- Workers / audit / senders / campaigns: page-scoped or slow cadence.

`vite.config.ts` `/api` proxy must keep `changeOrigin: false`.

## Types

`src/types.ts` is the console DTO layer. When `backend/api/feed_builder.py` or OpenAPI changes a field the UI shows, update types + a unit test in the same turn.

## Tests

- Vitest + Testing Library via `src/test/render.tsx` (`renderWithConsole`).
- `src/test/engine.ts` resets the dashboard singleton between tests.
- Do not hit the real API in unit tests; stub `fetch` in `src/test/setup.ts`.

## Styling

Most layout is `src/app.css` plus `Login.css`. Match existing tokens (verdict classes `v-clean` … `v-malicious`). No new CSS framework unless asked.

## Infra touchpoints

Changing a public path (`/api/...`, `/scim/...`, console routes that must not fall through to S3) requires `infra/openapi.yaml` / CloudFront behaviors. SPA fallback: unknown paths should still serve `index.html` except `/api*` and `/scim*`.
