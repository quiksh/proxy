---
title: Identity-aware proxy
description: Put corporate sign-in in front of every app - quik enforces a session JWT issued by a separate sign-in service. This is the contract between the two.
---

quik can sit in front of internal apps as the enforcement half of an
identity-aware proxy (IAP): no request reaches an app until the user has a
valid corporate session, and individual routes can demand more - membership of
a group, a hardware key, a recent sign-in. The apps keep their own login on
top.

quik deliberately does **not** sign anyone in. It never talks to the identity
provider, holds no signing keys and keeps no session state. A separate
**sign-in service** does all of that and hands the browser a signed JWT in a
cookie; quik validates that JWT on every request. This page is the contract
between the two.

```
browser ──► LB ──► quik ───────────────────────────────► app (own login on top)
              │      │ no/expired session on a page load
              │      └─ 302 ─► sign-in service ─► IdP (e.g. Google)
              │                 │ verifies, checks policy, optional key step-up
              │                 └─ Set-Cookie: session JWT ─► 302 back to rd
              └─ quik fetches the sign-in service's JWKS (on kid miss)
```

## Who does what

| Concern | quik | Sign-in service |
|---|---|---|
| Talk to the IdP (OIDC code flow, PKCE, state, nonce) | | ✓ |
| Decide who may have a session at all (domain, account state) | | ✓ |
| Hardware-key (WebAuthn) challenge and verification | | ✓ |
| Look up groups, decide `amr`, set `auth_time` | | ✓ |
| Sign session JWTs, publish the JWKS, rotate keys | | ✓ |
| Validate the return URL (`rd`), log out | | ✓ |
| Verify the JWT signature, `iss`, `aud`, `exp` on every request | ✓ | |
| Per-issuer and per-route policy: claim values, groups, `amr`, `auth_time` age | ✓ | |
| Redirect page loads to sign in; 401/403 everything else | ✓ | |
| Inject verified identity headers; strip the session cookie | ✓ | |

The split keeps the proxy small and stateless, and puts the parts that change
with your identity provider in one service you can replace.

## The contract

### Cookie

The sign-in service sets one cookie, named in `token_cookie`:

```
Set-Cookie: __Secure-corp_session=<jwt>; Domain=corp.example.test; Path=/;
            Secure; HttpOnly; SameSite=Lax; Max-Age=28800
```

- **`Domain`** must cover every host behind quik and **nothing else**. A cookie
  on a parent domain is sent to every subdomain - a marketing site or
  third-party-hosted page there could capture and replay the session. Use a
  dedicated zone such as `corp.example.test`.
- `HttpOnly` keeps it out of page scripts; `SameSite=Lax` stops other sites
  riding it on cross-site POSTs.
- `Max-Age` should not exceed the JWT's `exp`.

### Session JWT

| Claim | Required | Meaning |
|---|---|---|
| `iss` | yes | The sign-in service's issuer URL; matches `issuer`. |
| `aud` | yes | Matches `audience` (e.g. `corp`). |
| `sub` | yes | Stable user id (e.g. the IdP subject). |
| `exp`, `iat` | yes | Session lifetime. Hours, not days. |
| `email` | typically | Injected for apps via `inject_headers`. |
| `hd` | for domain checks | The user's organisation domain, checked with `claim_equals`. |
| `groups` | for group checks | Array of group names, checked with `claim_contains`. |
| `amr` | for step-up | Array of [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176) methods used, e.g. `["google", "hwk"]`. |
| `auth_time` | for recency | NumericDate of the most recent interactive authentication that the `amr` values describe. |

Header: an asymmetric algorithm listed in `algorithms` (ES256 recommended) and
a `kid` present in the JWKS. Claims are top-level; quik doesn't read nested
paths.

### JWKS

- Served at the `jwks_url` quik is configured with, over HTTPS.
- Every key has a `kid`. quik caches keys and re-fetches only when it sees an
  unknown `kid`, so **publish a new key before signing with it**, and keep the
  old one published until the last token it signed has expired.

### Login endpoint

quik redirects to `login_redirect` with `{url}` replaced by the
percent-encoded original URL. The service must:

1. **Validate `rd`** - absolute `https://` URL on an allow-listed host (for
   example `*.corp.example.test`). Anything else is an open redirect.
2. Sign the user in (skipping the IdP if a valid IdP session exists).
3. Satisfy the step-up parameters quik appends for routes with
   `[routes.require]`:
   - `amr_values`: space-separated methods the session must include, for
     example `hwk`. Perform each (such as a hardware-key touch) and add it to
     `amr`.
   - `max_age`: seconds. If the last interactive authentication is older than
     this, authenticate again and set `auth_time` to now.
4. Set the cookie and redirect to `rd`.

## Example: frontend with Google sign-in, API needs a hardware key

One `[[auth]]` block describes the session: how to verify it, and what every
session must satisfy. Each route adds what it needs with `[routes.require]`.

```toml
[[auth]]
name           = "corp"
jwks_url       = "https://auth.corp.example.test/.well-known/jwks.json"
issuer         = "https://auth.corp.example.test"
audience       = "corp"
algorithms     = ["ES256"]
token_cookie   = "__Secure-corp_session"
login_redirect = "https://auth.corp.example.test/login?rd={url}"
claim_equals   = { hd = "example.test" }
inject_headers = [{ claim = "email", header = "x-auth-email", required = true }]

# Any signed-in employee.
[[routes]]
hosts    = ["admin.corp.example.test"]
auth     = "corp"
upstream = "admin-frontend"

# The API: in the group, with a hardware-key touch in the last 12 hours.
[[routes]]
hosts    = ["admin-api.corp.example.test"]
methods  = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
auth     = "corp"
upstream = "admin-api"

[routes.require]
claim_contains       = { groups = "admin-api-users" }
amr                  = ["hwk"]
max_auth_age_seconds = 43200

# CORS preflights carry no cookies: let them through to the API unauthenticated.
[[routes]]
hosts    = ["admin-api.corp.example.test"]
methods  = ["OPTIONS"]
upstream = "admin-api"
```

The app's own `Authorization: Bearer` token passes through quik untouched, so
the API keeps its existing check as a second layer.

### What the browser sees

| Situation | Page load | `fetch` / XHR / script |
|---|---|---|
| No session, or expired / unverifiable | 302 to sign-in | 401 (expired: 403) |
| Signed in, but no `hwk` or `auth_time` too old | 302 to sign-in with `amr_values=hwk&max_age=43200` | 401 + `WWW-Authenticate: Bearer error="insufficient_user_authentication", amr_values="hwk", max_age=43200` |
| Wrong domain or not in the group | 403 | 403 |

A single-page app should treat a 401 from its API as "send the user to sign
in": navigate the top-level window to the sign-in URL with `rd` set to the
current page. When the challenge says `insufficient_user_authentication`, copy
its `amr_values` and `max_age` onto that URL.

## Checklist

- [ ] Apps accept traffic only from quik (security groups / network policy).
      Injected `x-auth-*` headers are only trustworthy if nothing else can
      reach the app. quik already rejects clients that send them.
- [ ] Cookie `Domain` scoped to a zone where every host is behind quik.
- [ ] Sign-in service validates `rd` against an allow-list.
- [ ] JWT lifetime in hours; `[routes.require] max_auth_age_seconds` on
      sensitive routes.
- [ ] Group-restricted routes use `[routes.require] claim_contains`, not just
      a valid session.
- [ ] Routes that change state either need the app's own token or rely on
      `SameSite=Lax` + no cookie-only state changes on GET.
