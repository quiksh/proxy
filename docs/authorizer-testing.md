---
title: Testing external authorisers
description: Run quik with a local mock authoriser to check allow, deny, error and body-inspection behaviour before connecting your real service.
---

quik includes a **mock authoriser**, `examples/mock_authorizer.rs`. It
follows the same contract as a real `[[authorizers]]` service (see the
[config reference](config-reference.md#authorizers)). It reads its decisions
from a small TOML rules file, so you can try allow, deny, error and slow
responses locally without building a service, or use it as a stand-in
authoriser in your own integration tests.

## Quick start

```bash
make authz-demo     # dev cert + echo backend + mock authoriser + quik
make authz-smoke    # in another shell: checks every outcome, exits non-zero on failure
```

`make authz-demo` runs `scripts/run-authz-demo.sh`. It starts:

| Process           | Address             | Role                                   |
|-------------------|---------------------|----------------------------------------|
| `echo_backend`    | `127.0.0.1:8080`    | Upstream. It echoes back the request it received, including any injected headers. |
| `mock_authorizer` | `127.0.0.1:9100`    | Authoriser, using `config/mock-authorizer.toml` |
| `quik`            | `https://localhost:8443` | Runs with `config/authorizer-demo.toml`. |

Try it:

```bash
curl -k https://localhost:8443/api/orders                         # 401
curl -k https://localhost:8443/api/orders -H 'x-api-key: dev-key' # 200, see x-user-id in the echo
curl -k https://localhost:8443/api/orders -H 'authorization: Bearer allow-alice'
curl -k https://localhost:8443/api/payments -H 'x-api-key: dev-key' -d '{"amount":1000}'  # 403 based on the body
curl -s localhost:9100/_mock/requests | jq                         # requests the authoriser received
```

## Rules

The mock checks rules from top to bottom and uses the first one that
matches. If none match, it uses `[default]`. A rule only matches when every
matcher it sets matches:

| Matcher         | Matches when                                                    |
|-----------------|-----------------------------------------------------------------|
| `method`        | the request method equals this (case-insensitive)               |
| `path_prefix`   | `path` starts with this                                         |
| `headers`       | each forwarded header equals its value (`"*"` = present)        |
| `claims`        | each JWT claim equals its value (`"*"` = present)              |
| `bearer_prefix` | the `authorization` bearer token starts with this               |
| `body_contains` | the decoded body contains this (requires `include_body`)        |

A matching rule then decides the response:

| Field              | Default | Effect                                                     |
|--------------------|---------|------------------------------------------------------------|
| `status`           | `200`   | Response status: 2xx allows, 4xx denies, anything else is an error. |
| `inject`           | `{}`    | Headers quik should inject (2xx only). Values can use the templates `{claims.X}`, `{header.X}`, `{bearer_suffix}`, `{method}` and `{path}`. |
| `body`             | empty   | Body of a deny response, which quik passes to the client.      |
| `www_authenticate` | unset   | `www-authenticate` header on a deny response.              |
| `delay_ms`         | `0`     | Waits this long before responding. Use it to test `timeout_ms`.         |

```toml
[[rules]]
name    = "dev api key"
headers = { "x-api-key" = "dev-key" }
inject  = { "x-user-id" = "dev-user", "x-tenant-id" = "dev-tenant" }

[default]
status = 401
body   = '{"message":"unauthorised"}'
```

When no `AUTHZ_RULES` file is given, a built-in set of rules is used and
printed at startup. It allows a verified JWT `sub`, the API key `dev-key`
and `allow-<user>` bearer tokens, and denies everything else with 401.

## Control headers

To force a particular outcome on a single request, send these headers and
list them in the authoriser's `forward_headers`. The demo config already does.
They take priority over the rules:

| Header            | Effect                                           |
|-------------------|--------------------------------------------------|
| `x-mock-status`   | Respond with this status, e.g. `503` to test `on_error` or `429` to test a relayed deny. |
| `x-mock-delay-ms` | Wait before responding, e.g. longer than `timeout_ms`. |

Don't forward `x-mock-*` headers to a real authoriser.

## Endpoints

| Endpoint                   | Purpose                                          |
|----------------------------|--------------------------------------------------|
| `POST <any path>`          | The authoriser itself.                            |
| `GET /_mock/requests`      | The last 100 requests it received, oldest first, for test assertions. |
| `DELETE /_mock/requests`   | Clears the recorded requests between test cases.     |
| `GET /healthz`             | Returns `ok`.                                     |

## Using it in your own tests

Run the mock on its own and point a `[[authorizers]]` block at it:

```bash
BIND_ADDR=127.0.0.1:9100 AUTHZ_RULES=my-rules.toml cargo run --example mock_authorizer
```

A test can then send requests through quik and assert on what the upstream
received, such as the injected headers. It can also read
`GET /_mock/requests` to check what quik sent the authoriser: forwarded
headers, claims and the body. `scripts/authz-smoke.sh` does exactly this,
and you can copy it as a starting point. Set `QUIK` and `AUTHZ` to point it at
other addresses.
