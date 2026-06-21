---
title: Homelab reverse proxy
description: Put quik in front of a handful of self-hosted services and terminate TLS once.
---

A homelab usually has a handful of services running on different boxes -
Proxmox at one IP, Plex at another, TrueNAS somewhere else - each on its own
port and most of them serving a self-signed certificate that browsers
complain about. quik can sit in front of all of them, handle TLS once with a
cert that *you* trust, and route by hostname.

The whole setup is one config file and a shell script.

## What you'll end up with

- `https://proxmox.internal:8443/` → Proxmox UI on 192.168.x.x:8006
- `https://plex.internal:8443/` → Plex on 192.168.x.x:32400
- `https://truenas.internal:8443/` → TrueNAS UI on 192.168.x.x:443

One cert, valid for all three hostnames. WebSocket consoles (Proxmox noVNC,
xterm.js) Just Work. Backend self-signed certs are accepted with
`skip_verify`.

quik binds the unprivileged `:8443`, so it runs directly on the host without
`sudo` or `setcap`. Want the bare `https://<service>.internal` on port 443?
Publish it with a Docker port mapping or a firewall redirect (443 → 8443).

## Step 1 - DNS

The hostnames you put in the routes (`proxmox.internal`, `plex.internal`,
etc.) have to resolve to the host running quik. Three common options:

- **`/etc/hosts`** on each client device:
  ```
  192.168.1.10  proxmox.internal plex.internal truenas.internal
  ```
- **Pi-hole / AdGuard / Unbound**: add a local A record pointing each name
  at the proxy host.
- **Your router's DNS**: most home routers let you set per-hostname A
  records.

`.internal` is the recommendation - it's reserved by ICANN for private use,
so it'll never collide with a real TLD.

## Step 2 - Edit the sample config

Copy `config/homelab.toml` and replace the backend IPs with your own:

```toml
[[upstreams]]
name = "proxmox"
members = [{ address = "192.168.1.20:8006", scheme = "https" }]

[upstreams.tls]
skip_verify = true   # most homelab services use self-signed certs

[[upstreams]]
name = "plex"
members = [{ address = "192.168.1.21:32400", scheme = "http" }]

[[upstreams]]
name = "truenas"
members = [{ address = "192.168.1.22:443", scheme = "https" }]

[upstreams.tls]
skip_verify = true

[[routes]]
hosts = ["proxmox.internal"]
path_prefix = "/"
upstream = "proxmox"

[[routes]]
hosts = ["plex.internal"]
path_prefix = "/"
upstream = "plex"

[[routes]]
hosts = ["truenas.internal"]
path_prefix = "/"
upstream = "truenas"
```

The shape stays the same for any homelab service: add an `[[upstreams]]`
block with its IP and scheme, then a `[[routes]]` block matching the
hostname.

## Step 3 - Run it

The bundled runner script generates a self-signed cert with SANs for each
hostname and starts the proxy:

```bash
./scripts/run-homelab.sh
```

That's it. Visit `https://proxmox.internal:8443/` (after accepting the
self-signed cert once) and you should see Proxmox.

If you'd rather run quik manually:

```bash
# Generate a cert with the SANs you need
SAN_HOSTS=proxmox.internal,plex.internal,truenas.internal \
  ./scripts/gen-dev-cert.sh

# Run
./target/release/quik --config config/homelab.toml
```

## Step 4 - A real cert (optional, but nice)

A browser-trusted certificate makes the experience cleaner. Two approaches
that work well in a homelab:

- **mkcert** - set up a local CA, then issue a cert quik trusts. Install the
  mkcert root on each client device and the green padlock comes back.
  ```bash
  mkcert -install
  mkcert -cert-file tls/cert.pem -key-file tls/key.pem \
    proxmox.internal plex.internal truenas.internal
  ```
- **Let's Encrypt with DNS-01** - if your `*.internal` names live in a real
  domain you control (e.g. `*.lab.example.com`), [certbot] or [lego] can
  issue a wildcard cert without exposing anything to the public internet.
  Drop the resulting fullchain/key into `tls/` and quik picks them up on
  restart.

Either way: replace `tls/cert.pem` and `tls/key.pem`, restart, done.

## Gotchas

**Absolute-URL redirects.** Some backend admin UIs (Proxmox and TrueNAS, in
particular) emit `Location` headers with the backend's IP rather than the
proxy hostname. quik does not rewrite response bodies or Location headers.
The fix is on the backend side - every one of these services has a setting
for "external URL" or "trusted proxy" that tells it to issue relative
redirects.

**Plex's `*.plex.direct` trick.** Plex's web app loads from your local server
on first request, then switches over to its own discovery URL on
`*.plex.direct`. That's Plex's own behaviour, not a quik issue, and there's
nothing the proxy can do about it without rewriting JavaScript.

**TLS upgrade for WebSocket consoles.** No config needed - quik forwards
`Upgrade: websocket` transparently. The Proxmox noVNC console and the
xterm.js terminal both work end-to-end.

**Performance.** None of this is in a hot path you need to tune. A homelab
proxy handling a handful of clicks per minute uses about 5 MB RSS on the
proxy host. The release binary is fine; you don't need to think about
threads or buffer sizes.

## What's next

- More backends? Same shape - copy an upstream + route pair and adjust IPs.
- A second proxy host for redundancy? See
  [HA reverse proxy](ha-reverse-proxy.md).
- Outbound filtering for the same network? See
  [forward proxy](forward-proxy.md).

[certbot]: https://certbot.eff.org/
[lego]: https://go-acme.github.io/lego/
