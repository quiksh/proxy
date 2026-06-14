#!/usr/bin/env python3
"""Mint test JWTs for quik and serve a matching JWKS.

This is a development / smoke-test helper. The private key it generates is
written to scripts/test_keys/private.pem with mode 0600 and is intended to
be regenerated freely - never reuse it in production.

Subcommands:
  init                       Generate a fresh Ed25519 keypair under scripts/test_keys/.
  jwks                       Print the JWKS JSON matching the current private key.
  serve [--port 9999]        Run a tiny HTTP server that returns the JWKS at /jwks.json.
  sign [--sub user-42]       Print a freshly signed JWT to stdout.

Typical flow against a local quik:

  ./scripts/mint_jwt.py init
  ./scripts/mint_jwt.py serve &                 # JWKS now at http://localhost:9999/jwks.json
  # configure quik with jwks_url = "http://localhost:9999/jwks.json"
  # (or "http://host.docker.internal:9999/jwks.json" if quik is in docker)
  TOKEN=$(./scripts/mint_jwt.py sign --sub user-42 --aud api)
  curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8443/secure

Dependencies:
  pip install PyJWT cryptography
"""

import argparse
import base64
import http.server
import json
import os
import socketserver
import sys
import time
from pathlib import Path

try:
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    sys.exit(
        "ERROR: missing python deps. Install with:\n"
        "  pip install PyJWT cryptography"
    )

SCRIPT_DIR = Path(__file__).resolve().parent
KEY_DIR = SCRIPT_DIR / "test_keys"
PRIVATE_KEY_PATH = KEY_DIR / "private.pem"
KID_PATH = KEY_DIR / "kid.txt"
DEFAULT_ISSUER = "https://issuer.test/"
DEFAULT_AUDIENCE = "api"


def current_kid() -> str:
    if not KID_PATH.exists():
        sys.exit(
            f"{KID_PATH} not found - generate one with:\n  {sys.argv[0]} init"
        )
    return KID_PATH.read_text().strip()


def load_private_pem() -> bytes:
    if not PRIVATE_KEY_PATH.exists():
        sys.exit(
            f"{PRIVATE_KEY_PATH} not found - generate one with:\n"
            f"  {sys.argv[0]} init"
        )
    return PRIVATE_KEY_PATH.read_bytes()


def jwks_for(private_pem: bytes, kid: str) -> dict:
    priv = serialization.load_pem_private_key(private_pem, password=None)
    pub = priv.public_key()
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": kid,
                "x": x,
            }
        ]
    }


def cmd_init(args: argparse.Namespace) -> None:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if PRIVATE_KEY_PATH.exists() and not args.force:
        sys.exit(
            f"{PRIVATE_KEY_PATH} already exists. Use --force to overwrite."
        )
    priv = ed25519.Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    PRIVATE_KEY_PATH.write_bytes(pem)
    try:
        PRIVATE_KEY_PATH.chmod(0o600)
    except OSError:
        pass
    # Stamp the kid with a timestamp so a re-init produces a fresh kid. That
    # way a running proxy's JwksCache misses on the new kid and refreshes,
    # instead of stubbornly using the cached (now-stale) key.
    kid = f"quik-test-{int(time.time())}"
    KID_PATH.write_text(kid)
    print(f"Wrote {PRIVATE_KEY_PATH}", file=sys.stderr)
    print(f"Wrote {KID_PATH} (kid={kid})", file=sys.stderr)
    print("JWKS:", file=sys.stderr)
    json.dump(jwks_for(pem, kid), sys.stdout, indent=2)
    print()


def cmd_jwks(args: argparse.Namespace) -> None:
    json.dump(jwks_for(load_private_pem(), current_kid()), sys.stdout, indent=2)
    print()


def cmd_serve(args: argparse.Namespace) -> None:
    body = json.dumps(jwks_for(load_private_pem(), current_kid())).encode("utf-8")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path in ("/jwks.json", "/.well-known/jwks.json"):
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("cache-control", "no-cache")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, fmt: str, *fmt_args) -> None:
            sys.stderr.write("jwks: " + (fmt % fmt_args) + "\n")

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", args.port), Handler) as srv:
        print(
            f"JWKS at http://localhost:{args.port}/jwks.json (and /.well-known/jwks.json)",
            file=sys.stderr,
        )
        srv.serve_forever()


def cmd_sign(args: argparse.Namespace) -> None:
    private_pem = load_private_pem()
    now = int(time.time())
    claims: dict = {
        "iss": args.iss,
        "aud": args.aud,
        "sub": args.sub,
        "iat": now,
        "exp": now + args.exp_offset,
    }
    if args.nbf_offset is not None:
        claims["nbf"] = now + args.nbf_offset

    for kv in args.claims:
        if "=" not in kv:
            sys.exit(f"--claim must be key=value, got: {kv}")
        k, v = kv.split("=", 1)
        # Try to parse the value as JSON so arrays/numbers/bools come through
        # as their natural types. Fall back to plain string.
        try:
            claims[k] = json.loads(v)
        except json.JSONDecodeError:
            claims[k] = v

    token = jwt.encode(
        claims,
        private_pem,
        algorithm="EdDSA",
        headers={"kid": current_kid()},
    )
    print(token)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="generate a test Ed25519 keypair")
    p_init.add_argument(
        "--force", action="store_true", help="overwrite an existing key"
    )
    p_init.set_defaults(fn=cmd_init)

    p_jwks = sub.add_parser("jwks", help="print the JWKS JSON for the current key")
    p_jwks.set_defaults(fn=cmd_jwks)

    p_serve = sub.add_parser("serve", help="run an HTTP server that returns the JWKS")
    p_serve.add_argument("--port", type=int, default=9999)
    p_serve.set_defaults(fn=cmd_serve)

    p_sign = sub.add_parser("sign", help="sign a test JWT and print it to stdout")
    p_sign.add_argument("--sub", default="user-42")
    p_sign.add_argument("--aud", default=DEFAULT_AUDIENCE)
    p_sign.add_argument("--iss", default=DEFAULT_ISSUER)
    p_sign.add_argument(
        "--exp-offset",
        type=int,
        default=3600,
        help="seconds from now to the exp claim (default 3600)",
    )
    p_sign.add_argument(
        "--nbf-offset",
        type=int,
        default=None,
        help="seconds from now to the nbf claim (omitted by default)",
    )
    p_sign.add_argument(
        "--claim",
        dest="claims",
        action="append",
        default=[],
        help="extra claim as key=value (repeatable). Values parsed as JSON when possible.",
    )
    p_sign.set_defaults(fn=cmd_sign)

    return p


def main() -> None:
    args = build_parser().parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
