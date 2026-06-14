#!/bin/sh
# Regenerate the throwaway decentralised-JWT creds + mem-resolver server config
# checked in alongside this script. Runs entirely inside nats-box (which bundles
# nsc), so you need nothing installed but Docker:
#
#   docker run --rm -v "$PWD:/work" -w /work natsio/nats-box sh gen-demo-creds.sh
#
# The output (admin/quik/register .creds + server.conf) is DEMO-ONLY and
# git-ignored: it's minted locally against a throwaway operator, so these creds
# are worthless as a secret. Never reuse them outside a localhost demo - for a real
# deployment mint your own (see ../../nats/bootstrap-creds.sh and the HA stack).
set -eu
export XDG_DATA_HOME=/work/.gen/local XDG_CONFIG_HOME=/work/.gen/config \
       XDG_CACHE_HOME=/work/.gen/cache NKEYS_PATH=/work/.gen/nkeys
rm -rf /work/.gen
B='$KV.quik_registrations'

nsc add operator --generate-signing-key --sys --name QUIK_DEMO >/dev/null
nsc add account SHOP >/dev/null
# KV is JetStream - the account must have JetStream enabled (unlimited for demo).
nsc edit account SHOP --js-mem-storage -1 --js-disk-storage -1 \
                      --js-streams -1 --js-consumer -1 >/dev/null

# register - the homelab PROJECT key: may write ANY service's registration under
# reg.shop.*, plus the JetStream bits a KV open/put needs (stream info + its
# reply inbox). It canNOT write override.* - that split makes operator-wins
# structural (docs §5). In the HA stack this is narrowed to a per-service key.
nsc add user -a SHOP -n register \
  --allow-pub "${B}.reg.shop.>" \
  --allow-pub '$JS.API.STREAM.INFO.KV_quik_registrations' \
  --allow-sub '_INBOX.>' >/dev/null

# quik - subscribes the whole bucket (the watch) and writes override.* (the
# admin facade); JS API for the watch consumer + stream info.
nsc add user -a SHOP -n quik \
  --allow-sub "${B}.>" --allow-pub "${B}.override.>" \
  --allow-pub '$JS.API.>' --allow-sub '_INBOX.>' >/dev/null

# admin - full account, used once by nats-setup to create the bucket.
nsc add user -a SHOP -n admin --allow-pub '>' --allow-sub '>' >/dev/null

for u in register quik admin; do nsc generate creds -a SHOP -n "$u" > "$u.creds"; done
nsc generate config --mem-resolver --config-file server.conf >/dev/null
printf '\njetstream { store_dir: "/data" }\nhttp: 8222\n' >> server.conf
rm -rf /work/.gen
echo "regenerated: admin.creds quik.creds register.creds server.conf"
