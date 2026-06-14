# syntax=docker/dockerfile:1.6
# Tier-2b shared-fate bundle: a service and the quik-register sidecar in ONE
# container, so the registrar cannot outlive the service (docs §6). Use this for
# a single-container runtime (plain Docker, a single-container PaaS) where you
# control the image but have no orchestrator to give you Pod/task-level shared
# fate. Where an orchestrator exists, prefer tier 2a (sidecar in the same
# Pod/task) - same shared fate, no image change.
#
# The sidecar binary is pulled from the published image - the canonical way to
# add quik-register to YOUR service image without building it from source:
#
#   # against the homelab demo (uses the locally-built quik-register:demo):
#   docker build -f examples/nats/bundled/Dockerfile -t checkout-bundled .
#   # for real use, point at the published image:
#   docker build -f examples/nats/bundled/Dockerfile \
#     --build-arg REGISTER_IMAGE=ghcr.io/quiksh/quik-register:1 -t checkout-bundled .
ARG REGISTER_IMAGE=quik-register:demo

FROM ${REGISTER_IMAGE} AS register

# Stand-in for YOUR service image. Here it is the repo's echo backend (built by
# the homelab compose as quik-echo:demo); swap in any image that has bash.
FROM quik-echo:demo AS service

USER root
COPY --from=register /usr/local/bin/quik-register /usr/local/bin/quik-register
COPY examples/nats/bundled/bundle-entrypoint.sh /usr/local/bin/bundle-entrypoint.sh
COPY examples/nats/bundled/quik-register.toml /etc/quik-register/quik-register.toml
RUN chmod +x /usr/local/bin/bundle-entrypoint.sh

USER echo
ENTRYPOINT ["/usr/local/bin/bundle-entrypoint.sh"]
