# syntax=docker/dockerfile:1
#
# The quik.sh website. Two stages: build the Astro static site with Node, then
# serve the output from static-web-server (SWS) - a small, fast static file
# server written in Rust (scratch-based image, ~5 MB).
#
# IMPORTANT: the build context is the REPOSITORY ROOT, not web/. The site
# renders the canonical docs straight from ../docs (see
# web/src/content.config.ts), so both trees must be in the context. Ignore
# rules live in web/Dockerfile.dockerignore (BuildKit prefers it over the
# repo-root .dockerignore, whose `**/*.md` would otherwise strip the docs).
#
#   docker build -f web/Dockerfile -t quik-website .
#   docker run --rm -p 8080:80 quik-website   # then open http://localhost:8080

# ── Build the static site ───────────────────────────────────────────────────
# Pinned to $BUILDPLATFORM: the output is platform-independent HTML/CSS/JS, so
# the (heavy) npm build runs once on the native arch and never under QEMU, even
# when the final image is built multi-arch.
FROM --platform=$BUILDPLATFORM node:22-alpine AS build
WORKDIR /app/web
# Dependencies first, so a content-only change doesn't bust the npm cache layer.
COPY web/package.json web/package-lock.json ./
RUN npm ci
# Site source, plus the docs it renders (../docs, relative to web/).
COPY web/ ./
COPY docs/ /app/docs/
RUN npm run build

# ── Serve with static-web-server ─────────────────────────────────────────────
FROM ghcr.io/static-web-server/static-web-server:2
# SWS serves ./public on :80 by default.
COPY --from=build /app/web/dist /public
# On-the-fly compression, cache-control headers, and the site's own 404 page.
ENV SERVER_COMPRESSION=true \
    SERVER_CACHE_CONTROL_HEADERS=true \
    SERVER_ERROR_PAGE_404=./404.html
EXPOSE 80
