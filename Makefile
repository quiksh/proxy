.DEFAULT_GOAL := help
CARGO ?= cargo
CONFIG ?= config/example.toml
NPM ?= npm
WEB_DIR ?= web

.PHONY: help build release run test test-quiet bench fmt fmt-check lint check clippy doc clean docker docker-up docker-down audit ci web-install web-dev web-build web-preview

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n\nTargets:\n"} \
		/^[a-zA-Z_-]+:.*?##/ {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Debug build of all workspace targets.
	$(CARGO) build --workspace --all-targets

release: ## Optimised release build of all workspace binaries.
	$(CARGO) build --workspace --release

run: ## Run quik against $(CONFIG) (default: config/example.toml).
	$(CARGO) run --release -- --config $(CONFIG)

test: ## Run the full test suite.
	$(CARGO) test --workspace

test-quiet: ## Run tests with reduced output.
	$(CARGO) test --workspace --quiet

bench: ## Run criterion benchmarks.
	$(CARGO) bench

fmt: ## Format the workspace with rustfmt.
	$(CARGO) fmt --all

fmt-check: ## Verify the workspace is formatted (used in CI).
	$(CARGO) fmt --all -- --check

lint: ## Run clippy with warnings as errors.
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

clippy: lint ## Alias for lint.

check: fmt-check lint ## Run formatter and clippy checks (no compilation of tests).

doc: ## Build rustdoc.
	$(CARGO) doc --no-deps --all-features

clean: ## Remove the target directory.
	$(CARGO) clean

docker: ## Build the docker image.
	docker compose build

docker-up: ## Bring up the demo compose stack in the background.
	docker compose up --build -d

docker-down: ## Stop and remove the compose stack.
	docker compose down

audit: ## Run `cargo audit` (requires cargo-audit installed).
	$(CARGO) audit

ci: fmt-check lint test ## Run the checks CI runs locally.

# ── Website (quik.sh) — Astro site in $(WEB_DIR), docs rendered from docs/*.md ──

web-install: ## Install website dependencies.
	cd $(WEB_DIR) && $(NPM) install

web-dev: ## Run the website dev server (astro dev).
	cd $(WEB_DIR) && $(NPM) run dev

web-build: ## Build the static website (astro build).
	cd $(WEB_DIR) && $(NPM) run build

web-preview: ## Preview the built website locally.
	cd $(WEB_DIR) && $(NPM) run preview
