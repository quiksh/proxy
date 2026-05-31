.DEFAULT_GOAL := help
CARGO ?= cargo
CONFIG ?= config/example.toml

.PHONY: help build release run test test-quiet bench fmt fmt-check lint check clippy doc clean docker docker-up docker-down audit ci

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n\nTargets:\n"} \
		/^[a-zA-Z_-]+:.*?##/ {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Debug build of all targets.
	$(CARGO) build --all-targets

release: ## Optimised release build of the binary.
	$(CARGO) build --release

run: ## Run quik against $(CONFIG) (default: config/example.toml).
	$(CARGO) run --release -- --config $(CONFIG)

test: ## Run the full test suite.
	$(CARGO) test

test-quiet: ## Run tests with reduced output.
	$(CARGO) test --quiet

bench: ## Run criterion benchmarks.
	$(CARGO) bench

fmt: ## Format the workspace with rustfmt.
	$(CARGO) fmt --all

fmt-check: ## Verify the workspace is formatted (used in CI).
	$(CARGO) fmt --all -- --check

lint: ## Run clippy with warnings as errors.
	$(CARGO) clippy --all-targets --all-features -- -D warnings

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
