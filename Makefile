.PHONY: prepare sync format lint basedpyright verifytypes ty typecheck test coverage coverage-report \
	test-unit test-integration test-commands test-concurrency test-migrations \
	test-security docs docs-serve changelog changelog-check build check \
	hooks workflow-lint workflow-test secret-scan

COVERAGE_MIN_BRANCH ?= 74
COVERAGE_REPORT ?= coverage.json
PROJECT_VERSION := $(shell uv version --short --frozen)
PREK := uvx --from prek==0.5.0 prek

prepare:
	uv sync --all-groups
	$(PREK) install

sync:
	uv lock --check
	uv sync --frozen --all-groups

hooks:
	$(PREK) run --all-files --show-diff-on-failure

workflow-lint:
	$(PREK) run actionlint --all-files --hook-stage manual
	$(PREK) run zizmor --all-files --hook-stage manual

workflow-test:
	node --test scripts/test_workflows.mjs

secret-scan:
	$(PREK) run gitleaks --all-files --hook-stage manual

format:
	uv run --frozen ruff format .
	uv run --frozen ruff check --fix .

lint:
	uv run --frozen ruff format --check .
	uv run --frozen ruff check .

basedpyright:
	uv run --frozen basedpyright

verifytypes:
	uv run --frozen basedpyright --verifytypes nonebot_plugin_1password --ignoreexternal

ty:
	uv run --frozen ty check src tests

typecheck: basedpyright verifytypes ty

test:
	uv run --frozen pytest

coverage-report:
	uv run --frozen pytest --cov=nonebot_plugin_1password --cov-branch \
		--cov-report="json:$(COVERAGE_REPORT)"

coverage: coverage-report
	uv run --frozen python3 scripts/check_branch_coverage.py "$(COVERAGE_REPORT)" \
		--minimum $(COVERAGE_MIN_BRANCH) \
		--minimum-file src/nonebot_plugin_1password/application/outbox.py=100 \
		--minimum-file src/nonebot_plugin_1password/application/workers.py=65 \
		--minimum-file src/nonebot_plugin_1password/broker/__main__.py=100 \
		--minimum-file src/nonebot_plugin_1password/broker/transport.py=65 \
		--minimum-file src/nonebot_plugin_1password/integrations/localstore/approval_routes.py=75 \
		--minimum-file src/nonebot_plugin_1password/integrations/nonebot/messaging.py=80 \
		--minimum-file src/nonebot_plugin_1password/integrations/unimessage_targets.py=90 \
		--minimum-file src/nonebot_plugin_1password/lifecycle.py=85

test-unit:
	uv run --frozen pytest tests/unit

test-integration:
	uv run --frozen pytest tests/integration

test-commands:
	uv run --frozen pytest tests/commands

test-concurrency:
	uv run --frozen pytest tests/integration/test_sqlite_concurrency.py

test-migrations:
	uv run --frozen pytest tests/integration/test_migrations.py

test-security:
	uv run --frozen pytest tests/security

docs:
	uv run --frozen zensical build --strict

docs-serve:
	uv run --frozen zensical serve

changelog:
	uv run --frozen towncrier build --version $(VERSION)

changelog-check:
	uv run --frozen python3 scripts/check_release_metadata.py \
		--version $(PROJECT_VERSION) \
		--changelog CHANGELOG.md \
		--documentation-changelog docs/changelog.md

build:
	uv build --clear
	uv run --frozen twine check dist/*
	uv run --frozen pytest tests/security/test_distribution.py

check: sync lint typecheck workflow-test build coverage changelog-check docs
