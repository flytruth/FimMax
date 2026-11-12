# wazuh-fim-telegram — Makefile
# Common dev + ops shortcuts. Run `make help` to see what's available.

.DEFAULT_GOAL := help
SHELL := /usr/bin/env bash
PYTHON ?= python3
VENV ?= .venv

.PHONY: help venv install install-dev lint format typecheck test test-cov \
        run send-test digest validate-config docker-build docker-up \
        docker-down clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} \
	  /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

venv: ## Create a virtualenv in $(VENV)
	$(PYTHON) -m venv $(VENV)
	@echo "Run: source $(VENV)/bin/activate"

install: ## Install runtime deps into the current env
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e .

install-dev: ## Install runtime + dev deps (editable)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"

lint: ## Run ruff
	$(PYTHON) -m ruff check src tests scripts

format: ## Run ruff format + import sort
	$(PYTHON) -m ruff format src tests
	$(PYTHON) -m ruff check --fix src tests

typecheck: ## Run mypy
	$(PYTHON) -m mypy

test: ## Run pytest
	$(PYTHON) -m pytest

test-cov: ## Run pytest with coverage report (html)
	$(PYTHON) -m pytest --cov-report=html

run: ## Start the bot locally (loads .env if present)
	./scripts/fim-watcher.sh run

send-test: ## Send a synthetic FIM alert to TELEGRAM_CHAT_ID
	./scripts/send-test-alert.sh

digest: ## Print today's digest without sending
	./scripts/fim-watcher.sh digest-now

validate-config: ## Validate settings + rules
	./scripts/fim-watcher.sh validate-config

docker-build: ## Build the Docker image
	docker build -t wazuh-fim-telegram:latest .

docker-up: ## docker compose up -d (build if needed)
	docker compose up -d --build

docker-down: ## docker compose down
	docker compose down

clean: ## Remove build / cache artefacts
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
