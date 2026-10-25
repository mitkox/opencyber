.PHONY: help install test test-cov lint typecheck guards shellcheck docs-tools docs-check catalog-record catalog-check version-check build check

VENV ?= .venv
# Prefer the project virtualenv, where the dev extras (build, ruff, mypy, ...) live.
# Falls back to system python3; override explicitly with: make build PYTHON=python3
PYTHON ?= $(if $(wildcard $(VENV)/bin/python),$(VENV)/bin/python,python3)

help:
	@printf '%s\n' \
	  'make install       install the package with test and dev extras' \
	  'make test          run the unit tests' \
	  'make test-cov      run the unit tests under coverage' \
	  'make lint          run ruff' \
	  'make typecheck     run mypy on src/opencyber' \
	  'make guards        check import boundaries and test discovery' \
	  'make shellcheck    lint shell entrypoints' \
	  'make docs-tools    regenerate docs/TOOLS.md, ERRORS.md, LIMITS.md, and the schema' \
	  'make docs-check    verify every generated reference is current' \
	  'make catalog-record record the advertised MCP catalog digest' \
	  'make catalog-check verify the recorded catalog digest is current' \
	  'make version-check verify release version aliases' \
	  'make build         build wheel and sdist' \
	  'make check         run every local gate'

install:
	$(PYTHON) -m pip install -e '.[test,dev]'

test:
	$(PYTHON) -m unittest discover -s tests -v

test-cov:
	$(PYTHON) -m coverage run -m unittest discover -s tests
	$(PYTHON) -m coverage report

lint:
	$(PYTHON) -m ruff check src tests scripts

typecheck:
	$(PYTHON) -m mypy src/opencyber

guards:
	$(PYTHON) scripts/check-test-discovery.py
	$(PYTHON) scripts/check-boundaries.py

shellcheck:
	shellcheck -x install.sh scripts/*.sh

docs-tools: catalog-record
	PYTHONPATH=src $(PYTHON) scripts/generate-tool-docs.py
	$(PYTHON) scripts/generate-error-docs.py
	$(PYTHON) scripts/generate-limit-docs.py

docs-check:
	PYTHONPATH=src $(PYTHON) scripts/generate-tool-docs.py --check
	$(PYTHON) scripts/generate-error-docs.py --check
	$(PYTHON) scripts/generate-limit-docs.py --check

catalog-record:
	$(PYTHON) scripts/record-catalog.py

catalog-check:
	$(PYTHON) scripts/record-catalog.py --check

version-check:
	$(PYTHON) scripts/check-version-consistency.py

build:
	$(PYTHON) -m build

check: lint typecheck guards docs-check catalog-check version-check test
