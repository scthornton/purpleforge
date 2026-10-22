.PHONY: install test lint format format-check typecheck all run-sample

install:
	pip install -e ".[dev,github]"

test:
	pytest --cov=purpleforge --cov-report=term-missing --cov-fail-under=80

lint:
	ruff check .

format:
	ruff format .

format-check:
	ruff format --check .

typecheck:
	mypy

all: lint format-check typecheck test

run-sample:
	purpleforge run --source ./tests/fixtures/sample_threat_report.pdf
