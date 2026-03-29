.PHONY: test lint typecheck all install

install:
	pip install -e ".[dev]"

test:
	pytest --cov=purpleforge -v

lint:
	ruff check src/ tests/

typecheck:
	mypy src/

all: lint typecheck test

run-sample:
	purpleforge run --source ./tests/fixtures/sample_threat_report.pdf
