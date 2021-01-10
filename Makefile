.PHONY: lint
lint:
	black . --check
	flake8
	mypy dispatcher cli *.py

.PHONY: test
test:
	pytest -v --cov .
