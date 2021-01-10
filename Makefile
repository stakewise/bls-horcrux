.PHONY: lint
lint:
	black . --exclude=eth2deposit --check
	flake8
	mypy dispatcher cli *.py

.PHONY: test
test:
	pytest -v --cov .
