.PHONY: lint
lint:
	black . --check
	flake8
	mypy dispatcher cli *.py
