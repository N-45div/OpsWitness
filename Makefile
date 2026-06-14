.PHONY: api frontend test build check splunk-app

api:
	.venv/bin/python -m uvicorn opswitness.api.app:app --reload --port 8000

frontend:
	cd frontend && npm run dev -- --port 3000

test:
	.venv/bin/python -m pytest tests

build:
	cd frontend && npm run build

check:
	.venv/bin/python -m ruff check src tests
	.venv/bin/python -m pytest tests
	cd frontend && npm run build

splunk-app:
	mkdir -p dist
	tar -C splunk -czf dist/opswitness-splunk-app.tgz opswitness
