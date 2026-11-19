.PHONY: help setup check backend-check frontend-check build compose-up compose-down clean

help:
	@printf "Available targets:\n"
	@printf "  setup          Install backend and frontend dependencies\n"
	@printf "  check          Run backend and frontend quality gates\n"
	@printf "  backend-check  Lint and test the backend\n"
	@printf "  frontend-check Type-check and build the frontend\n"
	@printf "  build          Build both Docker images\n"
	@printf "  compose-up     Start the local Docker Compose stack\n"
	@printf "  compose-down   Stop the local Docker Compose stack\n"

setup:
	python3 -m pip install -r backend/requirements-dev.txt
	npm ci --prefix frontend

check: backend-check frontend-check

backend-check:
	cd backend && ruff check app tests
	cd backend && ruff format --check app tests
	cd backend && python -m pytest

frontend-check:
	npm run typecheck --prefix frontend
	npm run build --prefix frontend

build:
	docker compose build

compose-up:
	docker compose up --build --detach --wait

compose-down:
	docker compose down
