.PHONY: build up down test demo

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

test:
	venv/bin/python3 -m pytest -v

demo:
	./scripts/run_demo.sh
