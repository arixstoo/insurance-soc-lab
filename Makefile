# Linux / macOS / WSL helpers. On Windows PowerShell, run the commands shown in README.md.
.PHONY: certs up down reset status test unit lint

certs:          ## generate TLS certificates (once)
	docker compose -f stack/certs.compose.yml run --rm generator

up:             ## build and start the whole lab
	@test -f .env || cp .env.example .env
	@test -d stack/certs || $(MAKE) certs
	docker compose up -d --build

down:           ## stop the lab (data is kept)
	docker compose down

reset:          ## stop and DELETE all lab data
	docker compose down -v

status:         ## agents and custom rules fired
	python3 scripts/lab_status.py

test: unit     ## all tests (unit + detection against the real engine)
	python3 detection/tests/run_tests.py

unit:
	cd simulator && python3 -m pytest -q

lint:
	ruff check simulator detection/tests scripts --line-length 120
