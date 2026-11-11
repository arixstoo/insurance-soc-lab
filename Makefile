# Lab commands for Linux / macOS / WSL. Windows PowerShell: .\scripts\lab.ps1 <verb> (same verbs).
PYTHON ?= python3
COMPOSE := docker compose

.PHONY: help certs rotate up down reset status test unit detection lint

help:           ## list the targets
	@grep -E '^[a-z]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-8s %s\n", $$1, $$2}'

certs:          ## generate TLS certificates (once)
	$(COMPOSE) -f stack/certs.compose.yml run --rm generator

rotate:         ## new passwords for a fresh lab; on a running lab: make rotate APPLY=1
	bash scripts/rotate-passwords.sh $(if $(APPLY),--apply)

up:             ## certs + passwords if missing, build, start, wait until healthy, apply retention
	@test -d stack/certs || $(MAKE) certs
	@test -f .env || $(MAKE) rotate
	@grep -q '^INDEXER_USERS_FILE=' .env || echo "WARNING: .env still has the public default passwords - run: make reset rotate up"
	$(COMPOSE) up -d --build --wait --wait-timeout 600
	$(PYTHON) scripts/apply_ism.py

down:           ## stop the lab (data is kept)
	$(COMPOSE) down

reset:          ## stop and DELETE all lab data (volumes)
	$(COMPOSE) down -v

status:         ## containers, agents, passwords, retention, custom rules fired
	$(PYTHON) scripts/lab_status.py

test: unit detection  ## unit tests + detection tests against the real engine

unit:
	cd simulator && $(PYTHON) -m pytest -q

detection:
	$(PYTHON) detection/tests/run_tests.py

lint:           ## ruff
	ruff check simulator detection/tests scripts
