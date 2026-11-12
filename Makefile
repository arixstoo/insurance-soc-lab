# Lab commands for Linux / macOS / WSL. Windows PowerShell: .\scripts\lab.ps1 <verb> (same verbs).
PYTHON ?= python3
COMPOSE := docker compose $(if $(REAL),--profile real)
# down / reset also stop the real hosts (compose profile `real`) when they run
COMPOSE_ALL := docker compose --profile real

.PHONY: help certs rotate up down reset status traffic test unit detection catalog noise lint

help:           ## list the targets
	@grep -E '^[a-z]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-8s %s\n", $$1, $$2}'

certs:          ## generate TLS certificates (once)
	$(COMPOSE) -f stack/certs.compose.yml run --rm generator

rotate:         ## new passwords for a fresh lab; on a running lab: make rotate APPLY=1
	bash scripts/rotate-passwords.sh $(if $(APPLY),--apply)

up:             ## certs + passwords if missing, build, start, wait, retention (REAL=1: + real hosts)
	@test -d stack/certs || $(MAKE) certs
	@test -f .env || $(MAKE) rotate
	@grep -q '^INDEXER_USERS_FILE=' .env || echo "WARNING: .env still has the public default passwords - run: make reset rotate up"
	$(COMPOSE) up -d --build --wait --wait-timeout 600
	$(PYTHON) scripts/apply_ism.py

down:           ## stop the lab (data is kept)
	$(COMPOSE_ALL) down

reset:          ## stop and DELETE all lab data (volumes)
	$(COMPOSE_ALL) down -v

status:         ## containers, agents, passwords, retention, custom rules fired
	$(PYTHON) scripts/lab_status.py

traffic:        ## real hosts (make up REAL=1): scripted test traffic from the lab test client
	$(COMPOSE_ALL) exec real-client lab-traffic all

test: unit detection  ## unit tests + detection tests against the real engine

unit:           ## simulator + static detection checks (coverage, catalog), no Docker
	cd simulator && $(PYTHON) -m pytest -q
	$(PYTHON) -m pytest -q detection/tests
	$(PYTHON) scripts/gen_catalog.py --check

detection:
	$(PYTHON) detection/tests/run_tests.py

catalog:        ## regenerate docs/detection-catalog.md from the rules XML
	$(PYTHON) scripts/gen_catalog.py

noise:          ## 24 h of background traffic through the real engine -> docs/tuning-report.md
	$(PYTHON) scripts/noise_report.py

lint:           ## ruff
	ruff check simulator detection/tests scripts real
