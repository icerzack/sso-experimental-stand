SHELL := /bin/bash

COMPOSE := docker compose
BASE    := docker-compose.yml

PROFILES := e1a e1b e1c e1d e2a e2b e2c e2d

.PHONY: help \
        up-e1a up-e1a-hard down-e1a logs-e1a \
        up-e1b up-e1b-hard down-e1b logs-e1b \
        up-e1c up-e1c-hard down-e1c logs-e1c \
        up-e1d up-e1d-hard down-e1d logs-e1d \
        up-e2a down-e2a logs-e2a \
        up-e2b bootstrap-e2b down-e2b logs-e2b \
        up-e2c down-e2c logs-e2c \
        up-e2d down-e2d logs-e2d \
        bench-e2a bench-e2b bench-e2c bench-e2d bench-e2-all \
        export-metrics generate-report \
        down gen-certs hosts-check hosts-add hosts-remove \
        attack-all attack-e1a attack-e1b attack-e1c attack-e1d \
        load-test clean-results

help:
	@echo "SSO Experimental Stand — experiment-based profiles"
	@echo ""
	@echo "Experiment 1 — Architectural Profile (protocol + pattern + verification):"
	@echo "  make up-e1a         E1A: Keycloak OIDC Password       [control point]"
	@echo "  make up-e1a-hard    E1A: Keycloak OIDC Password       [hardened]"
	@echo "  make up-e1b         E1B: Keycloak SAML Password"
	@echo "  make up-e1b-hard    E1B: Keycloak SAML Password       [hardened]"
	@echo "  make up-e1c         E1C: Authelia Forward Auth Password"
	@echo "  make up-e1c-hard    E1C: Authelia Forward Auth         [hardened]"
	@echo "  make up-e1d         E1D: Keycloak OIDC WebAuthn"
	@echo "  make up-e1d-hard    E1D: Keycloak OIDC WebAuthn       [hardened]"
	@echo ""
	@echo "Experiment 2 — IdP Platform (operational benchmarks only, no attacks):"
	@echo "  make up-e2a         E2A: Keycloak OIDC Password       [control point]"
	@echo "  make up-e2b         E2B: Authentik OIDC"
	@echo "  make bootstrap-e2b  E2B: Configure Authentik (run after up-e2b)"
	@echo "  make up-e2c         E2C: Zitadel OIDC"
	@echo "  make up-e2d         E2D: Authelia OIDC beta"
	@echo ""
	@echo "Attacks:"
	@echo "  make attack-all     run all attack scripts for Experiment 1"
	@echo "  make attack-e1a      A1-A5,A9 against profile E1A (OIDC + Password)"
	@echo "  make attack-e1b      A11-A12 against profile E1B (SAML)"
	@echo "  make attack-e1c      A6-A8 against profile E1C (Forward Auth)"
	@echo "  make attack-e1d      A1-A5,A10 against profile E1D (OIDC + WebAuthn)"
	@echo ""
	@echo "Load Testing (Experiment 2):"
	@echo "  make load-test       run k6 load test against current profile"
	@echo ""
	@echo "E2 Full Benchmarks (automated: up → warmup → k6 → export → down):"
	@echo "  make bench-e2a       E2A: Keycloak OIDC benchmark"
	@echo "  make bench-e2b       E2B: Authentik OIDC benchmark"
	@echo "  make bench-e2c       E2C: Zitadel OIDC benchmark"
	@echo "  make bench-e2d       E2D: Authelia OIDC benchmark"
	@echo "  make bench-e2-all    Run all four benchmarks sequentially"
	@echo ""
	@echo "Metrics Export & Reports:"
	@echo "  make export-metrics  export Prometheus metrics to JSON (profile must be running)"
	@echo "  make generate-report generate summary HTML report from raw results"
	@echo ""
	@echo "Utilities:"
	@echo "  make down            stop all containers + volumes"
	@echo "  make gen-certs       generate TLS certs with mkcert"
	@echo "  make hosts-check     verify /etc/hosts entries"

# ── Experiment 1 — Architectural Profile ───────────────────────────

up-e1a:
	HARDENED=false $(COMPOSE) -f $(BASE) -f profiles/profile-e1a.yml --project-name sso-lab up -d --build

up-e1a-hard:
	$(COMPOSE) -f $(BASE) -f profiles/profile-e1a.yml -f profiles/profile-e1a-hard.yml --project-name sso-lab up -d --build

down-e1a:
	-$(COMPOSE) -f $(BASE) -f profiles/profile-e1a.yml --project-name sso-lab down -v

logs-e1a:
	$(COMPOSE) -f $(BASE) -f profiles/profile-e1a.yml --project-name sso-lab logs -f --tail=100

up-e1b:
	HARDENED=false $(COMPOSE) -f $(BASE) -f profiles/profile-e1b.yml --project-name sso-lab up -d --build

up-e1b-hard:
	$(COMPOSE) -f $(BASE) -f profiles/profile-e1b.yml -f profiles/profile-e1b-hard.yml --project-name sso-lab up -d --build

down-e1b:
	-$(COMPOSE) -f $(BASE) -f profiles/profile-e1b.yml --project-name sso-lab down -v

logs-e1b:
	$(COMPOSE) -f $(BASE) -f profiles/profile-e1b.yml --project-name sso-lab logs -f --tail=100

up-e1c:
	HARDENED=false $(COMPOSE) -f $(BASE) -f profiles/profile-e1c.yml --project-name sso-lab up -d --build

up-e1c-hard:
	$(COMPOSE) -f $(BASE) -f profiles/profile-e1c.yml -f profiles/profile-e1c-hard.yml --project-name sso-lab up -d --build

down-e1c:
	-$(COMPOSE) -f $(BASE) -f profiles/profile-e1c.yml --project-name sso-lab down -v

logs-e1c:
	$(COMPOSE) -f $(BASE) -f profiles/profile-e1c.yml --project-name sso-lab logs -f --tail=100

up-e1d:
	HARDENED=false $(COMPOSE) -f $(BASE) -f profiles/profile-e1d.yml --project-name sso-lab up -d --build

up-e1d-hard:
	$(COMPOSE) -f $(BASE) -f profiles/profile-e1d.yml -f profiles/profile-e1d-hard.yml --project-name sso-lab up -d --build

down-e1d:
	-$(COMPOSE) -f $(BASE) -f profiles/profile-e1d.yml --project-name sso-lab down -v

logs-e1d:
	$(COMPOSE) -f $(BASE) -f profiles/profile-e1d.yml --project-name sso-lab logs -f --tail=100

# ── Experiment 2 — IdP Platform (operational benchmarks) ────────────

up-e2a:
	HARDENED=false $(COMPOSE) -f $(BASE) -f profiles/profile-e2a.yml --project-name sso-lab up -d --build

down-e2a:
	-$(COMPOSE) -f $(BASE) -f profiles/profile-e2a.yml --project-name sso-lab down -v

logs-e2a:
	$(COMPOSE) -f $(BASE) -f profiles/profile-e2a.yml --project-name sso-lab logs -f --tail=100

up-e2b:
	$(COMPOSE) -f $(BASE) -f profiles/profile-e2b.yml --project-name sso-lab up -d --build
	@echo ""
	@echo "Authentik is starting. Wait ~60s for health checks, then run:"
	@echo "  make bootstrap-e2b"

bootstrap-e2b: ## Configure Authentik (create users, OIDC provider, app)
	@echo "Running Authentik bootstrap..."
	docker exec sso-lab-idp bash -c '\
		TOKEN=$$(curl -sf http://localhost:9000/api/v3/flows/executor/initial-setup/ 2>/dev/null | grep -o "ak-stage-prompt" || true); \
		if [ -n "$$TOKEN" ]; then \
			echo "Performing initial setup..."; \
			curl -sf http://localhost:9000/api/v3/flows/executor/initial-setup/ \
				-X POST -H "Content-Type: application/json" \
				-d "{\"component\":\"ak-stage-prompt\",\"username\":\"admin\",\"name\":\"Admin\",\"email\":\"admin@sso-lab.local\",\"password\":\"admin\",\"password_repeat\":\"admin\"}" > /dev/null 2>&1 || true; \
			sleep 5; \
		fi'
	@bash configs/authentik/bootstrap.sh
	@echo "Removing MFA stage from default auth flow..."
	docker exec sso-lab-idp ak shell -c "\
from authentik.flows.models import FlowStageBinding; \
from authentik.stages.authenticator_validate import AuthenticatorValidateStage; \
flow = Flow.objects.get(slug='default-authentication-flow'); \
[b.delete() for b in FlowStageBinding.objects.filter(target=flow, stage__in=AuthenticatorValidateStage.objects.all())]; \
print('MFA stage removed')" 2>/dev/null || echo "NOTE: Could not auto-remove MFA stage — may need manual removal"

down-e2b:
	-$(COMPOSE) -f $(BASE) -f profiles/profile-e2b.yml --project-name sso-lab down -v

logs-e2b:
	$(COMPOSE) -f $(BASE) -f profiles/profile-e2b.yml --project-name sso-lab logs -f --tail=100

up-e2c:
	$(COMPOSE) -f $(BASE) -f profiles/profile-e2c.yml --project-name sso-lab up -d --build

down-e2c:
	-$(COMPOSE) -f $(BASE) -f profiles/profile-e2c.yml --project-name sso-lab down -v

logs-e2c:
	$(COMPOSE) -f $(BASE) -f profiles/profile-e2c.yml --project-name sso-lab logs -f --tail=100

up-e2d:
	$(COMPOSE) -f $(BASE) -f profiles/profile-e2d.yml --project-name sso-lab up -d --build

down-e2d:
	-$(COMPOSE) -f $(BASE) -f profiles/profile-e2d.yml --project-name sso-lab down -v

logs-e2d:
	$(COMPOSE) -f $(BASE) -f profiles/profile-e2d.yml --project-name sso-lab logs -f --tail=100

# ── Attacks (Experiment 1 only) ─────────────────────────────────────
#
# Сводный набор сценариев (Таблица 3.3):
#
# | №   | Сценарий                           | E1A | E1B | E1C | E1D |
# |-----|------------------------------------|-----|-----|-----|-----|
# | C1  | JWT algorithm confusion            | ✓   |     |     | ✓   |
# | C2  | Token replay                       | ✓   |     |     | ✓   |
# | C3  | Open redirect через redirect_uri   | ✓   |     |     | ✓   |
# | C4  | PKCE downgrade                     | ✓   |     |     | ✓   |
# | C5  | Credential stuffing                 | ✓   |     |     |     |
# | C6  | RT-фишинг через поддельный IdP      | ✓   |     |     |     |
# | C7  | XML Signature Wrapping (XSW)       |     | ✓   |     |     |
# | C8  | SAML assertion replay              |     | ✓   |     |     |
# | C9  | Header injection (X-Remote-User)    |     |     | ✓   |     |
# | C10 | Session fixation                    |     |     | ✓   |     |
# | C11 | CSRF logout                         |     |     | ✓   |     |
# | C12 | RP ID mismatch / phishing page      |     |     |     | ✓   |
# | C13 | Challenge replay                    |     |     |     | ✓   |
#
# Script mapping: C1→A1+A2, C2→A3, C3→A4, C4→A5, C5→A9,
#                 C6=TODO(RT-phishing), C7→A12, C8→A11, C9→A6, C10→A7, C11→A8,
#                 C12→A10, C13=TODO(challenge-replay)

APP_URL ?= https://app.sso-lab.local
IDP_URL ?= https://idp.sso-lab.local
REALM   ?= sso-lab

# ── E1A attacks: Keycloak OIDC Password (control point) ──
attack-e1a: ## Run attacks for Profile E1A (Keycloak OIDC Password)
	@echo "═══ Running attacks against Profile E1A (Keycloak OIDC Password) ═══"
	@bash attacks/A1_jwt_alg_none.sh       $(APP_URL) $(IDP_URL) $(REALM) || true
	@bash attacks/A2_jwt_key_confusion.sh   $(APP_URL) $(IDP_URL) $(REALM) || true
	@bash attacks/A3_token_replay.sh        $(APP_URL) $(IDP_URL) $(REALM) || true
	@bash attacks/A4_open_redirect.sh       $(IDP_URL) $(REALM) || true
	@bash attacks/A5_pkce_downgrade.sh       $(IDP_URL) $(REALM) || true
	@bash attacks/A9_credential_stuffing.sh  $(IDP_URL) $(REALM) || true

# ── E1B attacks: Keycloak SAML Password ──
attack-e1b: ## Run attacks for Profile E1B (Keycloak SAML)
	@echo "═══ Running attacks against Profile E1B (Keycloak SAML) ═══"
	@bash attacks/A11_saml_assertion_replay.sh   $(APP_URL) $(IDP_URL) $(REALM) || true
	@bash attacks/A12_saml_signature_wrapping.sh $(APP_URL) || true

# ── E1C attacks: Authelia Forward Auth ──
attack-e1c: ## Run attacks for Profile E1C (Authelia Forward Auth)
	@echo "═══ Running attacks against Profile E1C (Authelia Forward Auth) ═══"
	@bash attacks/A6_header_injection.sh   $(APP_URL) || true
	@bash attacks/A7_session_fixation.sh    $(APP_URL) $(IDP_URL) $(REALM) || true
	@bash attacks/A8_csrf_logout.sh          $(APP_URL) $(IDP_URL) $(REALM) || true

# ── E1D attacks: Keycloak OIDC WebAuthn ──
attack-e1d: ## Run attacks for Profile E1D (Keycloak OIDC WebAuthn)
	@echo "═══ Running attacks against Profile E1D (Keycloak OIDC WebAuthn) ═══"
	@bash attacks/A1_jwt_alg_none.sh          $(APP_URL) $(IDP_URL) $(REALM) || true
	@bash attacks/A2_jwt_key_confusion.sh      $(APP_URL) $(IDP_URL) $(REALM) || true
	@bash attacks/A3_token_replay.sh           $(APP_URL) $(IDP_URL) $(REALM) || true
	@bash attacks/A4_open_redirect.sh          $(IDP_URL) $(REALM) || true
	@bash attacks/A5_pkce_downgrade.sh          $(IDP_URL) $(REALM) || true
	@bash attacks/A10_webauthn_rp_mismatch.sh  $(APP_URL) || true

# ── Run all attack experiment groups ──
attack-all: attack-e1a attack-e1b attack-e1c attack-e1d

# ── Load Testing (Experiment 2) ─────────────────────────────────────

load-test:
	@echo "Running k6 load test against $(APP_URL)..."
	bash k6/run.sh $(APP_URL)

# ── E2 Full Benchmarks (automated cycle) ───────────────────────────
#
# Each bench-e2? target runs the full cycle:
#   make up → warmup → k6 load → export metrics → make down
#
# Customization via environment variables:
#   WARMUP=120          extra warm-up seconds (default: 60)
#   VUS_PEAK=100        peak virtual users (default: from k6 script)
#   LOAD_MODE=ropc      ROPC-only / browser / mixed (default: mixed)
#   K6_EXTRA="K=V ..." additional k6 env vars

WARMUP ?= 60

bench-e2a:
	bash scripts/bench-e2.sh e2a $(WARMUP) $(K6_EXTRA)

bench-e2b:
	bash scripts/bench-e2.sh e2b $(WARMUP) $(K6_EXTRA)

bench-e2c:
	bash scripts/bench-e2.sh e2c $(WARMUP) $(K6_EXTRA)

bench-e2d:
	bash scripts/bench-e2.sh e2d $(WARMUP) $(K6_EXTRA)

bench-e2-all: bench-e2a bench-e2b bench-e2c bench-e2d

# ── Metrics Export & Reports ───────────────────────────────────────

export-metrics: ## Export Prometheus metrics for currently running profile
	@echo "Exporting Prometheus metrics for profile '${PROFILE:-unknown}'..."
	bash scripts/export_metrics.sh ${PROFILE:-unknown}

generate-report: ## Generate HTML report from raw results
	python3 scripts/generate_attack_report.py
	python3 scripts/generate_e2_report.py

# ── Common ──────────────────────────────────────────────────────────

down:
	-$(COMPOSE) --project-name sso-lab down -v

gen-certs:
	bash configs/traefik/gen-certs.sh

hosts-check:
	@echo "Checking /etc/hosts for required entries..."
	@for h in app.sso-lab.local idp.sso-lab.local; do \
		if grep -q "$$h" /etc/hosts 2>/dev/null; then \
			echo "  OK      $$h"; \
		else \
			echo "  MISSING $$h → sudo sh -c 'echo \"127.0.0.1 $$h\" >> /etc/hosts'"; \
		fi; \
	done

hosts-add:
	@echo "Adding required hosts entries to /etc/hosts..."
	@for h in app.sso-lab.local idp.sso-lab.local; do \
		if grep -qE "[[:space:]]$$h([[:space:]]|$$)" /etc/hosts 2>/dev/null; then \
			echo "  SKIP    $$h (already present)"; \
		else \
			sudo sh -c "printf '127.0.0.1 %s\n' $$h >> /etc/hosts"; \
			echo "  ADDED   $$h"; \
		fi; \
	done

hosts-remove:
	@for h in app.sso-lab.local idp.sso-lab.local; do \
		if grep -qE "[[:space:]]$$h([[:space:]]|$$)" /etc/hosts 2>/dev/null; then \
			sudo sed -i.bak "/[[:space:]]$$h\\([[:space:]]\\|$$\\)/d" /etc/hosts; \
			echo "  REMOVED $$h"; \
		fi; \
	done

clean-results:
	rm -rf results/raw/* results/processed/*
