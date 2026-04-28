SHELL := /bin/bash

# ====================================================================
# SSO Experimental Stand — Makefile
# ====================================================================
# Each profile exists in two configurations: vulnerable / hardened.
# Profiles are isolated; never run two variants of the same profile
# simultaneously (they share the same host ports).
# ====================================================================

COMPOSE    := docker compose
ATTACK_DIR := attacks

.PHONY: help \
        up-a-vuln up-a-hard down-a logs-a \
        up-b-vuln up-b-hard down-b logs-b \
        up-c-vuln up-c-hard down-c logs-c \
        down \
        attack-all attack-a attack-b attack-c \
        hosts-check hosts-add hosts-remove clean-results

# ── Help ─────────────────────────────────────────────────────────────
help:
	@echo "Profile A  (Keycloak + OIDC / Go app):"
	@echo "  make up-a-vuln      start Profile A vulnerable  (http://app-a-v.local:8081, KC: :8080)"
	@echo "  make up-a-hard      start Profile A hardened    (https://app-a-h.local)"
	@echo "  make down-a         stop and remove Profile A containers + volumes"
	@echo "  make logs-a         tail logs for whichever A variant is running"
	@echo ""
	@echo "Profile B  (WebAuthn / FIDO2 / Go app):"
	@echo "  make up-b-vuln      start Profile B vulnerable  (http://app-b-v.local:8082)"
	@echo "  make up-b-hard      start Profile B hardened    (https://app-b-h.local)"
	@echo "  make down-b         stop and remove Profile B"
	@echo "  make logs-b         tail logs"
	@echo ""
	@echo "Profile C  (Go app + Vaultwarden backend):"
	@echo "  make up-c-vuln      start Profile C vulnerable  (http://app-c-v.local:8083)"
	@echo "  make up-c-hard      start Profile C hardened    (https://app-c-h.local)"
	@echo "  make down-c         stop and remove Profile C"
	@echo "  make logs-c         tail logs"
	@echo ""
	@echo "Attacks:"
	@echo "  make attack-a       run A-series scripts against Profile A"
	@echo "  make attack-b       run A-series scripts against Profile B"
	@echo "  make attack-c       run A-series scripts against Profile C"
	@echo "  make attack-all     run all attack scripts (all profiles)"
	@echo ""
	@echo "Utilities:"
	@echo "  make down           stop every profile"
	@echo "  make hosts-check    verify /etc/hosts entries"
	@echo "  make hosts-add      add all required hosts entries"
	@echo "  make hosts-remove   remove all required hosts entries"
	@echo "  make clean-results  wipe results/ artifacts"

# ── Profile A ────────────────────────────────────────────────────────
up-a-vuln:
	$(COMPOSE) -f profile-a/vulnerable/docker-compose.yml --project-name profile-a-vuln up -d --build

up-a-hard:
	$(COMPOSE) -f profile-a/hardened/docker-compose.yml --project-name profile-a-hard up -d --build

down-a:
	-$(COMPOSE) -f profile-a/vulnerable/docker-compose.yml --project-name profile-a-vuln down -v
	-$(COMPOSE) -f profile-a/hardened/docker-compose.yml   --project-name profile-a-hard down -v

logs-a:
	$(COMPOSE) -f profile-a/vulnerable/docker-compose.yml --project-name profile-a-vuln logs -f --tail=100 2>/dev/null || \
	$(COMPOSE) -f profile-a/hardened/docker-compose.yml   --project-name profile-a-hard logs -f --tail=100

# ── Profile B ────────────────────────────────────────────────────────
up-b-vuln:
	$(COMPOSE) -f profile-b/vulnerable/docker-compose.yml --project-name profile-b-vuln up -d --build

up-b-hard:
	$(COMPOSE) -f profile-b/hardened/docker-compose.yml --project-name profile-b-hard up -d --build

down-b:
	-$(COMPOSE) -f profile-b/vulnerable/docker-compose.yml --project-name profile-b-vuln down -v
	-$(COMPOSE) -f profile-b/hardened/docker-compose.yml   --project-name profile-b-hard down -v

logs-b:
	$(COMPOSE) -f profile-b/vulnerable/docker-compose.yml --project-name profile-b-vuln logs -f --tail=100 2>/dev/null || \
	$(COMPOSE) -f profile-b/hardened/docker-compose.yml   --project-name profile-b-hard logs -f --tail=100

# ── Profile C ────────────────────────────────────────────────────────
up-c-vuln:
	$(COMPOSE) -f profile-c/vulnerable/docker-compose.yml --project-name profile-c-vuln up -d

up-c-hard:
	$(COMPOSE) -f profile-c/hardened/docker-compose.yml --project-name profile-c-hard up -d

down-c:
	-$(COMPOSE) -f profile-c/vulnerable/docker-compose.yml --project-name profile-c-vuln down -v
	-$(COMPOSE) -f profile-c/hardened/docker-compose.yml   --project-name profile-c-hard down -v

logs-c:
	$(COMPOSE) -f profile-c/vulnerable/docker-compose.yml --project-name profile-c-vuln logs -f --tail=100 2>/dev/null || \
	$(COMPOSE) -f profile-c/hardened/docker-compose.yml   --project-name profile-c-hard logs -f --tail=100

# ── Attacks ──────────────────────────────────────────────────────────
# Profile A — target the vulnerable variant by default.
# Override APP_A / KC_A env vars to target the hardened variant.
APP_A ?= http://app-a-v.local:8081
KC_A  ?= http://keycloak.local:8080

attack-a:
	@python3 $(ATTACK_DIR)/A1_brute_force.py        $(APP_A) keycloak  || true
	@python3 $(ATTACK_DIR)/A2_credential_stuffing.py $(APP_A) keycloak  || true
	@bash    $(ATTACK_DIR)/A7_redirect_uri.sh        $(KC_A)            || true
	@bash    $(ATTACK_DIR)/A8_csrf_state.sh          $(APP_A) $(KC_A)   || true
	@bash    $(ATTACK_DIR)/A9_open_redirect.sh       $(APP_A) app-a-v.local || true
	@bash    $(ATTACK_DIR)/A4_token_replay.sh        $(APP_A) ""        || true
	@bash    $(ATTACK_DIR)/A5_jwt_algnone.sh         $(APP_A) ""        || true
	@bash    $(ATTACK_DIR)/A6_session_hijack.sh      $(APP_A) ""        || true
	@bash    $(ATTACK_DIR)/A10_idp_spof.sh           $(APP_A) ""        || true
	@bash    $(ATTACK_DIR)/A11_db_leak.sh            profile-a/vulnerable || true
	@bash    $(ATTACK_DIR)/A12_security_headers.sh   $(APP_A)            || true

# Profile B — target the vulnerable variant by default.
APP_B ?= http://app-b-v.local:8082

attack-b:
	@python3 $(ATTACK_DIR)/A3_phishing_check.py     $(APP_B)          || true
	@bash    $(ATTACK_DIR)/A9_open_redirect.sh      $(APP_B) app-b-v.local || true
	@bash    $(ATTACK_DIR)/A6_session_hijack.sh     $(APP_B) ""        || true
	@bash    $(ATTACK_DIR)/A12_security_headers.sh  $(APP_B)           || true

# Profile C — target the vulnerable variant by default.
APP_C ?= http://app-c-v.local:8083

attack-c:
	@python3 $(ATTACK_DIR)/A1_brute_force.py        $(APP_C) vaultwarden || true
	@python3 $(ATTACK_DIR)/A2_credential_stuffing.py $(APP_C) vaultwarden || true
	@bash    $(ATTACK_DIR)/A11_db_leak.sh            profile-c/vulnerable || true
	@bash    $(ATTACK_DIR)/A12_security_headers.sh   $(APP_C)              || true

attack-all: attack-a attack-b attack-c

# ── Common ───────────────────────────────────────────────────────────
down: down-a down-b down-c

hosts-check:
	@echo "Checking /etc/hosts for required entries..."
	@for h in app-a-v.local app-a-h.local app-b-v.local app-b-h.local app-c-v.local app-c-h.local keycloak.local evil-clone.local; do \
		if grep -q "$$h" /etc/hosts 2>/dev/null; then \
			echo "  OK      $$h"; \
		else \
			echo "  MISSING $$h  →  sudo sh -c 'echo \"127.0.0.1 $$h\" >> /etc/hosts'"; \
		fi; \
	done

hosts-add:
	@echo "Adding required hosts entries to /etc/hosts..."
	@for h in app-a-v.local app-a-h.local app-b-v.local app-b-h.local app-c-v.local app-c-h.local keycloak.local evil-clone.local; do \
		if grep -qE "[[:space:]]$$h([[:space:]]|$$)" /etc/hosts 2>/dev/null; then \
			echo "  SKIP    $$h (already present)"; \
		else \
			sudo sh -c "printf '127.0.0.1 %s\n' $$h >> /etc/hosts"; \
			echo "  ADDED   $$h"; \
		fi; \
	done

hosts-remove:
	@echo "Removing required hosts entries from /etc/hosts..."
	@for h in app-a-v.local app-a-h.local app-b-v.local app-b-h.local app-c-v.local app-c-h.local keycloak.local evil-clone.local; do \
		if grep -qE "[[:space:]]$$h([[:space:]]|$$)" /etc/hosts 2>/dev/null; then \
			sudo sed -i.bak "/[[:space:]]$$h\\([[:space:]]\\|$$\\)/d" /etc/hosts; \
			echo "  REMOVED $$h"; \
		else \
			echo "  SKIP    $$h (not found)"; \
		fi; \
	done
	@echo "Done. Backup file: /etc/hosts.bak"

clean-results:
	rm -rf results/raw/* results/processed/* results/playwright/*
	@echo "Result artifacts cleaned."
