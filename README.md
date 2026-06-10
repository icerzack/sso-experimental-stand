# SSO Experimental Stand

Экспериментальный стенд для исследования влияния архитектурной модели
аутентификации на защищённость и операционные характеристики веб-приложения.

## О проекте

Проект представляет собой полностью контейнеризованный испытательный полигон,
на котором развёрнуты четыре различные архитектуры Single Sign-On (SSO). Каждая
архитектура — это связка **IdP (Identity Provider) + прокси-сервер +
тестовое Go-приложение**, запускаемая одной командой `make up-e1?`.

Стенд решает две исследовательские задачи:

1. **Эксперимент 1** — как выбор *протокола*, *паттерна интеграции* и
   *метода верификации* определяет классы уязвимостей и трудоёмкость защиты.
   Для каждого профиля выполняется набор атак в двух конфигурациях
   (vulnerable / hardened), чтобы измерить остаточный риск после hardening.

2. **Эксперимент 2** — при фиксированных OIDC + Password, как конкретная
   IdP-платформа влияет на производительность и операционную сложность.
   Измеряются latency, throughput, потребление RAM/CPU и время старта.

Оба эксперимента объединены контрольной точкой: **Keycloak + OIDC + Password**
(профиль E1A = профиль E2A).

---

## Зафиксированные версии компонентов

Все Docker-образы зафиксированы по тегам для воспроизводимости результатов.

### IdP-платформы

| Компонент | Версия | Образ | Используется в |
|-----------|--------|-------|----------------|
| Keycloak | 24.0 | `quay.io/keycloak/keycloak:24.0` | E1A, E1B, E1D, E2A |
| Authentik | 2024.8 | `ghcr.io/goauthentik/server:2024.8` | E2B |
| Zitadel | stable | `ghcr.io/zitadel/zitadel:stable` | E2C |
| Authelia | 4.38 | `authelia/authelia:4.38` | E1C, E2D |

### Инфраструктура

| Компонент | Версия | Образ | Назначение |
|-----------|--------|-------|------------|
| Traefik | 3.3 | `traefik:v3.3` | Reverse proxy / TLS terminator |
| PostgreSQL | 16-alpine | `postgres:16-alpine` | Хранилище данных IdP |
| Redis | 7-alpine | `redis:7-alpine` | Сессии Authelia / Authentik |

### Тестовое приложение

| Компонент | Версия |
|-----------|--------|
| Go runtime | 1.24 (`golang:1.24-alpine`) |
| Alpine runtime | 3.20 |
| go-oidc | v3.18.0 |
| gorilla/sessions | v1.4.0 |
| golang.org/x/oauth2 | v0.36.0 |
| go-jose | v4.1.4 |

Приложение собирается из `app/main.go` (~1140 строк), поддерживает три режима
работы через переменную окружения `AUTH_MODE`:
- `oidc` — стандартный Authorization Code Flow с PKCE;
- `saml` — SAML SP-initiated SSO;
- `forward-auth` — доверие заголовку `X-Remote-User` от reverse proxy.

### Мониторинг

| Компонент | Версия | Порт |
|-----------|--------|------|
| Prometheus | v2.54.1 | 9090 |
| Grafana | 10.4.1 | 3000 |
| cAdvisor | latest | 8081 |
| Node Exporter | latest | 9100 |

### Нагрузочное тестирование

| Компонент | Примечание |
|-----------|------------|
| k6 | Устанавливается на хост (`brew install k6` / см. https://k6.io) |

---

## Структура экспериментов

### Эксперимент 1 — Влияние архитектурного профиля на защищённость

**Исследовательский вопрос:** как выбор протокола, паттерна интеграции и метода
верификации определяет классы угроз и трудоёмкость защиты?

| Профиль | Конфигурация                       | Специфический attack surface                                                        |
|---------|------------------------------------|-------------------------------------------------------------------------------------|
| **E1A** | Keycloak + OIDC + Password         | JWT alg confusion, token replay, open redirect, PKCE downgrade, credential stuffing |
| **E1B** | Keycloak + SAML + Password         | XML Signature Wrapping, assertion replay                                            |
| **E1C** | Authelia + Forward Auth + Password | Header injection (X-Remote-User), session fixation, CSRF logout                     |
| **E1D** | Keycloak + OIDC + WebAuthn         | RP ID mismatch; credential stuffing и RT-фишинг структурно устранены                |

Профиль E1A — контрольная точка всего исследования.
Профиль E1D отличается от E1A единственным параметром (метод верификации) — чистое измерение его эффекта.

Каждый профиль доступен в дефолтной (**vulnerable**) и **hardened** конфигурации.
Сравнение «до/после hardening» даёт delta hardening; остаточные после hardening уязвимости формируют метрику остаточного риска.

Hardened-конфигурация реализуется через overlay-файлы (`profile-e1?-hard.yml`),
которые подменяют realm export (Keycloak) или configuration.yml (Authelia)
и выставляют переменную `HARDENED=true` в приложении. Пересборка не требуется —
достаточно `make down-e1? && make up-e1?-hard`.

### Эксперимент 2 — Сравнение IdP-платформ по операционным характеристикам

**Исследовательский вопрос:** при фиксированных OIDC и пароле, насколько конкретная IdP-платформа влияет на производительность и операционную сложность?

Э2 не исследует защищённость: при фиксированном OIDC + пароль attack surface одинаков для всех платформ.

| Профиль | Конфигурация                | Класс платформы               |
|---------|-----------------------------|-------------------------------|
| **E2A** | Keycloak + OIDC + Password  | Heavyweight enterprise (JVM)  |
| **E2B** | Authentik + OIDC + Password | Modern all-in-one (Python/Go) |
| **E2C** | Zitadel + OIDC + Password   | Cloud-native minimal (Go)     |
| **E2D** | Authelia + OIDC + Password  | Lightweight proxy-first (Go)  |

Профиль E2A идентичен профилю E1A (единая контрольная точка).
Hardened-варианты для Э2 не предусмотрены — эксперимент измеряет только производительность и operability.

---

## Архитектура стенда

Каждый профиль разворачивает общий базовый стек (`docker-compose.yml`) плюс
профиль-специфичный overlay из `profiles/profile-eXX.yml`.

```
┌───────────────────────────────────────────────────────────────┐
│                        Хост-машина                            │
│                                                               │
│  :443/:80 ───► Traefik (v3.3)                                │
│                  │                                            │
│         ┌───────┴────────┐                                    │
│         ▼                ▼                                    │
│   app.sso-lab.local   idp.sso-lab.local                      │
│         │                │                                    │
│    ┌────▼────┐    ┌──────▼──────┐                            │
│    │ App     │    │ IdP         │                             │
│    │ (Go)    │◄──►│ (Keycloak / │                            │
│    │ :8080   │OIDC│ Authelia)   │                            │
│    │         │SAML│ :8080/9091  │                            │
│    └─────────┘    └──────┬──────┘                            │
│                          │                                    │
│                    ┌─────▼─────┐                              │
│                    │ PostgreSQL│                              │
│                    │ :5432     │                              │
│                    └───────────┘                              │
│                                                               │
│  Мониторинг:                                                  │
│  Prometheus(:9090) ← cAdvisor, Node Exporter, Traefik        │
│  Grafana(:3000)    ← data source: Prometheus                  │
└───────────────────────────────────────────────────────────────┘
```

### Как работает переключение профилей

Базовый `docker-compose.yml` описывает общие сервисы (Traefik, Postgres, App,
мониторинг). Профиль-override переопределяет образ IdP, монтирует нужный
realm-export / config и задаёт переменные окружения приложения.
Собрать и запустить — одна команда:

```bash
make up-e1a      # → docker compose -f docker-compose.yml -f profiles/profile-e1a.yml up -d --build
```

---

## Требования

| Инструмент     | Мин. версия            | Примечание                              |
| -------------- | ---------------------- | --------------------------------------- |
| Docker Engine  | 24+                    | Требуется для всех операций             |
| Docker Compose | v2.24+                 | Плагин `docker compose`                 |
| bash           | любой                  | Для скриптов атак                       |
| curl           | любой                  | Зависимость скриптов атак               |
| python3        | любой                  | Парсинг JSON в скриптах атак            |

Опционально:
- **k6** — нагрузочное тестирование (Эксперимент 2): `brew install k6`
- **mkcert** — генерация доверенных локальных TLS-сертификатов: `brew install mkcert`
- **jq** — удобный просмотр JSON-результатов нагрузочных тестов

> Без mkcert стенд будет работать, но браузер покажет предупреждение о
> самоподписанном сертификате. Скрипты атак используют `curl -sk`, поэтому
> им доверенный сертификат не нужен.

---

## /etc/hosts

Все профили используют виртуальные хосты `app.sso-lab.local` и `idp.sso-lab.local`.
TLS-сертификат выписан на `*.sso-lab.local`.

```bash
# Автоматическое добавление (требует sudo):
make hosts-add

# Проверка:
make hosts-check

# Удаление после работы:
make hosts-remove
```

Или вручную добавьте в `/etc/hosts`:

```
127.0.0.1  app.sso-lab.local idp.sso-lab.local
```

> На macOS `.local` домены могут перехватываться mDNS (Bonjour).
> Скрипты атак автоматически используют `--resolve host:port:127.0.0.1`,
> поэтому проблем не возникает. При ручном тестировании в браузере
> запись в `/etc/hosts` обязательна.

---

## Быстрый старт

### Эксперимент 1 — Запуск профилей и атак

```bash
# ── Профиль E1A: Keycloak OIDC Password (контрольная точка) ──

# Дефолтная (vulnerable) конфигурация:
make up-e1a && sleep 30          # ждём health checks (Keycloak стартует ~30 сек)

# hardened конфигурация:
make up-e1a-hard && sleep 30

# Запуск атак против текущего профиля:
make attack-e1a

# Остановка и удаление volumes:
make down-e1a


# ── Профиль E1B: Keycloak SAML Password ──

make up-e1b          # vulnerable
make up-e1b-hard     # hardened
make attack-e1b
make down-e1b


# ── Профиль E1C: Authelia Forward Auth Password ──

make up-e1c          # vulnerable
make up-e1c-hard     # hardened
make attack-e1c
make down-e1c


# ── Профиль E1D: Keycloak OIDC WebAuthn ──

make up-e1d          # vulnerable
make up-e1d-hard     # hardened
make attack-e1d
make down-e1d


# ── Все атаки Эксперимента 1 разом ──

make attack-all


# ── Просмотр логов запущенного профиля ──

make logs-e1a        # Ctrl+C для выхода
```

### Полная процедура Э1: vulnerable → атаки → hardened → повтор атак

Это основная рабочая процедура Эксперимента 1. Она выполняется отдельно для
каждого профиля (e1a, e1b, e1c, e1d):

```bash
# Шаг 1: Поднять дефолтную конфигурацию
make up-e1a && sleep 30           # ждём health checks

# Шаг 2: Запустить атаки, зафиксировать результаты
make attack-e1a | tee results/raw/e1a_vulnerable_$(date +%Y%m%d).txt

# Шаг 3: Переключиться на hardened (down + up-hard)
make down-e1a
make up-e1a-hard && sleep 30

# Шаг 4: Повторить атаки
make attack-e1a | tee results/raw/e1a_hardened_$(date +%Y%m%d).txt

# Шаг 5: Зафиксировать дельту — какие атаки закрылись, какие остались
make down-e1a

# Шаг 6: Генерация сводного HTML-отчёта
python3 scripts/generate_attack_report.py
# → results/processed/index.html   (человекочитаемый отчёт)
# → results/processed/attack-summary.json   (машинночитаемый)
```

Повторить для e1b, e1c, e1d.

### Эксперимент 2 — Нагрузочное тестирование платформ

Нагрузочное тестирование проводится ступенчато: 10 → 50 → 100 → 200 virtual users
(см. `k6/run.sh`). Результаты сохраняются как JSON в `results/raw/`.

```bash
# ── Профиль E2A: Keycloak (контрольная точка = E1A) ──

make up-e2a && sleep 60           # JVM нужен тёплый старт
make load-test                    # k6 → results/raw/
make down-e2a


# ── Профиль E2B: Authentik ──

make up-e2b && sleep 90           # несколько контейнеров + worker
make load-test
make down-e2b


# ── Профиль E2C: Zitadel ──

make up-e2c && sleep 45
make load-test
make down-e2c


# ── Профиль E2D: Authelia OIDC beta ──

make up-e2d && sleep 30
make load-test
make down-e2d
```

Результаты k6 сохраняются в `results/raw/`. Prometheus и Grafana доступны во время нагрузки:

- Grafana: http://localhost:3000 (admin/admin)
- Prometheus: http://localhost:9090
- cAdvisor: http://localhost:8081

---

## Учётные данные по умолчанию

| Профиль       | Роль              | Логин             | Пароль       |
| ------------- | ----------------- | ------------------ | ------------ |
| E1A, E1B, E1D | Тестовый пользователь | `testuser`    | `password123`|
| E1A, E1B, E1D | Keycloak admin    | `admin`            | `admin`      |
| E1C, E2D      | Тестовый пользователь | `testuser`    | `password123`|

Эти учётные данные намеренно слабые — они являются частью модели угроз
(используются в атаках credential stuffing, A9).

---

## Набор скриптов атак (attacks/)

Все скрипты расположены в `attacks/` и принимают позиционные аргументы
(целевые URL, realm). Запускаются через `make attack-e1?` или напрямую.

Каждый скрипт выводит результат в формате `[Ax] НАЗВАНИЕ: VULNERABLE / PROTECTED / PARTIAL / INCONCLUSIVE`.

| Скрипт                             | Атака                                        | Профили    |
|-------------------------------------|----------------------------------------------|------------|
| `A1_jwt_alg_none.sh`                | JWT `alg=none` — подмена алгоритма           | E1A, E1D   |
| `A2_jwt_key_confusion.sh`           | JWT key confusion — подмена ключа подписи   | E1A, E1D   |
| `A3_token_replay.sh`                | Token / session replay после logout          | E1A, E1D   |
| `A4_open_redirect.sh`              | Open redirect через redirect_uri            | E1A, E1D   |
| `A5_pkce_downgrade.sh`             | PKCE downgrade (S256 → plain → none)         | E1A, E1D   |
| `A6_header_injection.sh`           | Header injection (X-Remote-User spoof)       | E1C        |
| `A7_session_fixation.sh`           | Session fixation                            | E1C        |
| `A8_csrf_logout.sh`                | CSRF logout                                 | E1C        |
| `A9_credential_stuffing.sh`        | Credential stuffing по словарю               | E1A        |
| `A10_webauthn_rp_mismatch.sh`      | RP ID mismatch / phishing page              | E1D        |
| `A11_saml_assertion_replay.sh`     | SAML assertion replay                      | E1B        |
| `A12_saml_signature_wrapping.sh`   | SAML Signature Wrapping (XSW)               | E1B        |

Общий хелпер `common.sh` предоставляет:
- `rcurl` — обёртка над `curl` с автоматическим `--resolve` для `.local` доменов;
- `b64url_encode` / `b64url_decode` — кодирование/декодирование Base64URL без внешних зависимостей;
- `get_id_token` — получение JWT через ROPC grant (Keycloak);
- `get_session_cookie` — получение session cookie через browser-like OIDC login flow;

---

## Маппинг скриптов → make-таргеты

```
make attack-e1a  →  A1  A2  A3  A4  A5  A9        (OIDC + Password)
make attack-e1b  →  A11 A12                        (SAML)
make attack-e1c  →  A6  A7  A8                     (Forward Auth)
make attack-e1d  →  A1  A2  A3  A4  A5  A10       (OIDC + WebAuthn)
make attack-all  →  все вышеперечисленные
```

Скрипты можно запускать и вручную, передав целевые параметры:

```bash
bash attacks/A1_jwt_alg_none.sh https://app.sso-lab.local https://idp.sso-lab.local sso-lab
```

---

## Hardening-конфигурации

Для каждого профиля Э1 существует overlay-файл, который подменяет конфигурацию
IdP на hardened и включает флаг `HARDENED=true` в приложении.

| Профиль | Vulnerable конфиг                                   | Hardened конф                                           | Что меняется                                       |
|---------|------------------------------------------------------|---------------------------------------------------------|----------------------------------------------------|
| E1A     | `realm-export.json`                                  | `realm-export-hardened.json`                            | ES256 подпись, PKCE обязательный, rotating refresh |
| E1B     | `realm-export-saml.json`                             | `realm-export-saml-hardened.json`                       | Строгая проверка XML-подписей                       |
| E1C     | `config-forward-auth-vuln.yml`                       | `config-forward-auth-hardened.yml`                      | HMAC verification на заголовках                     |
| E1D     | `realm-export-webauthn.json`                         | `realm-export-webauthn-hardened.json`                   | Строгий RP ID, require user verification            |

Приложение при `HARDENED=true` включает дополнительные проверки:
- Верификация подписи JWT по JWKS endpoint (вместо слепого доверия `alg`);
- Проверка `token_use` claim;
- Отклонение релевантных воспроизводимых токенов;
- CSRF-защита logout.

---

## Генерация TLS-сертификатов

```bash
make gen-certs     # mkcert → configs/traefik/certs/
```

Если mkcert не установлен, Traefik будет использовать самоподписанные сертификаты
(уже сгенерированные лежат в `certs/`). Все скрипты атак игнорируют ошибки TLS
(`curl -sk`), так что отсутствие доверенного сертификата не влияет на результаты.

Wildcard-сертификат выписан на `*.sso-lab.local`.

---

## Мониторинг (Prometheus + Grafana)

Запускается автоматически как часть базового `docker-compose.yml`.
Доступно при любом запущенном профиле:

| Сервис      | URL                            | Логин       | Назначение                    |
|-------------|--------------------------------|-------------|-------------------------------|
| Grafana     | http://localhost:3000          | admin/admin | Дашборды метрик               |
| Prometheus  | http://localhost:9090          | —           | TSDB + запросы PromQL         |
| cAdvisor    | http://localhost:8081          | —           | Контейнерные метрики CPU/RAM  |

Prometheus собирает метрики со следующих endpoints:
- `traefik:8082` — HTTP-метрики reverse proxy;
- `app:8080/metrics` — метрики приложения;
- `cadvisor:8080` — контейнерные метрики;
- `node-exporter:9100` — хостовые метрики;
- `idp:8080/realms/sso-lab/metrics` — Keycloak metrics endpoint (только Keycloak-профили).

Используется для замеров CPU/RAM при нагрузочном тестировании (Эксперимент 2).

---

## Структура каталогов

```
sso-experimental-stand/
├── app/                         ← Go-приложение (OIDC/SAML/ForwardAuth клиент)
│   ├── main.go                  ← ~1140 строк, три режима AUTH_MODE
│   ├── Dockerfile               ← Multi-stage build (Go 1.24 → Alpine 3.20)
│   ├── go.mod                   ← go-oidc v3.18, gorilla/sessions v1.4, oauth2 v0.36
│   └── go.sum
├── profiles/                    ← Overlay-файлы docker-compose
│   ├── profile-e1a.yml         ← Э1: Keycloak OIDC Password
│   ├── profile-e1a-hard.yml       hardened override
│   ├── profile-e1b.yml         ← Э1: Keycloak SAML Password
│   ├── profile-e1b-hard.yml
│   ├── profile-e1c.yml         ← Э1: Authelia Forward Auth
│   ├── profile-e1c-hard.yml
│   ├── profile-e1d.yml         ← Э1: Keycloak OIDC WebAuthn
│   ├── profile-e1d-hard.yml
│   ├── profile-e2a.yml         ← Э2: Keycloak OIDC (control = E1A)
│   ├── profile-e2b.yml         ← Э2: Authentik OIDC
│   ├── profile-e2c.yml         ← Э2: Zitadel OIDC
│   └── profile-e2d.yml         ← Э2: Authelia OIDC
├── configs/
│   ├── keycloak/               ← Realm exports
│   │   ├── realm-export.json             ← Default (vulnerable) OIDC
│   │   ├── realm-export-hardened.json    ← Hardened OIDC
│   │   ├── realm-export-saml.json        ← Default SAML
│   │   ├── realm-export-saml-hardened.json
│   │   ├── realm-export-webauthn.json    ← Default WebAuthn
│   │   └── realm-export-webauthn-hardened.json
│   ├── authelia/               ← Config YAML + users_database
│   │   ├── config-forward-auth-vuln.yml
│   │   ├── config-forward-auth-hardened.yml
│   │   ├── config-oidc-provider.yml      ← Э2D (OIDC provider mode)
│   │   └── users_database.yml
│   ├── postgres/               ← init.sql (multi-schema setup)
│   └── traefik/                ← Static + dynamic config, gen-certs.sh
│       ├── traefik.yml                   ← Entrypoints, TLS, providers
│       ├── dynamic/dynamic.yml           ← Cert store + middlewares
│       └── gen-certs.sh
├── attacks/                     ← Bash-скрипты атак
│   ├── common.sh               ← Shared helpers (rcurl, b64url, get_id_token)
│   ├── A1_jwt_alg_none.sh
│   ├── A2_jwt_key_confusion.sh
│   ├── A3_token_replay.sh
│   ├── A4_open_redirect.sh
│   ├── A5_pkce_downgrade.sh
│   ├── A6_header_injection.sh
│   ├── A7_session_fixation.sh
│   ├── A8_csrf_logout.sh
│   ├── A9_credential_stuffing.sh
│   ├── A10_webauthn_rp_mismatch.sh
│   ├── A11_saml_assertion_replay.sh
│   └── A12_saml_signature_wrapping.sh
├── k6/
│   ├── login-flow.js            ← k6 scenario (Authorization Code + ROPC)
│   └── run.sh                   ← Wrapper: 10→50→100→200 VU ступенчато
├── monitoring/
│   ├── prometheus.yml           ← Scrape configs
│   └── grafana/
│       ├── provisioning/
│       └── dashboards/
├── scripts/
│   ├── generate_attack_report.py ← Парсер raw → summary JSON + HTML
│   └── generate_site.py
├── wordlists/
│   └── top100_passwords.txt     ← Словарь для A9_credential_stuffing
├── results/
│   ├── raw/                     ← Сырые логи атак (tee) и k6 JSON
│   └── processed/               ← Итоговые JSON + HTML отчёты
├── certs/                       ← Сгенерированные TLS-сертификаты (*.sso-lab.local)
├── docker-compose.yml           ← Base stack (Traefik, Postgres, App, Monitoring)
├── Makefile                     ← All make targets
└── .env                         ← Environment defaults
```

---

## Переменные окружения (.env)

Основные параметры задаются в `.env` и могут быть перекрыты в профиль-overlay'ях:

| Переменная              | По умолчанию              | Назначение                                   |
|-------------------------|---------------------------|----------------------------------------------|
| `AUTH_MODE`             | `oidc`                    | Режим приложения: oidc / saml / forward-auth |
| `HARDENED`              | `false`                   | Включает защитные проверки в приложении       |
| `APP_BASE_URL`          | `https://app.sso-lab.local` | Внешний URL приложения                     |
| `IDP_ISSUER_HOST`       | `idp.sso-lab.local`       | Хост IdP (для формирования issuer URL)       |
| `IDP_INTERNAL_HOST`     | `idp`                     | Внутренний hostname контейнера IdP           |
| `IDP_PORT`              | `8080`                    | Внутренний порт IdP                         |
| `OIDC_REALM`            | `sso-lab`                 | Keycloak realm (пустой строкой для других IdP)|
| `CLIENT_ID`             | `sso-test-app`            | OAuth2/OIDC client ID                       |
| `CLIENT_SECRET`         | `testpass123`             | OAuth2/OIDC client secret                   |
| `SESSION_SECRET`        | `insecure-key`            | Ключ шифрования сессионных cookie            |
| `REMOTE_USER_HEADER`    | `X-Remote-User`           | Заголовок forward-auth (только E1C)          |
| `ALLOWED_REDIRECT_DOMAIN`| `app.sso-lab.local`      | Whitelist redirect URI (только E1C)          |
| `POSTGRES_PASSWORD`     | `postgres`                | Пароль PostgreSQL                            |
| `POSTGRES_USER`         | `postgres`                | Пользователь PostgreSQL                      |

> Значения по умолчанию намеренно небезопасны — это часть модели угроз стенда.
> Не используйте эти секреты в production.

---

## Методология проведения экспериментов

### Эксперимент 1 (защищённость)

Для каждого профиля (E1A, E1B, E1C, E1D):

1. Развернуть дефолтную конфигурацию (`make up-e1?`);
2. Воспроизвести применимые сценарии из сводного набора — зафиксировать результаты;
3. Применить hardening (`make up-e1?-hard`) — переключение на hardened realm config;
4. Повторить атаки — зафиксировать, какие закрылись;
5. Зафиксировать **остаточный риск**: классы угроз, не закрытые hardening-ом ни при каких настройках.

**Итоговая метрика — остаточный риск после hardening**: для каждого профиля есть ли атаки,
структурно неустранимые вне зависимости от конфигурации.

### Эксперимент 2 (операционные характеристики)

Для каждого профиля (E2A, E2B, E2C, E2D):

1. Развернуть платформу (`make up-e2?`);
2. Замерить время от старта до первого успешного логина;
3. Провести ступенчатую нагрузку через k6 (`make load-test`);
4. Собрать метрики через Prometheus/Grafana: latency P50/P95/P99, error rate, CPU, RAM;
5. Зафиксировать операционную сложность: число шагов для регистрации нового клиента;
6. Замерить startup/recovery time после рестарта.

**Итоговая метрика — разброс между платформами по latency P95 и RAM при одинаковой нагрузке.**

---

## Полный список make-таргетов

```
make help              Показать справку

# Эксперимент 1 — запуск/остановка профилей
make up-e1a            E1A: Keycloak OIDC Password (vulnerable)
make up-e1a-hard       E1A: Keycloak OIDC Password (hardened)
make down-e1a
make logs-e1a

make up-e1b            E1B: Keycloak SAML Password (vulnerable)
make up-e1b-hard       E1B: Keycloak SAML Password (hardened)
make down-e1b
make logs-e1b

make up-e1c            E1C: Authelia Forward Auth (vulnerable)
make up-e1c-hard       E1C: Authelia Forward Auth (hardened)
make down-e1c
make logs-e1c

make up-e1d            E1D: Keycloak OIDC WebAuthn (vulnerable)
make up-e1d-hard       E1D: Keycloak OIDC WebAuthn (hardened)
make down-e1d
make logs-e1d

# Эксперимент 2 — запуск/остановка платформ
make up-e2a            E2A: Keycloak OIDC (control point)
make down-e2a
make logs-e2a

make up-e2b            E2B: Authentik OIDC
make down-e2b
make logs-e2b

make up-e2c            E2C: Zitadel OIDC
make down-e2c
make logs-e2c

make up-e2d            E2D: Authelia OIDC beta
make down-e2d
make logs-e2d

# Атаки (Эксперимент 1)
make attack-e1a        A1-A5,A9 против E1A (OIDC+Password)
make attack-e1b        A11-A12 против E1B (SAML)
make attack-e1c        A6-A8 против E1C (Forward Auth)
make attack-e1d        A1-A5,A10 против E1D (OIDC+WebAuthn)
make attack-all        Все атаки всех профилей Э1

# Нагрузочное тестирование (Эксперимент 2)
make load-test         k6 load test против текущего профиля

# Утилиты
make down              Остановить все контейнеры + volumes
make gen-certs         Сгенерировать TLS сертификаты
make hosts-check       Проверить /etc/hosts
make hosts-add         Добавить записи в /etc/hosts
make hosts-remove      Удалить записи из /etc/hosts
make clean-results     Очистить результаты
```

---

## Результаты исследования

### Матрица выбора решения

> Hardening обязателен для **всех** профилей. Состав мер определяется протоколом:
> OIDC — 6 шагов конфигурации IdP; SAML — верификация XML-структуры;
> Forward Auth — дополнительно сетевая изоляция на инфраструктурном уровне.

#### Выбор протокола и паттерна интеграции (результаты Эксперимента 1)

| Сценарий | Протокол / паттерн | Ключевое условие |
|---|---|---|
| Риск фишинга или credential stuffing | OIDC + **WebAuthn** | Структурно закрывает угрозу без доп. шагов hardening |
| Стандартный сценарий, парольная аутентификация | OIDC + Password | 6 шагов hardening закрывают 4 из 6 уязвимостей; token replay — архитектурное ограничение stateless JWT |
| B2B, legacy-интеграция с корпоративными системами | **SAML 2.0** | Только Full IdP; XSW и assertion replay закрываются hardening-ом |
| Приложение нельзя изменить (legacy, внутренние сервисы) | **Forward Auth** | Обязательна сетевая изоляция контейнеров — атака A6 неустранима конфигурацией IdP |

#### Выбор платформы (результаты Эксперимента 2)

| Сценарий | Платформа | Обоснование |
|---|---|---|
| Ресурсно-ограниченная среда, только OIDC | **Authelia** | 48 МБ RAM idle, P95 105 мс при 100 VU, 5 шагов регистрации клиента |
| Full IdP с полным стеком протоколов, умеренная нагрузка | **Zitadel** | 165 МБ RAM, линейная деградация без выбросов, OIDC + SAML + WebAuthn + web-UI |
| Нужны оба паттерна — Full IdP и Forward Auth — в одном решении | **Authentik** | Единственная платформа из рассмотренных, поддерживающая оба паттерна одновременно |
| Enterprise: кластеризация, LDAP, Kerberos, поддержка Red Hat | **Keycloak** | Наиболее зрелое решение; 520 МБ RAM — норма для enterprise с горизонтальным масштабированием |
| ГИС, КИИ, требования ФСТЭК и Реестр Минцифры | **Blitz IdP / Trusted.net** | Единственные сертифицированные отечественные Full IdP; Blitz IdP — №4525 ФСТЭК от 10.03.2022, реестр Минцифры №842 |

---

### Hardening-чеклисты

#### OIDC (профили E1A, E1D, E2A–E2D)

| # | Мера | Что закрывает | Где настраивается |
|---|---|---|---|
| 1 | Алгоритм подписи токенов → **ES256** (вместо RS256) | A2: JWT key confusion RS256→HS256 | Keycloak realm / настройки клиента |
| 2 | **PKCE S256** обязателен; plain и отсутствие `code_challenge` — запретить | A5: PKCE downgrade | Keycloak realm → Advanced settings |
| 3 | **Redirect URI** — точный список без wildcard | A4: Open redirect | Keycloak client → Valid redirect URIs |
| 4 | **TTL access token** → 60 секунд (вместо дефолтных 300) | A3: уменьшает окно token replay | Keycloak realm → Token settings |
| 5 | **Rotating refresh token** — включить | A3: перехваченный refresh token инвалидируется после использования | Keycloak realm → Token settings |
| 6 | **Brute Force Protection** — включить (блокировка после 5 попыток) | A9: замедляет credential stuffing | Keycloak realm → Security defences |
| ⚠️ | **Rate limiting** на уровне reverse proxy (Traefik / Nginx / WAF) | A9: distributed credential stuffing с разных IP | Traefik middleware / внешний WAF |
| ⚠️ | **Token Introspection** при каждом запросе | A3: полное закрытие token replay | Изменение архитектуры приложения |

> ⚠️ — меры, выходящие за рамки конфигурации IdP; остаточный риск после hardening без них.

Проверка в стенде: `make up-e1a-hard && make attack-e1a`

---

#### SAML 2.0 (профиль E1B)

| # | Мера | Что закрывает | Где настраивается |
|---|---|---|---|
| 1 | **Строгая верификация XML-структуры** — структура документа должна соответствовать ожидаемой, перестановка элементов отклоняется | A12: XML Signature Wrapping (XSW) | Keycloak realm → SAML settings |
| 2 | **Отслеживание использованных AssertionID** — Keycloak хранит кэш предъявленных ID в рамках TTL assertion | A11: SAML assertion replay | Keycloak realm → SAML settings |
| 3 | Запретить слабые алгоритмы XML-подписи — разрешить только **SHA-256** и выше; SHA-1 — запретить явно | A12: XSW через слабые алгоритмы | Keycloak realm → SAML signature |
| 4 | **Brute Force Protection** — те же параметры, что и для OIDC | A9: credential stuffing | Keycloak realm → Security defences |

Проверка в стенде: `make up-e1b-hard && make attack-e1b`

---

#### Forward Auth (профиль E1C)

| # | Мера | Что закрывает | Где настраивается |
|---|---|---|---|
| 1 | **HMAC-верификация заголовка** `X-Remote-User` — Authelia подписывает заголовок; приложение проверяет подпись при `HARDENED=true` | A6: header injection извне | Authelia config + приложение |
| 2 | **Ротация session ID** после успешной аутентификации | A7: session fixation | Authelia config |
| 3 | **CSRF-токен** на logout-endpoint | A8: CSRF logout | Приложение (`HARDENED=true`) |
| 4 | **Rate limiting** на endpoint аутентификации — не более 5 попыток в минуту с одного IP | A9: credential stuffing | Authelia config → regulation |
| ⚠️ | **Сетевая изоляция контейнеров** — запретить прямой доступ к приложению в обход Traefik (Docker network policy / Kubernetes NetworkPolicy) | A6: header injection изнутри Docker-сети | Инфраструктурный уровень |

> ⚠️ — **структурный риск паттерна**: без сетевой изоляции атака A6 воспроизводима из любого контейнера той же Docker-сети даже при включённой HMAC-верификации. Это единственный неустранимый риск во всём исследовании.

Проверка в стенде: `make up-e1c-hard && make attack-e1c`

---
