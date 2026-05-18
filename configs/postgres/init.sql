-- Databases for IdP backends. Each IdP expects its own database.
-- Schemas are created inside each database so that IdPs can auto-create
-- their tables on startup without permission issues.
CREATE DATABASE keycloak;
CREATE DATABASE authentik;
CREATE DATABASE zitadel;

\c keycloak
CREATE SCHEMA IF NOT EXISTS keycloak;

\c authentik
CREATE SCHEMA IF NOT EXISTS authentik;

\c zitadel
CREATE SCHEMA IF NOT EXISTS zitadel;
