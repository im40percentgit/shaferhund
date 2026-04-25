# Shaferhund — Master Plan

## Original Intent

Build a fully automated, agentic blue-team cybersecurity defense platform. The user's vision (from the `hund` spec) covers 25 capability domains; the ultimate goal is a self-evolving offensive-defensive loop that attacks its own infrastructure, finds gaps, writes rules, and retests — an immune system, not a tool.

The user is having fun building this while also thinking about it as a potential startup. The name "Shaferhund" (German Shepherd) is a guard dog.

## Project Overview

Agentic blue-team cybersecurity defense platform for solo security engineers at startups. AI-powered alert triage that ingests Wazuh + Suricata + AWS CloudTrail, clusters alerts, sends to Claude API for severity classification / IOC detection / YARA + Sigma rule generation, and runs a self-evaluating posture loop with adversarial Atomic Red Team validation.

**Current state (post-Phase 5 archive):** 5 phases shipped end-to-end (Alert Triage → Wazuh + Suricata → Sigma auto-deploy → Immune System → Adaptive Immune System → Cloud Eyes). 9 orchestrator tools registered via `register_tool()`. 5 services in `compose.yaml` (Wazuh manager, Suricata, agent, redteam-target, urlhaus-feed). `/health` exposes 6 nested blocks; `/metrics` is auth-gated. 308 passing tests. SQLite is the single store; idempotent ALTER TABLE migrations only.

See `archived-plans/2026-04-25_immune-system-and-cloud-eyes.md` for full Phase 1–5 history (REQ-IDs, DEC-IDs, decision logs, verification traces).

**Target user:** Solo security engineer, <100 endpoints, no SIEM budget. Same target as Phase 1.

---

## Phase 6: Fleet + Auth — Operational Maturity (3–4 weeks)

**Status:** planned
**Timebox:** 3–4 weeks

### Intent

Phase 1–5 produced a closed-loop immune system over signals from Wazuh hosts, Suricata wires, AWS audit logs, canary tokens, and an in-house red team — all running on **one** manager talking to **one** operator over a **single shared bearer token**. That's the right shape for Phase 1's solo-dev-with-a-laptop, but it's also why every "scale out" requirement (multi-cloud, multi-tenant, multi-endpoint, multi-team) has been deferred phase after phase. The blocker is identical each time: there is no per-identity surface to attach scope to. `SHAFERHUND_TOKEN` is a coarse on/off and every authenticated route trusts every authenticated caller equally.

Phase 6 closes that blocker by pairing the two REQ-NOGO entries the Phase 5 archive explicitly tagged Phase 6: **rule fleet distribution to remote Wazuh agents** (`REQ-NOGO-P5-002`) and **multi-user auth / RBAC / signed audit logs** (`REQ-NOGO-P5-003`, the carry-forward of `REQ-NOGO-P2-006` and `REQ-NOGO-P4-007`). They reinforce each other: fleet distribution requires per-endpoint identity to scope which agents pull which rules, and auth/RBAC needs concrete operational requirements to avoid theoretical over-engineering. Building either alone produces the wrong shape; building them together produces the right one.

This phase unlocks Phase 7+ work that has been blocked the whole time — multi-tenant posture, multi-cloud (GCP + Azure each as their own integration week), and any "team of operators sharing one Shaferhund" deployment. Honeypots, federation, and adversarial cloud scoring stay deferred — each is its own real week and forcing them into Phase 6 reproduces the fused-phase trap Phase 4 and Phase 5 explicitly avoided.

### Goals

- Rule fleet distribution: a remote Wazuh agent can authenticate to the manager, pull a scoped rule manifest, and apply it without operator hand-copying YAML files (REQ-P0-P6-001, REQ-P0-P6-002).
- Multi-user auth: the manager supports N named operators with hashed credentials and per-user bearer tokens; `SHAFERHUND_TOKEN` continues to work as a single-user fallback for unmodified deployments (REQ-P0-P6-003).
- RBAC: every auth-gated route is annotated with one of `{viewer, operator, admin}`; admin-only routes reject operator tokens with 403 (REQ-P0-P6-004).
- Signed audit log: every write-side request (deploy_rule, ack finding, approve recommendation, fleet rollout, user CRUD) lands in a tamper-evident `audit_log` table with a per-row HMAC chained to the previous row (REQ-P0-P6-005).
- Backwards compatible: existing single-user `SHAFERHUND_TOKEN` deployments keep working; migration is opt-in via `SHAFERHUND_AUTH_MODE=multi` (REQ-P0-P6-006).
- All Phase 1–5 tests pass unchanged; new tests prove auth boundaries hold (REQ-P0-P6-007).

### Non-Goals

- REQ-NOGO-P6-001: Multi-cloud (GCP Audit Logs / Azure Monitor) — Phase 7; same source-pipeline pattern as Phase 5 CloudTrail, but each provider is its own real integration week. Auth/RBAC unblocks per-provider scoping.
- REQ-NOGO-P6-002: Multi-tenant posture (per-team scores, per-AWS-account isolation) — Phase 7; depends on Phase 6 RBAC being stable for at least one full operational cycle.
- REQ-NOGO-P6-003: STIX/TAXII threat-intel federation (multi-feed, indicator deconfliction) — Phase 7; URLhaus is sufficient until federation has a real scoping requirement.
- REQ-NOGO-P6-004: Containerised service honeypots (SSH/MySQL/Redis) — Phase 7; doubles attack surface and needs separate isolation analysis.
- REQ-NOGO-P6-005: Adversarial rule-effectiveness scoring against cloud techniques — Phase 7; depends on stable Phase 4 `recommend_attack` baseline.
- REQ-NOGO-P6-006: OIDC / SAML / SSO — Phase 7+; Phase 6 ships local password-based auth + per-user bearer tokens. SSO is one of the standard "after we have multi-user" follow-ups; not on the critical path.
- REQ-NOGO-P6-007: Cryptographic signing of fleet rule packages with a separate key (e.g. cosign / minisign) — Phase 7; Phase 6 uses HMAC over the manifest with the per-agent shared secret. Real signing is a follow-up after the signed-package contract is operational.
- REQ-NOGO-P6-008: Replacing the existing `redteam-target` Ubuntu container with Windows or macOS — Phase 7; broader technique coverage requires separate licensing and image strategy.
- REQ-NOGO-P6-009: CloudTrail Lake / Athena query backend; real-time CloudTrail via EventBridge — Phase 7+ (REQ-NOGO-P5-007 / REQ-NOGO-P5-008 carry-forward).
- REQ-NOGO-P6-010: Cloud-native rule deploy (push to AWS GuardDuty / Security Hub) — Phase 7+ (REQ-NOGO-P5-009 carry-forward).

### Requirements

**Must-Have (P0):**

- REQ-P0-P6-001: `agent/fleet.py` implements a rule-manifest server. `GET /fleet/manifest` (auth-gated, role≥`operator`, scoped by per-agent `agent_id` claim) returns a JSON manifest listing all rules tagged for that agent's group(s), each entry containing `rule_id`, `rule_type` (`yara|sigma|wazuh`), `content_sha256`, `download_url`, and `version`. `GET /fleet/rule/{rule_id}` returns the rule body with `Content-Type` matching the rule type. Manifests are HMAC-signed using the agent's shared secret (header `X-Shaferhund-Signature`).
  - Acceptance: a unit test seeds 3 rules with `tags=['group:web']` and 2 with `tags=['group:db']`, registers two agents in groups `web` and `db`, and asserts `GET /fleet/manifest` returns 3 rules to `web`-agent and 2 rules to `db`-agent. The HMAC validates against the per-agent secret; tampering with the body fails verification.
- REQ-P0-P6-002: `docker/shaferhund-fleet-agent` is a small standalone container (or systemd unit reference + Python entrypoint) that polls `/fleet/manifest` every `FLEET_POLL_SECONDS` (default 300), downloads any new/updated rules, verifies HMAC + SHA256, atomically replaces the rule files in the local Wazuh agent's `etc/rules/` directory, and triggers a `wazuh-control reload`. Successful and failed pulls are reported back via `POST /fleet/checkin` (last-pulled-version, last-error, last-checkin-at).
  - Acceptance: an integration test (gated by `FLEET_INTEGRATION=1`) spins up a second Wazuh agent container, registers it via `POST /fleet/agents`, advances the manager's rule set, and asserts the second agent's rules directory updates within one poll interval; tamper test (modified rule body in flight) fails verification and increments a poll-error counter visible at `/metrics`.
- REQ-P0-P6-003: Multi-user auth via a `users` table (`id, username UNIQUE, password_hash, role, created_at, last_login_at, is_active`) and a `user_tokens` table (`id, user_id, token_hash, name, created_at, expires_at, revoked_at`). `POST /auth/login` (public) accepts `{username, password}`, verifies via Argon2id, and issues a per-session bearer token. `POST /auth/tokens` (admin) creates named long-lived tokens for service accounts (e.g. fleet agents). `_require_auth` resolves either the legacy `SHAFERHUND_TOKEN` (mapped to a synthetic `admin` user when set) or a row in `user_tokens` whose hash matches the presented bearer.
  - Acceptance: a unit test registers `alice` (operator) and `bob` (viewer); `alice`'s token can `POST /rules/{id}/deploy` (operator role) and gets 200; `bob`'s token gets 403; an unknown token gets 401; `SHAFERHUND_TOKEN` set in env continues to work as today.
- REQ-P0-P6-004: New `_require_role(role)` FastAPI dependency. Every existing auth-gated route gains an explicit role tag at registration time. Default role for unannotated routes is `operator`. Admin-only routes: `POST /auth/users`, `DELETE /auth/users/{id}`, `POST /auth/tokens`, `POST /fleet/agents`, `DELETE /fleet/agents/{id}`. Viewer role can hit read-only routes (`GET /health`, `GET /` dashboard, `GET /cloud/findings`, `GET /redteam/recommendations`, `GET /metrics`) but not write/exec routes.
  - Acceptance: the existing 16 auth-gated routes each have a documented role; a route-RBAC table test enumerates all routes and asserts viewer/operator/admin tokens get 200/403 as expected; the test fails loudly if a new route is added without a role tag (enforced via a registry probe).
- REQ-P0-P6-005: New `audit_log` table (`id, ts, actor_user_id, actor_token_id, route, method, request_summary, status_code, prev_hmac, row_hmac`). A FastAPI middleware records every non-GET request (and every GET hitting an admin-only route) after the response is generated. `row_hmac = HMAC-SHA256(SHAFERHUND_AUDIT_KEY, prev_hmac || canonical(row_minus_hmac))`. `GET /audit` (admin) returns paginated history. `GET /audit/verify` re-computes the chain and returns `{ok: bool, broken_at: id|null}`.
  - Acceptance: a unit test issues 5 deploy_rule calls, verifies 5 audit rows, manually corrupts row 3's `request_summary`, and asserts `/audit/verify` returns `{ok: false, broken_at: 3}`. A second test asserts deletion of any audit row also breaks the chain (rows are append-only; there is no `DELETE /audit/{id}` route).
- REQ-P0-P6-006: `SHAFERHUND_AUTH_MODE` env var (default `single`, alternate `multi`). In `single` mode, the existing single-token path is unchanged and the multi-user routes return 503 with a setup hint. In `multi` mode, `POST /auth/login` is enabled and an admin user is bootstrapped from `SHAFERHUND_BOOTSTRAP_ADMIN_USERNAME` + `SHAFERHUND_BOOTSTRAP_ADMIN_PASSWORD` on first start (idempotent). `SHAFERHUND_TOKEN` continues to grant admin-equivalent access in both modes for backwards compatibility — a one-line operator note in `docs/PHASE6_OPERATOR_GUIDE.md` documents the phase-out path.
  - Acceptance: a deployment test boots the agent twice — once in `single` mode (existing behaviour, no schema additions visible in `/health`), once in `multi` mode (login route enabled, bootstrap admin created). Toggling the mode env var without changing the database is non-destructive.
- REQ-P0-P6-007: All Phase 1–5 tests pass unchanged. ≥1 new unit test per P0 capability above. The Phase 5 9-tool transcript test continues to pass; orchestrator behaviour is unchanged in Phase 6 (no new tools).

**Nice-to-Have (P1):**

- REQ-P1-P6-001: `/auth/users` HTML dashboard — admin-only operator list with role pills and last-login. HTMX, no SPA.
- REQ-P1-P6-002: `/fleet/agents` HTML dashboard — admin-only fleet view: agent name, group(s), last check-in, last-pulled rule version, error state.
- REQ-P1-P6-003: Rule tag editor on the existing rule deploy flow — when an operator deploys a rule, a tag field lets them pick `group:*` tags from a known list, persisting to a new `rule_tags` table.
- REQ-P1-P6-004: `lookup_cloud_identity` (Phase 5 tool) augmented to surface the Shaferhund operator who triaged a related on-prem alert, so cross-correlation includes the human chain — read-only join on `audit_log.actor_user_id`.
- REQ-P1-P6-005: `/health` adds `auth.mode` (`single|multi`), `auth.user_count`, `fleet.agent_count`, `fleet.last_checkin_at`. `/metrics` adds per-role request counts.

**Future Consideration (P2):**

- REQ-P2-P6-001: OIDC / SAML SSO integration — Phase 7+. Local password auth is the foundation.
- REQ-P2-P6-002: Real cryptographic signing of fleet rule packages (cosign / minisign) — Phase 7+. HMAC is the operational baseline.
- REQ-P2-P6-003: Per-tenant data scoping (multi-account AWS audit logs, per-team posture) — Phase 7. Auth/RBAC is the precondition.
- REQ-P2-P6-004: Multi-cloud (GCP Audit, Azure Monitor) using Phase 5 source-pipeline pattern + Phase 6 per-provider RBAC — Phase 7.
- REQ-P2-P6-005: WebAuthn / hardware token second factor for admin operations — Phase 7+.

### Architecture

```
[Phase 1–5 surface, unchanged: 5 services, 9 orchestrator tools, /health 6 keys]
                                          |
                          ┌───────────────┴───────────────┐
                          |                               |
                          v                               v
              [NEW: Auth & RBAC layer]           [NEW: Fleet distribution]
              agent/auth.py                      agent/fleet.py
              ┌────────────────────┐             ┌────────────────────────┐
              | users table        |             | rules + rule_tags      |
              | user_tokens table  |             | fleet_agents table     |
              | _require_auth (V2) |             | fleet_checkins table   |
              | _require_role(r)   |             | per-agent shared secret|
              | Argon2id hashing   |             | HMAC-signed manifests  |
              | bootstrap admin    |             | scoped by group tag    |
              └─────────┬──────────┘             └────────────┬───────────┘
                        |                                     |
                        v                                     v
              ┌───────────────────────────────────────────────────────────┐
              |              audit_log middleware                          |
              |   POST/PUT/DELETE + admin GETs → append-only HMAC chain    |
              |   prev_hmac chained → tamper-evident                       |
              |   GET /audit, GET /audit/verify                            |
              └─────────────────────────────────┬─────────────────────────┘
                                                |
                          ┌─────────────────────┴─────────────────────┐
                          v                                           v
              [Existing 16 auth-gated routes]               [NEW remote agent path]
              now with role tags:                            (docker/shaferhund-fleet-agent)
              GET /health        viewer                      every FLEET_POLL_SECONDS:
              GET /metrics       viewer                       1. POST /fleet/checkin
              POST /rules/.../deploy   operator               2. GET /fleet/manifest (HMAC)
              POST /redteam/exec       operator               3. for each new/changed rule:
              POST /cloud/findings/{id}/ack  operator              GET /fleet/rule/{id}
              POST /auth/users           admin                     verify SHA256 + HMAC
              POST /fleet/agents         admin                     atomic write to rules dir
              POST /audit                admin                4. wazuh-control reload
              ...                                             5. report success/error
                                                |
                                                v
              [Existing /health adds auth.* + fleet.* keys; existing /metrics adds per-role + fleet counters]
```

### Stack Delta vs Phase 5

- **No new prod containers.** The fleet **server** lives inside the existing `shaferhund-agent` (new module `agent/fleet.py`, new lifespan task for cleaning up stale `fleet_checkins`). The fleet **client** is a new container image (`docker/shaferhund-fleet-agent`, distinct from the Wazuh-manager-side `shaferhund-agent`) that operators run alongside their remote Wazuh agents — but it does not run in our `compose.yaml`, which stays at 5 services.
- **New Python libraries:** `argon2-cffi` (password hashing — industry standard, fast on solo-dev hardware), `python-multipart` (form login handling). No new system packages on the manager side.
- **New env vars (manager):** `SHAFERHUND_AUTH_MODE` (default `single`), `SHAFERHUND_BOOTSTRAP_ADMIN_USERNAME`, `SHAFERHUND_BOOTSTRAP_ADMIN_PASSWORD` (read once at first boot, then ignored — store in `.env`, not committed), `SHAFERHUND_AUDIT_KEY` (32-byte hex, used to seed the audit-log HMAC chain; rotation is a manual operator process documented in `PHASE6_OPERATOR_GUIDE.md`), `FLEET_POLL_INTERVAL_DEFAULT` (default 300, what new agents inherit).
- **New env vars (fleet client):** `SHAFERHUND_MANAGER_URL`, `SHAFERHUND_AGENT_ID`, `SHAFERHUND_AGENT_SECRET`, `FLEET_POLL_SECONDS` (override of manager default), `WAZUH_RULES_DIR` (default `/var/ossec/etc/rules`).
- **New tables (manager-side, idempotent ALTER per DEC-SCHEMA-002):** `users`, `user_tokens`, `audit_log`, `fleet_agents`, `fleet_checkins`, `rule_tags`. Six new tables; all created via `init_db()` extension; all primary-keyed on `id INTEGER PRIMARY KEY AUTOINCREMENT`.

### Eng Review Decisions

1. **Pair fleet with auth, don't ship them separately.** Splitting them yields the wrong shape: fleet without auth requires a bolted-on identity model later; auth without fleet has no concrete operational requirements and risks over-engineering. The archive's REQ-NOGO-P5-002 + REQ-NOGO-P5-003 are explicitly paired ("pairs better with auth/RBAC tightening"). Phase 6 honours that pairing.
2. **Argon2id over bcrypt.** Argon2id is the OWASP-current recommendation (2024+), is constant-time, and offers tunable memory cost — fine for a solo-dev manager that authenticates a handful of operators per day. Bcrypt would also work; the deciding factor is that `argon2-cffi` is a single drop-in dep with no system requirements, while bcrypt occasionally has wheel issues on Alpine images. We chose simplicity of the Phase 6 ship.
3. **HMAC over digital signatures for the fleet protocol.** Cosign / minisign / GPG would offer non-repudiation and a public-key trust chain; HMAC offers integrity + authenticity given a pre-shared secret, which is the actually-relevant property for a manager-pulls-by-known-agent-secret model. Real cryptographic signing is REQ-NOGO-P6-007 / REQ-P2-P6-002 — a worthwhile follow-up once the contract is operational, but not a blocker.
4. **Append-only audit log with chained HMAC, not a separate signing service.** The HMAC chain (`row_hmac = HMAC(prev_hmac || canonical_row)`) gives tamper evidence without requiring an external signer. Same in-DB-state-with-cryptographic-integrity shape as Phase 4's `slo_breaches`. Operators can verify the chain with one route call (`GET /audit/verify`); the moment a row is mutated or deleted, the chain breaks at exactly that ID.
5. **`SHAFERHUND_TOKEN` survives as an admin-equivalent fallback.** The archive's working philosophy ("fail-closed on new behaviour, default-on for existing behaviour") demands backwards compatibility. Forcing operators to migrate their `.env` immediately would break every Phase 1–5 deployment. Instead: legacy token still works (mapped to a synthetic `admin` user), `SHAFERHUND_AUTH_MODE=multi` enables the new flows, the operator guide documents a deliberate phase-out timeline.
6. **`_require_role(role)` decorator pattern, not custom per-route logic.** The existing `_require_auth` is a FastAPI `Depends(...)` dep; `_require_role(r)` becomes a parameterised dep that *includes* `_require_auth` and additionally checks the resolved user's role. Keeps the route-decoration shape identical to today; no per-handler `if user.role != 'admin': raise 403` boilerplate. Same shape as Phase 4's tool-registration centralisation (DEC-ORCH-006).
7. **Role enum is a code-resident frozenset; users are config in DB.** Same reasoning as DEC-RECOMMEND-002 / DEC-CLOUD-009: the *set* of roles (`viewer`, `operator`, `admin`) is reviewed at code-review time. The *list* of users (Alice, Bob, the fleet agent for the New York office) is operational config. New roles via PR; new users via `POST /auth/users`.
8. **Fleet agent is a separate container image, not a `compose.yaml` service.** The Phase 6 fleet client runs on the **remote** host alongside the operator's remote Wazuh agent — by definition it is not in our local compose. Shipping a `docker/shaferhund-fleet-agent` Dockerfile + `docs/PHASE6_FLEET_AGENT_GUIDE.md` is enough; we don't add it to `compose.yaml` because the local manager-side test environment doesn't need a fleet client (the manager has its rules directly).
9. **Rule scoping by `group:*` tags, not per-rule ACLs.** Tagging is coarse, operator-friendly, and matches how the field actually thinks about deployments ("the web tier", "the db tier"). Per-rule ACLs are over-engineered for <100 endpoints. Scaling to per-rule scoping is a Phase 7+ refinement only if the operational signal demands it.
10. **HMAC-signed manifests over TLS-only trust.** Even with TLS, an MITM at the proxy boundary or a compromised manager-side credential could serve tampered manifests. HMAC over the manifest body provides defense-in-depth: the fleet agent verifies the body cryptographically against the per-agent secret, so a tampered manifest fails even if TLS is compromised. The cost is one HMAC computation per manifest fetch — negligible.
11. **LiveStack-style integration test for the fleet pull (`FLEET_INTEGRATION=1` env gate).** Per the standing rule from `DEC-SLO-004` + `DEC-CLOUD-013`: every new external-integration code path needs a real-environment test, gated so CI stays green when the env isn't there. The fleet integration test boots a second Wazuh agent container locally (or uses the existing `redteam-target` image with a Wazuh agent installed) and exercises the full pull → verify → reload cycle. Mocked-only testing has burned us twice already.
12. **No new orchestrator tools in Phase 6.** Phase 6 is operational maturity, not feature surface. Adding tools (`audit_search`, `lookup_user`, etc.) is tempting but adds review burden for the agent's tool-call payload size. Operators query audit logs and users via routes; Claude does not need direct DB access to either. The 9-tool count from Phase 5 holds.

### Files to Create / Update

```
shaferhund/
  compose.yaml                          # (UPDATE) document new SHAFERHUND_AUTH_MODE / SHAFERHUND_AUDIT_KEY env vars
                                        #          in the agent service block; no new services
  requirements.txt                      # (UPDATE) add argon2-cffi, python-multipart
  .env.example                          # (UPDATE) document Phase 6 env vars + bootstrap admin guidance
  docs/
    PHASE6_OPERATOR_GUIDE.md            # (NEW) auth migration single→multi, audit log verification,
                                        #       audit key rotation, fleet agent registration
    PHASE6_FLEET_AGENT_GUIDE.md         # (NEW) fleet agent install (docker run / systemd unit),
                                        #       per-agent secret provisioning, troubleshooting
    fleet-protocol.md                   # (NEW) wire-format spec for /fleet/manifest, /fleet/rule/{id},
                                        #       /fleet/checkin: HMAC scheme, retry semantics, error codes
  docker/
    Dockerfile.fleet-agent              # (NEW) standalone fleet client container
    fleet_agent_entrypoint.py           # (NEW) poll loop, HMAC verify, atomic rule write, wazuh-control reload
  agent/
    auth.py                             # (NEW) Argon2id hashing, user CRUD, token CRUD, _require_role,
                                        #       SHAFERHUND_TOKEN legacy mapping, multi-vs-single mode resolver
    audit.py                            # (NEW) audit_log middleware + chain HMAC + /audit/verify
    fleet.py                            # (NEW) manifest builder, manifest signing, agent registration,
                                        #       checkin handler, rule_tags helpers
    main.py                             # (UPDATE) tag every existing auth-gated route with _require_role(...);
                                        #          add /auth/login, /auth/users, /auth/tokens routes;
                                        #          add /fleet/manifest, /fleet/rule/{id}, /fleet/checkin,
                                        #          /fleet/agents routes; add /audit, /audit/verify routes;
                                        #          register audit middleware in lifespan;
                                        #          add auth.* + fleet.* blocks to /health
    models.py                           # (UPDATE) users, user_tokens, audit_log, fleet_agents,
                                        #          fleet_checkins, rule_tags tables + CRUD helpers (DEC-SCHEMA-002)
    config.py                           # (UPDATE) Phase 6 env fields + role enum + auth mode resolver
    templates/
      login.html                        # (NEW) operator login page (P0 — needed for multi mode)
      auth_users.html                   # (NEW, P1) admin user list
      fleet_agents.html                 # (NEW, P1) admin fleet list
  tests/
    test_auth_users.py                  # (NEW) Argon2id flow, login, token issue/revoke, mode toggle
    test_auth_rbac.py                   # (NEW) per-route role matrix; SHAFERHUND_TOKEN compat;
                                        #       missing-role-tag-on-new-route assertion
    test_audit_log.py                   # (NEW) chain integrity, /audit/verify pass + tamper detection
    test_fleet_manifest.py              # (NEW) tag-scoped manifest, HMAC sign/verify, expired-secret reject
    test_fleet_protocol.py              # (NEW) checkin idempotency, agent register/unregister, role gate
    test_phase6_zero_regression.py      # (NEW) all Phase 1–5 9-tool transcripts + 6-block /health pass
                                        #       under SHAFERHUND_AUTH_MODE=single AND multi
    integration/
      test_fleet_pull_localagent.py     # (NEW) real fleet agent container exercising pull-verify-reload
                                        #       (FLEET_INTEGRATION=1 gated)
    fixtures/
      sample_rule_yara.yar              # (NEW) golden rule for fleet manifest test
      sample_rule_sigma.yml             # (NEW) golden rule for fleet manifest test
```

### Success Criteria

- `podman compose up` with default env (no Phase 6 vars) brings up the existing 5-service stack unchanged; all Phase 1–5 routes return 200 for the legacy `SHAFERHUND_TOKEN`; `/health` shows `auth.mode='single'` and `fleet.agent_count=0`.
- Re-launching with `SHAFERHUND_AUTH_MODE=multi` + bootstrap admin env vars enables `POST /auth/login`; the bootstrap admin is created idempotently; subsequent restarts do not duplicate the user.
- A second locally-deployed Wazuh agent registers via `POST /fleet/agents`, polls `/fleet/manifest`, downloads its scoped rules, verifies HMAC + SHA256, applies them, and reports back via `POST /fleet/checkin`. End-to-end timing: rule deploy on manager → applied on remote agent in ≤ 1 × `FLEET_POLL_SECONDS`.
- `GET /audit/verify` returns `{ok: true, broken_at: null}` after a clean operational session; deliberately corrupting one row breaks the chain at exactly that ID.
- Issuing a viewer token to `bob` and an operator token to `alice`: alice can `POST /rules/{id}/deploy` (200), bob cannot (403); both can `GET /` (dashboard, 200); neither can `POST /auth/users` (admin-only, 403).
- All Phase 1–5 tests pass unchanged. Test count grows from 308 to ~340 (≥1 new test per P0; ~30 new tests across the six P0 capabilities).
- The Phase 5 9-tool transcript test continues to pass; `_REGISTRY` count is exactly 9 (no orchestrator-tool growth in Phase 6).

### GitHub Issues

| Wave | Parallel? | Issue | Title | Depends |
|------|-----------|-------|-------|---------|
| **A** | yes | #68 | Phase 6 Wave A1: users + user_tokens schema + Argon2id auth (REQ-P0-P6-003) | — |
| **A** | yes | #69 | Phase 6 Wave A2: `_require_role(role)` dependency + per-route role tags (REQ-P0-P6-004) | — |
| **A** | yes | #70 | Phase 6 Wave A3: audit_log middleware + chained HMAC + `/audit` + `/audit/verify` (REQ-P0-P6-005) | — |
| **A** | yes | #71 | Phase 6 Wave A4: rule_tags table + scoped manifest builder + HMAC manifest signing (REQ-P0-P6-001) | — |
| **B** | gated on A | #72 | Phase 6 Wave B1: `SHAFERHUND_AUTH_MODE` resolver + bootstrap admin + multi/single mode toggle (REQ-P0-P6-006) | #68, #69 |
| **B** | gated on A | #73 | Phase 6 Wave B2: fleet agent container + entrypoint + integration test (REQ-P0-P6-002) | #71 |
| **B** | gated on A | #74 | Phase 6 Wave B3: Phase 6 observability — `/health` auth.* + fleet.* blocks; `/metrics` per-role counters (REQ-P1-P6-005 partial — P0 health exposure) | #68, #71, #73 |
| **C** | regression gate | #75 | Phase 6 Wave C: zero-regression gate — all Phase 1–5 tests pass; 9-tool transcript + 6-block `/health` hold under both auth modes (REQ-P0-P6-007) | #68–74 |
| **D** | P1 polish | #76 | Phase 6 Wave D1: P1 dashboards (`/auth/users`, `/fleet/agents`, rule tag editor) (REQ-P1-P6-001 / 002 / 003) | #75 |
| **D** | P1 polish | #77 | Phase 6 Wave D2: `lookup_cloud_identity` operator-chain join (REQ-P1-P6-004) | #75 |

Wave A is fully parallel — four independent worktrees (auth schema, RBAC dep, audit middleware, fleet manifest server). Wave B gates on A: B1 needs the auth schema in place; B2 needs the manifest server; B3 needs both. Wave C is the single regression gate. Wave D is P1 polish, all gated on Wave C.

### Decision Log

| Decision | Description | Status |
|----------|-------------|--------|
| DEC-AUTH-P6-001 | Argon2id over bcrypt for password hashing; `argon2-cffi` is a single drop-in dep with no system reqs | planned |
| DEC-AUTH-P6-002 | Role enum (`viewer`, `operator`, `admin`) is a code-resident frozenset; users + tokens are DB config | planned |
| DEC-AUTH-P6-003 | `_require_role(role)` as a parameterised FastAPI Depends; includes `_require_auth` transitively | planned |
| DEC-AUTH-P6-004 | `SHAFERHUND_TOKEN` survives as admin-equivalent legacy fallback; multi mode is opt-in via `SHAFERHUND_AUTH_MODE=multi`; documented phase-out path | planned |
| DEC-AUTH-P6-005 | Bootstrap admin reads `SHAFERHUND_BOOTSTRAP_ADMIN_*` once at first boot; idempotent; vars ignored after the row exists | planned |
| DEC-AUDIT-P6-001 | Append-only `audit_log` table with chained HMAC (`row_hmac = HMAC(prev_hmac \|\| canonical_row)`); `GET /audit/verify` exposes chain integrity | planned |
| DEC-AUDIT-P6-002 | Audit middleware records non-GET requests + admin-only GETs; readonly viewer/operator GETs are not audited (signal-to-noise) | planned |
| DEC-AUDIT-P6-003 | `SHAFERHUND_AUDIT_KEY` is an env var, rotation is operator-driven (documented), no automatic rotation in Phase 6 | planned |
| DEC-FLEET-P6-001 | HMAC-signed manifests over per-agent shared secret; real cryptographic signing (cosign/minisign) is REQ-P2-P6-002 | planned |
| DEC-FLEET-P6-002 | Rule scoping via `group:*` tags on rules + per-agent group memberships; per-rule ACLs out of scope | planned |
| DEC-FLEET-P6-003 | Fleet agent is a separate Docker image (`docker/shaferhund-fleet-agent`), not in `compose.yaml`; runs alongside remote Wazuh agent | planned |
| DEC-FLEET-P6-004 | Cursor / state held in DB (`fleet_agents`, `fleet_checkins`, `cloudtrail_progress`-style); same shape as DEC-CLOUD-011 | planned |
| DEC-FLEET-P6-005 | LocalStack-style integration test gated by `FLEET_INTEGRATION=1` env; honours DEC-CLOUD-013 standing rule | planned |
| DEC-ORCH-P6-001 | No new orchestrator tools in Phase 6; tool count stays at 9; auth/audit/fleet are operator-facing routes, not Claude-facing tools | planned |
| DEC-SCHEMA-P6-001 | Six new tables (`users`, `user_tokens`, `audit_log`, `fleet_agents`, `fleet_checkins`, `rule_tags`) — all idempotent ALTER per DEC-SCHEMA-002 | planned |
| DEC-COMPAT-P6-001 | `single` mode is default; existing deployments are byte-identical at `/health` until they opt into `multi` mode | planned |

---

## TODOs

- [ ] Phase 7+ scoping (carry-forward from Phase 5 archive + Phase 6 NOGOs):
      multi-cloud GCP Audit + Azure Monitor (REQ-NOGO-P6-001 / REQ-NOGO-P5-001 / REQ-P2-P5-001 / REQ-P2-P5-002 carry-forward, same source-pipeline pattern as Phase 5 + per-provider Phase 6 RBAC scoping);
      multi-tenant posture / per-team scores (REQ-NOGO-P6-002 / REQ-NOGO-P5-006 / REQ-NOGO-P3-007 carry-forward, gated on stable Phase 6 RBAC);
      STIX/TAXII threat-intel federation (REQ-NOGO-P6-003 / REQ-NOGO-P5-004 / REQ-P2-P3-003 carry-forward);
      containerised service honeypots SSH/MySQL/Redis (REQ-NOGO-P6-004 / REQ-NOGO-P5-005 / REQ-P2-P3-002 carry-forward);
      adversarial cloud-technique scoring T1078.004/T1098.x (REQ-NOGO-P6-005 / REQ-NOGO-P5-010 carry-forward);
      OIDC / SAML SSO (REQ-NOGO-P6-006 / REQ-P2-P6-001);
      cosign / minisign real cryptographic fleet signing (REQ-NOGO-P6-007 / REQ-P2-P6-002);
      Windows / macOS redteam target (REQ-NOGO-P6-008);
      CloudTrail Lake / Athena query backend (REQ-NOGO-P6-009 / REQ-NOGO-P5-007 / REQ-P2-P5-004 carry-forward);
      real-time CloudTrail via EventBridge / SQS (REQ-NOGO-P5-008 / REQ-P2-P5-003 carry-forward);
      multi-account / Organization Trail (REQ-P2-P5-006 carry-forward);
      cloud-native rule deploy to GuardDuty / Security Hub (REQ-NOGO-P6-010 / REQ-NOGO-P5-009 / REQ-P2-P5-005 carry-forward);
      WebAuthn / hardware second factor (REQ-P2-P6-005).
- [ ] Convert `hund` repo to ROADMAP.md form once Phase 6 lands — long-standing carry-forward from Phase 4 boundary precedent; recommend close after Phase 6 because the architecture is no longer in flux.
- [ ] CONFIG-level harness todos surviving from Phase 5: backlog #2 (rule-test fixtures harness), backlog #4 (Wazuh integration test harness), backlog #6 (CI matrix for source pipelines). Backlog #5 was closed by DEC-CLOUD-013 in Phase 5.
