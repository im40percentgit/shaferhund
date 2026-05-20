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

**Status:** completed
**Timebox:** 3–4 weeks
**Landed:** 2026-04-25 across PRs #79, #80, #81, #82, #83, #84, #85 (all squash-merged from `feature/phase6-*` branches; final commit `018486f`)
**Verified:** 2026-04-25 via Phase 6 zero-regression gate (issue #76): 594 passed / 1 skipped / 6 deselected / 0 failed; `/health` integrates all 9 blocks (status, poller_healthy + 7 nested keys: threat_intel, canary, posture-with-4-sub-keys, recommendations, cloudtrail, auth, fleet); DB migration Phase 5 → Phase 6 idempotent (adds `users`, `user_tokens`, `audit_log`, `rule_tags` tables); TOOLS=9; compose stable (5 services in `compose.yaml` + 2 opt-in compose files: `compose.localstack.yaml` from #58, `compose.fleet.yaml` from #74); 4 critical safety properties verified end-to-end (audit chain tamper detection, fleet manifest signature verification, no `password_hash`/`token_hash` in API responses, closed-default on unknown roles); backwards compat preserved (legacy `SHAFERHUND_TOKEN` works on every Phase 1–5 route AND every Phase 6 admin route via synthetic admin).

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
| DEC-AUTH-P6-001 | Argon2id over bcrypt for password hashing; `argon2-cffi` is a single drop-in dep with no system reqs | accepted |
| DEC-AUTH-P6-002 | Role enum (`viewer`, `operator`, `admin`) is a code-resident frozenset; users + tokens are DB config | accepted |
| DEC-AUTH-P6-003 | `_require_role(role)` as a parameterised FastAPI Depends; includes `_require_auth` transitively | accepted |
| DEC-AUTH-P6-004 | `SHAFERHUND_TOKEN` survives as admin-equivalent legacy fallback; multi mode is opt-in via `SHAFERHUND_AUTH_MODE=multi`; documented phase-out path | accepted |
| DEC-AUTH-P6-005 | Bootstrap admin reads `SHAFERHUND_BOOTSTRAP_ADMIN_*` once at first boot; idempotent; vars ignored after the row exists | accepted |
| DEC-AUTH-P6-006 | **(new — Wave A2 #80)** `_require_role(role)` factory raises `ValueError` at import time for unknown role names so typos surface at boot, not at first request; 401 always precedes 403 because the inner dep is `_require_auth`; codifies the runtime-shape promise of DEC-AUTH-P6-003 | accepted |
| DEC-AUTH-P6-007 | **(new — Wave B1 #83)** Bootstrap admin runs once at startup when users table is empty + `SHAFERHUND_AUTH_MODE=multi` + bootstrap env set; idempotent and unconditionally skipped if any user exists; plaintext password lives only in env/memory at startup, only the Argon2id hash persists | accepted |
| DEC-AUTH-P6-008 | **(new — Wave B1 #83)** Admin-only user/token CRUD surface; `POST /auth/login` is the sole public auth entry; password and token hashes are NEVER serialised into responses (enforced by explicit field projection in every handler); operators/viewers may only change their own password | accepted |
| DEC-AUDIT-P6-001 | Append-only `audit_log` table with chained HMAC (`row_hmac = HMAC(prev_hmac \|\| canonical_row)`); `GET /audit/verify` exposes chain integrity | accepted |
| DEC-AUDIT-P6-002 | Audit middleware records non-GET requests + admin-only GETs; readonly viewer/operator GETs are not audited (signal-to-noise) | accepted |
| DEC-AUDIT-P6-003 | `SHAFERHUND_AUDIT_KEY` is an env var, rotation is operator-driven (documented), no automatic rotation in Phase 6 | accepted |
| DEC-FLEET-P6-001 | HMAC-signed manifests over per-agent shared secret; real cryptographic signing (cosign/minisign) is REQ-P2-P6-002 | accepted |
| DEC-FLEET-P6-002 | Rule scoping via `group:*` tags on rules + per-agent group memberships; per-rule ACLs out of scope | accepted |
| DEC-FLEET-P6-003 | Fleet agent is a separate Docker image (`docker/shaferhund-fleet-agent`), not in `compose.yaml`; runs alongside remote Wazuh agent | accepted |
| DEC-FLEET-P6-004 | Cursor / state held in DB (`fleet_agents`, `fleet_checkins`, `cloudtrail_progress`-style); same shape as DEC-CLOUD-011 | accepted |
| DEC-FLEET-P6-005 | LocalStack-style integration test gated by `FLEET_INTEGRATION=1` env; honours DEC-CLOUD-013 standing rule | accepted |
| DEC-ORCH-P6-001 | No new orchestrator tools in Phase 6; tool count stays at 9; auth/audit/fleet are operator-facing routes, not Claude-facing tools | accepted |
| DEC-SCHEMA-P6-001 | Six new tables (`users`, `user_tokens`, `audit_log`, `fleet_agents`, `fleet_checkins`, `rule_tags`) — all idempotent ALTER per DEC-SCHEMA-002 | accepted |
| DEC-COMPAT-P6-001 | `single` mode is default; existing deployments are byte-identical at `/health` until they opt into `multi` mode | accepted |
| DEC-OBSERVABILITY-P6-001 | **(new — Wave B3 #85)** `audit_log` is the source-of-truth for fleet manifest-fetch counters (rejecting an in-memory `FLEET_STATS` dict that resets on restart and duplicates state); block builders extracted into `agent/observability.py` to keep `agent/main.py` under ~2k lines; `/health` keeps minimal counters + one timestamp per DEC-HEALTH-002, rich per-role/per-token stats live on auth-gated `/metrics` | accepted |

---

## Phase 7: Multi-Cloud + Adversarial Cloud-Technique Scoring (3–4 weeks)

**Status:** planned
**Timebox:** 3–4 weeks
**Entry checklist:** PR #87 (`chore/security-hardening-htmx-cve-sigmac3`) merged so `main` is on sigma-cli 3.x with the honest probe; issue #77 (Wave D dashboards) folded into Wave A4 below; issue #78 (`lookup_cloud_identity` operator-chain join) recommend-closed (see DEC-PHASE7-009).

### Intent

Phase 5 delivered "Cloud Eyes" against **AWS** CloudTrail with a deterministic detector, a `lookup_cloud_identity` orchestrator tool, and a single-provider observability surface. Phase 6 unlocked the per-identity scoping needed to safely run multi-provider signals through the same manager. Phase 7 closes the cloud arc by:

1. Extending the Phase 5 source-pipeline pattern to **two more providers** — GCP Cloud Audit Logs and Azure Monitor / Activity Logs — each delivered as its own minimal source (sink-shape-compatible with `agent/sources/cloudtrail.py`), each scoped via Phase 6's per-agent RBAC + tag model so an operator with only AWS access can never accidentally see GCP findings.
2. Pairing it with the adversarial half: a real **cloud-technique scoring loop** (T1078.004 *Valid Accounts: Cloud Accounts*, T1098.x *Account Manipulation* family) that exercises the existing `/redteam/exec` harness against per-provider deterministic-detector rules, scores how often each detector fires on a known-bad event sequence, and feeds the result into the existing posture stack.

These pair the same way Phase 6's fleet + auth paired: multi-cloud creates the **surface** that adversarial scoring needs (you cannot meaningfully score cloud-technique coverage against a single provider — that's an AWS-detector test, not a coverage measurement), and adversarial scoring is the **concrete operational requirement** that makes the multi-cloud surface earn its weight (without it, "we ingest GCP audit logs too" is just more pipes). Building either alone reproduces the wrong-shape trap: multi-cloud without adversarial scoring becomes more taps with no signal-quality feedback; adversarial scoring without multi-cloud becomes a single-vendor benchmark.

Phase 7 explicitly does NOT touch multi-tenant (Phase 6 RBAC has not yet completed one operational cycle — same gating reason as DEC-COMPAT-P6-001 carry-forward), federation, SSO, honeypots, or real cryptographic signing. Those each remain their own real week and are NOGO'd below.

### Stack Delta vs Phase 6

- **No new prod containers in `compose.yaml`.** GCP and Azure sources run inside the existing `shaferhund-agent` lifespan exactly like `agent/sources/cloudtrail.py` does today — new background tasks added in `lifespan`, no new docker services.
- **New Python libraries:** `google-cloud-logging` (GCP Audit Logs subscriber/pull API), `azure-monitor-query` + `azure-identity` (Azure Activity Logs query API). No new system packages.
- **New env vars (manager):** `SHAFERHUND_GCP_PROJECT_ID`, `SHAFERHUND_GCP_CREDENTIALS_JSON` (path or inline JSON), `SHAFERHUND_GCP_POLL_INTERVAL` (default 300); `SHAFERHUND_AZURE_TENANT_ID`, `SHAFERHUND_AZURE_SUBSCRIPTION_ID`, `SHAFERHUND_AZURE_CLIENT_ID`, `SHAFERHUND_AZURE_CLIENT_SECRET`, `SHAFERHUND_AZURE_POLL_INTERVAL` (default 300); `SHAFERHUND_CLOUD_SCORE_ENABLED` (default `false` — opt-in for the adversarial scoring loop, fail-safe default per DEC-RECOMMEND-002 pattern).
- **New tables (manager-side, idempotent ALTER per DEC-SCHEMA-002):** `gcp_audit_progress`, `azure_activity_progress` (per-provider cursors, same shape as `cloudtrail_progress` from Phase 5), `cloud_technique_scores` (per-technique × per-provider scoring rows). Three new tables.
- **New routes:** `GET /cloud/findings?provider={aws|gcp|azure}` extension (existing route gains optional `provider` filter), `GET /cloud/score` (latest per-technique score matrix), `POST /cloud/score/run` (operator-only — kick the scoring loop on demand). No new orchestrator tools — same rationale as DEC-ORCH-P6-001.
- **`/health` adds `cloud.providers[]` array** (`{name, healthy, last_poll_at, lag_seconds}`) and `cloud.score.{last_run, technique_count}` keys per DEC-HEALTH-002 (minimal at `/health`, rich at `/metrics`).

### Goals

- **REQ-P0-P7-001:** GCP Cloud Audit Logs source ingests, normalises (matching `parse_cloudtrail_event` shape — `rule_id`, `src_ip`, `severity`, `dest_ip`, `protocol`, `normalized_severity`), and stores under `source='gcp_audit'`; per-project scoping respects the Phase 6 RBAC tag model (DEC-FLEET-P6-002 pattern).
- **REQ-P0-P7-002:** Azure Monitor Activity Logs source ingests + normalises + stores under `source='azure_activity'`; per-subscription scoping via Phase 6 RBAC tags.
- **REQ-P0-P7-003:** Deterministic detector extended to fire across all three providers — at least one shared rule (e.g. `cloud:iam:CreateUser`) maps to AWS/GCP/Azure equivalents in a code-resident allowlist (DEC-RECOMMEND-002 pattern); per-provider findings remain isolated by source.
- **REQ-P0-P7-004:** Restore Sigma → Wazuh runtime conversion (carry-forward from **DEC-DEPS-001**) — vendor or fork `pysigma-backend-wazuh` so `sigma convert -t wazuh` succeeds; `_probe_sigmac` flips `sigmac_available=True`; Sigma auto-deploy resumes.
- **REQ-P0-P7-005:** Adversarial cloud-technique scoring loop — `agent/cloud_score.py` runs T1078.004 + T1098.001 + T1098.002 + T1098.003 scenarios via `agent/redteam_target.py`, executes them against each provider's normalised event store, records `cloud_technique_scores` rows (technique × provider × score × ran_at), surfaces via `GET /cloud/score`.
- **REQ-P0-P7-006:** Wave D #77 dashboards folded in — `/auth/users`, `/fleet/agents`, rule-tag editor (REQ-P1-P6-001 / 002 / 003 carry-forward) with the per-provider filter added to the cluster + cloud-findings views.
- **REQ-P0-P7-007:** Zero-regression gate — all Phase 1–6 tests pass unchanged; `/health` block count grows from 9 to 10 (adds `cloud.providers` + `cloud.score`); orchestrator tool count stays at 9 (Phase 7 is source + scoring, not new agent tools).

### Non-Goals

- **REQ-NOGO-P7-001:** Multi-tenant posture / per-team scores (REQ-NOGO-P6-002 / REQ-NOGO-P5-006 / REQ-NOGO-P3-007 carry-forward) — Phase 6 RBAC has not yet completed one operational cycle; baking multi-tenant in before that cycle reproduces the fused-phase trap Phase 4 and Phase 6 explicitly avoided. Phase 8+ candidate.
- **REQ-NOGO-P7-002:** STIX/TAXII threat-intel federation (REQ-NOGO-P6-003 / REQ-NOGO-P5-004 / REQ-P2-P3-003 carry-forward) — URLhaus single-feed remains operationally sufficient until federation has a real scoping requirement.
- **REQ-NOGO-P7-003:** Containerised service honeypots SSH/MySQL/Redis (REQ-NOGO-P6-004 / REQ-NOGO-P5-005 / REQ-P2-P3-002 carry-forward) — doubles attack surface; needs its own isolation analysis week. Phase 8+ candidate.
- **REQ-NOGO-P7-004:** OIDC / SAML / SSO (REQ-NOGO-P6-006 / REQ-P2-P6-001 carry-forward) — local password auth + per-user bearer tokens shipped in Phase 6 remains the operational baseline; no SSO requirement has surfaced. Phase 8+.
- **REQ-NOGO-P7-005:** Real cryptographic fleet-package signing (cosign / minisign — REQ-NOGO-P6-007 / REQ-P2-P6-002 carry-forward) — HMAC signing remains the operational baseline; revisit after one full fleet operational cycle.
- **REQ-NOGO-P7-006:** Windows / macOS `redteam-target` (REQ-NOGO-P6-008 carry-forward) — licensing + image strategy; Phase 8+.
- **REQ-NOGO-P7-007:** CloudTrail Lake / Athena query backend (REQ-NOGO-P6-009 / REQ-NOGO-P5-007 carry-forward) — capacity not yet exercised; Phase 8+.
- **REQ-NOGO-P7-008:** Real-time CloudTrail via EventBridge / SQS (REQ-NOGO-P5-008 carry-forward) — pulls EventBridge into the architecture; Phase 8+.
- **REQ-NOGO-P7-009:** Multi-account / Organization Trail (REQ-P2-P5-006 carry-forward) — gated on multi-tenant posture.
- **REQ-NOGO-P7-010:** Cloud-native rule deploy to GuardDuty / Security Hub (REQ-NOGO-P6-010 / REQ-NOGO-P5-009 carry-forward) — gated on REQ-P0-P7-004 (Sigma → Wazuh runtime restored first).
- **REQ-NOGO-P7-011:** WebAuthn / hardware second factor (REQ-P2-P6-005 carry-forward) — gated on operational SSO baseline.
- **REQ-NOGO-P7-012:** New orchestrator tools — same rationale as DEC-ORCH-P6-001; multi-cloud and scoring are source + observability, not Claude-facing tool surface. Tool count stays at 9.

### Pair Rationale

Phase 6 succeeded because fleet + auth reinforced each other (per-endpoint identity unblocked rule scoping; rule scoping was the concrete requirement that prevented over-engineering the identity surface). Phase 7 picks the same shape:

- **Multi-cloud creates the surface** adversarial scoring needs. Coverage measurement against one provider tells you about *that detector*, not about cloud-technique coverage. Three providers × shared techniques is the smallest matrix that produces a real coverage signal.
- **Adversarial scoring earns the multi-cloud spend.** Without it, "we ingest GCP audit logs too" is just three taps instead of one. The scoring loop turns the broader surface into a falsifiable claim: *for technique T, on provider P, our detector fires N% of the time we exercise the adversary path.*
- **Both halves use Phase 6 primitives.** GCP + Azure ingest scopes through the Phase 6 RBAC tag model; scoring runs through `_require_role('operator')` + `audit_log` exactly like every other write-side route. No new identity surface needed.

Alternative pairs considered and rejected:

| Pair | Why rejected |
|------|--------------|
| Multi-cloud + real-time CloudTrail | Performance-flavoured; doesn't add coverage signal — same provider × same detector, just faster. |
| Honeypots + adversarial scoring | Doubles attack surface; honeypots need separate isolation analysis and operator-secret-handling work. Phase 8+. |
| OIDC + WebAuthn | Auth-stack maturation; no operational requirement has surfaced; would be paving cowpaths. |
| Multi-tenant + per-team scores | Gated on Phase 6 RBAC operational cycle (DEC-COMPAT-P6-001 reasoning carries forward). |
| Sigma backend restore + GuardDuty/SecurityHub push | Sigma backend restore is a P0 here (REQ-P0-P7-004), but pairing it with GuardDuty/SecurityHub adds AWS-specific work that pulls attention away from the multi-cloud spine. GuardDuty/SecurityHub gates on Sigma restoration → Phase 8+. |

### Wave Structure (preview)

- **Wave A** (parallel, ~5 issues): Sigma → Wazuh backend restoration (REQ-P0-P7-004 — pre-req for Sigma resume); GCP audit source skeleton (REQ-P0-P7-001); Azure activity source skeleton (REQ-P0-P7-002); cross-provider detector mapping (REQ-P0-P7-003); P1 dashboards fold-in (REQ-P0-P7-006).
- **Wave B** (gated on A, ~3 issues): GCP source end-to-end + RBAC scoping; Azure source end-to-end + RBAC scoping; per-provider `/cloud/findings` filter + `/health` `cloud.providers[]` block.
- **Wave C** (gated on B, ~2 issues): adversarial cloud-technique scoring loop (REQ-P0-P7-005); `/cloud/score` + `POST /cloud/score/run`; `cloud_technique_scores` table + history retention.
- **Wave D** (regression gate, 1 issue): zero-regression on all Phase 1–6 tests; 9-tool transcript holds; `/health` grows to 10 blocks (REQ-P0-P7-007).

Wave A is fully parallel: five independent worktrees. Wave B gates on A. Wave C gates on B (needs the multi-provider surface populated). Wave D is the regression gate, same shape as Phase 6 Wave C.

### Decision Log (proposed — flips to `accepted` as PRs land)

| Decision | Description | Status |
|----------|-------------|--------|
| DEC-PHASE7-001 | Pair = multi-cloud (GCP + Azure) + adversarial cloud-technique scoring; rejected alternatives logged in Pair Rationale | planned |
| DEC-PHASE7-002 | GCP + Azure sources sink-shape-compatible with `agent/sources/cloudtrail.py`; same `parse_*_event` normaliser API | planned |
| DEC-PHASE7-003 | Per-provider RBAC scoping via Phase 6 `rule_tags` extended to source-tag scoping (`source:aws`, `source:gcp`, `source:azure`) — no new identity surface | planned |
| DEC-PHASE7-004 | `cloud_technique_scores` table is append-only (history matters for trend); same shape as Phase 4 `slo_breaches`; no soft-delete, no in-place update | planned |
| DEC-PHASE7-005 | Adversarial scoring loop is opt-in via `SHAFERHUND_CLOUD_SCORE_ENABLED=true`; fail-safe default; documented operator-enable path | planned |
| DEC-PHASE7-006 | No new orchestrator tools (count stays at 9); same rationale as DEC-ORCH-P6-001 | planned |
| DEC-PHASE7-007 | Sigma → Wazuh backend restoration in Wave A is **mandatory** — DEC-DEPS-001 (sigma-cli 3.x dropped wazuh plugin) cannot stand for the duration of Phase 7; either upstream restores, we fork, or we vendor | planned |
| DEC-PHASE7-008 | Wave D #77 dashboards (auth/users, fleet/agents, rule-tag editor) **folded in** as REQ-P0-P7-006 — already P1 polish, dashboards are needed regardless once multi-cloud lands so users can filter by provider | planned |
| DEC-PHASE7-009 | Wave D #78 (`lookup_cloud_identity` operator-chain join, REQ-P1-P6-004) **recommend-close** — AWS-specific principal-chain join; multi-cloud architecture supersedes the single-provider chain model; revisit if Phase 8+ multi-tenant work demands it | planned |
| DEC-PHASE7-010 | `hund → ROADMAP.md` carry-forward **recommend-close** — Phase 6 architecture is settled; the `hund` repo's intent is now operationally encoded in this `MASTER_PLAN.md` plus the archived Phase 1–5 plan; further conversion adds no signal | planned |

### Standing Invariants Honoured

- **DEC-HEALTH-002** — `/health` stays minimal (one timestamp + per-provider boolean + scoring summary); rich per-provider lag + per-technique scores live on auth-gated `/metrics`.
- **DEC-SCHEMA-002** — three new tables, all idempotent `ALTER TABLE ... ADD COLUMN ... IF NOT EXISTS` + `CREATE TABLE IF NOT EXISTS`; no migration framework.
- **DEC-ORCH-006/007** — `register_tool()` API unchanged; Phase 7 adds zero new orchestrator tools.
- **DEC-RECOMMEND-002** — code-resident allowlists for the per-provider technique → detector mapping; new mappings via PR review.
- **DEC-CLOUD-013** — live-integration tests for new external paths; GCP + Azure each get a `*_INTEGRATION=1` gated end-to-end test mirroring the LocalStack pattern from Phase 5 / `FLEET_INTEGRATION=1` from Phase 6.
- **DEC-COMPAT-P6-001** — existing deployments are byte-identical at `/health` until they opt into multi-cloud (cloud.providers[] only populated when at least one provider env block is present).

---

## TODOs

- [x] Phase 7 scoping — superseded by the `## Phase 7` section above (pair = multi-cloud + adversarial cloud-technique scoring; 10 P0 requirements + 12 NOGOs enumerated). Carry-forward candidates not selected for Phase 7 remain NOGO until a future phase picks them up.
- [x] Phase 6 Wave D — resolved in DEC-PHASE7-008 (#77 dashboards **folded into Phase 7 as REQ-P0-P7-006**) and DEC-PHASE7-009 (#78 `lookup_cloud_identity` operator-chain join **recommend-close** as superseded by the multi-cloud architecture).
- [x] Convert `hund` repo to ROADMAP.md form — **recommend-close** per DEC-PHASE7-010 (Phase 6 architecture is settled; intent is operationally encoded in this `MASTER_PLAN.md` plus the archived Phase 1–5 plan; further conversion adds no signal).
- [ ] CONFIG-level harness todos surviving from Phase 5: backlog #2 (rule-test fixtures harness), backlog #4 (Wazuh integration test harness), backlog #6 (CI matrix for source pipelines). Backlog #5 was closed by DEC-CLOUD-013 in Phase 5. Phase 6 added no new harness debt — DEC-FLEET-P6-005 honours the standing `*_INTEGRATION=1` gate pattern.
