# SKX Infra Guard — Target Architecture

This document maps the complete requirements of Skydropx (41 sections) into concrete system modules. It is not a line-by-line implementation plan — that resides in the phased implementation plan (Section 9). SKX Infra Guard is an in-house Python implementation, developed exclusively for internal use at Skydropx.

---

## 1. Hook Integration Architecture

Integration with Claude Code (stdin JSON → exit 0/2 + blocking JSON, per-tool matchers, registered in `settings.json`) is maintained using optimized wrapper commands that run as life-cycle hooks of the agent.

```
                         CLAUDE CODE
                              |
                    (stdin JSON / exit code)
                              v
                     hook shim (per event)
                              |
                              v
                  ┌───────────────────────────┐
                  │      SKX INFRA GUARD       │
                  │                            │
                  │  Command Normalizer        │  ← unwraps bash -c/eval/pipes/alias
                  │  Context Detector          │  ← environment (5 tiers) + user vs agent
                  │  Domain Parsers            │  ← kubectl/terraform/gcloud/sql/redis/...
                  │  Risk Engine               │  ← factors → level (LOW..CRITICAL)
                  │  Policy Engine             │  ← policies-as-code YAML → decision
                  │  Audit Engine              │  ← structured event logging, always
                  │  Approval Engine           │  ← only if the decision is ASK
                  └─────────────┬──────────────┘
                                v
                    ┌───────────┼───────────┐
                    v           v           v
                  ALLOW        ASK        BLOCK
                                |
                                v
                        Approval Flow
                                |
                                v
                          EXECUTION
```

---

## 2. Unified Rules Engine

Unlike ad-hoc shell script solutions, SKX Infra Guard consolidates all governance logic into a robust shared core written in Python. Each lifecycle hook delegates to this unified policy engine to determine the appropriate risk, safety constraints, and actions based on the global execution context.

---

## 3. User Policy vs. Agent Policy

SKX Infra Guard evaluates two independent policy layers in parallel before querying the Risk Engine:

- **User Policy**: Defines what operations *the human developer* behind the session is authorized to run (their roles, cloud permissions, etc.).
- **Agent Policy**: Defines what operations *the autonomous agent (Claude Code)* is allowed to execute on its own. This acts as a logical security ceiling, ensuring that even if the developer has high administrative permissions (e.g., Owner/Admin in GCP/AWS), the agent cannot run high-risk commands autonomously without peer review or explicit approvals.

The final verdict is the most restrictive intersection of both policies.

---

## 4. Core Modules

### 4.1 Command Normalizer
Recursively unwraps complex console commands prior to classification: `bash -c "..."`, `sh -c`, `eval`, `$(...)`, backticks, `;`/`&&`/`||`/`|`, `xargs`, simple environment variables, and shell aliases. The output is a clean list of "effective commands" that are evaluated individually by the Domain Parsers, preventing evasion via shell command nesting or wrapping.

### 4.2 Context Detector
Unifies and encapsulates environment detection into 5 logical tiers (`sandbox`/`dev`/`qa`/`staging`/`production`), applying a conservative fallback cascade (explicit env override → resource properties → project configuration → safe default). It also resolves the User vs. Agent execution context.

### 4.3 Domain Parsers
Separate pluggable modules for each key infrastructure domain that process the normalized command and return a structured model containing the resource, operation class, and scope:
* **Kubernetes/GKE**: Maps cluster topology, namespaces (prod vs. non-prod), and resource targets.
* **Helm**: Validates chart lifecycle actions (`template`/`diff` → ALLOW; `upgrade`/`rollback`/`uninstall` → ASK or BLOCK based on environment tier).
* **GCP (`gcloud`)**: Parses complex gcloud invocations across compute, container, sql, secrets, storage, kms, and redis/memorystore.
* **AWS**: Audits AWS API commands, S3 actions, and critical IAM/STS privilege-altering calls.
* **Terraform**: Semantically analyzes the content of generated `terraform plan` logs (detecting planned destructions, additions, and modifications of IAM or network configurations) rather than merely verifying command execution.
* **SQL (PostgreSQL/MySQL/Cloud SQL)**: Employs a robust lexical tokenization parser (`sqlparse`) instead of regex string searches.
* **MongoDB**: A dedicated domain adapter for JavaScript shell operations and administrative collection mutations.
* **Redis**: Validates key-value and in-memory datastore commands (blocking `FLUSHALL`/`FLUSHDB` globally).
* **Secrets**: Enforces boundaries between metadata lookups (e.g., describing a secret) and actual cleartext value extraction.
* **IAM**: Monitors and governs access control mutations in GCP, AWS, and Kubernetes RBAC.
* **Linux/SSH**: Evaluates general OS and shell-level safety (privilege escalations, destructive file paths, local inyections).
* **Git**: Oversees repository-level actions, including protected branch push restrictions, force pushes, and hard resets.

### 4.4 Risk Engine
Calculates a unified, cross-domain risk score (LOW/MEDIUM/HIGH/CRITICAL) using pure, isolated risk-evaluation factors: environment tier, operation class (read, change, destructive, security-critical), blast radius, data sensitivity, and privilege requirements.

### 4.5 Policy Engine
Intersects the computed operational risk with declarative, versioned YAML configuration files (`policies/`) to produce the final verdict (`ALLOW`/`ASK`/`BLOCK`) and a human-readable justification.

### 4.6 Audit Engine
Atomically writes detailed execution traces in real-time to a JSONL log file (`audit.jsonl`), utilizing a file-locking mechanism (`flock`) to prevent collisions across multiple active sessions.

### 4.7 Approval Engine
A pluggable backend (CLI-based in the MVP; Slack, GitHub, PagerDuty, or Web Portal in future phases) that verifies the status, TTL, and validity of active approvals for operations requiring an `ASK` confirmation.

---

## 5. Blast Radius and Data Sensitivity

* **Blast Radius**: Computed dynamically based on command parameters (e.g., mutating a single pod vs. an entire namespace, or updating a single row vs. a whole database). It serves as a multiplication factor in the Risk Engine.
* **Data Sensitivity**: Classifies data resources into sensitivity tiers (`PUBLIC`, `INTERNAL`, `SENSITIVE`, `PII`, `FINANCIAL`, `CREDENTIAL`, `CRITICAL`), raising the risk category of bulk reads or unfiltered queries.

---

## 6. Policies as Code

System rules and environment constraints are managed as versioned YAML documents:

```
policies/
├── global.yaml        # Immutable rules applied globally across all environments
├── sandbox.yaml
├── dev.yaml
├── qa.yaml
├── staging.yaml
└── production.yaml
```

---

## 7. Key Engineering Decisions

### 7.1 Language Implementation: Python
Python was chosen to ensure rapid maintenance and extensibility by SRE and DevOps engineering teams. It runs inside a virtual environment (`.venv/`), using reliable and light packages (`PyYAML`, `sqlparse`, `pytest`).

### 7.2 The "ASK" State Flow
Because the agent hook protocol is strictly binary (allow/deny), the "ASK" flow is implemented at the application level. When an operation evaluates to `ASK`, the Policy Engine queries the Approval Engine. If a valid, non-expired approval exists in the local store, it returns `ALLOW`; otherwise, it returns `DENY` along with clear instructions on how the developer can request the approval.

### 7.3 Inter-Environment Security (Sandbox to Production Escalation)
Any action initiated in a lower-tier environment (like Sandbox or Dev) that references a production resource (such as a production namespace `prd-*`, target database host, or GCP project) is automatically reclassified using the target's environment tier, escalating the risk to `CRITICAL` and blocking the action.

---

## 8. Out of Scope for MVP

Cloud Run, advanced DNS manipulation, Artifact Registry security, and automated SRE incident responses are considered out of scope for the MVP. They will be added as pluggable domain parsers in future iterations without requiring structural changes to the core.

---

## 9. Implementation Phases

Development and rollout follow the phased implementation plan (Fases A to R) defined in Skydropx's engineering backlog.
