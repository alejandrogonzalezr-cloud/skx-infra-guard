# SKX Infra Guard — Policy Model

## 1. The Decision Formula

```
COMMAND + TOOL + RESOURCE + ENVIRONMENT + OPERATION + USER + AGENT
  + DATA SENSITIVITY + BLAST RADIUS + RISK + POLICY
  = DECISION ∈ {ALLOW, ASK, BLOCK}
```

No single factor decides alone. The Risk Engine combines all factors into a risk level (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`); the Policy Engine crosses this level with the environment tier and the User Policy / Agent Policy (see `skydropx-architecture.md` §3) to arrive at the final decision. This replaces naive inline checks, providing a unified risk-aware decision matrix.

## 2. Environments (5 Tiers, not 3)

SKX Infra Guard supports 5 distinct environment tiers: `sandbox`, `dev`, `qa`, `staging`, and `production`. Base default matrix (refined per domain in policies-as-code):

| Operation | sandbox | dev | qa | staging | production |
|---|---|---|---|---|---|
| READ | ALLOW | ALLOW | ALLOW | ALLOW | ALLOW |
| CHANGE | ALLOW | ALLOW/ASK | ASK | ASK | ASK |
| DESTRUCTIVE | ASK | ASK | BLOCK | BLOCK | BLOCK |

**Sandbox is not a blank check.** An operation initiated from sandbox that targets a production resource, shared resource, critical IAM policy, production database, credentials, or critical networking is automatically re-evaluated using the *target resource's* tier rather than the origin's sandbox tier. It scales up in risk or is blocked just as if it came from production. This is an explicit rule of the Context Detector (§4.2 of `skydropx-architecture.md`), not a manual exception.

## 3. Policy Design Baseline

The decision matrix spans 5 columns, introducing `sandbox` (the most permissive tier) and `qa` (positioned between `dev` and `staging`, leaning closer to `staging` for DESTRUCTIVE actions). Critical risk cases ("always blocked regardless of environment" such as `terraform destroy`, `kubectl delete`, `git push --force`, `flyway clean`, `liquibase dropAll`, fork bombs, `rm -rf /`) are enforced universally as global rules in `global.yaml` and cannot be relaxed per environment or per project.

## 4. Kubernetes / GKE

| Command | Classification | Default |
|---|---|---|
| `get`, `describe`, `logs`, `top`, `explain` | READ | ALLOW |
| `apply`, `patch`, `scale`, `rollout restart`, `edit` | CHANGE | ASK depending on env |
| `delete namespace`, `delete --all`, `drain`, `replace --force` | DESTRUCTIVE | BLOCK in critical envs |

SKX Infra Guard generalizes Kubernetes verbs to the matrix above, with namespace + cluster included as part of the resource to compute the blast radius (blast radius hierarchy: a single pod < a deployment < a namespace < a cluster).

## 5. Helm

`template`/`diff` → ALLOW. `upgrade`/`rollback` → ASK. `uninstall` → ASK/BLOCK depending on environment, strictly blocked in production.

## 6. GCP (`gcloud`)

Governed granularly per service: `compute`, `container`, `sql`, `logging`, `monitoring`, `iam`, `secrets`, `storage` — each differentiating between READ / CHANGE / DESTRUCTIVE / SECURITY CRITICAL. For instance: `gcloud sql instances describe` → ALLOW, `... patch` → ASK, `... delete` → BLOCK.

## 7. Terraform

`fmt`/`validate`/`plan` → ALLOW. `apply` → ASK. `destroy` → BLOCK (global, non-relaxable). The system implements an automated gate requiring a valid `terraform plan` output prior to allowing `apply`. Furthermore, the Terraform Domain Parser reads the **content** of the plan (checking for resources to be added/modified/destroyed, IAM changes, network, or database modifications) and feeds this into the Risk Engine. A `terraform apply` that plans to delete a production database immediately escalates to CRITICAL risk even if the CLI command is a standard `apply`.

## 8. Databases

Initial engines: PostgreSQL, MySQL, Redis, Cloud SQL, and MongoDB. Extensible later to Elasticsearch, DynamoDB, etc.

Risk taxonomy of SQL operations:

| Command | Risk | Default |
|---|---|---|
| `SELECT`, `EXPLAIN`, `SHOW`, `DESCRIBE` | SAFE | ALLOW |
| `INSERT`, `UPDATE` (with WHERE), `DELETE` (with WHERE), `ALTER` | MEDIUM/HIGH | ASK |
| `DROP`, `TRUNCATE`, `DROP DATABASE`, `DELETE`/`UPDATE` without WHERE | CRITICAL | BLOCK in critical envs |

SKX Infra Guard uses a real SQL parser (`sqlparse`) instead of regular expressions to reliably distinguish `WHERE` clauses, subqueries, joins, and multi-statements. This prevents evasion via case changes, comments (`DR/**/OP TABLE`), or semicolon-chained statements.

## 9. Data Sensitivity

`PUBLIC` / `INTERNAL` / `SENSITIVE` / `PII` / `FINANCIAL` / `CREDENTIAL` / `CRITICAL`. This serves as a key factor in the Risk Engine: a `SELECT metadata` remains LOW even if executed over a large database, whereas a `SELECT * FROM customers` scales up in risk due to the sensitivity tier of the target table, not just the SQL verb. This is driven by a data catalog mapping (table → sensitivity) — see `skydropx-architecture.md` §7.3.

## 10. Redis (Dedicated Domain)

Redis has its own parser (`parsers/redis.py`) and domain adapter (`domains/redis.py`) separate from generic SQL. This avoids parsing errors where SQL rules (like "no WHERE clause equals unrestricted delete") are incorrectly applied to a key-value vocabulary.

* `GET`/`MGET`/`SCAN`/`KEYS`/`HGET`/`SMEMBERS`/etc. → READ → ALLOW.
* `SET`/`HSET`/`EXPIRE`/etc. → CHANGE → ASK depending on environment.
* `DEL`/`HDEL`/`SREM`/etc. → DESTRUCTIVE → ASK in sandbox/dev, BLOCK in qa/staging/production.
* `FLUSHDB`/`FLUSHALL` → BLOCK unconditionally in every environment, enforced via `policies/global.yaml`.

## 11. Secrets (Dedicated Domain)

Extends file read/write protection (which blocks read/write to `.env`, `.aws/credentials`, `.kube/config`, SSH keys, etc.) with a clear distinction between metadata access vs. actual secret value retrieval, applied consistently across domains:

| Source | Metadata (ALLOW) | Real Value (SECURITY_CRITICAL) |
|---|---|---|
| Kubernetes Secrets | `kubectl get secret foo` | `kubectl get secret foo -o yaml/json` |
| GCP Secret Manager | `gcloud secrets describe` | `gcloud secrets versions access` |
| Terraform state | `terraform state list` (address list) | `terraform state show <addr>` (can print cleartext sensitive values) |
| Environment variables | — | `printenv SECRET_NAME`, `env \| grep TOKEN` — domain `domains/secrets.py`, escalates risk dynamically |
| Files | Handled by `file_guard` | Handled by `file_guard` |

## 12. IAM (Cross-Cutting Domain)

IAM changes are treated as high-risk and are blocked unconditionally in production environments via the `touches_iam` factor in the Risk Engine. This is applied consistently across all infrastructure layers:

- **GCP** (`domains/gcloud.py`): `add-iam-policy-binding`, `remove-iam-policy-binding`, `set-iam-policy` operations.
- **AWS** (`domains/aws.py`): `aws iam create-*/delete-*/attach-*/detach-*/put-*/add-*/remove-*/update-*` and `aws sts assume-role` (privilege escalation protection).
- **Kubernetes RBAC** (`domains/kubernetes.py`): Creating, editing, or deleting `Role`, `RoleBinding`, `ClusterRole`, or `ClusterRoleBinding` is treated as a major IAM change with cluster-wide blast radius.

IAM does not have its own binary (it lives inside the syntax of each cloud provider), which is why it is modeled as a cross-cutting risk factor (`touches_iam`) that any domain can trigger, rather than a standalone command prefix.

## 13. Linux / SSH

Enforces the HIGH-severity safety net covering `sudo`/`su`, recursive `chmod`/`chown` over root directories, `systemctl` modifications, and firewall manipulations (`iptables`), integrated directly into the Risk Engine.

## 14. Overrides / Exceptions

SKX Infra Guard provides a structured override capability. Silence or bypasses must be explicitly defined, approved, and fully audited, specifying owner, reason, expiration, and approvals:

```yaml
overrides:
  - rule: k8s.delete.namespace
    environment: staging
    resource: "ns/legacy-migration"
    user: alejandro.gonzalezr@skydropx.com
    reason: "One-off migration approved under incident INC-1234"
    expires_at: "2026-09-20T00:00:00Z"
    approved_by: juanma.maffei@skydropx.com
```

## 15. Fail-Safe

The Policy Engine itself is designed to fail-closed. Any unknown command, unclassifiable domain, unrecognized environment, or invalid policy configuration defaults to a `BLOCK` or `ASK` decision (configurable by severity), never defaulting to a silent `ALLOW`.
