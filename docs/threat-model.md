# SKX Infra Guard — Threat Model

This document defines the threat model of SKX Infra Guard, analyzing the logical and infrastructure-level attack vectors relevant to autonomous AI agents operating on Skydropx corporate systems.

---

## 1. Mitigated Threat Categories

| # | Threat | Scenario & Impact | Mitigation in SKX Infra Guard |
|---|---|---|---|
| 1 | Prompt Injection | The LLM receives malicious instructions embedded in user prompts to bypass security controls. | Structured validation of input prompts (`user_prompt_guard`) and SSRF protection (`web_guard`). |
| 2 | Command Injection | Injection of destructive system commands inside variables or via command concatenation. | Strict shell-level safety filters (`shell_safety`) reinforced by the mandatory `Command Normalizer`. |
| 3 | Credential Harvesting | The agent attempts to read sensitive local credential files (`.env`, SSH keys, cloud tokens). | Absolute path restrictions on sensitive files (`file_guard`) and active output scanning (`post_audit`). |
| 4 | Data Exfiltration | Unauthorized extraction of customer data or secrets through external network calls. | Network egress controls and query throttling in database domain operations. |
| 5 | Supply Chain Abuse | Execution of untrusted package managers or un-audited third-party installation scripts. | Active blocking of non-supervised interactive command lines and installers. |
| 6 | Privilege Escalation | The agent attempts to run superuser system commands (e.g., `sudo`, `su`) to elevate privilege. | Inconditional blocking of known privilege escalation commands inside the shell safety domain. |
| 7 | Persistence | The agent tries to establish persistent backdoor access (e.g., modifying `~/.ssh/authorized_keys`). | Absolute write protection on SSH configurations, shell startup files, and key stores. |
| 8 | Destructive Operations | Accidental or malicious execution of data-destroying commands (e.g., `terraform destroy`). | Rigorous OperationClass mapping in the Risk Engine and global bans in `policies/global.yaml`. |

---

## 2. Advanced Attack Vectors and Evasion Tactics

### 9. Command Nesting and Evasion (Confirmed Vector)
A common evasion technique is wrapping forbidden console commands inside standard shells (e.g., `bash -c "kubectl delete namespace production"` or creating temporary aliases like `alias k=kubectl; k delete`). If domain parsers only evaluated the raw input string statically, these would bypass regex matches.
* **Mitigación**: Mandatory execution of the **Command Normalizer** at the entry of the evaluation pipeline. The normalizer recursively peels away wrappers like `bash -c`, `sh -c`, `eval`, and `xargs`, expands in-line aliases, and splits chained sequences (`;`, `&&`, `||`) so each effective command is evaluated individually.

### 10. Sandbox-to-Production Environment Escalation
An escalation where a destructive operation is initiated within a permissive Sandbox or Dev tier but targets actual production resources (via flags like `-n namespace-prod` or production-grade database host string parameters).
* **Mitigación**: The Risk Engine evaluates the environment tier of the **target resource** rather than the origin environment. If an access to a production namespace or project is detected from Sandbox, it instantly escalates the risk to `CRITICAL` and blocks the action.

### 11. Agent-over-User Privilege Escalation
Blindly inheriting the full access of the SRE or developer executing the agent. If the human operator holds Owner or Admin access in GCP/AWS, the agent could act autonomously with those extensive powers without any secondary oversight.
* **Mitigación**: Strict separation between **User Policy** and **Agent Policy**. The autonomous agent operates within a logical ceiling that cannot be exceeded even if the developer has higher permissions.

### 12. Silent Data Harvesting of Sensitive Information
Performing unrestricted queries over production databases (e.g., `SELECT * FROM customers`) which do not contain raw credentials but expose massive amount of PII or financial data.
* **Mitigación**: **Data Sensitivity** classification in the Risk Engine. Database queries are evaluated based on target table sensitivity and filter presence, raising the risk level and logging massive reads under strict audit traces.

### 13. Decoupled Terraform Apply
Executing an innocuous `terraform plan` to generate a valid approval file (sentinel) and then running a destructive and un-audited `apply` within the approval time window.
* **Mitigación**: Semantic, text-based analysis of the plan output. The Terraform parser reads the planned resource modifications, preventing unapproved destructions or security-altering mutations from riding on a benign plan's sentinel.

---

## 3. Attack Surface of SKX Infra Guard

Security guidelines to protect the guardrail system itself:

* **Audit Log Integrity**: The structured log (`audit.jsonl`) is a prime target for deletion or manipulation by an attacker trying to cover their tracks. It is secured using exclusive locks (`flock`), read-only permissions (`chmod 600`), and system-level append-only attributes (`chattr +a`).
* **Policies as Code Security**: The environment policies (`policies/*.yaml`) govern the agent's boundaries. Unsanctioned modifications represent a critical vulnerability. They must be stored in Git, requiring mandatory Pull Request reviews and automated CI testing before deployment.
* **Approval Chain Security**: The sentinel approval verification backend must be highly secure. If a developer can forge a local sentinel file, they bypass the verification flow. The Approval Engine enforces secure tokens, owner-verification checks, and strict TTL expirations on sentinel JSON payloads.
* **Fail-Closed Integration (Fail-Safe)**: In the event of a system crash, timeout, or uncaught exception in the Python core, the integration layer must fail-closed, blocking high-risk operations by default instead of allowing un-audited access.

---

## 4. Adversarial Regression Testing

The test suite incorporates extensive adversarial tests to actively evaluate and stress-test the parsers against:
* Semicolon-chaining, nested shell wraps, eval commands, and complex pipe combinations.
* Variable casing (case insensitivity) and comment insertions (`DR/**/OP TABLE`) in SQL statements.
* Missing or malformed parameters in cloud provider CLI calls.
* Every bypass vector discovered or simulated is added to `tests/security/test_bypass_regression.py` as a permanent automated regression test.
