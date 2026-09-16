"""Context Detector.

Consolidates the environment detection mechanism across all hooks, implementing 
Skydropx's 5 tiers, and adds the User Policy / Agent Policy split 
(docs/skydropx-architecture.md #3).

Conservative philosophy: explicit signals first, then progressively fuzzier signals, 
then the safest possible default. Never "unknown = allow" — an environment we can't 
determine is treated as production for risk purposes.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from skx_infra_guard.core.decision import EnvironmentTier

_PROD_KEYWORDS = re.compile(r"\b(prod|production|prd)\b", re.IGNORECASE)
_STAGING_KEYWORDS = re.compile(r"\b(stag|staging|stg)\b", re.IGNORECASE)
_QA_KEYWORDS = re.compile(r"\b(qa|quality-assurance)\b", re.IGNORECASE)
_DEV_KEYWORDS = re.compile(r"\b(dev|development)\b", re.IGNORECASE)
_SANDBOX_KEYWORDS = re.compile(r"\b(sandbox|sbx)\b", re.IGNORECASE)

_TIER_ALIASES = {
    "prod": EnvironmentTier.PRODUCTION,
    "production": EnvironmentTier.PRODUCTION,
    "prd": EnvironmentTier.PRODUCTION,
    "stag": EnvironmentTier.STAGING,
    "staging": EnvironmentTier.STAGING,
    "stg": EnvironmentTier.STAGING,
    "qa": EnvironmentTier.QA,
    "dev": EnvironmentTier.DEV,
    "development": EnvironmentTier.DEV,
    "sandbox": EnvironmentTier.SANDBOX,
    "sbx": EnvironmentTier.SANDBOX,
}


def classify_resource_tier(text: str) -> EnvironmentTier | None:
    """Public wrapper so domain modules can check a specific resource
    identifier (a namespace, a workspace, a hostname) against the same
    keyword cascade used for the ambient environment — needed to detect
    "sandbox/dev reaching into a production resource" (see
    docs/threat-model.md #10), which is a distinct signal from "what tier
    is this whole session running in"."""
    return _keyword_tier(text)


def _keyword_tier(text: str) -> EnvironmentTier | None:
    if _PROD_KEYWORDS.search(text):
        return EnvironmentTier.PRODUCTION
    if _STAGING_KEYWORDS.search(text):
        return EnvironmentTier.STAGING
    if _QA_KEYWORDS.search(text):
        return EnvironmentTier.QA
    if _SANDBOX_KEYWORDS.search(text):
        return EnvironmentTier.SANDBOX
    if _DEV_KEYWORDS.search(text):
        return EnvironmentTier.DEV
    return None


def detect_environment(
    command: str,
    *,
    env: dict[str, str] | None = None,
    cwd: str | Path | None = None,
) -> EnvironmentTier:
    """5-tier environment detection, conservative default = production.

    Cascade (each step only runs if the previous one found nothing):
      1. SKX_ENV / CLAUDE_ENV explicit override
      2. Resource-identifying env vars (DATABASE_URL, KUBECONFIG, CLOUDSDK_*)
      3. Keywords in the command text itself
      4. A .env / project config file in cwd
      5. ASSUME_PROD_WHEN_UNKNOWN default (production unless explicitly
         disabled)
    """
    env = os.environ if env is None else env

    explicit = env.get("SKX_ENV") or env.get("CLAUDE_ENV")
    if explicit:
        tier = _TIER_ALIASES.get(explicit.strip().lower())
        if tier is not None:
            return tier

    for var in ("DATABASE_URL", "KUBECONFIG", "CLOUDSDK_CORE_PROJECT", "GOOGLE_CLOUD_PROJECT"):
        value = env.get(var)
        if value:
            tier = _keyword_tier(value)
            if tier is not None:
                return tier

    tier = _keyword_tier(command)
    if tier is not None:
        return tier

    if cwd is not None:
        dotenv = Path(cwd) / ".env"
        if dotenv.is_file():
            try:
                content = dotenv.read_text(errors="ignore")
            except OSError:
                content = ""
            for line in content.splitlines():
                m = re.match(
                    r"^(APP_ENV|RAILS_ENV|NODE_ENV|DJANGO_SETTINGS_MODULE|ENVIRONMENT)=(.+)$",
                    line.strip(),
                    re.IGNORECASE,
                )
                if m:
                    tier = _keyword_tier(m.group(2))
                    if tier is not None:
                        return tier

    assume_prod = env.get("ASSUME_PROD_WHEN_UNKNOWN", "true").strip().lower() != "false"
    return EnvironmentTier.PRODUCTION if assume_prod else EnvironmentTier.DEV


class Actor(str):
    """Who is asking: the human behind the session, or the agent itself."""

    USER = "user"
    AGENT = "agent"


@dataclass
class ActorPolicy:
    """A named ceiling on what an actor (user or agent) may do.

    MVP note: this is NOT wired to a real identity provider or GCP/AWS IAM —
    that integration is an explicit open point (docs/skydropx-architecture.md
    #7.3). For now these are loaded from a plain YAML file the operator
    edits by hand (policies/actors.yaml), which is the honest, non-invented
    starting point until a real IAM source is decided.
    """

    name: str
    max_risk: dict[EnvironmentTier, str] = field(default_factory=dict)


@dataclass
class RequestContext:
    """Everything the Risk/Policy Engine needs about the current request."""

    tool_name: str
    environment: EnvironmentTier
    user_policy: ActorPolicy | None = None
    agent_policy: ActorPolicy | None = None
    session_id: str | None = None
    cwd: str | None = None
