"""Domain modules: one per infrastructure domain, each a thin adapter that
turns a Domain Parser's typed result into RiskFactors, asks the Risk Engine
for a level, and asks the Policy Engine for a Verdict. See
docs/skydropx-architecture.md #4.3 for the full domain list and MVP scope.
"""

from skx_infra_guard.domains import aws, database, gcloud, git, helm, kubernetes, mongodb, redis, secrets, terraform  # noqa: F401

ALL_DOMAINS = (kubernetes, terraform, database, git, gcloud, aws, redis, mongodb, helm, secrets)
