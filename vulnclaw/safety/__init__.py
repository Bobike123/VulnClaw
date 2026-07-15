"""VulnClaw safety subsystem - centralized authorization & auditing controls.

This package is the single home for the safety spine:

- :mod:`redaction` - secret scrubbing for logs, reports, audit records.
- :mod:`scope`     - the engagement scope model + central network authorization.
- :mod:`audit`     - tamper-evident structured audit logging.
- :mod:`sandbox`   - the hardened runner for the high-risk ``python_execute`` tool.

Safety checks are centralized here rather than scattered across tools so that no
network-capable tool can bypass scope validation and no secret reaches a log.
"""

from __future__ import annotations

from vulnclaw.safety.approval import (
    ApprovalDecision,
    ApprovalGate,
    ApprovalRequest,
    classify_risk,
    required_capability,
)
from vulnclaw.safety.audit import AuditLogger, summarize, verify_chain
from vulnclaw.safety.budget import Budget, BudgetStatus
from vulnclaw.safety.credentials import (
    PermissionFinding,
    audit_sensitive_files,
    check_file_permissions,
    harden_dir_permissions,
    harden_file_permissions,
)
from vulnclaw.safety.redaction import (
    contains_secret,
    detect_secrets,
    fingerprint,
    redact,
    redact_obj,
)
from vulnclaw.safety.sandbox import (
    SandboxResult,
    capability_report,
    code_hash,
    precheck,
    run_sandboxed,
)
from vulnclaw.safety.scope import (
    Scope,
    ScopeDecision,
    ScopeValidator,
    build_scope_validator,
    load_scope,
)

__all__ = [
    # redaction
    "redact",
    "redact_obj",
    "fingerprint",
    "detect_secrets",
    "contains_secret",
    # scope
    "Scope",
    "ScopeDecision",
    "ScopeValidator",
    "load_scope",
    "build_scope_validator",
    # audit
    "AuditLogger",
    "verify_chain",
    "summarize",
    # budget
    "Budget",
    "BudgetStatus",
    # credentials
    "harden_file_permissions",
    "harden_dir_permissions",
    "check_file_permissions",
    "audit_sensitive_files",
    "PermissionFinding",
    # sandbox
    "run_sandboxed",
    "SandboxResult",
    "code_hash",
    "capability_report",
    "precheck",
    # approval
    "ApprovalGate",
    "ApprovalRequest",
    "ApprovalDecision",
    "classify_risk",
    "required_capability",
]
