"""VulnClaw session context management — track pentest state across turns."""

from __future__ import annotations

import copy
import json
import re
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Literal, Optional

from pydantic import BaseModel, Field, PrivateAttr

from vulnclaw.agent.blackboard import Blackboard
from vulnclaw.agent.reasoning_state import ReasoningState


class PentestPhase(str, Enum):
    """Penetration test phases."""

    IDLE = "就绪"
    RECON = "信息收集"
    VULN_DISCOVERY = "漏洞发现"
    EXPLOITATION = "漏洞利用"
    POST_EXPLOITATION = "后渗透"
    REPORTING = "报告生成"


# Typed evidence-reference kinds. ``sandbox_output`` refs land under
# ``evidence/sandbox/`` (produced by the sandbox PRD), ``http_capture`` refs are
# resolved against the traffic store via ``request_id`` (traffic-store PRD), and
# ``file`` refs point at any other artifact inside the per-run ``evidence/`` tree.
EvidenceKind = Literal["sandbox_output", "http_capture", "file"]


class EvidenceRef(BaseModel):
    """A typed pointer from a finding into the per-run ``evidence/`` tree.

    ``path`` is always relative to that tree so evidence stays portable across
    machines. ``request_id`` is the optional hook a traffic store resolves an
    ``http_capture`` against; it is ``None`` for refs that are self-contained
    files (``sandbox_output`` / ``file``).
    """

    kind: EvidenceKind = Field(description="sandbox_output | http_capture | file")
    path: str = Field(default="", description="Path relative to the per-run evidence/ tree")
    request_id: Optional[str] = Field(
        default=None, description="Traffic-store request id for http_capture refs"
    )


class VulnerabilityFinding(BaseModel):
    """A single vulnerability finding."""

    title: str = Field(description="Vulnerability title")
    severity: str = Field(default="Medium", description="Critical/High/Medium/Low/Info")
    vuln_type: str = Field(default="", description="Vulnerability type (SQLi, XSS, RCE, etc.)")
    description: str = Field(default="", description="Detailed description (what/where)")
    impact: str = Field(
        default="", description="Consequence / business risk (distinct from description)"
    )
    evidence: str = Field(default="", description="Proof/evidence of the finding")
    cve: Optional[str] = Field(default=None, description="Associated CVE ID")
    cvss: Optional[float] = Field(default=None, description="CVSS base score (0.0-10.0)")
    cwe: Optional[str] = Field(default=None, description="CWE identifier, e.g. 'CWE-89'")
    remediation: str = Field(default="", description="Fix recommendation")
    # ★ Structured location — ties findings to a concrete request/route or code site.
    target: str = Field(default="", description="Owning target (ties to the Target model)")
    endpoint: Optional[str] = Field(default=None, description="Affected URL/endpoint")
    method: Optional[str] = Field(default=None, description="HTTP method, e.g. 'POST'")
    code_location: Optional[str] = Field(
        default=None, description="file:line for repo/SAST-style findings"
    )
    # ★ Typed evidence references into the per-run evidence/ tree (alongside the
    # free-text ``evidence`` blob, which is retained for backward compatibility).
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    # ★ Optional skill-loading provenance (reserved by the skill-loading PRD);
    # mapped into finding metadata / SARIF ``properties`` when present.
    skill_provenance: Optional[dict[str, Any]] = Field(default=None)
    poc_script: Optional[str] = Field(default=None, description="Generated PoC script path")
    evidence_level: str = Field(default="L1", description="L1-L4 evidence strength")
    lifecycle_status: str = Field(
        default="candidate",
        description="candidate/pending_verification/verified/rejected/needs_manual_review",
    )

    # ★ 漏洞验证状态追踪
    verified: bool = Field(default=False, description="是否已通过 PoC 验证")
    verification_status: str = Field(
        default="pending", description="验证状态: pending/verified/rejected"
    )
    verified_at: Optional[str] = Field(default=None, description="验证时间")
    verification_note: str = Field(default="", description="验证备注/排除原因")

    # ★ 漏洞唯一标识（用于去重）
    finding_id: str = Field(default="", description="漏洞唯一标识：vuln_type + target + location")

    def model_post_init(self, *args, **kwargs) -> None:
        # ★ Generate the dedup identity FIRST, from the caller-supplied fields —
        # before the intake quarantine below rewrites the description. Otherwise the
        # injected warning text (which contains "/vuln_type/…") is picked up as a
        # bogus location and every bare finding collides on the same nonsense id.
        if not self.finding_id:
            self.finding_id = self._generate_finding_id()

        # ★ Intake quarantine (no hard rejection).
        # A finding with no evidence, no vuln_type and no remediation carries no
        # substantiating signal. For ANY severity we prefix the title, annotate the
        # description, and quarantine it as ``needs_manual_review`` — it stays in run
        # state / audit trail but is excluded from the report/SARIF gate until an
        # actual evidence chain is attached. (Previously this fired for High/Critical
        # only and did not set a lifecycle status.) The whole unit is skipped for a
        # finding that is already verified/rejected — an explicitly promoted finding
        # keeps its terminal status and is never re-stamped "[未验证]".
        is_bare = not self.evidence and not self.vuln_type and not self.remediation
        is_terminal = self.verified or self.verification_status in ("verified", "rejected")
        if is_bare and not is_terminal:
            if not self.title.startswith("[未验证]"):
                self.title = f"[未验证] {self.title}"
            if "缺少验证证据" not in self.description:
                self.description = (
                    "(⚠️ 此漏洞缺少验证证据/vuln_type/修复建议三字段，"
                    "LLM 上报时未附实际测试结果。请补充证据后再作为正式漏洞。)"
                    + (f" {self.description}" if self.description else "")
                )
            self.lifecycle_status = "needs_manual_review"

        self._sync_status_fields()

    def _sync_status_fields(self) -> None:
        """Keep lifecycle and evidence metadata consistent with verification state."""
        if self.verified or self.verification_status == "verified":
            self.verified = True
            self.verification_status = "verified"
            self.lifecycle_status = "verified"
            if self.evidence_level in ("", "L1", "L2", "L3"):
                self.evidence_level = "L4"
            return

        if self.verification_status == "rejected":
            self.verified = False
            self.lifecycle_status = "rejected"
            if self.evidence_level in ("", "L1", "L2"):
                self.evidence_level = "L3"
            return

        self.verified = False
        self.verification_status = "pending"
        if self.lifecycle_status == "needs_manual_review":
            if self.evidence_level in ("", "L1"):
                self.evidence_level = "L2"
            return
        if self.lifecycle_status == "candidate":
            self.evidence_level = self.evidence_level or "L1"
            return
        if self.evidence_level in ("", "L1"):
            self.lifecycle_status = "candidate"
            self.evidence_level = "L1"
        else:
            self.lifecycle_status = "pending_verification"

    def mark_manual_review(self, note: str = "", evidence_level: str = "L2") -> None:
        """Mark a finding as requiring manual review."""
        self.verified = False
        self.verification_status = "pending"
        self.lifecycle_status = "needs_manual_review"
        self.evidence_level = evidence_level
        if note:
            self.verification_note = note

    def _generate_finding_id(self) -> str:
        """Generate unique vulnerability identifier for deduplication.

        Key improvement: also checks the evidence field (populated by Layer 2
        auto-detection) in addition to description, since auto-detected findings
        put URLs/paths in evidence, not description.
        """
        location = ""
        # Try description first, then evidence (Layer 2 auto-findings put URLs there)
        for field in (self.description, self.evidence):
            if not field:
                continue
            url_match = re.search(r'https?://[^\s<>"\')\]]+', field)
            if url_match:
                location = url_match.group(0)
                break
            path_match = re.search(r'/[^\s<>"\')\]]+', field)
            if path_match:
                location = path_match.group(0)
                break

        # Use vuln_type as dedup key; location only if non-empty (avoids "SQL注入_")
        if location:
            return f"{self.vuln_type}_{location}"[:50]
        if self.vuln_type:
            return self.vuln_type[:50]
        # Bare finding (no vuln_type, no location): fall back to a title-derived key
        # so distinct placeholders stay distinct in state / findings.json audit.
        base_title = re.sub(r"^\[未验证\]\s*", "", self.title).strip()
        return base_title[:50]

    def mark_verified(self, note: str = "", evidence_level: str = "L4") -> None:
        """标记漏洞为已验证."""
        from datetime import datetime

        self.verified = True
        self.verification_status = "verified"
        self.lifecycle_status = "verified"
        self.evidence_level = evidence_level
        self.verified_at = datetime.now().isoformat()
        self.verification_note = note

    def mark_rejected(self, reason: str, evidence_level: str = "L3") -> None:
        """标记漏洞为已拒绝（误报）."""
        from datetime import datetime

        self.verified = False
        self.verification_status = "rejected"
        self.lifecycle_status = "rejected"
        self.evidence_level = evidence_level
        self.verified_at = datetime.now().isoformat()
        self.verification_note = reason


class StepStatus(str, Enum):
    """步骤执行状态."""

    SUCCESS = "success"  # 成功
    FAILURE = "failure"  # 失败
    SKIPPED = "skipped"  # 跳过
    INFO = "info"  # 信息收集


class StepRecord(BaseModel):
    """单个渗透步骤的结构化记录.

    用于生成可读的攻击路径摘要。
    """

    phase: PentestPhase = Field(description="所属阶段")
    round: int = Field(default=0, description="轮次")
    action: str = Field(default="", description="执行的动作（如端口扫描、漏洞探测）")
    target: str = Field(default="", description="目标（IP/URL/路径等）")
    result: str = Field(default="", description="执行结果摘要")
    status: StepStatus = Field(default=StepStatus.INFO, description="执行状态")
    detail: str = Field(default="", description="详细信息（可选）")

    def to_summary(self) -> str:
        """转换为可读的摘要行."""
        status_icon = {
            StepStatus.SUCCESS: "✅",
            StepStatus.FAILURE: "❌",
            StepStatus.SKIPPED: "⏭️",
            StepStatus.INFO: "ℹ️",
        }.get(self.status, "")

        result = self.result[:60] + ("..." if len(self.result) > 60 else "")
        return f"{status_icon} Round {self.round}: {self.action} → {result}"

    def to_brief(self) -> str:
        """转换为简短摘要（用于列表显示）."""
        return f"{self.action}: {self.result}"[:80]


class TaskConstraints(BaseModel):
    """Structured hard constraints for an autonomous pentest task."""

    allowed_ports: list[int] = Field(default_factory=list)
    blocked_ports: list[int] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(default_factory=list)
    blocked_hosts: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    blocked_paths: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    blocked_actions: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    strict_mode: bool = Field(default=False)

    def is_empty(self) -> bool:
        return not any(
            [
                self.allowed_ports,
                self.blocked_ports,
                self.allowed_hosts,
                self.blocked_hosts,
                self.allowed_paths,
                self.blocked_paths,
                self.allowed_actions,
                self.blocked_actions,
                self.notes,
                self.strict_mode,
            ]
        )

    def to_prompt_block(self) -> str:
        """Render constraints into a stable prompt block for every round."""
        if self.is_empty():
            return ""

        lines = ["## 当前任务硬约束"]
        if self.allowed_ports:
            lines.append(f"- 仅允许测试端口: {', '.join(str(p) for p in self.allowed_ports)}")
        if self.blocked_ports:
            lines.append(f"- 禁止测试端口: {', '.join(str(p) for p in self.blocked_ports)}")
        if self.allowed_hosts:
            lines.append(f"- 仅允许测试主机: {', '.join(self.allowed_hosts)}")
        if self.blocked_hosts:
            lines.append(f"- 禁止测试主机: {', '.join(self.blocked_hosts)}")
        if self.allowed_paths:
            lines.append(f"- 仅允许测试路径: {', '.join(self.allowed_paths)}")
        if self.blocked_paths:
            lines.append(f"- 禁止测试路径: {', '.join(self.blocked_paths)}")
        if self.allowed_actions:
            lines.append(f"- 仅允许动作: {', '.join(self.allowed_actions)}")
        if self.blocked_actions:
            lines.append(f"- 禁止动作: {', '.join(self.blocked_actions)}")
        if self.notes:
            lines.append(f"- 其他限制: {'; '.join(self.notes)}")
        if self.strict_mode:
            lines.append("- 严格模式: 超出范围时只记录，不主动测试，不调用工具执行。")
        return "\n".join(lines)


class ConstraintViolationEvent(BaseModel):
    """Structured audit event for a blocked constraint violation."""

    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    kind: str = Field(default="constraint_violation")
    code: str = Field(default="", description="Stable violation code")
    severity: str = Field(default="medium", description="low | medium | high")
    source: str = Field(default="", description="command | phase | tool")
    action: str = Field(default="", description="Normalized action name")
    tool_name: str = Field(default="", description="Tool name when source=tool")
    phase: str = Field(default="", description="Current phase label")
    summary: str = Field(default="", description="Human-readable summary")
    detail: str = Field(default="", description="Detailed diagnostic message")


class SessionState(BaseModel):
    """Full session state for a pentest engagement."""

    target: Optional[str] = None
    phase: PentestPhase = PentestPhase.IDLE
    started_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    resume_summary: str = Field(default="", description="恢复时注入的历史成果摘要")
    resume_meta: dict[str, Any] = Field(default_factory=dict, description="恢复元信息")
    task_constraints: TaskConstraints = Field(default_factory=TaskConstraints)
    constraint_violations: list[str] = Field(default_factory=list)
    constraint_violation_events: list[ConstraintViolationEvent] = Field(default_factory=list)
    reasoning: ReasoningState = Field(default_factory=ReasoningState)
    # 目标驱动求解引擎的黑板图（Fact/Intent），随会话持久化
    board: Blackboard = Field(default_factory=Blackboard)
    # 反思引擎跨周期记忆快照（persistent 模式），存为 dict 以避免与 reflexion 模块循环导入
    reflexion_snapshot: dict[str, Any] = Field(default_factory=dict)
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    # ★ Active skill selection for this turn/child task — structured provenance
    # source. Stored as a plain dict to avoid importing the resolver here.
    active_skill_selection: Optional[dict[str, Any]] = Field(
        default=None, description="Active SkillSelection.to_provenance() for the current turn"
    )
    # ★ Run events emitted whenever the active skill selection changes.
    skill_selection_events: list[dict[str, Any]] = Field(
        default_factory=list, description="Audit log of skill-selection changes"
    )
    recon_data: dict[str, Any] = Field(default_factory=dict)
    # ★ 原始步骤日志（向后兼容）
    executed_steps: list[str] = Field(default_factory=list)
    # ★ 结构化步骤记录（用于生成可读摘要）
    step_records: list[StepRecord] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    # ★ Confirmed facts vs unverified assumptions — critical for CTF reasoning
    confirmed_facts: list[str] = Field(default_factory=list, description="已通过工具验证确认的事实")
    unverified_assumptions: list[str] = Field(
        default_factory=list, description="推理中基于但未验证的假设"
    )
    # ★ Recon dimension completion tracking — prevent premature [DONE] in info gathering
    recon_dimensions_completed: dict[str, bool] = Field(
        default_factory=lambda: {
            "server": False,  # 维度一：服务器信息（端口/真实IP/OS/中间件/数据库）
            "website": False,  # 维度二：网站信息（架构/指纹/WAF/敏感目录/源码泄露/旁站/C段）
            "domain": False,  # 维度三：域名信息（WHOIS/ICP备案/子域名/DNS/证书透明度）
            "personnel": False,  # 维度四：人员信息（条件触发 — 仅明确社工需求时激活）
        },
        description="信息收集四维模型完成度追踪",
    )
    recon_dimension4_active: bool = Field(default=False, description="维度四（人员信息）是否被激活")

    # ★ 漏洞去重追踪（PrivateAttr 不受 Pydantic 字段命名限制）
    _finding_ids_cache: set[str] = PrivateAttr(default_factory=set)
    _checkpoint_callback: Callable[["SessionState", str], None] | None = PrivateAttr(
        default=None
    )

    # 语义去重相似度阈值（高于此值视为同一漏洞的不同表述）
    semantic_dedup_threshold: float = Field(
        default=0.75, description="语义去重的相似度阈值（0-1）"
    )

    def set_checkpoint_callback(
        self, callback: Callable[["SessionState", str], None] | None
    ) -> None:
        """Install a persistence callback fired at durable state boundaries."""
        self._checkpoint_callback = callback

    def _notify_checkpoint(self, reason: str) -> None:
        if self._checkpoint_callback is None:
            return
        self._checkpoint_callback(self, reason)

    def add_finding(self, finding: VulnerabilityFinding) -> bool:
        """Add a vulnerability finding with deduplication.

        去重分两层：
            1. finding_id 精确 hash 匹配（快）
            2. 语义相似度匹配（捕获"同一漏洞不同表述"），命中后保留证据更强者

        Returns:
            True if finding was added, False if duplicate (skipped).
        """
        # 生成 finding_id（如果还没有）
        if hasattr(finding, "_sync_status_fields"):
            finding._sync_status_fields()
        if not finding.finding_id:
            finding.finding_id = finding._generate_finding_id()

        # Tie the finding to the owning target when the caller didn't set one.
        if not finding.target and self.target:
            finding.target = self.target

        # 第一层：finding_id 精确去重
        if finding.finding_id in self._finding_ids_cache:
            print(f"[DEDUP] 跳过重复漏洞: {finding.title} (ID: {finding.finding_id})")
            return False

        # 第二层：语义相似度去重
        from vulnclaw.agent.finding_similarity import (
            _evidence_strength,
            finding_similarity,
        )

        for idx, existing in enumerate(self.findings):
            if finding_similarity(finding, existing) >= self.semantic_dedup_threshold:
                # 命中语义重复：保留证据更强者
                if _evidence_strength(finding) > _evidence_strength(existing):
                    print(
                        f"[DEDUP-SEM] 语义重复，替换为证据更强的漏洞: "
                        f"{finding.title} 取代 {existing.title}"
                    )
                    self._finding_ids_cache.discard(existing.finding_id)
                    self._finding_ids_cache.add(finding.finding_id)
                    self.findings[idx] = finding
                    self._notify_checkpoint("finding_updated")
                else:
                    print(f"[DEDUP-SEM] 跳过语义重复漏洞: {finding.title}")
                return False

        # 附加 skill 溯源（若未显式提供且当前有活跃选择）。深拷贝以免其中的
        # references_loaded 列表与 active_skill_selection 共享 —— 否则之后
        # record_loaded_reference() 会追溯性地修改已记录漏洞的溯源。
        if finding.skill_provenance is None and self.active_skill_selection is not None:
            finding.skill_provenance = copy.deepcopy(self.active_skill_selection)

        # 添加到追踪集合和列表
        self._finding_ids_cache.add(finding.finding_id)
        self.findings.append(finding)
        self._notify_checkpoint("finding_added")
        return True

    def set_active_skill_selection(self, provenance: Optional[dict[str, Any]]) -> bool:
        """Record the active skill selection; emit a run event when it changes.

        Args:
            provenance: A ``SkillSelection.to_provenance()`` dict (or None).

        Returns:
            True if the selection changed from the previous turn.
        """
        prev = self.active_skill_selection
        changed = (prev or {}).get("primary") != (provenance or {}).get("primary") or (
            (prev or {}).get("supporting") != (provenance or {}).get("supporting")
        )
        # Same bundle as last turn: carry over references already loaded under it
        # so provenance keeps a complete record across turns.
        if not changed and prev is not None and provenance is not None:
            loaded = prev.get("references_loaded")
            if loaded and not provenance.get("references_loaded"):
                provenance = {**provenance, "references_loaded": list(loaded)}
        self.active_skill_selection = provenance
        if changed:
            event = {
                "kind": "skill_selection_changed" if provenance is not None else "skill_selection_cleared",
                "timestamp": datetime.now().isoformat(),
                "primary": (provenance or {}).get("primary"),
                "supporting": (provenance or {}).get("supporting", []),
                "reason": (provenance or {}).get("reason", ""),
                "confidence": (provenance or {}).get("confidence", 0.0),
            }
            self.skill_selection_events.append(event)
            self.skill_selection_events = self.skill_selection_events[-50:]
        return changed

    def record_loaded_reference(self, skill_name: str, ref_name: str) -> None:
        """Record a reference loaded via ``load_skill_reference`` onto provenance.

        Findings created after this call inherit the reference in their
        ``skill_provenance['references_loaded']``.
        """
        if self.active_skill_selection is None:
            return
        entry = f"{skill_name}/{ref_name}" if skill_name else ref_name
        loaded = self.active_skill_selection.setdefault("references_loaded", [])
        if entry and entry not in loaded:
            loaded.append(entry)

    def get_verified_findings(self) -> list[VulnerabilityFinding]:
        """获取已验证的漏洞列表.

        只返回 verified=True 的漏洞，未验证的不返回。
        """
        return [f for f in self.findings if f.verified]

    def get_rejected_findings(self) -> list[VulnerabilityFinding]:
        """获取已拒绝的漏洞列表（误报）."""
        return [f for f in self.findings if f.verification_status == "rejected"]

    def get_pending_findings(self) -> list[VulnerabilityFinding]:
        """获取待验证的漏洞列表."""
        return [f for f in self.findings if f.verification_status == "pending"]

    def get_candidate_findings(self) -> list[VulnerabilityFinding]:
        """Get findings that are still low-confidence candidates."""
        return [f for f in self.findings if f.lifecycle_status == "candidate"]

    def get_pending_verification_findings(self) -> list[VulnerabilityFinding]:
        """Get findings that have some evidence but still need verification."""
        return [f for f in self.findings if f.lifecycle_status == "pending_verification"]

    def get_manual_review_findings(self) -> list[VulnerabilityFinding]:
        """Get findings that require explicit or implicit manual review."""
        return [
            f
            for f in self.findings
            if (
                f.lifecycle_status == "needs_manual_review"
                or (
                    not f.verified
                    and f.verification_status != "rejected"
                    and f.severity in {"Critical", "High"}
                    and f.lifecycle_status in {"candidate", "pending_verification"}
                )
            )
        ]

    def add_recon_subdomain(self, subdomain: str) -> None:
        """Record a discovered subdomain into recon_data['subdomains'].

        The LLM can call this via python_execute when it discovers subdomains
        during the recon phase (维度三). Subdomains are displayed in the
        attack surface summary in reports.
        """
        if "subdomains" not in self.recon_data:
            self.recon_data["subdomains"] = []
        if subdomain and subdomain not in self.recon_data["subdomains"]:
            self.recon_data["subdomains"].append(subdomain)

    def add_constraint_violation(self, message: str) -> None:
        """Record a constraint violation audit event."""
        if not message:
            return
        if message not in self.constraint_violations:
            self.constraint_violations.append(message)
        elif self.constraint_violations and self.constraint_violations[-1] != message:
            self.constraint_violations.append(message)

        self.constraint_violations = self.constraint_violations[-20:]

    def add_constraint_violation_event(
        self,
        *,
        source: str,
        action: str = "",
        tool_name: str = "",
        code: str = "",
        severity: str = "medium",
        summary: str,
        detail: str = "",
    ) -> None:
        """Record a structured constraint violation audit event."""
        event = ConstraintViolationEvent(
            source=source,
            action=action,
            tool_name=tool_name,
            code=code,
            severity=severity,
            phase=self.phase.value if hasattr(self.phase, "value") else str(self.phase),
            summary=summary,
            detail=detail or summary,
        )
        self.constraint_violation_events.append(event)
        self.constraint_violation_events = self.constraint_violation_events[-20:]
        self.add_constraint_violation(summary)

    def add_step(
        self,
        step: str,
        action: str = "",
        target: str = "",
        result: str = "",
        status: StepStatus = StepStatus.INFO,
        detail: str = "",
    ) -> None:
        """Record an executed step.

        Args:
            step: Original step string (for backward compatibility).
            action: Short action description (e.g. "端口扫描", "漏洞探测").
            target: Target of the action (e.g. "192.168.1.1:80", "/admin/login").
            result: Brief result summary (e.g. "发现22个开放端口").
            status: Execution status.
            detail: Optional detailed information.
        """
        # 保留原始步骤（向后兼容），连续去重避免标题刷屏污染报告
        if not self.executed_steps or self.executed_steps[-1] != step:
            self.executed_steps.append(step)
        # Note: step_records creation removed — it was dead code after the return above

        # 创建结构化记录
        if action:
            record = StepRecord(
                phase=self.phase,
                round=len(self.executed_steps),
                action=action,
                target=target,
                result=result or step[:60],
                status=status,
                detail=detail,
            )
            self.step_records.append(record)
        self._notify_checkpoint("step_complete")

    def get_step_summary(self) -> dict[str, Any]:
        """生成攻击路径摘要.

        Returns:
            按阶段分组的步骤摘要，包含关键发现。
        """
        # ★ 优先使用结构化 step_records
        if self.step_records:
            return self._build_step_summary_from_records()

        # ★ 回退：从原始 executed_steps 解析结构化信息
        if self.executed_steps:
            return self._parse_raw_steps()

        return {"total_steps": 0, "phases": {}, "key_findings": []}

    def _build_step_summary_from_records(self) -> dict[str, Any]:
        """从结构化 step_records 构建摘要."""
        # 按阶段分组
        phases: dict[str, list[StepRecord]] = {}
        for record in self.step_records:
            phase_name = record.phase.value
            if phase_name not in phases:
                phases[phase_name] = []
            phases[phase_name].append(record)

        # 生成每个阶段的摘要
        phase_summaries = {}
        for phase_name, records in phases.items():
            phase_summaries[phase_name] = {
                "count": len(records),
                "actions": list(set(r.action for r in records)),
                "success_count": len([r for r in records if r.status == StepStatus.SUCCESS]),
                "failure_count": len([r for r in records if r.status == StepStatus.FAILURE]),
                "key_results": [r.to_brief() for r in records if r.status == StepStatus.SUCCESS][
                    :5
                ],
            }

        # 提取关键发现
        key_findings = [
            r.to_brief() for r in self.step_records if r.status == StepStatus.SUCCESS and r.result
        ][:10]

        return {
            "total_steps": len(self.step_records),
            "phases": phase_summaries,
            "key_findings": key_findings,
        }

    def _parse_raw_steps(self) -> dict[str, Any]:
        """从原始 executed_steps 解析出可读的步骤摘要.

        当 step_records 为空时使用（向后兼容）。
        """
        import re

        # 关键词模式
        DISCOVERY_KEYWORDS = [
            "发现",
            "漏洞",
            "端口",
            "服务",
            "路径",
            "泄露",
            "确认",
            "验证",
            "成功",
            "连接",
            "可访问",
            "CVE",
            "flag",
            "敏感",
        ]
        FAILURE_KEYWORDS = [
            "失败",
            "错误",
            "超时",
            "拒绝",
            "拦截",
            "无法",
            "404",
            "502",
            "503",
            "不存在",
            "失败",
            "连接失败",
        ]

        phases: dict[str, dict] = {}
        key_findings: list[str] = []
        total_steps = len(self.executed_steps)

        for i, step in enumerate(self.executed_steps):
            # 提取 Round 号
            round_match = re.search(r"Round\s*(\d+)", step)
            int(round_match.group(1)) if round_match else i + 1

            # 判定成功/失败
            has_failure = any(kw in step for kw in FAILURE_KEYWORDS)
            has_discovery = any(kw in step for kw in DISCOVERY_KEYWORDS)

            if has_discovery and not has_failure:
                status = StepStatus.SUCCESS
            elif has_failure:
                status = StepStatus.FAILURE
            else:
                status = StepStatus.INFO

            # 提取动作（第一个有意义的短句）
            action = self._extract_action(step)

            # 提取结果（发现的关键信息）
            result = self._extract_result(step)

            # 分配到阶段（根据关键词猜测）
            phase = self._guess_phase(step)

            if phase not in phases:
                phases[phase] = {
                    "count": 0,
                    "actions": set(),
                    "success_count": 0,
                    "failure_count": 0,
                    "key_results": [],
                }

            phases[phase]["count"] += 1
            if action:
                phases[phase]["actions"].add(action)
            if status == StepStatus.SUCCESS:
                phases[phase]["success_count"] += 1
                if result:
                    phases[phase]["key_results"].append(f"{action}: {result}" if action else result)
            elif status == StepStatus.FAILURE:
                phases[phase]["failure_count"] += 1

            # 收集关键发现
            if status == StepStatus.SUCCESS and result:
                key_findings.append(f"{action}: {result}" if action else result)

        # 转换 phases 中的 set 为 list（JSON 序列化）
        phase_summaries = {}
        for phase_name, data in phases.items():
            phase_summaries[phase_name] = {
                "count": data["count"],
                "actions": list(data["actions"])[:5],
                "success_count": data["success_count"],
                "failure_count": data["failure_count"],
                "key_results": data["key_results"][:5],
            }

        return {
            "total_steps": total_steps,
            "phases": phase_summaries,
            "key_findings": key_findings[:10],
        }

    def get_constraints_prompt_block(self) -> str:
        """Return a stable prompt block for current task constraints."""
        return self.task_constraints.to_prompt_block()

    def _extract_action(self, step: str) -> str:
        """从步骤文本中提取简短动作描述."""
        import re

        # 优先提取明确的动作词
        action_patterns = [
            r"尝试[^\s，。]+",
            r"测试[^\s，。]+",
            r"扫描[^\s，。]+",
            r"探测[^\s，。]+",
            r"枚举[^\s，。]+",
            r"验证[^\s，。]+",
            r"利用[^\s，。]+",
            r"检查[^\s，。]+",
            r"分析[^\s，。]+",
            r"访问[^\s，。]+",
            r"连接[^\s，。]+",
        ]
        for pattern in action_patterns:
            match = re.search(pattern, step)
            if match:
                action = match.group(0)[:20]
                return action

        # 回退：提取第一个有意义的短句（去除 Round 号和思考标签）
        clean = re.sub(r"Round\s*\d+:", "", step)
        clean = re.sub(r"<think>.*?</think>", "", clean)
        clean = clean.strip()[:40]
        return clean if clean else "执行步骤"

    def _extract_result(self, step: str) -> str:
        """从步骤文本中提取结果摘要."""
        import re

        # 提取发现类结果
        discovery_patterns = [
            r"发现[^\s，。；]+",
            r"确认[^\s，。；]+",
            r"漏洞[^\s，。；]+",
            r"端口[^\s，。；]+",
            r"路径[^\s，。；]+",
            r"连接[^\s，。；]+",
            r"返回[^\s，。；]+",
            r"可访问[^\s，。；]+",
            r"成功[^\s，。；]+",
        ]
        for pattern in discovery_patterns:
            match = re.search(pattern, step)
            if match:
                result = match.group(0)[:50]
                # 去除思考标签内容
                result = re.sub(r"<think>.*?</think>", "", result)
                return result.strip()

        # 提取失败原因
        failure_patterns = [
            r"失败[^\s，。；]+",
            r"错误[^\s，。；]+",
            r"超时[^\s，。；]+",
            r"拒绝[^\s，。；]+",
            r"拦截[^\s，。；]+",
            r"无法[^\s，。；]+",
            r"404[^\s，。；]+",
        ]
        for pattern in failure_patterns:
            match = re.search(pattern, step)
            if match:
                return match.group(0)[:50]

        return ""

    def _guess_phase(self, step: str) -> str:
        """根据步骤内容猜测所属阶段."""
        # 阶段切换标记
        if "阶段切换" in step or "进入" in step:
            if "信息收集" in step or "Recon" in step:
                return "信息收集"
            elif "漏洞发现" in step or "漏洞探测" in step:
                return "漏洞发现"
            elif "漏洞利用" in step or "利用" in step:
                return "漏洞利用"
            elif "报告" in step:
                return "报告生成"

        # 关键词判定
        recon_keywords = ["端口", "服务", "指纹", "架构", "WAF", "目录", "子域名", "WHOIS"]
        vuln_keywords = ["漏洞", "注入", "XSS", "SQL", "CSRF", "SSTI", "探测"]
        exploit_keywords = ["利用", "PoC", "验证", "exploit", "验证成功"]

        for kw in exploit_keywords:
            if kw in step:
                return "漏洞利用"

        for kw in vuln_keywords:
            if kw in step:
                return "漏洞发现"

        for kw in recon_keywords:
            if kw in step:
                return "信息收集"

        return self.phase.value  # 使用当前阶段

    def add_note(self, note: str) -> None:
        """Add a session note, filtering out code/symbol-heavy noise."""
        import re as _re

        # Reject notes that are primarily code/symbols — these pollute evidence extraction
        # and create fake URLs/paths in findings.
        # Count Chinese characters vs code symbols
        chinese = _re.findall(r"[\u4e00-\u9fff]", note)
        code_symbols = _re.findall(
            r"[{}()=+*/<>\-\\[\\]|;|import |def |return |print\(|requests\.|socket\.|re\.|sys\.]",
            note,
        )
        if len(note) > 20 and len(code_symbols) > len(chinese) * 0.5:
            # Too much code, skip it
            return
        # Reject very short notes that are just code symbols or numbers
        if len(note) < 5 or note in ("---", "**", ">>>", "..."):
            return
        self.notes.append(note)

    def add_confirmed_fact(self, fact: str) -> None:
        """Add a confirmed fact (verified by tool output)."""
        if fact and fact not in self.confirmed_facts:
            self.confirmed_facts.append(fact)
        if fact:
            self.reasoning.add_fact(
                key=self._fact_key_from_text(fact),
                value=fact,
                source="confirmed_fact",
                confidence=0.9,
            )

    def _fact_key_from_text(self, fact: str) -> str:
        text = fact.lower()
        if "cve-" in text:
            return "cve"
        if "http://" in text or "https://" in text:
            return "url"
        if "port" in text or "端口" in fact:
            return "port"
        if "server" in text or "x-powered-by" in text:
            return "service"
        if "waf" in text:
            return "waf"
        return "confirmed_fact"

    def add_assumption(self, assumption: str) -> None:
        """Add an unverified assumption."""
        if assumption and assumption not in self.unverified_assumptions:
            self.unverified_assumptions.append(assumption)

    def mark_recon_dimension(self, dimension: str) -> None:
        """Mark a recon dimension as completed.

        Args:
            dimension: One of 'server', 'website', 'domain', 'personnel'
        """
        if dimension in self.recon_dimensions_completed:
            self.recon_dimensions_completed[dimension] = True

    def is_recon_complete(self) -> bool:
        """Check if all active recon dimensions have been completed at least once.

        Dimension 4 (personnel) is only checked if it's been activated.
        """
        for dim, completed in self.recon_dimensions_completed.items():
            if dim == "personnel" and not self.recon_dimension4_active:
                continue  # Skip inactive dimension 4
            if not completed:
                return False
        return True

    def get_recon_status_text(self) -> str:
        """Get a human-readable recon dimension completion status."""
        parts = []
        dim_names = {
            "server": "维度一(服务器)",
            "website": "维度二(网站)",
            "domain": "维度三(域名)",
            "personnel": "维度四(人员)",
        }
        for dim, completed in self.recon_dimensions_completed.items():
            if dim == "personnel" and not self.recon_dimension4_active:
                continue  # Skip inactive dimension 4
            name = dim_names.get(dim, dim)
            parts.append(f"{'✅' if completed else '❌'} {name}")
        incomplete = [
            dim
            for dim, done in self.recon_dimensions_completed.items()
            if (dim != "personnel" or self.recon_dimension4_active) and not done
        ]
        status = " | ".join(parts)
        if incomplete:
            status += f"\n→ 还有 {len(incomplete)} 个维度未检查，继续收集，不要标记 [DONE]"
        return status

    def advance_phase(self, phase: PentestPhase) -> None:
        """Move to a new phase."""
        old_phase = self.phase
        self.phase = phase
        # 记录阶段切换
        self.add_step(
            step=f"阶段切换 → {phase.value}",
            action="阶段切换",
            target=f"{old_phase.value} → {phase.value}",
            result=f"进入{phase.value}阶段",
            status=StepStatus.INFO,
        )
        self._notify_checkpoint("phase_transition")

    def save(self, path: Optional[Path] = None) -> Path:
        """Save session state to JSON file."""
        if path is None:
            from vulnclaw.config.settings import SESSIONS_DIR

            safe_target = (self.target or "unknown").replace("/", "_").replace(":", "_")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = SESSIONS_DIR / f"{timestamp}_{safe_target}.json"

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.model_dump(mode="json"), f, ensure_ascii=False, indent=2)
        return path

    @classmethod
    def load(cls, path: Path) -> "SessionState":
        """Load session state from JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)


class ContextManager:
    """Manages conversation context and session state."""

    def __init__(self, max_history: int = 200) -> None:
        self.max_history = max_history
        self.messages: list[dict[str, str]] = []
        self.state = SessionState()

    def add_user_message(self, content: str) -> None:
        """Add a user message to context."""
        self.messages.append({"role": "user", "content": content})
        self._trim()

    def add_assistant_message(self, content: str) -> None:
        """Add an assistant message to context."""
        self.messages.append({"role": "assistant", "content": content})
        self._trim()

    def add_system_message(self, content: str) -> None:
        """Add a system message (inserted at beginning)."""
        # System messages are handled separately in the API call
        pass

    def get_messages(self) -> list[dict[str, str]]:
        """Get conversation messages for API call."""
        return self.messages.copy()

    def reset(self) -> None:
        """Reset context and session state."""
        self.messages = []
        self.state = SessionState()

    def _trim(self) -> None:
        """Trim old messages to stay within limit.

        Instead of blindly dropping old messages, we compress them
        into a summary to preserve key discoveries for multi-round loops.
        """
        if len(self.messages) <= self.max_history:
            return

        # Keep the most recent 70% of messages intact
        keep_count = int(self.max_history * 0.7)
        recent = self.messages[-keep_count:]
        old = self.messages[:-keep_count]

        # Compress old messages into a summary instead of discarding
        summary = self._compress_messages(old)

        self.messages = []
        if summary:
            self.messages.append(
                {
                    "role": "system",
                    "content": f"[之前的会话摘要]\n{summary}",
                }
            )
        self.messages.extend(recent)

    @staticmethod
    def _compress_messages(messages: list[dict[str, str]]) -> str:
        """Compress a list of messages into a concise summary.

        Extracts key findings, tool results, and discoveries from the
        conversation history so the LLM doesn't completely lose context.
        """
        key_parts = []

        for msg in messages:
            content = msg.get("content", "")
            # Extract tool call/result information — these contain actual findings
            if "调用工具:" in content or "工具结果:" in content:
                key_parts.append(content[:300])

            # Extract lines that look like findings/discoveries
            for line in content.split("\n"):
                stripped = line.strip()
                if any(
                    marker in stripped
                    for marker in [
                        "[+]",
                        "[!]",
                        "[-]",
                        "发现",
                        "漏洞",
                        "flag",
                        "CVE",
                        "端口",
                        "开放",
                        "服务",
                        "路径",
                        "泄露",
                        "注入",
                        "Status:",
                        "Headers:",
                        "Body",
                        # ★ Negative/failure markers — critical for CTF to avoid repeating
                        "失败",
                        "无效",
                        "没有",
                        "返回相同",
                        "被拦截",
                        "未成功",
                        "不存在",
                        "错误",
                        "404",
                        "timeout",
                        # ★ Confirmed fact markers — verified by actual tool output
                        "已确认",
                        "确认",
                        "验证成功",
                        "verified",
                        "confirmed",
                        # ★ Assumption markers — things the LLM assumed but didn't verify
                        "假设",
                        "应该",
                        "可能",
                        "推测",
                        "猜测",
                        "估计",
                    ]
                ):
                    key_parts.append(stripped[:200])

        if not key_parts:
            return ""

        # Limit total summary size to avoid context bloat
        summary = "\n".join(key_parts)
        if len(summary) > 3000:
            summary = summary[:3000] + "\n...(更多历史记录已省略)"

        return summary

    def trim_messages(self, max_messages: int = 20) -> None:
        """Forcefully trim conversation history to a specific size.

        Used when context overflow causes repeated LLM errors.
        """
        if len(self.messages) > max_messages:
            self.messages = self.messages[-max_messages:]
