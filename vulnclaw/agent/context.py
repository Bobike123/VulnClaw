"""VulnClaw session context management - track pentest state across turns."""

from __future__ import annotations

import json
import re
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field, PrivateAttr

from vulnclaw.agent.blackboard import Blackboard
from vulnclaw.agent.reasoning_state import ReasoningState


class PentestPhase(str, Enum):
    """Penetration test phases."""

    IDLE = "Ready"
    RECON = "Recon"
    VULN_DISCOVERY = "Vulnerability Discovery"
    EXPLOITATION = "Exploitation"
    POST_EXPLOITATION = "Post-exploitation"
    REPORTING = "Reporting"

    @classmethod
    def _missing_(cls, value: object) -> "PentestPhase | None":
        """Map legacy Chinese phase values (from older saved sessions) to members."""
        legacy = {
            "就绪": cls.IDLE,
            "信息收集": cls.RECON,
            "漏洞发现": cls.VULN_DISCOVERY,
            "漏洞利用": cls.EXPLOITATION,
            "后渗透": cls.POST_EXPLOITATION,
            "报告生成": cls.REPORTING,
        }
        return legacy.get(value) if isinstance(value, str) else None


class VulnerabilityFinding(BaseModel):
    """A single vulnerability finding."""

    title: str = Field(description="Vulnerability title")
    severity: str = Field(default="Medium", description="Critical/High/Medium/Low/Info")
    vuln_type: str = Field(default="", description="Vulnerability type (SQLi, XSS, RCE, etc.)")
    description: str = Field(default="", description="Detailed description")
    evidence: str = Field(default="", description="Proof/evidence of the finding")
    cve: Optional[str] = Field(default=None, description="Associated CVE ID")
    remediation: str = Field(default="", description="Fix recommendation")
    poc_script: Optional[str] = Field(default=None, description="Generated PoC script path")
    evidence_level: str = Field(default="L1", description="L1-L4 evidence strength")
    lifecycle_status: str = Field(
        default="candidate",
        description="candidate/pending_verification/verified/rejected/needs_manual_review",
    )

    # ★ 漏洞验证状态追踪
    verified: bool = Field(default=False, description="whether it has passed PoC verification")
    verification_status: str = Field(
        default="pending", description="verification status: pending/verified/rejected"
    )
    verified_at: Optional[str] = Field(default=None, description="verification time")
    verification_note: str = Field(default="", description="verification note / exclusion reason")

    # ★ 漏洞唯一标识（用于去重）
    finding_id: str = Field(default="", description="unique finding id: vuln_type + target + location")

    def model_post_init(self, *args, **kwargs) -> None:
        # ★ Vulnerability completeness validation
        # If severity is High/Critical but evidence, vuln_type, remediation are all empty,
        # this is a placeholder finding - warn but allow it.
        if self.severity in ("Critical", "High"):
            if not self.evidence and not self.vuln_type and not self.remediation:
                self.title = f"[unverified] {self.title}"
                self.description = (
                    "(⚠️ This finding is missing the evidence/vuln_type/remediation fields; "
                    "the LLM reported it without actual test results. Add evidence before treating it as a confirmed vulnerability.)"
                    + (f" {self.description}" if self.description else "")
                )

        # ★ 生成唯一标识
        if not self.finding_id:
            self.finding_id = self._generate_finding_id()
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
        return self.vuln_type[:50]

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

    SUCCESS = "success"  # success
    FAILURE = "failure"  # failure
    SKIPPED = "skipped"  # skipped
    INFO = "info"  # informational


class StepRecord(BaseModel):
    """单个渗透步骤的结构化记录.

    Used to generate a readable attack-path summary.
    """

    phase: PentestPhase = Field(description="the phase it belongs to")
    round: int = Field(default=0, description="round number")
    action: str = Field(default="", description="the action taken (e.g. port scan, vulnerability probe)")
    target: str = Field(default="", description="target (IP/URL/path, etc.)")
    result: str = Field(default="", description="result summary")
    status: StepStatus = Field(default=StepStatus.INFO, description="execution status")
    detail: str = Field(default="", description="details (optional)")

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

        lines = ["## Current Task Hard Constraints"]
        if self.allowed_ports:
            lines.append(f"- Only test ports: {', '.join(str(p) for p in self.allowed_ports)}")
        if self.blocked_ports:
            lines.append(f"- Blocked ports: {', '.join(str(p) for p in self.blocked_ports)}")
        if self.allowed_hosts:
            lines.append(f"- Only test hosts: {', '.join(self.allowed_hosts)}")
        if self.blocked_hosts:
            lines.append(f"- Blocked hosts: {', '.join(self.blocked_hosts)}")
        if self.allowed_paths:
            lines.append(f"- Only test paths: {', '.join(self.allowed_paths)}")
        if self.blocked_paths:
            lines.append(f"- Blocked paths: {', '.join(self.blocked_paths)}")
        if self.allowed_actions:
            lines.append(f"- Only actions: {', '.join(self.allowed_actions)}")
        if self.blocked_actions:
            lines.append(f"- Blocked actions: {', '.join(self.blocked_actions)}")
        if self.notes:
            lines.append(f"- Other restrictions: {'; '.join(self.notes)}")
        if self.strict_mode:
            lines.append("- Strict mode: out-of-scope activity is only recorded, not actively tested, and no tools are executed.")
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
    resume_summary: str = Field(default="", description="historical-results summary injected on resume")
    resume_meta: dict[str, Any] = Field(default_factory=dict, description="resume metadata")
    task_constraints: TaskConstraints = Field(default_factory=TaskConstraints)
    constraint_violations: list[str] = Field(default_factory=list)
    constraint_violation_events: list[ConstraintViolationEvent] = Field(default_factory=list)
    reasoning: ReasoningState = Field(default_factory=ReasoningState)
    # 目标驱动求解引擎的黑板图（Fact/Intent），随会话持久化
    board: Blackboard = Field(default_factory=Blackboard)
    # 反思引擎跨周期记忆快照（persistent 模式），存为 dict 以避免与 reflexion 模块循环导入
    reflexion_snapshot: dict[str, Any] = Field(default_factory=dict)
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    recon_data: dict[str, Any] = Field(default_factory=dict)
    # ★ 原始步骤日志（向后兼容）
    executed_steps: list[str] = Field(default_factory=list)
    # ★ 结构化步骤记录（用于生成可读摘要）
    step_records: list[StepRecord] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    # ★ Confirmed facts vs unverified assumptions - critical for CTF reasoning
    confirmed_facts: list[str] = Field(default_factory=list, description="facts confirmed via tool verification")
    unverified_assumptions: list[str] = Field(
        default_factory=list, description="assumptions relied on in reasoning but not verified"
    )
    # ★ Recon dimension completion tracking - prevent premature [DONE] in info gathering
    recon_dimensions_completed: dict[str, bool] = Field(
        default_factory=lambda: {
            "server": False,  # Dimension 1: server info (ports/real IP/OS/middleware/database)
            "website": False,  # Dimension 2: website info (architecture/fingerprint/WAF/sensitive dirs/source leaks/co-hosted sites/C-segment)
            "domain": False,  # Dimension 3: domain info (WHOIS/ICP filing/subdomains/DNS/certificate transparency)
            "personnel": False,  # Dimension 4: personnel info (conditional - activated only on explicit social-eng need)
        },
        description="four-dimension recon-model coverage tracking",
    )
    recon_dimension4_active: bool = Field(default=False, description="whether Dimension 4 (personnel info) is activated")

    # ★ Finding-dedup tracking (PrivateAttr is exempt from Pydantic field-naming rules)
    _finding_ids_cache: set[str] = PrivateAttr(default_factory=set)

    # Semantic-dedup similarity threshold (above this = the same vulnerability worded differently)
    semantic_dedup_threshold: float = Field(
        default=0.75, description="semantic-dedup similarity threshold (0-1)"
    )

    def add_finding(self, finding: VulnerabilityFinding) -> bool:
        """Add a vulnerability finding with deduplication.

        Two-layer dedup:
            1. exact finding_id hash match (fast)
            2. semantic-similarity match (catches "the same vulnerability worded differently"); on a hit, keep the better-evidenced one

        Returns:
            True if finding was added, False if duplicate (skipped).
        """
        # Generate finding_id (if not already set)
        if hasattr(finding, "_sync_status_fields"):
            finding._sync_status_fields()
        if not finding.finding_id:
            finding.finding_id = finding._generate_finding_id()

        # Layer 1: exact finding_id dedup
        if finding.finding_id in self._finding_ids_cache:
            print(f"[DEDUP] skipping duplicate finding: {finding.title} (ID: {finding.finding_id})")
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
                        f"[DEDUP-SEM] semantic duplicate; replaced with a better-evidenced finding: "
                        f"{finding.title} replaces {existing.title}"
                    )
                    self._finding_ids_cache.discard(existing.finding_id)
                    self._finding_ids_cache.add(finding.finding_id)
                    self.findings[idx] = finding
                else:
                    print(f"[DEDUP-SEM] skipping semantic-duplicate finding: {finding.title}")
                return False

        # 添加到追踪集合和列表
        self._finding_ids_cache.add(finding.finding_id)
        self.findings.append(finding)
        return True

    def get_verified_findings(self) -> list[VulnerabilityFinding]:
        """获取已验证的漏洞列表.

        Returns only verified=True findings; unverified ones are excluded.
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
        during the recon phase (Dimension 3). Subdomains are displayed in the
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
            action: Short action description (e.g. "port scan", "vulnerability probe").
            target: Target of the action (e.g. "192.168.1.1:80", "/admin/login").
            result: Brief result summary (e.g. "found 22 open ports").
            status: Execution status.
            detail: Optional detailed information.
        """
        # 保留原始步骤（向后兼容），连续去重避免标题刷屏污染报告
        if not self.executed_steps or self.executed_steps[-1] != step:
            self.executed_steps.append(step)
        # Note: step_records creation removed - it was dead code after the return above

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

    def get_step_summary(self) -> dict[str, Any]:
        """生成攻击路径摘要.

        Returns:
            A phase-grouped step summary, including key findings.
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

        # Keyword patterns (bilingual: legacy Chinese + English model output)
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
            "found",
            "vulnerability",
            "port",
            "service",
            "path",
            "leak",
            "confirmed",
            "verified",
            "success",
            "accessible",
            "sensitive",
        ]
        FAILURE_KEYWORDS = [
            "失败",
            "错误",
            "超时",
            "拒绝",
            "拦截",
            "无法",
            "fail",
            "error",
            "timeout",
            "denied",
            "blocked",
            "unable",
            "not found",
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
        return clean if clean else "execution step"

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

        # Reject notes that are primarily code/symbols - these pollute evidence extraction
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
            status += f"\n→ {len(incomplete)} dimension(s) still unchecked; keep gathering, do not mark [DONE]"
        return status

    def advance_phase(self, phase: PentestPhase) -> None:
        """Move to a new phase."""
        old_phase = self.phase
        self.phase = phase
        # Record the phase transition
        self.add_step(
            step=f"Phase change → {phase.value}",
            action="phase change",
            target=f"{old_phase.value} → {phase.value}",
            result=f"Entered {phase.value} phase",
            status=StepStatus.INFO,
        )

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
                    "content": f"[Previous session summary]\n{summary}",
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
            # Extract tool call/result information - these contain actual findings
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
                        # ★ Negative/failure markers - critical for CTF to avoid repeating
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
                        # ★ Confirmed fact markers - verified by actual tool output
                        "已确认",
                        "确认",
                        "验证成功",
                        "verified",
                        "confirmed",
                        # ★ Assumption markers - things the LLM assumed but didn't verify
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
