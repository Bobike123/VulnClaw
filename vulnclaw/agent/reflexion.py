from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from vulnclaw.agent.anti_loop import FAILED_ACCESS_PATTERNS


class FailureCategory(str, Enum):
    ENV_CONSTRAINT = "env_constraint"
    PATH_ERROR = "path_error"
    PARAM_ERROR = "param_error"
    INFO_NEEDED = "info_needed"
    UNKNOWN = "unknown"


class Attempt(BaseModel):
    path: str
    success: bool
    category: FailureCategory | None = None
    details: str = ""
    vuln_type: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ReflexionState(BaseModel):
    attempts: list[Attempt] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)
    failed_paths: list[str] = Field(default_factory=list)
    reflections: list[dict[str, Any]] = Field(default_factory=list)
    consecutive_failures: int = 0
    last_vuln_type: str = ""
    vuln_type_fail_count: int = 0


class ReflexionEngine(BaseModel):
    max_same_vuln_fails: int = 2
    max_total_no_progress: int = 5
    max_reflections_before_escalate: int = 3
    escalation_max_level: int = 4
    state: ReflexionState = Field(default_factory=ReflexionState)

    def record_attempt(
        self,
        path: str,
        success: bool,
        category: FailureCategory | None = None,
        details: str = "",
        vuln_type: str = "",
    ) -> None:
        attempt = Attempt(
            path=path,
            success=success,
            category=category,
            details=details,
            vuln_type=vuln_type,
        )
        self.state.attempts.append(attempt)

        if success:
            self.state.consecutive_failures = 0
            self.state.vuln_type_fail_count = 0
            if vuln_type:
                self.state.last_vuln_type = vuln_type
            return

        self.state.consecutive_failures += 1
        # 不把占位符 "unknown"/空路径塞进失败路径列表，避免污染失败历史与归因
        if path and path != "unknown":
            self.state.failed_paths.append(path)

        if vuln_type:
            if vuln_type == self.state.last_vuln_type:
                self.state.vuln_type_fail_count += 1
            else:
                self.state.last_vuln_type = vuln_type
                self.state.vuln_type_fail_count = 1

        if category and category != FailureCategory.UNKNOWN and details:
            self.state.constraints.append(details)

    def should_reflect(self) -> bool:
        same_vuln_stale = self.state.vuln_type_fail_count >= self.max_same_vuln_fails
        no_progress_stale = self.state.consecutive_failures >= self.max_total_no_progress
        return same_vuln_stale or no_progress_stale

    def should_escalate(self) -> bool:
        return len(self.state.reflections) >= self.max_reflections_before_escalate

    def get_escalation_level(self) -> int:
        level = (self.state.consecutive_failures // 2) + len(self.state.reflections)
        return min(self.escalation_max_level, max(0, level))

    def get_escalation_hints(self) -> list[str]:
        hints_by_level = {
            0: ["Try the original payload first (no encoding)."],
            1: [
                "URL-encode special characters.",
                "Switch keyword case (SeLeCt).",
                "Try whitespace variants (/**/, newline, Tab).",
            ],
            2: [
                "Try double URL encoding.",
                "Insert inline comments, e.g. /**/.",
                "Use HTML entity encoding for browser-facing injection points.",
            ],
            3: [
                "Try Unicode escapes (\\u0027).",
                "Try hex encoding (0x...).",
                "Split keywords with string concatenation (con||cat).",
                "Bypass banned functions with equivalent alternatives.",
            ],
            4: [
                "Combine multiple layers of encoding/obfuscation.",
                "Use alternative syntax for the same effect (e.g. HANDLER instead of SELECT).",
                "Switch to time-based blind or out-of-band (OOB) confirmation.",
                "Switch to a completely different vulnerability type / attack surface.",
            ],
        }
        return hints_by_level[self.get_escalation_level()]

    def record_reflection(self, old_path: str, new_path: str, reasoning: str) -> None:
        self.state.reflections.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "old_path": old_path,
                "new_path": new_path,
                "reasoning": reasoning,
            }
        )
        self.state.consecutive_failures = 0
        self.state.vuln_type_fail_count = 0

    def analyze_failure_patterns(self) -> list[dict[str, Any]]:
        patterns: dict[str, dict[str, Any]] = {}
        for attempt in self.state.attempts:
            if attempt.success:
                continue
            category = attempt.category.value if attempt.category else FailureCategory.UNKNOWN.value
            if category not in patterns:
                patterns[category] = {"count": 0, "paths": set(), "examples": []}
            patterns[category]["count"] += 1
            patterns[category]["paths"].add(attempt.path)
            if attempt.details and len(patterns[category]["examples"]) < 3:
                patterns[category]["examples"].append(attempt.details[:200])

        result = []
        for category, info in sorted(patterns.items(), key=lambda item: item[1]["count"], reverse=True):
            result.append(
                {
                    "category": category,
                    "occurrences": info["count"],
                    "affected_paths": sorted(info["paths"]),
                    "example_details": info["examples"],
                    "suggested_action": self._suggest_for_category(category),
                }
            )
        return result

    def get_failed_paths(self) -> list[str]:
        return list(dict.fromkeys(self.state.failed_paths))

    def to_prompt_block(self) -> str:
        """Lightweight status block (injected each round). Detailed failure
        patterns / escalation hints are emitted only by to_reflection_prompt when
        reflection triggers, to avoid duplicate injection and wasted tokens."""
        if not self.state.attempts and not self.state.reflections:
            return ""

        lines = [
            "🔁 Reflexion status:",
            f"- Consecutive no-progress rounds: {self.state.consecutive_failures}",
            f"- Same-type vulnerability failures: {self.state.vuln_type_fail_count}",
            f"- Current escalation level: L{self.get_escalation_level()}",
        ]

        failed_paths = self.get_failed_paths()
        if failed_paths:
            lines.append(f"- Failed paths (do not repeat): {', '.join(failed_paths[:8])}")

        return "\n".join(lines)

    def to_reflection_prompt(self) -> str:
        """Reflexion-takeover directive, emitted only when should_reflect() triggers; carries detailed failure attribution + escalation hints."""
        if not self.should_reflect():
            return ""

        lines = [
            "🔴 Reflexion takeover (repeated failures on the same attack type; you must change strategy):",
            "- Stop swapping payloads on the current attack path.",
            "- Review the failure history and pinpoint which earlier assumption was likely wrong.",
            "- Before the next payload, choose a substantially different attack path / vulnerability type.",
            f"- Current escalation level: L{self.get_escalation_level()}",
        ]

        if self.should_escalate():
            lines.append("- ⚠️ Forced escalation: switch to a completely different vulnerability type or attack surface; stop fixating on the current direction.")

        patterns = self.analyze_failure_patterns()
        if patterns:
            lines.append("- Failure-pattern analysis:")
            for pattern in patterns[:3]:
                lines.append(
                    f"  - {pattern['category']} ×{pattern['occurrences']}: "
                    f"{pattern['suggested_action']}"
                )

        hints = self.get_escalation_hints()
        if hints:
            lines.append(f"- Level L{self.get_escalation_level()} bypass hints:")
            for hint in hints:
                lines.append(f"  - {hint}")

        return "\n".join(lines)

    def extract_experience(self) -> dict[str, Any] | None:
        if not self.state.attempts:
            return None

        successful_paths = [attempt.path for attempt in self.state.attempts if attempt.success]
        return {
            "total_attempts": len(self.state.attempts),
            "successful_paths": successful_paths,
            "failed_paths": self.get_failed_paths(),
            "constraints": list(dict.fromkeys(self.state.constraints)),
            "reflections": self.state.reflections,
            "failure_patterns": self.analyze_failure_patterns(),
            "last_vuln_type": self.state.last_vuln_type,
            "escalation_level": self.get_escalation_level(),
        }

    @staticmethod
    def _suggest_for_category(category: str) -> str:
        suggestions = {
            FailureCategory.ENV_CONSTRAINT.value: (
                "Bypass filtering with encoding/obfuscation, switch protocol or endpoint, and confirm access limits (WAF/permissions/rate-limiting)."
            ),
            FailureCategory.PATH_ERROR.value: (
                "Lower this path's priority and switch to a different attack surface / vulnerability type."
            ),
            FailureCategory.PARAM_ERROR.value: (
                "Adjust the parameter name, delimiter, payload syntax, or injection position."
            ),
            FailureCategory.INFO_NEEDED.value: (
                "Gather more recon first, then retry this path."
            ),
        }
        return suggestions.get(category, "Review the failure history and try a different approach.")


def classify_failure(response_text: str) -> FailureCategory | None:
    text = response_text.lower()
    if not text.strip():
        return None

    if any(pattern.lower() in text for pattern in FAILED_ACCESS_PATTERNS):
        return FailureCategory.ENV_CONSTRAINT

    category_patterns = {
        FailureCategory.ENV_CONSTRAINT: [
            # English
            "waf",
            "403",
            "forbidden",
            "blocked",
            "filtered",
            "permission denied",
            "unauthorized",
            "rate limit",
            "timeout",
            "connection refused",
            "bad gateway",
            "service unavailable",
            # 中文
            "被拦截",
            "被过滤",
            "被waf",
            "拦截",
            "过滤掉",
            "转义",
            "禁止访问",
            "无权限",
            "权限不足",
            "频率限制",
            "限流",
        ],
        FailureCategory.PATH_ERROR: [
            # English
            "vulnerability does not exist",
            "not vulnerable",
            "no injection",
            "not injectable",
            "false positive",
            "dead end",
            "wrong attack surface",
            # 中文
            "不存在该漏洞",
            "没有漏洞",
            "无漏洞",
            "不是注入点",
            "无注入",
            "此处无",
            "误报",
            "死胡同",
            "走不通",
            "换攻击面",
            "换个方向",
        ],
        FailureCategory.PARAM_ERROR: [
            # English
            "invalid payload",
            "syntax error",
            "bad parameter",
            "wrong parameter",
            "encoding error",
            "malformed",
            "parse error",
            "delimiter",
            # 中文
            "参数错误",
            "参数不对",
            "payload无效",
            "payload 无效",
            "语法错误",
            "编码错误",
            "格式错误",
            "分隔符",
        ],
        FailureCategory.INFO_NEEDED: [
            # English
            "need more information",
            "need more recon",
            "unknown parameter",
            "insufficient information",
            "collect more",
            "fingerprint first",
            "enumerate first",
            # 中文
            "需要更多信息",
            "信息不足",
            "未知参数",
            "先收集",
            "先侦察",
            "先枚举",
            "先指纹",
            "再收集",
        ],
    }

    for category, patterns in category_patterns.items():
        if any(pattern in text for pattern in patterns):
            return category

    return FailureCategory.UNKNOWN
