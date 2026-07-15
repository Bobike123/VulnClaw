"""VulnClaw Report Generator - generate structured penetration test reports."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from jinja2 import Template

from vulnclaw.agent.context import SessionState, VulnerabilityFinding

# ── Report Template ─────────────────────────────────────────────────

REPORT_TEMPLATE = """\
# Penetration Test Report

## 1. Overview

| Item | Details |
|------|------|
| **Test target** | {{ target }} |
| **Test time** | {{ started_at }} |
| **Report generated** | {{ generated_at }} |
| **Testing tool** | VulnClaw v{{ version }} |
| **Task constraints** | {{ task_constraints_summary }} |

## 2. Executive Summary

{% if verified_count > 0 %}
- **Verified vulnerabilities**: {{ verified_count }} (of which {{ critical_count }} Critical, {{ high_count }} High)
{% else %}
- **Verified vulnerabilities**: 0
{% endif %}
- **False positives excluded**: {{ rejected_count }}
- **Pending verification**: {{ pending_count }} (not shown in the report)
- **Candidates**: {{ candidate_count }}
- **Pending-verification items**: {{ pending_verification_count }}
- **Needs manual review**: {{ manual_review_count }}
- **Attack surface**: {{ attack_surface_summary }}
{% if constraint_violation_events or constraint_violations %}
- **Constraint violations blocked**: {{ constraint_violations|length }} time(s)
{% endif %}

{% if rejected_count > 0 %}
### Excluded false positives

The following vulnerability hypotheses failed PoC verification and are excluded from the report:

{% for f in rejected_findings %}
- {{ f.title }} - {{ f.verification_note }}
{% endfor %}
{% endif %}

### Risk-level distribution

| Level | Count |
|------|------|
| Critical | {{ critical_count }} |
| High | {{ high_count }} |
| Medium | {{ medium_count }} |
| Low/Info | {{ low_count }} |

{% if verified_findings %}
### Key recommendations

{% for rec in key_recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}
{% else %}
### Vulnerability findings

**No valid vulnerabilities were found in this test.**

Possible reasons:
- The target system is well-configured for security
- Insufficient testing depth (too few recon rounds)
- Exploitation preconditions were not met

Recommendations:
- Increase the number of testing rounds
- Try more vulnerability types
- Check whether special authentication or access is required
{% endif %}

## 3. Detailed Findings

{% for finding in findings %}
### 3.{{ loop.index }} {{ finding.title }} - [{{ finding.severity }}]
{% if finding.verification_status == "pending" %}
> ⚠️ **Pending verification** - this vulnerability was found by automatic detection and has not passed PoC verification. Please review manually.
{% elif finding.verification_status == "rejected" %}
> ❌ **Excluded (false positive)** - {{ finding.verification_note or "verified as a false positive" }}
{% elif finding.lifecycle_status == "needs_manual_review" %}
> 🔎 **Needs manual review** - there is indirect evidence, but manual review is still required before promoting it to a confirmed vulnerability.
{% endif %}

- **Vulnerability type**: {{ finding.vuln_type or "Unclassified" }}
- **Lifecycle**: {{ finding.lifecycle_status or "pending_verification" }}
- **Evidence level**: {{ finding.evidence_level or "L1" }}
- **CVE**: {{ finding.cve or "N/A" }}
- **Impact**: {{ finding.description or "none" }}
{% if finding.evidence %}
- **Verification evidence**: {{ finding.evidence }}
{% endif %}
{% if finding.poc_script %}
- **PoC script**: see attachment `{{ finding.poc_script }}`
{% endif %}
- **Remediation**: {{ finding.remediation or "Apply appropriate remediation for the vulnerability type" }}
{% if finding.verified and finding.verified_at %}
- **Verified at**: {{ finding.verified_at }}
{% endif %}

{% endfor %}

{% if llm_attack_summary %}
## 4. Attack-Path Summary

{{ llm_attack_summary }}

{% elif step_summary and step_summary.total_steps > 0 %}
## 4. Attack-Path Summary

{% for phase_name, phase_data in step_summary.phases.items() %}
### {{ phase_name }} ({{ phase_data.count }} steps)

| Status | Count |
|------|------|
| ✅ Success | {{ phase_data.success_count }} |
| ❌ Failure | {{ phase_data.failure_count }} |

**Key actions**: {{ phase_data.actions[:5]|join(', ') }}

{% if phase_data.key_results %}
**Main findings**:
{% for result in phase_data.key_results %}
- {{ result }}
{% endfor %}
{% endif %}

---
{% endfor %}

**Total**: {{ step_summary.total_steps }} steps

{% if step_summary.key_findings %}
### Key-finding timeline

{% for finding in step_summary.key_findings %}
- {{ finding }}
{% endfor %}
{% endif %}

{% elif findings %}
## 4. Attack Path

{% for step in executed_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}
{% endif %}

{% if constraint_violation_events or constraint_violations %}
## 5. Constraint-Violation Audit

{% if constraint_violation_events %}
{% for item in constraint_violation_events %}
- [{{ item.source or "unknown" }}] {{ item.summary }}
{% endfor %}
{% else %}
{% for item in constraint_violations %}
- {{ item }}
{% endfor %}
{% endif %}
{% endif %}

## 6. Attachments

- PoC scripts: see the `pocs/` directory
- Traffic captures: see the `captures/` directory
- Screenshot evidence: see the `screenshots/` directory

---

> 🦞 Report auto-generated by VulnClaw | {{ generated_at }}
> **Principle**: an unverified vulnerability = a false positive = not written to the report
"""


def generate_report(
    session: SessionState,
    output_path: Optional[str] = None,
    llm_attack_summary: str = "",
    report_format: str = "markdown",
    target_state_context: Optional[dict[str, Any]] = None,
) -> Path:
    """Generate a penetration test report from session state.

    Only verified findings are rendered into the main detailed findings section.
    Pending, candidate, and rejected findings remain in summary/governance views.
    """
    from vulnclaw import __version__
    from vulnclaw.report.filter import deduplicate_report_findings

    all_findings = session.findings
    verified_findings = deduplicate_report_findings(session.get_verified_findings())
    pending_findings = session.get_pending_findings()
    rejected_findings = session.get_rejected_findings()
    candidate_findings = (
        session.get_candidate_findings() if hasattr(session, "get_candidate_findings") else []
    )
    pending_verification_findings = (
        session.get_pending_verification_findings()
        if hasattr(session, "get_pending_verification_findings")
        else []
    )
    manual_review_findings = (
        session.get_manual_review_findings()
        if hasattr(session, "get_manual_review_findings")
        else []
    )

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in verified_findings:
        sev = finding.severity
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["Medium"] += 1

    seen_vuln_types = set()
    recommendations = []
    for finding in verified_findings:
        if finding.severity in ("Critical", "High"):
            vt = finding.vuln_type or "Unclassified"
            if vt in seen_vuln_types:
                continue
            seen_vuln_types.add(vt)
            rec = finding.remediation or f"Prioritize fixing the {vt} risk: {finding.title}"
            recommendations.append(rec)

    if not recommendations:
        recommendations.append("Prioritize reviewing the attack surface and adding verification chains; confirm high-risk entry points are fixed.")

    if output_path is None:
        from vulnclaw.config.settings import SESSIONS_DIR

        safe_target = (session.target or "unknown").replace("/", "_").replace(":", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = str(SESSIONS_DIR / f"report_{timestamp}_{safe_target}.md")

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    from vulnclaw.report.poc_builder import generate_pocs

    pocs_dir = output.parent / "pocs"
    generate_pocs(session, pocs_dir)

    from vulnclaw.report.filter import ReportContentFilter

    if not llm_attack_summary:
        llm_attack_summary = _generate_attack_summary_from_session(session)
        if llm_attack_summary:
            print("[*] LLM attack summary generated for report section 4")
    filtered_summary = ReportContentFilter.filter(llm_attack_summary) if llm_attack_summary else ""

    context = {
        "target": session.target or "unknown",
        "started_at": session.started_at,
        "generated_at": datetime.now().isoformat(),
        "version": __version__,
        "critical_count": severity_counts["Critical"],
        "high_count": severity_counts["High"],
        "medium_count": severity_counts["Medium"],
        "low_count": severity_counts["Low"] + severity_counts["Info"],
        "task_constraints_summary": _format_task_constraints_summary(session),
        "attack_surface_summary": _summarize_attack_surface(session),
        "constraint_violations": list(getattr(session, "constraint_violations", [])),
        "constraint_violation_events": [
            item.model_dump(mode="json") if hasattr(item, "model_dump") else item
            for item in getattr(session, "constraint_violation_events", [])
        ],
        "key_recommendations": recommendations,
        "verified_findings": [_build_report_finding(finding) for finding in verified_findings],
        "findings": [_build_report_finding(finding) for finding in verified_findings],
        "executed_steps": session.executed_steps,
        "total_findings_submitted": len(all_findings),
        "verified_count": len(verified_findings),
        "rejected_count": len(rejected_findings),
        "pending_count": len(pending_findings),
        "candidate_count": len(candidate_findings),
        "pending_verification_count": len(pending_verification_findings),
        "manual_review_count": len(manual_review_findings),
        "rejected_findings": rejected_findings,
        "step_summary": session.get_step_summary(),
        "llm_attack_summary": filtered_summary,
    }

    template = Template(REPORT_TEMPLATE)
    report_content = template.render(**context)
    if verified_findings:
        report_content += "\n\n" + _render_verified_finding_details_clean(
            verified_findings,
            heading="## 6. Verified Vulnerability Location & Reproduction Info",
        )
    if target_state_context:
        report_content += "\n\n" + _render_target_state_context(target_state_context)

    if report_format.lower() == "html":
        html_content = Template(
            """<!doctype html><html><head><meta charset="utf-8"><title>VulnClaw Report</title></head><body><pre>{{ content }}</pre></body></html>"""
        ).render(content=report_content)
        output = output.with_suffix(".html") if output.suffix.lower() != ".html" else output
        output.write_text(html_content, encoding="utf-8")
    else:
        output.write_text(report_content, encoding="utf-8")

    return output


def generate_report_from_file(session_path: str) -> Path:
    """Generate a report from a saved session JSON file."""
    session = SessionState.load(Path(session_path))
    return generate_report(session)


def generate_report_from_target_state(
    target_state: dict[str, Any],
    report_format: str = "markdown",
    output_path: str | None = None,
) -> Path:
    """Generate a report from a target-state snapshot."""
    raw = dict(target_state)
    target_state_context = {
        "resume_meta": raw.pop("resume_meta", None),
        "resume_summary": raw.pop("resume_summary", None),
        "recon_meta": raw.pop("recon_meta", None),
        "runtime_meta": raw.pop("runtime_meta", None),
        "finding_meta": raw.pop("finding_meta", None),
    }
    session = SessionState(**raw)
    return generate_report(
        session,
        output_path=output_path,
        report_format=report_format,
        target_state_context=target_state_context,
    )


def _summarize_attack_surface(session: SessionState) -> str:
    """Summarize the attack surface from recon data, including subdomains."""
    parts = []
    recon = session.recon_data

    if "subdomains" in recon and recon["subdomains"]:
        parts.append(f"Subdomains: {', '.join(recon['subdomains'][:10])}")
    if "ports" in recon:
        parts.append(f"Open ports: {recon['ports']}")
    if "services" in recon:
        parts.append(f"Services: {recon['services']}")
    if "technologies" in recon:
        parts.append(f"Tech stack: {recon['technologies']}")
    if "waf" in recon:
        parts.append(f"WAF: {recon['waf']}")
    if "domains" in recon:
        parts.append(f"Related domains: {', '.join(recon['domains'][:5])}")

    return "; ".join(parts) if parts else "not collected"


# ── Persistent Pentest Cycle Report ──────────────────────────────────

CYCLE_REPORT_TEMPLATE = """\
# Persistent Penetration Test - Cycle Report

## Cycle Info

| Item | Details |
|------|------|
| **Test target** | {{ target }} |
| **Current cycle** | Cycle {{ cycle_num }} |
| **Rounds per cycle** | {{ rounds_per_cycle }} |
| **New verified vulnerabilities this cycle** | {{ new_findings }} |
| **Total verified vulnerabilities** | {{ total_findings }} |
| **Total steps executed** | {{ total_steps }} |
| **Report generated at** | {{ generated_at }} |

{% if cycle_findings %}
## Vulnerabilities Found This Cycle

{% for finding in cycle_findings %}
### {{ loop.index }}. {{ finding.title }} - [{{ finding.severity }}]
{% if finding.verification_status == "pending" %}
> ⚠️ **Pending verification** - this vulnerability was found by automatic detection and has not passed PoC verification.
{% elif finding.lifecycle_status == "needs_manual_review" %}
> 🔎 **Needs manual review** - there is indirect evidence, but manual review is still required before promoting it to a confirmed vulnerability.
{% endif %}
- **Vulnerability type**: {{ finding.vuln_type or "Unclassified" }}
- **Lifecycle**: {{ finding.lifecycle_status or "pending_verification" }}
- **Evidence level**: {{ finding.evidence_level or "L1" }}
- **CVE**: {{ finding.cve or "N/A" }}
- **Impact**: {{ finding.description or "none" }}
{% if finding.evidence %}
- **Verification evidence**: {{ finding.evidence }}
{% endif %}
- **Remediation**: {{ finding.remediation or "Apply appropriate remediation for the vulnerability type" }}
{% if finding.verified_at %}
- **Verified at**: {{ finding.verified_at }}
{% endif %}

{% endfor %}
{% else %}
## Vulnerabilities Found This Cycle

No new vulnerabilities were found this cycle.
{% endif %}

## Cumulative Vulnerability Summary

| # | Title | Level | Type | Evidence/URL | Status |
|---|---------|------|------|---------|------|
{% for finding in all_findings %}
{% set ev = (finding.evidence or finding.description or "")[:80] %}
| {{ loop.index }} | {{ finding.title }} | {{ finding.severity }} | {{ finding.vuln_type or "-" }} | {{ ev if ev else "-" }} | {% if finding.verification_status == "verified" %}✅ Verified{% elif finding.lifecycle_status == "needs_manual_review" %}🔎 Needs manual review{% elif finding.verification_status == "pending" %}⚠️ Pending{% else %}❌ Excluded{% endif %} |
{% endfor %}

{% if not all_findings %}
No vulnerabilities found yet
{% endif %}

## 风险等级分布

| Level | Count |
|------|------|
| Critical | {{ critical_count }} |
| High | {{ high_count }} |
| Medium | {{ medium_count }} |
| Low/Info | {{ low_count }} |

{% if llm_attack_summary %}
## Attack-Path Summary

{{ llm_attack_summary }}

{% elif step_summary and step_summary.total_steps > 0 %}
## Attack-Path Summary

{% for phase_name, phase_data in step_summary.phases.items() %}
### {{ phase_name }} ({{ phase_data.count }} steps)

| Status | Count |
|------|------|
| ✅ Success | {{ phase_data.success_count }} |
| ❌ Failure | {{ phase_data.failure_count }} |

**Key actions**: {{ phase_data.actions[:5]|join(', ') }}

{% if phase_data.key_results %}
**Main findings**:
{% for result in phase_data.key_results %}
- {{ result }}
{% endfor %}
{% endif %}

---
{% endfor %}

**Total**: {{ step_summary.total_steps }} steps

{% if step_summary.key_findings %}
### Key-finding timeline

{% for finding in step_summary.key_findings %}
- {{ finding }}
{% endfor %}
{% endif %}

{% elif recent_steps %}
## Attack-Path Summary

{% for step in recent_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}
{% endif %}

## Key Recommendations

{% for rec in recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}

---

> 🦞 Persistent Penetration Test Cycle Report | VulnClaw | {{ generated_at }}
> **Principle**: an unverified vulnerability = a false positive = not written to the report
"""


def _generate_attack_summary_from_session(session: SessionState) -> str:
    """Generate a readable attack-path summary using VulnClaw's configured LLM."""
    try:
        from vulnclaw.agent.think_filter import strip_think_tags
        from vulnclaw.config.settings import load_config, make_openai_client
        from vulnclaw.config.token_provider import (
            TokenResolutionError,
            has_llm_credentials,
            resolve_llm_token,
        )

        config = load_config()
        if not has_llm_credentials(config.llm):
            return ""

        try:
            token = resolve_llm_token(config.llm)
        except TokenResolutionError:
            return ""

        client = make_openai_client(
            api_key=token,
            base_url=config.llm.base_url,
        )

        steps = session.executed_steps[-40:] if session.executed_steps else []
        notes = session.notes[-25:] if session.notes else []
        findings = session.findings[-20:] if session.findings else []

        steps_text = (
            "\n".join(f"{idx + 1}. {step}" for idx, step in enumerate(steps))
            if steps
            else "No step records"
        )
        notes_text = "\n".join(f"- {note}" for note in notes) if notes else "No key observations"
        findings_text = (
            "\n".join(
                f"- [{finding.severity}] {finding.title} | Evidence: {(finding.evidence or '')[:200]}"
                for finding in findings
            )
            if findings
            else "No findings"
        )

        prompt = (
            f"Target: {session.target or 'unknown'}\n"
            f"Phase: {getattr(session.phase, 'value', str(session.phase))}\n\n"
            f"=== Executed Steps ===\n{steps_text}\n\n"
            f"=== Key Observations ===\n{notes_text}\n\n"
            f"=== Findings ===\n{findings_text}\n\n"
            "Please write a readable Chinese attack-path summary. Requirements:\n"
            "1. Clearly explain how the testing progressed, not generic filler.\n"
            "2. Mention URLs, paths, parameters, stack, and verification actions when available.\n"
            "3. Explicitly call out false positives or findings that failed to reproduce.\n"
            "4. Output 2-5 short natural-language paragraphs only. No markdown headings. No thinking tags.\n"
            "5. Do not invent steps that were never executed.\n"
        )

        response = client.chat.completions.create(
            **_build_report_summary_llm_kwargs(
                config,
                [{"role": "user", "content": prompt}],
            )
        )
        if response and response.choices:
            raw = response.choices[0].message.content or ""
            return strip_think_tags(raw).strip()
    except Exception as exc:
        print(f"[!] LLM attack summary generation failed: {exc}")
        return ""
    return ""


def _build_report_summary_llm_kwargs(config: Any, messages: list[dict[str, Any]]) -> dict[str, Any]:
    """Build Chat Completions kwargs for report summary generation."""
    from vulnclaw.agent.llm_client import build_chat_completion_kwargs

    class _AgentShim:
        def __init__(self, config: Any) -> None:
            self.config = config

    return build_chat_completion_kwargs(
        _AgentShim(config),
        messages,
        max_tokens=min(config.llm.max_tokens, 1200),
        temperature=0.2,
    )


def generate_persistent_cycle_report(
    session: SessionState,
    cycle_num: int,
    total_findings: int,
    new_findings: int,
    total_steps: int,
    rounds_per_cycle: int,
    output_path: Optional[str] = None,
    llm_attack_summary: str = "",  # ★ LLM-generated attack-path summary
    prev_verified_ids: Optional[set] = None,
) -> Path:
    """Generate a cycle report for persistent pentest.

    Only includes verified (verified=True) vulnerabilities.

    Args:
        session: Current session state with findings.
        cycle_num: Current cycle number (1-based).
        total_findings: Total findings so far (cumulative).
        new_findings: New findings in this cycle (all findings delta; used only
            as a fallback when prev_verified_ids is not supplied).
        total_steps: Total executed steps so far (cumulative).
        rounds_per_cycle: Rounds per cycle.
        output_path: Output file path. If None, auto-generate.
        prev_verified_ids: finding_id set of findings already verified before this
            cycle. When provided, "new this cycle" is computed by identity against
            this set instead of slicing by an all-findings count - the count-based
            slice mislabels prior verified findings as new when a cycle adds
            unverified findings.

    Returns:
        Path to the generated report file.
    """
    from vulnclaw import __version__
    from vulnclaw.report.filter import deduplicate_report_findings

    # ★ 包含所有 findings（包括 pending 和 confirmed，不只是 verified）
    all_findings = session.findings
    verified_findings = deduplicate_report_findings(session.get_verified_findings())
    manual_review_findings = (
        session.get_manual_review_findings()
        if hasattr(session, "get_manual_review_findings")
        else []
    )

    # Count verified findings by severity only (pending doesn't count as real result)
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in verified_findings:
        sev = finding.severity
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["Medium"] += 1

    # ★ 本周期新增已验证 findings（只统计 verified）
    if prev_verified_ids is not None:
        # 按 finding_id 身份判定本周期新验证的漏洞，避免用"全部 findings 增量"
        # 去切片"已验证子集"导致把往期漏洞误标为本周期新增。
        cycle_findings = [
            f for f in verified_findings if f.finding_id not in prev_verified_ids
        ]
    else:
        cycle_findings = verified_findings[-new_findings:] if new_findings > 0 else []

    # Generate recommendations from verified high/critical findings only
    # Deduplicate by vuln_type: only one recommendation per vulnerability type
    seen_vuln_types = set()
    recommendations = []
    for finding in verified_findings:
        if finding.severity in ("Critical", "High"):
            vt = finding.vuln_type or "Unclassified"
            if vt in seen_vuln_types:
                continue
            seen_vuln_types.add(vt)
            rec = finding.remediation or f"Fix the {vt} vulnerability: {finding.title}"
            recommendations.append(rec)
    if not recommendations:
        recommendations.append("No high-risk findings yet; keep testing deeper")

    if output_path is None:
        from vulnclaw.config.settings import SESSIONS_DIR

        safe_target = (session.target or "unknown").replace("/", "_").replace(":", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = str(
            SESSIONS_DIR / f"persistent_cycle{cycle_num:03d}_{timestamp}_{safe_target}.md"
        )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    from vulnclaw.report.poc_builder import generate_pocs

    pocs_dir = output.parent / "pocs"
    generate_pocs(session, pocs_dir)

    # Recent steps (last 20 to avoid bloat)
    recent_steps = session.executed_steps[-20:]

    # ★ 攻击路径摘要（过滤 LLM 原始输出中的 think 标签 / 调试标记）
    step_summary = session.get_step_summary()
    from vulnclaw.report.filter import ReportContentFilter

    if not llm_attack_summary:
        llm_attack_summary = _generate_attack_summary_from_session(session)
    filtered_summary = ReportContentFilter.filter(llm_attack_summary) if llm_attack_summary else ""

    context = {
        "target": session.target or "unspecified",
        "cycle_num": cycle_num,
        "rounds_per_cycle": rounds_per_cycle,
        "new_findings": len(cycle_findings),
        "total_findings": len(all_findings),
        "total_steps": total_steps,
        "generated_at": datetime.now().isoformat(),
        "version": __version__,
        "cycle_findings": cycle_findings,
        "all_findings": all_findings,  # ★ includes all findings (including pending)
        "critical_count": severity_counts["Critical"],
        "high_count": severity_counts["High"],
        "medium_count": severity_counts["Medium"],
        "low_count": severity_counts["Low"] + severity_counts["Info"],
        "recent_steps": recent_steps,
        "recommendations": recommendations,
        "manual_review_count": len(manual_review_findings),
        "step_summary": step_summary,
        "llm_attack_summary": filtered_summary,
    }

    # Render report
    template = Template(CYCLE_REPORT_TEMPLATE)
    report_content = template.render(**context)
    if verified_findings:
        report_content += "\n\n" + _render_verified_finding_details_clean(
            verified_findings,
            heading="## Verified Vulnerability Location & Reproduction Info",
        )
    output.write_text(report_content, encoding="utf-8")

    return output


def _render_target_state_context(target_state_context: dict[str, Any]) -> str:
    """Render extra governance context for target-state based reports."""
    resume_meta = target_state_context.get("resume_meta") or {}
    recon_meta = target_state_context.get("recon_meta") or {}
    runtime_meta = target_state_context.get("runtime_meta") or {}
    resume_summary = target_state_context.get("resume_summary") or ""

    lines = ["## 6. Target History Governance Context"]

    if resume_meta:
        lines.extend(
            [
                "",
                f"- Resume strategy: {resume_meta.get('resume_strategy', 'unknown')}",
                f"- Strategy reason: {resume_meta.get('resume_strategy_reason', 'N/A')}",
            ]
        )
        if resume_meta.get("priority_targets"):
            lines.append(f"- Priority resume targets: {', '.join(resume_meta['priority_targets'][:5])}")
        if resume_meta.get("priority_recon_assets"):
            lines.append(
                f"- Priority resume recon assets: {', '.join(resume_meta['priority_recon_assets'][:5])}"
            )
        if resume_meta.get("blocked_targets"):
            lines.append(f"- Blocked targets: {', '.join(resume_meta['blocked_targets'][:5])}")
        if resume_meta.get("failed_targets"):
            lines.append(f"- Historically failed targets: {', '.join(resume_meta['failed_targets'][:5])}")
        if resume_meta.get("recent_failed_steps"):
            lines.append("- Recent failed paths/steps:")
            for item in resume_meta["recent_failed_steps"][:5]:
                lines.append(f"  - {item}")

    top_assets = _top_recon_assets_for_report(recon_meta)
    if top_assets:
        lines.extend(["", "### High-value recon assets"])
        for item in top_assets[:8]:
            lines.append(f"- {item}")

    if runtime_meta.get("current_attack_path"):
        lines.extend(["", f"- Recent attack path: {runtime_meta['current_attack_path']}"])

    if resume_summary:
        lines.extend(["", "### Resume summary", "```text", resume_summary.strip(), "```"])

    return "\n".join(lines)


def _top_recon_assets_for_report(recon_meta: dict[str, Any]) -> list[str]:
    ranked: list[tuple[float, str]] = []
    for category, items in recon_meta.items():
        if not isinstance(items, dict):
            continue
        for value, meta in items.items():
            confidence = float(meta.get("confidence", 0))
            ranked.append((confidence, f"{category}:{value} (conf={confidence:.2f})"))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return [label for _, label in ranked]


def _extract_location_summary_clean(finding: VulnerabilityFinding) -> str:
    text = " ".join(part for part in [finding.evidence or "", finding.description or ""] if part)
    urls = re.findall(r'https?://[^\s<>"\')\]]+', text)
    paths = re.findall(r"(?:/[\w%&=?\-]+)+", text)

    items: list[str] = []
    seen: set[str] = set()
    for value in urls + paths:
        if value not in seen:
            seen.add(value)
            items.append(value)
        if len(items) >= 4:
            break
    return " | ".join(items)


def _build_repro_summary_clean(finding: VulnerabilityFinding) -> str:
    parts: list[str] = []
    if finding.poc_script:
        parts.append(f"Run the PoC script: {finding.poc_script}")
    if finding.verification_note:
        parts.append(f"Verification note: {finding.verification_note}")
    elif finding.evidence:
        parts.append(f"Reproduce from verified evidence: {finding.evidence[:160]}")
    if finding.verified_at:
        parts.append(f"Verified at: {finding.verified_at}")
    return "; ".join(parts) if parts else "No reproduction info available"


def _render_verified_finding_details_clean(
    findings: list[VulnerabilityFinding], heading: str
) -> str:
    lines = [heading, ""]
    for idx, finding in enumerate(findings, 1):
        location = _extract_location_summary_clean(finding) or "Not located / no URL extracted"
        lines.append(f"### {idx}. {finding.title} [{finding.severity}]")
        lines.append(f"- Vulnerability type: {finding.vuln_type or 'Unclassified'}")
        lines.append(f"- Lifecycle: {finding.lifecycle_status or 'verified'}")
        lines.append(f"- Evidence level: {finding.evidence_level or 'L4'}")
        lines.append(f"- Location / URL: {location}")
        if finding.evidence:
            lines.append(f"- Verification evidence: {finding.evidence}")
        lines.append(f"- Reproduction / PoC: {_build_repro_summary_clean(finding)}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _extract_location_summary(finding: VulnerabilityFinding) -> str:
    text = " ".join(part for part in [finding.evidence or "", finding.description or ""] if part)
    urls = re.findall(r'https?://[^\s<>"\')\]]+', text)
    paths = re.findall(r"(?:/[\w%&=?\-]+)+", text)

    items: list[str] = []
    seen: set[str] = set()
    for value in urls + paths:
        if value not in seen:
            seen.add(value)
            items.append(value)
        if len(items) >= 4:
            break
    return " | ".join(items)


def _build_repro_summary(finding: VulnerabilityFinding) -> str:
    parts: list[str] = []
    if finding.poc_script:
        parts.append(f"Run the PoC script: {finding.poc_script}")
    if finding.verification_note:
        parts.append(f"Verification note: {finding.verification_note}")
    elif finding.evidence:
        parts.append(f"Reproduce from verified evidence: {finding.evidence[:160]}")
    if finding.verified_at:
        parts.append(f"Verified at: {finding.verified_at}")
    return "; ".join(parts) if parts else "No reproduction info available"


def _format_task_constraints_summary(session: SessionState) -> str:
    constraints = getattr(session, "task_constraints", None)
    if constraints is None or constraints.is_empty():
        return "unspecified"

    parts: list[str] = []
    if constraints.allowed_ports:
        parts.append(f"only port {','.join(str(p) for p in constraints.allowed_ports)}")
    if constraints.blocked_ports:
        parts.append(f"blocked port {','.join(str(p) for p in constraints.blocked_ports)}")
    if constraints.allowed_hosts:
        parts.append(f"only host {','.join(constraints.allowed_hosts)}")
    if constraints.allowed_paths:
        parts.append(f"only path {','.join(constraints.allowed_paths)}")
    if constraints.allowed_actions:
        parts.append(f"only action {','.join(constraints.allowed_actions)}")
    if constraints.blocked_actions:
        parts.append(f"blocked action {','.join(constraints.blocked_actions)}")
    return "; ".join(parts) if parts else "constraints enabled"


def _build_report_finding(finding: VulnerabilityFinding) -> dict[str, Any]:
    return {
        "title": finding.title,
        "severity": finding.severity,
        "vuln_type": finding.vuln_type,
        "description": finding.description,
        "evidence": finding.evidence,
        "cve": finding.cve,
        "remediation": finding.remediation,
        "poc_script": finding.poc_script,
        "verified": finding.verified,
        "verified_at": finding.verified_at,
        "verification_status": finding.verification_status,
        "verification_note": finding.verification_note,
        "lifecycle_status": finding.lifecycle_status,
        "evidence_level": finding.evidence_level,
        "location_summary": _extract_location_summary(finding),
        "repro_summary": _build_repro_summary(finding),
    }


def _render_verified_finding_details(findings: list[VulnerabilityFinding], heading: str) -> str:
    lines = [heading, ""]
    for idx, finding in enumerate(findings, 1):
        location = _extract_location_summary(finding) or "Not located / no URL extracted"
        lines.append(f"### {idx}. {finding.title} [{finding.severity}]")
        lines.append(f"- Vulnerability type: {finding.vuln_type or 'Unclassified'}")
        lines.append(f"- Location / URL: {location}")
        if finding.evidence:
            lines.append(f"- Verification evidence: {finding.evidence}")
        lines.append(f"- Reproduction / PoC: {_build_repro_summary(finding)}")
        lines.append("")
    return "\n".join(lines).rstrip()
