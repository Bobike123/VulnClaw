"""Dynamic system prompt assembly for AgentCore."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from vulnclaw.agent.prompts import AUTO_PENTEST_INSTRUCTION, RECON_INSTRUCTION, build_system_prompt

if TYPE_CHECKING:
    from vulnclaw.agent.context import TaskConstraints


def build_dynamic_system_prompt(
    *,
    target: Optional[str],
    phase: Optional[str],
    skill_context: Optional[str],
    mcp_tools: list[dict],
    enable_personnel_dim: bool,
    auto_mode: bool,
    user_input: Optional[str],
    kb_context: str,
    task_constraints: Optional["TaskConstraints"] = None,
) -> str:
    """Build the dynamic system prompt for one turn."""
    prompt = build_system_prompt(
        target=target,
        phase=phase,
        skill_context=skill_context,
        mcp_tools=mcp_tools,
        enable_personnel_dim=enable_personnel_dim,
    )

    if auto_mode:
        prompt += "\n\n" + AUTO_PENTEST_INSTRUCTION

    if user_input:
        recon_triggers = [
            # Chinese
            "搜集",
            "收集",
            "信息收集",
            "侦察",
            "社会工程",
            "社工",
            "调查",
            "作者",
            "人物",
            "情报",
            "分析目标",
            "目标分析",
            "资产发现",
            "子域名",
            # English
            "recon",
            "osint",
            "gather",
            "collect information",
            "reconnaissance",
            "social engineering",
            "investigate",
            "author",
            "persona",
            "intelligence",
            "analyze target",
            "asset discovery",
            "subdomain",
        ]
        if any(trigger in user_input.lower() for trigger in recon_triggers):
            if enable_personnel_dim:
                prompt += "\n\n" + RECON_INSTRUCTION
            else:
                recon_no_personnel = RECON_INSTRUCTION.replace(
                    "### Dimension 4: Personnel information ⚡ conditional",
                    "### Dimension 4: Personnel information ⚡ conditional "
                    "(not activated this run - user did not mention social-eng / people-tracking needs)",
                )
                recon_no_personnel = (
                    recon_no_personnel.replace(
                        "- [ ] Name & role",
                        "- [x] Name & role (not activated, skipped)",
                    )
                    .replace(
                        "- [ ] Birthday & phone number",
                        "- [x] Birthday & phone number (not activated, skipped)",
                    )
                    .replace(
                        "- [ ] Email address",
                        "- [x] Email address (not activated, skipped)",
                    )
                    .replace(
                        "- [ ] Social-media accounts (Bilibili, Weibo, Zhihu, Twitter, LinkedIn, GitHub)",
                        "- [x] Social-media accounts (not activated, skipped)",
                    )
                    .replace(
                        "- [ ] Cross-platform correlation (search other platforms by username/email; check emails in commit history)",
                        "- [x] Cross-platform correlation (not activated, skipped)",
                    )
                )
                prompt += "\n\n" + recon_no_personnel

    if kb_context:
        prompt += "\n\n" + kb_context

    if task_constraints is not None:
        constraints_block = task_constraints.to_prompt_block()
        if constraints_block:
            prompt += "\n\n" + constraints_block

    return prompt
