"""Input analysis helpers for AgentCore."""

from __future__ import annotations

import re
from typing import Optional

from vulnclaw.agent.context import PentestPhase, TaskConstraints


def detect_phase(user_input: str) -> Optional[PentestPhase]:
    """Detect pentest phase from user input using keyword matching."""
    input_lower = user_input.lower()
    phase_keywords = {
        PentestPhase.RECON: [
            "信息收集",
            "侦察",
            "端口扫描",
            "子域名",
            "指纹",
            "目录扫描",
            "recon",
            "scan",
            "端口",
            "nmap",
            "收集",
        ],
        PentestPhase.VULN_DISCOVERY: [
            "漏洞发现",
            "漏洞扫描",
            "有什么漏洞",
            "cve",
            "安全检测",
            "vulnerability",
            "漏洞",
            "注入",
            "xss",
            "sqli",
        ],
        PentestPhase.EXPLOITATION: [
            "利用",
            "exploit",
            "poc",
            "验证漏洞",
            "执行命令",
            "rce",
            "getshell",
            "拿权限",
            "打一下",
            "尝试",
        ],
        PentestPhase.POST_EXPLOITATION: [
            "后渗透",
            "内网",
            "横向",
            "提权",
            "维持",
            "pivot",
            "post-exploitation",
            "隧道",
            "代理",
        ],
        PentestPhase.REPORTING: ["报告", "report", "总结", "整理", "生成报告"],
    }
    for phase, keywords in phase_keywords.items():
        if any(keyword in input_lower for keyword in keywords):
            return phase
    for pattern in (r"\d{1,3}(?:\.\d{1,3}){3}", r"https?://\S+"):
        if re.search(pattern, user_input):
            return PentestPhase.RECON
    return None


def detect_target(user_input: str) -> Optional[str]:
    """Extract target from user input."""
    for pattern in (
        r"(https?://[a-zA-Z0-9][-a-zA-Z0-9.:]*)",
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        r"([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)",
    ):
        match = re.search(pattern, user_input)
        if match:
            return match.group(1).rstrip("/.") if match.groups() else match.group(0)
    return None


def extract_task_constraints(user_input: str) -> TaskConstraints:
    """Extract structured hard constraints from natural-language user input."""
    text = user_input or ""
    lowered = text.lower()
    constraints = TaskConstraints()
    detected_target = detect_target(text)

    allowed_port_patterns = [
        r"(?:只测|仅测|只测试|仅测试|仅允许测试|只允许测试)\s*(\d{1,5})(?:\s*端口)?",
        r"(?:only|just)\s+(?:test|scan)\s+(?:port\s+)?(\d{1,5})",
    ]
    for pattern in allowed_port_patterns:
        for match in re.findall(pattern, text, flags=re.IGNORECASE):
            port = int(match)
            if 0 < port <= 65535 and port not in constraints.allowed_ports:
                constraints.allowed_ports.append(port)

    blocked_group_patterns = [
        r"(?:不要碰|不要测|禁止测试|禁止扫描|不要扫描)\s*([0-9,\s和及与、]+)(?:\s*端口)?",
    ]
    for pattern in blocked_group_patterns:
        for group in re.findall(pattern, text):
            for match in re.findall(r"\d{1,5}", group):
                port = int(match)
                if 0 < port <= 65535 and port not in constraints.blocked_ports:
                    constraints.blocked_ports.append(port)

    if any(
        token in lowered for token in ["仅做信息收集", "只做信息收集", "recon only", "only recon"]
    ):
        constraints.allowed_actions = ["recon"]
    if any(token in lowered for token in ["不要利用", "禁止利用", "do not exploit", "no exploit"]):
        constraints.blocked_actions.append("exploit")

    allow_match = re.search(r"only allowed actions:\s*([a-z_,\s-]+)", lowered)
    if allow_match:
        constraints.allowed_actions = [
            item.strip() for item in allow_match.group(1).split(",") if item.strip()
        ]

    block_match = re.search(r"blocked actions:\s*([a-z_,\s-]+)", lowered)
    if block_match:
        constraints.blocked_actions.extend(
            [
                item.strip()
                for item in block_match.group(1).split(",")
                if item.strip() and item.strip() not in constraints.blocked_actions
            ]
        )

    if any(
        token in lowered
        for token in ["只测这个路径", "仅测试这个路径", "只测试这个路径", "只测该路径"]
    ):
        path_match = re.search(r"https?://[^\s]+(/[^\s?#]*)", text)
        if not path_match:
            path_match = re.search(r"(/[A-Za-z0-9._/\-]+)", text)
        if path_match:
            path = path_match.group(1).rstrip("/")
            if path and path not in constraints.allowed_paths:
                constraints.allowed_paths.append(path)

    blocked_host_match = re.search(r"blocked host\s+([a-z0-9.-]+)", lowered)
    if blocked_host_match:
        host = blocked_host_match.group(1).strip()
        if host and host not in constraints.blocked_hosts:
            constraints.blocked_hosts.append(host)

    blocked_path_match = re.search(r"blocked path\s+(/[^\s]+)", lowered)
    if blocked_path_match:
        path = blocked_path_match.group(1).rstrip("/")
        if path and path not in constraints.blocked_paths:
            constraints.blocked_paths.append(path)

    if detected_target:
        target_lower = detected_target.lower()
        if target_lower.startswith("http://") or target_lower.startswith("https://"):
            host_match = re.search(r"^https?://([^/:?#]+)", target_lower)
            if host_match:
                host = host_match.group(1)
                if host and host not in constraints.allowed_hosts:
                    constraints.allowed_hosts.append(host)
        elif "." in target_lower:
            if target_lower not in constraints.allowed_hosts:
                constraints.allowed_hosts.append(target_lower)

    if (
        constraints.allowed_ports
        or constraints.blocked_ports
        or constraints.allowed_hosts
        or constraints.blocked_hosts
        or constraints.allowed_paths
        or constraints.blocked_paths
        or constraints.allowed_actions
        or constraints.blocked_actions
    ):
        constraints.strict_mode = True

    return constraints


def extract_user_vuln_hint(user_input: str) -> str:
    """Extract explicit vulnerability hints from user input."""
    vuln_keywords = [
        "SQL注入",
        "SQLi",
        "XSS",
        "RCE",
        "命令注入",
        "文件包含",
        "路径遍历",
        "LFI",
        "RFI",
        "SSRF",
        "CSRF",
        "弱口令",
        "暴力破解",
        "认证绕过",
        "未授权",
        "信息泄露",
        "敏感信息泄露",
    ]
    user_lower = user_input.lower()
    found_vulns = [v for v in vuln_keywords if v.lower() in user_lower]
    if not found_vulns:
        return ""
    url_match = re.search(r"https?://\S+", user_input)
    path_match = re.search(r"/[\w\-./?=&%#]+", user_input)
    target = url_match.group(0) if url_match else (path_match.group(0) if path_match else "")
    vuln_str = "/".join(found_vulns[:3])
    if target:
        return (
            f"[Explicit user hint - Round 1]\n"
            f"The user explicitly told you that [{target}] has a [{vuln_str}] vulnerability.\n"
            f"\n"
            f"→ You must immediately construct and send a PoC test request!\n"
            f"→ Use the fetch tool to send the request directly and observe the real response!\n"
            f"→ Do not explore paths or do recon first - test the vulnerability directly!\n"
            f"\n"
            f"{get_payload_examples(found_vulns, target)}"
        )
    return (
        f"[Explicit user hint]\n"
        f"The user asked you to test a [{vuln_str}] vulnerability.\n"
        f"→ Immediately construct a PoC test from the already-discovered target info; do not do extra recon first!"
    )


def get_payload_examples(found_vulns: list[str], target: str) -> str:
    """Return concrete PoC payload examples for the given vulnerability types."""
    lines = ["[PoC payload examples]"]
    for vuln in found_vulns[:2]:
        if "SQL" in vuln:
            lines += [
                "SQL injection test (boolean blind):",
                f"  GET {target}?id=1' AND 1=1--  → observe the response length",
                f"  GET {target}?id=1' AND 1=2--  → is the length different?",
                "SQL injection test (error-based):",
                f"  GET {target}?id=1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
            ]
        elif "XSS" in vuln:
            lines += [
                "XSS test:",
                f"  GET {target}?q=<script>alert(1)</script>  → does the page reflect this content?",
                f"  GET {target}?q=<img src=x onerror=alert(1)>",
            ]
        elif "RCE" in vuln or "命令注入" in vuln:
            lines += [
                "RCE / command-injection test:",
                f"  GET {target}?cmd=whoami  → check for command output",
                f"  GET {target}?c=whoami  → try different parameter names",
            ]
        elif "文件包含" in vuln or "路径遍历" in vuln or "LFI" in vuln or "RFI" in vuln:
            lines += [
                "File-inclusion / path-traversal test:",
                f"  GET {target}?f=/etc/passwd  → read a system file",
                f"  GET {target}?f=../../../../etc/passwd",
            ]
        elif "SSRF" in vuln:
            lines += [
                "SSRF test:",
                f"  GET {target}?url=http://127.0.0.1  → any response?",
                f"  GET {target}?url=http://169.254.169.254/latest/meta-data/",
            ]
    return "\n".join(lines[:12])


def build_user_vuln_directive(user_input: str) -> str:
    """Backward-compatible alias for explicit vulnerability hint extraction."""
    return extract_user_vuln_hint(user_input)
