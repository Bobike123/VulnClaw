"""VulnClaw Knowledge Updater - update and seed the knowledge base."""

from __future__ import annotations

from vulnclaw.kb.store import KnowledgeStore


def seed_knowledge_base(store: KnowledgeStore) -> None:
    """Seed the knowledge base with initial data.

    This populates the KB with essential security knowledge for MVP.
    """
    # ── CVE Entries ──────────────────────────────────────────────

    cves = [
        {
            "id": "CVE-2026-21858",
            "title": "n8n Arbitrary File Read via Public Form",
            "description": "n8n versions >= 1.65.0 and < 1.121.0 allow unauthenticated "
            "arbitrary file read through public form submission endpoints when "
            "a workflow contains a Form Ending node returning a binary file.",
            "severity": "Critical",
            "affected": "n8n >= 1.65.0, < 1.121.0",
            "tags": ["n8n", "file-read", "rce", "critical"],
            "exploitation_steps": [
                "Identify a public form path on the n8n instance",
                "Send POST request with forged files object containing filepath",
                "Read server files including /etc/passwd, config, database",
                "Extract encryption key from config",
                "Use extracted credentials to login",
                "Create malicious workflow with expression injection for RCE",
            ],
            "remediation": "Upgrade to n8n >= 1.121.0",
        },
        {
            "id": "CVE-2025-68613",
            "title": "n8n Authenticated Expression Injection RCE",
            "description": "Authenticated expression injection in n8n allows RCE via "
            "malicious workflow expressions.",
            "severity": "Critical",
            "affected": "n8n >= 0.211.0, < 1.120.4",
            "tags": ["n8n", "rce", "expression-injection", "critical"],
            "exploitation_steps": [
                "Login with valid credentials",
                "Create a workflow with manualTrigger + set node",
                "Insert expression payload: ={{ (function(){...execSync(cmd)...})() }}",
                "Run the workflow",
                "Read execution result for command output",
            ],
            "remediation": "Upgrade to n8n >= 1.120.4 or 1.121.1",
        },
    ]

    for cve in cves:
        existing = store.get_entry("cve", cve["id"])
        if not existing:
            store.add_entry("cve", cve["id"], cve)

    # ── Technique Entries ────────────────────────────────────────

    techniques = [
        {
            "id": "sqli-bypass",
            "title": "SQL injection bypass techniques",
            "description": "Methods for constructing SQL injection payloads that bypass a WAF",
            "tags": ["sqli", "waf-bypass", "web"],
            "bypass_methods": [
                "Case mixing: SeLeCt",
                "Inline comment: S/*!ELECT*/",
                "Double encoding: %2565",
                "Equivalent functions: GROUP_CONCAT instead of concat_ws",
            ],
        },
        {
            "id": "rce-bypass-php",
            "title": "PHP command-execution bypass techniques",
            "description": "Constructing command-execution payloads that bypass a PHP WAF",
            "tags": ["rce", "waf-bypass", "php", "web"],
            "bypass_methods": [
                "Base64-encoded function name: $f=base64_decode('c3lzdGVt');$f('id');",
                "String concatenation: $f='sys'.'tem';$f('id');",
                "Split path: '/va'.'r/ww'.'w/ht'.'ml'",
                "Reversed string: $f=strrev('metsys');$f('id');",
            ],
        },
        {
            "id": "xss-bypass",
            "title": "XSS bypass techniques",
            "description": "Constructing payloads that bypass WAF/XSS filters",
            "tags": ["xss", "waf-bypass", "web"],
            "bypass_methods": [
                "Event handler: <img src=x onerror=alert(1)>",
                "SVG tag: <svg onload=alert(1)>",
                "HTML entity encoding",
                "Unicode encoding",
            ],
        },
        {
            "id": "cmd-injection-bypass",
            "title": "Command-injection bypass techniques",
            "description": "Methods for bypassing command-injection filters",
            "tags": ["command-injection", "waf-bypass", "web"],
            "bypass_methods": [
                "Newline: id\\nwhoami",
                "Pipe: id|whoami",
                "Variable concatenation: a=i;b=d;$a$b",
                "Wildcards: /bin/ca? /etc/pas?d",
            ],
        },
    ]

    for tech in techniques:
        existing = store.get_entry("techniques", tech["id"])
        if not existing:
            store.add_entry("techniques", tech["id"], tech)

    # ── Tool Guides ──────────────────────────────────────────────

    tools = [
        {
            "id": "nmap",
            "title": "Nmap port-scan cheatsheet",
            "description": "Common Nmap scan commands and options",
            "tags": ["nmap", "recon", "scanning"],
            "commands": [
                "nmap -sV -sC -p- TARGET    # All-port scan + version detection",
                "nmap -sS -TOP_PORTS 1000 TARGET   # SYN scan of top 1000 ports",
                "nmap --script vuln TARGET   # Vulnerability-scan scripts",
                "nmap -sU -TOP_PORTS 100 TARGET     # UDP scan",
            ],
        },
        {
            "id": "burp",
            "title": "Burp Suite workflow",
            "description": "Burp Suite penetration-testing workflow",
            "tags": ["burp", "proxy", "web"],
            "workflow": [
                "Configure the browser proxy → Burp",
                "Browse the target site and collect requests",
                "Analyze parameters and endpoints in the requests",
                "Use Intruder for fuzzing",
                "Use Repeater to manually verify vulnerabilities",
            ],
        },
    ]

    for tool in tools:
        existing = store.get_entry("tools", tool["id"])
        if not existing:
            store.add_entry("tools", tool["id"], tool)
