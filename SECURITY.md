# Security Policy

## Authorized Testing & Legal Warning

VulnClaw is designed for legal, authorized penetration testing, security auditing, and educational Capture the Flag (CTF) challenges. Running automated scans or exploit payloads against unauthorized targets is illegal. Ensure you have explicit written consent from target owners before initiating any operations.

## Safety Architecture

VulnClaw is **default-deny**: nothing beyond the local machine is contacted, and no high-risk capability runs, unless you explicitly authorize it. The controls below live in `vulnclaw/safety/` and are enforced at a single central chokepoint (`builtin_tools.execute_mcp_tool`) that every tool call passes through.

### 1. Engagement scope (the authorization boundary)

All target-directed network activity is checked against an engagement scope before it runs. Scope is deny-by-default: `localhost` is allowed, private-lab ranges require an opt-in, and public targets **must** be explicitly allowlisted.

- Define scope in `./.vulnclaw-scope.yaml` (or point `scope.scope_file` at one). Run `vulnclaw scope init` to generate a starter file.
- Deny entries always win over allow entries (deny precedence).
- Inspect and test it:

```bash
vulnclaw scope init                       # write a starter .vulnclaw-scope.yaml
vulnclaw scope show                       # show the resolved scope + enforcement
vulnclaw scope check https://api.target/  # is a target in scope? (exit 1 if not)
```

### 2. Human-approval gates for high-risk actions

Exploitation, post-exploitation, credential brute-force, OSINT, JS-secret extraction, PoC generation, active browser interaction (form submit / click / in-page JS), and crafted-request mutation (Burp / browser network context) require explicit approval before running.

- Modes: `dry-run` (never executes — explains what would happen), `interactive` (prompt on a TTY), `non-interactive` (requires a matching entry in a signed `./.vulnclaw-approvals.yaml`). There is **no silent auto-approve**.
- Configure via `approval.mode` / `approval.require_approval` or `VULNCLAW_APPROVAL_MODE`.

### 3. Risky-capability switches (all default-off)

Every high-risk capability has an enable switch under `risky_tools.*`, all defaulting to `false`. A capability runs only when it is enabled **and** scope permits it **and** the action is approved. Switches: `enable_exploit`, `enable_post_exploitation`, `enable_waf_bypass`, `enable_persistent`, `enable_poc_generation`, `enable_js_secret_extraction`, `enable_osint`, `enable_brute_force`, `enable_browser`, `enable_request_mutation` (also settable via `VULNCLAW_RISKY_ENABLE_*`).

### 4. Persistent-mode budgets & emergency stop

Open-ended persistent runs enforce opt-in ceilings (wall-clock duration, cycles, total tool calls; `0` = unlimited) under `budget.*` / `VULNCLAW_BUDGET_*`. Independently, an **emergency stop** halts a run out-of-band:

```bash
touch .vulnclaw-STOP     # halts the persistent run at the next checkpoint
```

The stop file is honoured even when budgets are otherwise disabled.

### 5. Tamper-evident audit trail

Every safety-relevant event — session start, tool call, scope denial, approval decision, budget stop — is appended to a per-session JSONL log, each record hash-chained to the previous one so edits, deletions, or reordering are detectable. Secrets are redacted before writing.

```bash
vulnclaw audit list                 # sessions on disk
vulnclaw audit inspect              # summarize the latest session + verify chain
vulnclaw audit verify <file>        # verify a chain (exit 1 if broken)
```

### 6. Secret handling & the python_execute sandbox

- The config file (which holds API keys) is written owner-only (`0600`), and the config directory is kept `0700`. `vulnclaw doctor --security` flags any secret file with loose permissions.
- Secrets are scrubbed from logs, reports, and audit records via `vulnclaw/safety/redaction.py`.
- `python_execute` **defaults to disabled** and runs in a hardened, best-effort sandbox (dedicated workdir, scrubbed environment, path/network guards, POSIX resource limits, subprocess/ctypes prechecks). **It is defense-in-depth, not containment** — do not rely on it to run untrusted code. Enable it only in controlled environments.

### Reviewing your posture

```bash
vulnclaw doctor --security
```

prints scope enforcement, approval mode, enabled risky capabilities, budget ceilings, audit status, and secret-file permissions in one place.

## Reporting a Vulnerability

If you identify a security vulnerability in the VulnClaw agent framework (e.g. command injections, logic bypasses, or unsafe payload executions), please do **not** open a public issue.

Please report vulnerabilities privately by emailing the repository owner or using GitHub's private vulnerability reporting system.

We will review your submission and coordinate a patch swiftly.
