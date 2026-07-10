# VulnClaw Tutorial — Setup & Usage

This guide takes you from a clean machine to running VulnClaw in all three interfaces: the **CLI/REPL**, the **TUI workbench**, and the **Web UI**. VulnClaw is an AI-powered penetration-testing assistant for **authorized** security testing only — you must have written permission for every target you test.

> New to the safety model? Read [SECURITY.md](SECURITY.md) first. VulnClaw is default-deny: nothing beyond `localhost` runs until you authorize it.

---

## 1. Prerequisites

| Requirement | Why | Notes |
|-------------|-----|-------|
| **Python ≥ 3.10** | Runs the agent | `python3 --version` |
| **pip** or **uv** | Installs the package | |
| **Node.js + npx** (optional) | Some MCP services (e.g. Chrome DevTools) | `node --version` |
| **nmap** (optional) | Port scanning | `nmap --version` |
| An **LLM API key** *or* keyless auth | The agent's brain | OpenAI-compatible, DeepSeek, MiniMax, etc. |

---

## 2. Install

### From PyPI (recommended)

```bash
pip install vulnclaw
```

### From source

```bash
git clone https://github.com/<your-fork>/VulnClaw.git
cd VulnClaw
pip install -e .
```

Verify the install:

```bash
vulnclaw --version
vulnclaw doctor          # checks Python, Node, npx, nmap, LLM config, MCP services
```

`vulnclaw doctor` is your friend whenever something looks off.

---

## 3. First-time configuration

### 3a. Pick a provider and set your API key

```bash
# List built-in providers (auto-fills base URL + mvulodel names)
vulnclaw config provider

# Switch to a providersource 
vulnclaw config provider deepseek

# Set your API key
vulnclaw config set llm.api_key sk-your-key-here
```

Config is stored at `~/.vulnclaw/config.yaml`, written **owner-only (0600)** because it holds secrets.

### 3b. Or use keyless auth

If you have a ChatGPT subscription or environment/file/command credential source:

```bash
vulnclaw login            # browser login (see docs/keyless-auth.md; note ToS risk)
# or set llm.auth_mode to env / file / command / wif
```

### 3c. Confirm it's ready

```bash
vulnclaw doctor --security
```

This prints your full posture: scope enforcement, approval mode, enabled risky capabilities, budget ceilings, audit status, and secret-file permissions.

---

## 4. Authorize your scope (do this before testing anything)

VulnClaw refuses to touch anything beyond `localhost` unless it's in scope.

```bash
vulnclaw scope init                       # writes .vulnclaw-scope.yaml in the current dir
```

Edit `.vulnclaw-scope.yaml` — add the domains / IP ranges / ports you are **authorized** to test:

```yaml
allow:
  domains:
    - localhost
    - example-lab.test          # subdomains match automatically
  ip_ranges:
    - 127.0.0.1/32
  ports: [80, 443, 8080]
deny:
  domains: [admin.example-lab.test]   # deny always wins
allowed_phases: [recon, scan]         # exploit_validation stays OFF unless listed
```

Test whether a target is in scope:

```bash
vulnclaw scope show                       # show the resolved scope
vulnclaw scope check https://example-lab.test/   # exit 0 = in scope, 1 = out
```

---

## 5. Using the CLI / REPL (default interface)

### Interactive REPL

```bash
vulnclaw                # opens the REPL
```

Inside the REPL you can type natural-language goals ("recon example-lab.test and look for exposed admin panels") and use slash commands. Type `/help` for the list.

### One-shot commands

```bash
vulnclaw recon example-lab.test                 # reconnaissance only (no exploitation)
vulnclaw scan  example-lab.test --ports 80,443  # vulnerability scanning
vulnclaw run   example-lab.test                 # full goal-driven run (solve engine)
vulnclaw exploit example-lab.test --cve CVE-2024-1234   # exploitation phase (needs approval)
vulnclaw report session_xxx.json                # generate a report from a session
```

### Persistent (open-ended) mode

```bash
vulnclaw persistent example-lab.test
```

Persistent mode runs cycles until it stops making progress. It is bounded by **safety budgets** (`budget.*` config) and you can stop it at any time:

```bash
touch .vulnclaw-STOP     # halts the run at the next checkpoint
```

### High-risk actions need approval

Exploitation, brute-force, OSINT, PoC generation, browser interaction, and request mutation are **default-deny**. To allow them for an authorized engagement:

1. Enable the capability: `vulnclaw config set risky_tools.enable_exploit true`
2. Make sure the scope permits the phase (`allowed_phases`).
3. Approve the action — either run in interactive mode, or add a signed entry to `.vulnclaw-approvals.yaml`:

```yaml
approvals:
  - action: exploit
    target: example-lab.test
    tool: "*"
```

Set the mode with `vulnclaw config set approval.mode interactive` (or `dry-run` to preview without executing).

---

## 6. Using the TUI workbench

A full-screen terminal UI with panels for targets, findings, and diagnostics:

```bash
vulnclaw tui                              # open the workbench
vulnclaw tui --target example-lab.test    # pre-fill a target
```

Navigate with the arrow keys / listed shortcuts. The TUI includes an environment-diagnostics panel (equivalent to `vulnclaw doctor`) and an in-app config editor for provider, model, and API key. Language and other settings are editable there too.

---

## 7. Using the Web UI

```bash
vulnclaw web                     # starts the local server (default http://127.0.0.1:7788)
vulnclaw web --port 8080         # custom port
```

Open the printed address in your browser. The interface is **dark-mode** and English.

- If you see the **fallback shell** page, the backend is running but the React frontend has.n't been built. Build it:

  ```bash
  cd frontend
  npm install
  npm run build
  ```

  Then restart `vulnclaw web`.

- The full UI provides a home check wizard, findings/evidence, a report center, the safety-boundary page (shows what was blocked and why), history/snapshots, and settings.

The Web UI honors the same scope, approval, budget, and audit controls as the CLI — nothing bypasses the safety spine.

---

## 8. Reviewing the audit trail

Every safety-relevant action is recorded in a tamper-evident, hash-chained log.

```bash
vulnclaw audit list                 # sessions on disk
vulnclaw audit inspect              # summarize the latest session + verify its chain
vulnclaw audit verify <file>        # verify a chain (exit 1 if tampered)
```

---

## 9. Language

The app defaults to **English**. To force a language:

```bash
export VULNCLAW_LANG=en      # or zh
# or
vulnclaw config set session.language en
```

---

## 10. Quick reference

| Task | Command |
|------|---------|
| Health / environment check | `vulnclaw doctor` |
| Security posture | `vulnclaw doctor --security` |
| Set provider / key | `vulnclaw config provider <name>` · `vulnclaw config set llm.api_key <key>` |
| Create scope | `vulnclaw scope init` → edit `.vulnclaw-scope.yaml` |
| Check a target | `vulnclaw scope check <target>` |
| Recon / scan / run | `vulnclaw recon\|scan\|run <target>` |
| Persistent mode | `vulnclaw persistent <target>` (stop with `touch .vulnclaw-STOP`) |
| TUI | `vulnclaw tui` |
| Web UI | `vulnclaw web` |
| Audit | `vulnclaw audit list\|inspect\|verify` |

---

**Reminder:** VulnClaw is for authorized testing, security research, and CTFs only. Running it against systems you do not have written permission to test is illegal. See [SECURITY.md](SECURITY.md).
