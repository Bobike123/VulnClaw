"""Audit trail is actually written by the central tool chokepoint.

The AuditLogger unit is covered by test_safety_audit.py; here we prove it is
wired into execute_mcp_tool so real tool calls and denials reach the log.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from vulnclaw.agent import builtin_tools
from vulnclaw.agent.context import TaskConstraints
from vulnclaw.safety.scope import Scope, ScopeAllow, ScopeValidator


class _Session:
    def __init__(self) -> None:
        self.target = "target.test"
        self.started_at = "2026-07-10T00:00:00"
        self.task_constraints = TaskConstraints()
        self.events: list[dict] = []

    def add_constraint_violation_event(self, **kwargs) -> None:
        self.events.append(kwargs)


class _Mcp:
    def __init__(self) -> None:
        self.called: list[tuple] = []

    async def call_tool(self, name, args):
        self.called.append((name, args))
        return {"ok": True, "content": f"hit {args.get('url')}", "structured_content": {}}


def _agent(audit_dir, *, enabled=True):
    validator = ScopeValidator(
        Scope(allow=ScopeAllow(domains=["target.test"])),
        enforce=True,
        allow_localhost=True,
    )
    agent = SimpleNamespace()
    agent.config = SimpleNamespace(
        safety=SimpleNamespace(enable_python_execute=False),
        audit=SimpleNamespace(enabled=enabled, hash_chain=True, audit_dir=str(audit_dir)),
        llm=SimpleNamespace(model="gpt-x", provider="openai"),
    )
    agent.runtime = SimpleNamespace(python_timeout_rounds=0)
    agent.session_state = _Session()
    agent.mcp_manager = _Mcp()
    agent._scope_validator = validator
    return agent


def _events(audit_dir) -> list[dict]:
    files = list(audit_dir.glob("session-*.jsonl"))
    assert files, "no audit file written"
    records = []
    for line in files[0].read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


class TestAuditWiring:
    async def test_dispatched_call_is_logged(self, tmp_path):
        agent = _agent(tmp_path)
        await builtin_tools.execute_mcp_tool(
            agent, "fetch", {"url": "https://target.test/x", "method": "GET"}
        )
        events = _events(tmp_path)
        kinds = [e["event"] for e in events]
        assert "session_start" in kinds
        assert "tool_call" in kinds
        tc = next(e for e in events if e["event"] == "tool_call")
        assert tc["data"]["tool"] == "fetch"
        assert tc["data"]["status"] == "dispatched"

    async def test_scope_denial_is_logged(self, tmp_path):
        agent = _agent(tmp_path)
        await builtin_tools.execute_mcp_tool(
            agent, "fetch", {"url": "https://evil.example/x", "method": "GET"}
        )
        events = _events(tmp_path)
        denied = [e for e in events if e["event"] == "denied"]
        assert denied and denied[0]["data"]["action"] == "scope"
        assert agent.mcp_manager.called == []

    async def test_chain_is_intact(self, tmp_path):
        from vulnclaw.safety.audit import verify_chain

        agent = _agent(tmp_path)
        for i in range(3):
            await builtin_tools.execute_mcp_tool(
                agent, "fetch", {"url": f"https://target.test/{i}", "method": "GET"}
            )
        audit_file = list(tmp_path.glob("session-*.jsonl"))[0]
        assert verify_chain(audit_file) is True

    async def test_disabled_writes_nothing(self, tmp_path):
        agent = _agent(tmp_path, enabled=False)
        await builtin_tools.execute_mcp_tool(
            agent, "fetch", {"url": "https://target.test/x", "method": "GET"}
        )
        assert list(tmp_path.glob("session-*.jsonl")) == []

    async def test_file_write_records_mutation_with_path(self, tmp_path):
        agent = _agent(tmp_path)
        agent.project_dir = tmp_path  # jail root for the file tools
        result = await builtin_tools.execute_mcp_tool(
            agent, "file_write", {"path": "poc.py", "content": "print('pwned')\n"}
        )
        assert result.startswith("[✓]")
        assert (tmp_path / "poc.py").read_text() == "print('pwned')\n"

        events = _events(tmp_path)
        mutations = [e for e in events if e["event"] == "file_mutation"]
        assert mutations, "file_write did not produce a file_mutation audit record"
        data = mutations[0]["data"]
        assert data["tool"] == "file_write"
        assert data["path"] == "poc.py"
        assert data["ok"] is True

    async def test_failed_file_edit_records_mutation_not_ok(self, tmp_path):
        agent = _agent(tmp_path)
        agent.project_dir = tmp_path
        # Editing a file that doesn't exist fails; the audit must still record it,
        # marked ok=false, so the trail shows attempted-but-failed mutations too.
        result = await builtin_tools.execute_mcp_tool(
            agent, "file_edit", {"path": "missing.py", "old_string": "a", "new_string": "b"}
        )
        assert result.startswith("[!]")
        mutations = [e for e in _events(tmp_path) if e["event"] == "file_mutation"]
        assert mutations and mutations[0]["data"]["ok"] is False
        assert mutations[0]["data"]["path"] == "missing.py"
