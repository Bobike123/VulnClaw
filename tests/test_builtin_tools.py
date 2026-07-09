import json


class DummyRuntime:
    def __init__(self):
        self.python_timeout_rounds = 0


class DummySession:
    def __init__(self, target="https://example.com"):
        self.target = target
        from vulnclaw.agent.context import TaskConstraints

        self.task_constraints = TaskConstraints()


class DummySafety:
    def __init__(self):
        self.enable_python_execute = True
        self.python_execute_restricted = False
        self.python_execute_mode = "trusted-local"
        self.python_execute_max_lines = 50
        self.python_execute_show_warning = False
        self.python_execute_max_output_chars = 8000
        self.python_execute_audit_enabled = True


class DummyConfig:
    def __init__(self):
        self.safety = DummySafety()


class DummyAgent:
    def __init__(self):
        self.config = DummyConfig()
        self.runtime = DummyRuntime()
        self.session_state = DummySession()
        self.mcp_manager = None


class TestBuiltinPythonExecute:
    async def test_safe_mode_blocks_network_access(self, monkeypatch, tmp_path):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.config.safety.python_execute_mode = "safe"
        monkeypatch.setattr(builtin_tools, "_write_python_audit", lambda *args, **kwargs: None)

        result = await builtin_tools.execute_python(
            agent,
            {
                "code": "import requests\nprint(requests.get('https://example.com').status_code)",
                "purpose": "recon",
            },
        )
        assert "safe mode blocked operation" in result

    async def test_lab_mode_blocks_subprocess(self, monkeypatch):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.config.safety.python_execute_mode = "lab"
        monkeypatch.setattr(builtin_tools, "_write_python_audit", lambda *args, **kwargs: None)

        result = await builtin_tools.execute_python(
            agent,
            {"code": "import subprocess\nprint('x')", "purpose": "local helper"},
        )
        assert "lab mode blocked operation" in result

    async def test_trusted_local_allows_basic_code(self, monkeypatch):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.config.safety.python_execute_mode = "trusted-local"
        monkeypatch.setattr(builtin_tools, "_write_python_audit", lambda *args, **kwargs: None)

        result = await builtin_tools.execute_python(
            agent,
            {"code": "print('ok')", "purpose": "demo"},
        )
        assert "ok" in result

    async def test_audit_writer_emits_jsonl(self, monkeypatch, tmp_path):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()

        monkeypatch.setattr(
            "vulnclaw.config.settings.PYTHON_EXECUTE_AUDIT_FILE",
            tmp_path / "python_execute_audit.jsonl",
        )
        monkeypatch.setattr("vulnclaw.config.settings.ensure_dirs", lambda: None)

        builtin_tools._write_python_audit(
            agent,
            purpose="demo",
            code="print('x')",
            mode="safe",
            outcome="blocked",
            blocked_reason="requests",
        )

        content = (tmp_path / "python_execute_audit.jsonl").read_text(encoding="utf-8").strip()
        record = json.loads(content)
        assert record["mode"] == "safe"
        assert record["outcome"] == "blocked"
        assert record["blocked_reason"] == "requests"


class TestBuiltinMcpExecution:
    def test_build_openai_tools_filters_schema_by_active_role(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        class DummyMcpManager:
            def get_tool_schemas(self):
                return [
                    {
                        "name": "fetch",
                        "description": "Fetch a URL",
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ]

        tool_names = {
            tool["function"]["name"]
            for tool in builtin_tools.build_openai_tools(
                DummyMcpManager(), active_role="developer"
            )
        }

        assert "python_execute" in tool_names
        assert "crypto_decode" in tool_names
        assert "fetch" not in tool_names
        assert "nmap_scan" not in tool_names

    async def test_execute_mcp_tool_rejects_out_of_role_tool(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        class DummyMcpManager:
            async def call_tool(self, tool_name, args):
                return {"ok": True, "content": "should not run"}

        agent = DummyAgent()
        agent.active_role = "adviser"
        agent.mcp_manager = DummyMcpManager()

        result = await builtin_tools.execute_mcp_tool(
            agent, "python_execute", {"code": "print('should not run')"}
        )

        assert "role_tool_violation" in result
        assert "adviser" in result
        assert "python_execute" in result

    async def test_execute_loads_secknowledge_reference(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        result = await builtin_tools.execute_mcp_tool(
            agent,
            "load_skill_reference",
            {
                "skill_name": "secknowledge-skill",
                "reference_name": "web-sqli.md",
            },
        )

        assert "SQL" in result or "sql" in result
        assert "注入" in result or "injection" in result.lower()

    async def test_execute_mcp_tool_includes_structured_content_summary(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        class DummyMcpManager:
            async def call_tool(self, tool_name, args):
                return {
                    "ok": True,
                    "content": "navigated to page",
                    "structured_content": {"url": "https://example.com", "status": "ok"},
                }

        agent = DummyAgent()
        agent.mcp_manager = DummyMcpManager()

        result = await builtin_tools.execute_mcp_tool(
            agent, "navigate", {"url": "https://example.com"}
        )
        assert "navigated to page" in result
        assert "[structured]" in result
        assert '"status": "ok"' in result

    async def test_execute_fetch_blocks_tool_level_exploit_when_only_recon_allowed(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        class DummyMcpManager:
            async def call_tool(self, tool_name, args):
                return {"ok": True, "content": "should not run", "structured_content": {}}

        agent = DummyAgent()
        agent.mcp_manager = DummyMcpManager()
        agent.session_state.task_constraints.allowed_actions = ["recon"]
        agent.session_state.task_constraints.strict_mode = True

        result = await builtin_tools.execute_mcp_tool(
            agent,
            "fetch",
            {"url": "https://example.com/login?id=1' OR 1=1--", "method": "GET"},
        )
        assert "constraint_violation" in result
        assert "tool 'fetch'" in result

    async def test_execute_python_blocks_tool_level_exploit_when_only_recon_allowed(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.session_state.task_constraints.allowed_actions = ["recon"]
        agent.session_state.task_constraints.strict_mode = True

        result = await builtin_tools.execute_mcp_tool(
            agent,
            "python_execute",
            {"code": "import requests\nrequests.get('https://example.com/admin?cmd=whoami')"},
        )
        assert "constraint_violation" in result
        assert "tool 'python_execute'" in result

    async def test_execute_python_blocks_blocked_host(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.session_state.task_constraints.blocked_hosts = ["example.com"]
        agent.session_state.task_constraints.strict_mode = True

        result = await builtin_tools.execute_python(
            agent,
            {"code": "import requests\nrequests.get('https://example.com/admin')"},
        )
        assert "constraint_violation" in result
        assert "Host example.com" in result

    async def test_execute_python_allows_in_scope_host_with_port(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.session_state.task_constraints.allowed_hosts = ["localhost"]
        agent.session_state.task_constraints.strict_mode = True

        result = await builtin_tools.execute_python(
            agent,
            {"code": "import requests\nrequests.get('http://localhost:3000/home')"},
        )
        assert "constraint_violation" not in result

    async def test_execute_python_blocks_out_of_scope_host_with_port(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.session_state.task_constraints.allowed_hosts = ["localhost"]
        agent.session_state.task_constraints.strict_mode = True

        result = await builtin_tools.execute_python(
            agent,
            {"code": "import requests\nrequests.get('http://evil.example:8080/x')"},
        )
        assert "constraint_violation" in result
        assert "Host evil.example" in result

    async def test_execute_nmap_blocks_out_of_scope_port(self):
        import vulnclaw.agent.builtin_tools as builtin_tools

        agent = DummyAgent()
        agent.session_state.task_constraints.allowed_ports = [443]
        agent.session_state.task_constraints.strict_mode = True

        result = await builtin_tools.execute_nmap(
            agent,
            {"target": "example.com", "ports": "80", "scan_type": "tcp"},
        )
        assert "constraint_violation" in result
        assert "80" in result
        assert "443" in result
