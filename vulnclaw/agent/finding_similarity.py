"""VulnClaw Finding Similarity - lightweight semantic deduplication.

Pure-Python semantic deduplication of vulnerability findings, with no external NLP libraries.

Core capabilities:
    - normalize_text:        text normalization (lowercase, collapse whitespace, normalize URL paths)
    - normalize_vuln_type:   vuln-type normalization (alias mapping, e.g. "sqli" -> "sql_injection")
    - text_similarity:       word-set Jaccard similarity
    - url_similarity:        parse URLs and compare host / path / query parameters
    - finding_similarity:    combined vuln_type / location / description similarity
    - deduplicate_findings:  dedupe by a similarity threshold, keeping the better-evidenced side

Complements the existing finding_id hash dedup: hash dedup handles exact matches,
this module handles semantic fuzzy matching of "the same vulnerability worded differently".
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional
from urllib.parse import parse_qs, urlsplit

if TYPE_CHECKING:
    from vulnclaw.agent.context import VulnerabilityFinding


# ── 漏洞类型归一化映射 ───────────────────────────────────────────────────

# Alias -> canonical type. Keys are normalized to lowercase, space-collapsed form.
_VULN_TYPE_ALIASES: dict[str, str] = {
    # SQL 注入
    "sqli": "sql_injection",
    "sql注入": "sql_injection",
    "sql injection": "sql_injection",
    "blind sqli": "sql_injection",
    "盲注": "sql_injection",
    "注入漏洞": "sql_injection",
    "sql_injection": "sql_injection",
    # XSS
    "xss": "cross_site_scripting",
    "跨站脚本": "cross_site_scripting",
    "反射型xss": "cross_site_scripting",
    "存储型xss": "cross_site_scripting",
    "xss跨站脚本": "cross_site_scripting",
    "cross site scripting": "cross_site_scripting",
    "cross_site_scripting": "cross_site_scripting",
    # SSRF
    "ssrf": "server_side_request_forgery",
    "服务端请求伪造": "server_side_request_forgery",
    "server side request forgery": "server_side_request_forgery",
    "server_side_request_forgery": "server_side_request_forgery",
    # RCE
    "rce": "remote_code_execution",
    "命令执行": "remote_code_execution",
    "远程代码执行": "remote_code_execution",
    "命令注入": "remote_code_execution",
    "remote code execution": "remote_code_execution",
    "remote_code_execution": "remote_code_execution",
    # LFI / 文件包含
    "lfi": "local_file_inclusion",
    "文件包含": "local_file_inclusion",
    "rfi": "local_file_inclusion",
    "路径遍历": "local_file_inclusion",
    "文件包含/遍历": "local_file_inclusion",
    "local file inclusion": "local_file_inclusion",
    "local_file_inclusion": "local_file_inclusion",
    # IDOR / 越权
    "idor": "insecure_direct_object_reference",
    "越权": "insecure_direct_object_reference",
    "横向越权": "insecure_direct_object_reference",
    "纵向越权": "insecure_direct_object_reference",
    "insecure direct object reference": "insecure_direct_object_reference",
    "insecure_direct_object_reference": "insecure_direct_object_reference",
    # CSRF
    "csrf": "cross_site_request_forgery",
    "跨站请求伪造": "cross_site_request_forgery",
    "cross site request forgery": "cross_site_request_forgery",
    # Auth bypass
    "认证绕过": "auth_bypass",
    "未授权": "auth_bypass",
    "未授权访问": "auth_bypass",
    "未认证": "auth_bypass",
    "无需认证": "auth_bypass",
    "auth bypass": "auth_bypass",
    "unauthorized access": "auth_bypass",
    "auth_bypass": "auth_bypass",
    # Info disclosure
    "信息泄露": "info_disclosure",
    "数据泄露": "info_disclosure",
    "敏感信息泄露": "info_disclosure",
    "info disclosure": "info_disclosure",
    "data leak": "info_disclosure",
    "info_disclosure": "info_disclosure",
    # Injection / file inclusion English labels emitted by finding_parser
    "injection": "sql_injection",
    "file inclusion / traversal": "local_file_inclusion",
}


def normalize_vuln_type(vuln_type: str) -> str:
    """Normalize a vuln type by mapping common aliases to a canonical name.

    Args:
        vuln_type: raw vuln-type string (any case / Chinese or English / with spaces).

    Returns:
        the canonical type; if no alias matches, the space-collapsed lowercase original.
    """
    if not vuln_type:
        return ""
    key = re.sub(r"\s+", " ", vuln_type.strip().lower())
    if key in _VULN_TYPE_ALIASES:
        return _VULN_TYPE_ALIASES[key]
    # Try swapping underscore/space, then match again
    underscore = key.replace(" ", "_")
    if underscore in _VULN_TYPE_ALIASES:
        return _VULN_TYPE_ALIASES[underscore]
    spaced = key.replace("_", " ")
    if spaced in _VULN_TYPE_ALIASES:
        return _VULN_TYPE_ALIASES[spaced]
    return underscore


# ── Text normalization & similarity ───────────────────────────────────────

_URL_RE = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
_TOKEN_RE = re.compile(r"[a-z0-9一-鿿]+", re.IGNORECASE)
# Bracket boundary tags (e.g. [auto], [confirmed]) should be stripped before
# tokenizing so they do not pollute the word set. Bilingual: English (current)
# + Chinese (legacy findings).
_NOISE_TAGS = (
    "[auto]",
    "[confirmed]",
    "[unverified]",
    "[rejected]",
    "[自动]",
    "[已确认]",
    "[未验证]",
)


def _normalize_url_path(url: str) -> str:
    """Normalize a URL: drop the scheme, drop the trailing slash, keep host+path."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url.lower()
    host = (parts.hostname or "").lower()
    path = parts.path or ""
    if len(path) > 1:
        path = path.rstrip("/")
    return f"{host}{path}"


def normalize_text(text: str) -> str:
    """Normalize text: lowercase, collapse whitespace, normalize embedded URL paths.

    Args:
        text: any free text (description/evidence/title).

    Returns:
        the normalized text.
    """
    if not text:
        return ""
    result = text
    for tag in _NOISE_TAGS:
        result = result.replace(tag, " ")
    # 将内嵌 URL 替换为标准化后的 host+path 形式
    result = _URL_RE.sub(lambda m: _normalize_url_path(m.group(0)), result)
    result = result.lower()
    result = re.sub(r"\s+", " ", result).strip()
    return result


def _tokenize(text: str) -> set[str]:
    """Split normalized text into a word set."""
    return set(_TOKEN_RE.findall(text))


def text_similarity(a: str, b: str) -> float:
    """Word-set Jaccard similarity.

    Args:
        a: text A.
        b: text B.

    Returns:
        similarity in [0.0, 1.0]. Returns 1.0 when both are empty; 0.0 when only one is empty.
    """
    na, nb = normalize_text(a), normalize_text(b)
    if not na and not nb:
        return 1.0
    if not na or not nb:
        return 0.0
    ta, tb = _tokenize(na), _tokenize(nb)
    if not ta and not tb:
        return 1.0
    if not ta or not tb:
        return 0.0
    inter = len(ta & tb)
    union = len(ta | tb)
    return inter / union if union else 0.0


def url_similarity(a: str, b: str) -> float:
    """Compare two URLs' host / path / query-parameter similarity.

    Weights: host 0.3 + path 0.4 + query parameter-name set 0.3.
    Non-URL strings fall back to Jaccard text similarity on the raw string.

    Args:
        a: URL or location string A.
        b: URL or location string B.

    Returns:
        similarity in [0.0, 1.0].
    """
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0

    pa, pb = urlsplit(a.strip()), urlsplit(b.strip())
    # 若两者都不像 URL（无 scheme 也无 netloc 也无 path 分隔），按文本比
    if not (pa.scheme or pa.netloc) and not (pb.scheme or pb.netloc):
        return text_similarity(a, b)

    # host 比较
    ha, hb = (pa.hostname or "").lower(), (pb.hostname or "").lower()
    if not ha and not hb:
        host_sim = 1.0
    elif not ha or not hb:
        host_sim = 0.0
    else:
        host_sim = 1.0 if ha == hb else 0.0

    # path 比较：按 "/" 分段做 Jaccard
    seg_a = {s for s in pa.path.split("/") if s}
    seg_b = {s for s in pb.path.split("/") if s}
    if not seg_a and not seg_b:
        path_sim = 1.0
    elif not seg_a or not seg_b:
        path_sim = 0.0
    else:
        path_sim = len(seg_a & seg_b) / len(seg_a | seg_b)

    # query 参数名集合比较（忽略具体值，不同分页/ID 视为同一接口）
    qa = set(parse_qs(pa.query).keys())
    qb = set(parse_qs(pb.query).keys())
    if not qa and not qb:
        query_sim = 1.0
    elif not qa or not qb:
        query_sim = 0.0
    else:
        query_sim = len(qa & qb) / len(qa | qb)

    return host_sim * 0.3 + path_sim * 0.4 + query_sim * 0.3


# ── 综合 finding 相似度 ─────────────────────────────────────────────────

_LOCATION_RE = re.compile(r'(?:https?://[^\s<>"\')\]]+)|(?:/[\w%&=?\-./]+)')


def _extract_location(finding: "VulnerabilityFinding") -> str:
    """Extract the first URL or path from a finding's evidence / description as its location."""
    for field in (finding.evidence or "", finding.description or ""):
        if not field:
            continue
        m = _LOCATION_RE.search(field)
        if m:
            return m.group(0)
    return ""


def _vuln_type_similarity(a: str, b: str) -> float:
    """Vuln-type similarity: exact match 1.0, normalized match 0.8, else 0.0."""
    ra, rb = (a or "").strip().lower(), (b or "").strip().lower()
    if ra and rb and ra == rb:
        return 1.0
    na, nb = normalize_vuln_type(a), normalize_vuln_type(b)
    if na and nb and na == nb:
        return 0.8
    return 0.0


def finding_similarity(a: "VulnerabilityFinding", b: "VulnerabilityFinding") -> float:
    """综合比较两个漏洞发现的相似度.

    维度权重:
        - vuln_type:    0.3（完全匹配 1.0 / 归一化匹配 0.8）
        - location/URL: 0.4（从 evidence/description 提取后做 url_similarity）
        - description:  0.3（标题+描述的文本 Jaccard）

    Args:
        a: 漏洞发现 A。
        b: 漏洞发现 B。

    Returns:
        [0.0, 1.0] 之间的综合相似度。
    """
    type_sim = _vuln_type_similarity(a.vuln_type, b.vuln_type)

    loc_a, loc_b = _extract_location(a), _extract_location(b)
    if not loc_a and not loc_b:
        # 两者都无明确位置 - 该维度不可比，视为中性（不加分也不减分）
        loc_sim = 0.5
    else:
        loc_sim = url_similarity(loc_a, loc_b)

    desc_a = f"{a.title} {a.description}".strip()
    desc_b = f"{b.title} {b.description}".strip()
    desc_sim = text_similarity(desc_a, desc_b)

    return type_sim * 0.3 + loc_sim * 0.4 + desc_sim * 0.3


# ── 证据强度比较与去重 ───────────────────────────────────────────────────

_EVIDENCE_LEVEL_RANK = {"L1": 1, "L2": 2, "L3": 3, "L4": 4}
_LIFECYCLE_RANK = {
    "rejected": 0,
    "candidate": 1,
    "pending_verification": 2,
    "needs_manual_review": 3,
    "verified": 4,
}


def _evidence_strength(finding: "VulnerabilityFinding") -> tuple:
    """计算 finding 的证据强度，用于在重复时决定保留哪个.

    排序键（越大越强）:
        1. 已验证优先（verified=True）
        2. 生命周期等级
        3. 证据等级 L1-L4
        4. evidence 文本长度（更详细的证据）
    """
    return (
        1 if finding.verified else 0,
        _LIFECYCLE_RANK.get(finding.lifecycle_status, 1),
        _EVIDENCE_LEVEL_RANK.get(finding.evidence_level, 1),
        len(finding.evidence or ""),
    )


def deduplicate_findings(
    findings: list["VulnerabilityFinding"], threshold: float = 0.75
) -> list["VulnerabilityFinding"]:
    """对漏洞发现列表做语义去重，保留证据更充分的一方.

    遍历 findings，对每个新 finding 与已保留的 findings 逐一比较，
    相似度超过阈值即判定为重复；保留证据强度更高者。

    Args:
        findings: 原始漏洞发现列表。
        threshold: 相似度阈值，默认 0.75。

    Returns:
        去重后的列表，保持首次出现的相对顺序。
    """
    kept: list["VulnerabilityFinding"] = []
    for cand in findings:
        dup_index: Optional[int] = None
        for idx, existing in enumerate(kept):
            if finding_similarity(cand, existing) >= threshold:
                dup_index = idx
                break
        if dup_index is None:
            kept.append(cand)
            continue
        # 命中重复：保留证据更强者
        if _evidence_strength(cand) > _evidence_strength(kept[dup_index]):
            kept[dup_index] = cand
    return kept
