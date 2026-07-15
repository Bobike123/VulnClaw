"""File-system access tools, jailed to the directory VulnClaw was launched from.

Gives the agent read/write/edit/list access to the project you're running it
in - the same "workbench" ergonomics as Claude Code's Read/Write/Edit tools -
scoped to ``agent.project_dir`` (captured once at :class:`AgentCore` startup,
see ``agent/core.py``). Unlike ``python_execute`` these are on by default (no
``safety.enable_*`` toggle): they never reach the network, and jailing +
symlink resolution + a sensitive-path blocklist bound the blast radius even
when the agent's next step is steered by content it just read from a scanned
target.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext

from vulnclaw.safety.sandbox import _SENSITIVE_PATTERNS

_MAX_READ_CHARS = 200_000
_MAX_WRITE_CHARS = 500_000
_MAX_LIST_ENTRIES = 500


class FileToolError(ValueError):
    """A file-tool request that must be reported back to the model, not raised."""


def _is_sensitive(path: Path) -> bool:
    low = str(path).replace("\\", "/").lower()
    return any(pat in low for pat in _SENSITIVE_PATTERNS)


def resolve_in_project(agent: "AgentContext", raw_path: str) -> Path:
    """Resolve *raw_path* against ``agent.project_dir`` and jail it there.

    Raises ``FileToolError`` for empty paths, paths that resolve outside the
    project directory (``..`` traversal or a symlink escape), or paths that
    match the sandbox's sensitive-path blocklist (SSH keys, ``.env``,
    ``.vulnclaw``, cloud/browser credentials, etc.) - even when they'd
    otherwise land inside the project dir, since a cloned repo can still
    contain real secrets.
    """
    raw_path = (raw_path or "").strip()
    if not raw_path:
        raise FileToolError("path is required")

    root = agent.project_dir
    candidate = (root / raw_path) if not Path(raw_path).is_absolute() else Path(raw_path)

    # Resolve symlinks against the *existing* portion of the path - for a
    # not-yet-created write target, resolve the nearest existing parent and
    # re-append the remaining components so a symlinked parent dir can't be
    # used to escape the jail either.
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise FileToolError(f"cannot resolve path: {exc}") from None

    if not (resolved == root or resolved.is_relative_to(root)):
        raise FileToolError(
            f"path '{raw_path}' resolves outside the project directory ({root}); refusing"
        )
    if _is_sensitive(resolved):
        raise FileToolError(f"path '{raw_path}' matches a sensitive-file pattern; refusing")
    return resolved


async def execute_file_read(agent: "AgentContext", args: dict[str, Any]) -> str:
    try:
        path = resolve_in_project(agent, str(args.get("path", "")))
    except FileToolError as exc:
        return f"[!] {exc}"

    if not path.exists():
        return f"[!] File not found: {path.relative_to(agent.project_dir)}"
    if path.is_dir():
        return f"[!] '{path.relative_to(agent.project_dir)}' is a directory; use list_dir instead"

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"[!] Failed to read file: {exc}"

    offset = int(args.get("offset") or 0)
    limit = args.get("limit")
    if offset or limit is not None:
        lines = text.splitlines(keepends=True)
        end = offset + int(limit) if limit is not None else len(lines)
        text = "".join(lines[offset:end])

    truncated = False
    if len(text) > _MAX_READ_CHARS:
        text = text[:_MAX_READ_CHARS]
        truncated = True

    header = f"[{path.relative_to(agent.project_dir)}]\n"
    footer = f"\n[...truncated, file exceeds {_MAX_READ_CHARS} chars; re-read with offset/limit...]" if truncated else ""
    return header + text + footer


async def execute_file_write(agent: "AgentContext", args: dict[str, Any]) -> str:
    try:
        path = resolve_in_project(agent, str(args.get("path", "")))
    except FileToolError as exc:
        return f"[!] {exc}"

    content = args.get("content", "")
    if not isinstance(content, str):
        content = str(content)
    if len(content) > _MAX_WRITE_CHARS:
        return f"[!] Content exceeds the max write size ({_MAX_WRITE_CHARS} chars); write it in smaller pieces"

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        existed = path.exists()
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        return f"[!] Failed to write file: {exc}"

    rel = path.relative_to(agent.project_dir)
    verb = "Updated" if existed else "Created"
    return f"[✓] {verb} {rel} ({len(content)} chars)"


async def execute_file_edit(agent: "AgentContext", args: dict[str, Any]) -> str:
    try:
        path = resolve_in_project(agent, str(args.get("path", "")))
    except FileToolError as exc:
        return f"[!] {exc}"

    old_string = args.get("old_string", "")
    new_string = args.get("new_string", "")
    replace_all = bool(args.get("replace_all", False))
    if not old_string:
        return "[!] old_string is required and must be non-empty"

    if not path.exists():
        return f"[!] File not found: {path.relative_to(agent.project_dir)}"

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"[!] Failed to read file: {exc}"

    count = text.count(old_string)
    if count == 0:
        return "[!] old_string not found in file"
    if count > 1 and not replace_all:
        return f"[!] old_string is not unique ({count} matches); pass replace_all=true or include more context"

    new_text = text.replace(old_string, new_string) if replace_all else text.replace(old_string, new_string, 1)

    try:
        path.write_text(new_text, encoding="utf-8")
    except OSError as exc:
        return f"[!] Failed to write file: {exc}"

    rel = path.relative_to(agent.project_dir)
    replaced = count if replace_all else 1
    return f"[✓] Edited {rel} ({replaced} replacement{'s' if replaced != 1 else ''})"


async def execute_list_dir(agent: "AgentContext", args: dict[str, Any]) -> str:
    try:
        path = resolve_in_project(agent, str(args.get("path", ".") or "."))
    except FileToolError as exc:
        return f"[!] {exc}"

    if not path.exists():
        return f"[!] Directory not found: {path.relative_to(agent.project_dir)}"
    if not path.is_dir():
        return f"[!] '{path.relative_to(agent.project_dir)}' is a file; use file_read instead"

    try:
        entries = sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
    except OSError as exc:
        return f"[!] Failed to list directory: {exc}"

    lines: list[str] = []
    for entry in entries[:_MAX_LIST_ENTRIES]:
        if _is_sensitive(entry):
            continue
        if entry.is_dir():
            lines.append(f"{entry.name}/")
        else:
            try:
                size = entry.stat().st_size
            except OSError:
                size = 0
            lines.append(f"{entry.name} ({size}B)")

    rel = path.relative_to(agent.project_dir) if path != agent.project_dir else Path(".")
    suffix = f"\n[...truncated, {len(entries) - _MAX_LIST_ENTRIES} more entries...]" if len(entries) > _MAX_LIST_ENTRIES else ""
    if not lines:
        return f"[{rel}] (empty)"
    return f"[{rel}]\n" + "\n".join(lines) + suffix
