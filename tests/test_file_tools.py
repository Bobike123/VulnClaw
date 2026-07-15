"""Tests for the project-directory file tools (file_read/write/edit/list_dir).

These are on by default (no safety.enable_* toggle, unlike python_execute) —
the jailing to agent.project_dir plus the sensitive-path blocklist are the
whole safety story, so that's what these tests exercise hardest.
"""

from types import SimpleNamespace

import pytest

from vulnclaw.agent.file_tools import (
    FileToolError,
    execute_file_edit,
    execute_file_read,
    execute_file_write,
    execute_list_dir,
    resolve_in_project,
)


def _agent(project_dir):
    return SimpleNamespace(project_dir=project_dir)


class TestResolveInProject:
    def test_resolves_relative_path_inside_project(self, tmp_path):
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "a.txt").write_text("hi")

        resolved = resolve_in_project(_agent(tmp_path), "sub/a.txt")

        assert resolved == (tmp_path / "sub" / "a.txt").resolve()

    def test_empty_path_raises(self, tmp_path):
        with pytest.raises(FileToolError, match="required"):
            resolve_in_project(_agent(tmp_path), "")

    def test_dot_dot_traversal_outside_project_is_refused(self, tmp_path):
        outside = tmp_path.parent / "definitely-outside.txt"
        with pytest.raises(FileToolError, match="outside the project directory"):
            resolve_in_project(_agent(tmp_path), f"../{outside.name}")

    def test_absolute_path_outside_project_is_refused(self, tmp_path):
        with pytest.raises(FileToolError, match="outside the project directory"):
            resolve_in_project(_agent(tmp_path), "/etc/hostname")

    def test_symlink_escape_is_refused(self, tmp_path):
        outside_dir = tmp_path.parent / "outside-target"
        outside_dir.mkdir(exist_ok=True)
        (outside_dir / "secret.txt").write_text("nope")
        link = tmp_path / "escape"
        link.symlink_to(outside_dir)

        with pytest.raises(FileToolError, match="outside the project directory"):
            resolve_in_project(_agent(tmp_path), "escape/secret.txt")

    @pytest.mark.parametrize(
        "rel_path",
        [
            ".ssh/id_rsa",
            ".env",
            ".aws/credentials",
            ".vulnclaw/config.yaml",
            "nested/.git-credentials",
        ],
    )
    def test_sensitive_paths_refused_even_inside_project(self, tmp_path, rel_path):
        target = tmp_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("secret")

        with pytest.raises(FileToolError, match="sensitive"):
            resolve_in_project(_agent(tmp_path), rel_path)


class TestFileRead:
    async def test_reads_file_content_with_relative_path_header(self, tmp_path):
        (tmp_path / "notes.txt").write_text("hello world")

        result = await execute_file_read(_agent(tmp_path), {"path": "notes.txt"})

        assert "[notes.txt]" in result
        assert "hello world" in result

    async def test_missing_file_reports_not_found(self, tmp_path):
        result = await execute_file_read(_agent(tmp_path), {"path": "nope.txt"})
        assert "[!]" in result
        assert "not found" in result.lower()

    async def test_directory_path_reports_use_list_dir(self, tmp_path):
        (tmp_path / "somedir").mkdir()
        result = await execute_file_read(_agent(tmp_path), {"path": "somedir"})
        assert "list_dir" in result

    async def test_offset_and_limit_select_a_line_range(self, tmp_path):
        (tmp_path / "lines.txt").write_text("l0\nl1\nl2\nl3\nl4\n")

        result = await execute_file_read(
            _agent(tmp_path), {"path": "lines.txt", "offset": 1, "limit": 2}
        )

        assert "l1" in result and "l2" in result
        assert "l0" not in result and "l3" not in result

    async def test_traversal_outside_project_is_refused(self, tmp_path):
        result = await execute_file_read(_agent(tmp_path), {"path": "../outside.txt"})
        assert "[!]" in result
        assert "outside the project directory" in result

    async def test_sensitive_path_is_refused(self, tmp_path):
        result = await execute_file_read(_agent(tmp_path), {"path": ".env"})
        assert "[!]" in result
        assert "sensitive" in result.lower()


class TestFileWrite:
    async def test_creates_new_file(self, tmp_path):
        result = await execute_file_write(
            _agent(tmp_path), {"path": "out.txt", "content": "created"}
        )

        assert "Created" in result
        assert (tmp_path / "out.txt").read_text() == "created"

    async def test_overwrites_existing_file(self, tmp_path):
        (tmp_path / "out.txt").write_text("old")

        result = await execute_file_write(
            _agent(tmp_path), {"path": "out.txt", "content": "new"}
        )

        assert "Updated" in result
        assert (tmp_path / "out.txt").read_text() == "new"

    async def test_creates_parent_directories(self, tmp_path):
        await execute_file_write(
            _agent(tmp_path), {"path": "a/b/c.txt", "content": "deep"}
        )
        assert (tmp_path / "a" / "b" / "c.txt").read_text() == "deep"

    async def test_refuses_write_outside_project(self, tmp_path):
        result = await execute_file_write(
            _agent(tmp_path), {"path": "../escape.txt", "content": "x"}
        )
        assert "[!]" in result
        assert not (tmp_path.parent / "escape.txt").exists()

    async def test_refuses_write_to_sensitive_path(self, tmp_path):
        result = await execute_file_write(
            _agent(tmp_path), {"path": ".ssh/id_rsa", "content": "fake-key"}
        )
        assert "[!]" in result
        assert not (tmp_path / ".ssh" / "id_rsa").exists()


class TestFileEdit:
    async def test_replaces_unique_match(self, tmp_path):
        (tmp_path / "f.py").write_text("x = 1\ny = 2\n")

        result = await execute_file_edit(
            _agent(tmp_path), {"path": "f.py", "old_string": "x = 1", "new_string": "x = 42"}
        )

        assert "Edited" in result
        assert (tmp_path / "f.py").read_text() == "x = 42\ny = 2\n"

    async def test_missing_old_string_reports_not_found(self, tmp_path):
        (tmp_path / "f.py").write_text("x = 1\n")

        result = await execute_file_edit(
            _agent(tmp_path), {"path": "f.py", "old_string": "nope", "new_string": "y"}
        )

        assert "[!]" in result
        assert "not found" in result.lower()

    async def test_non_unique_match_without_replace_all_is_refused(self, tmp_path):
        (tmp_path / "f.py").write_text("x = 1\nx = 1\n")

        result = await execute_file_edit(
            _agent(tmp_path), {"path": "f.py", "old_string": "x = 1", "new_string": "x = 2"}
        )

        assert "[!]" in result
        assert "not unique" in result
        assert (tmp_path / "f.py").read_text() == "x = 1\nx = 1\n"

    async def test_replace_all_replaces_every_match(self, tmp_path):
        (tmp_path / "f.py").write_text("x = 1\nx = 1\n")

        result = await execute_file_edit(
            _agent(tmp_path),
            {"path": "f.py", "old_string": "x = 1", "new_string": "x = 2", "replace_all": True},
        )

        assert "2 replacements" in result
        assert (tmp_path / "f.py").read_text() == "x = 2\nx = 2\n"

    async def test_missing_file_reports_not_found(self, tmp_path):
        result = await execute_file_edit(
            _agent(tmp_path), {"path": "ghost.py", "old_string": "a", "new_string": "b"}
        )
        assert "[!]" in result
        assert "not found" in result.lower()


class TestListDir:
    async def test_lists_files_and_subdirs(self, tmp_path):
        (tmp_path / "a.txt").write_text("hi")
        (tmp_path / "subdir").mkdir()

        result = await execute_list_dir(_agent(tmp_path), {"path": "."})

        assert "a.txt" in result
        assert "subdir/" in result

    async def test_default_path_lists_project_root(self, tmp_path):
        (tmp_path / "a.txt").write_text("hi")

        result = await execute_list_dir(_agent(tmp_path), {})

        assert "a.txt" in result

    async def test_empty_directory_reports_empty(self, tmp_path):
        result = await execute_list_dir(_agent(tmp_path), {"path": "."})
        assert "empty" in result

    async def test_hides_sensitive_entries(self, tmp_path):
        (tmp_path / "normal.txt").write_text("hi")
        (tmp_path / ".env").write_text("SECRET=1")

        result = await execute_list_dir(_agent(tmp_path), {"path": "."})

        assert "normal.txt" in result
        assert ".env" not in result

    async def test_file_path_reports_use_file_read(self, tmp_path):
        (tmp_path / "a.txt").write_text("hi")
        result = await execute_list_dir(_agent(tmp_path), {"path": "a.txt"})
        assert "file_read" in result

    async def test_refuses_path_outside_project(self, tmp_path):
        result = await execute_list_dir(_agent(tmp_path), {"path": ".."})
        assert "[!]" in result
