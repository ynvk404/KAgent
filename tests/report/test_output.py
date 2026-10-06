from concurrent.futures import ThreadPoolExecutor
import errno
import os
import stat

import pytest

from src.report.model import ReportError
from src.report.output import default_filename, stage_report, validate_filename

PDF = b"%PDF-1.4\ncomplete-test-stream\n%%EOF\n"


@pytest.mark.parametrize("name", ["../x.pdf", "/tmp/x.pdf", "a/b.pdf", "a\\b.pdf", "C:x.pdf", "\\\\server\\x.pdf", "~x.pdf", "$(x).pdf", "*.pdf", "x..pdf", "a\x00.pdf", "%2e%2e.pdf", "no.txt", "x"*100 + ".pdf"])
def test_invalid_leaf_rejected_without_writes(tmp_path, name):
    with pytest.raises(ReportError):
        stage_report(tmp_path, name, PDF)
    assert list(tmp_path.iterdir()) == []


def test_default_name_contains_no_raw_id_or_target():
    name = default_filename("untrusted-id", "objective-id", "2026-10-06T12:01:02Z")
    assert name.endswith("20261006T120102Z.pdf") and "untrusted" not in name
    assert "untracked-target" in default_filename("", "", "2026-10-06T00:00:00Z")
    validate_filename(name)


def test_collision_never_overwrites_and_modes_private(tmp_path):
    first = stage_report(tmp_path, "report.pdf", PDF).publish()
    second = stage_report(tmp_path, "report.pdf", PDF + b"\n").publish()
    assert first.name == "report.pdf" and second.name == "report-2.pdf"
    assert first.read_bytes() == PDF and second.read_bytes() == PDF + b"\n"
    assert stat.S_IMODE(first.stat().st_mode) == 0o600
    assert stat.S_IMODE(first.parent.stat().st_mode) == 0o700
    assert not list(first.parent.glob("*.tmp"))


def test_concurrent_collision_names_are_unique(tmp_path):
    with ThreadPoolExecutor(max_workers=4) as pool:
        paths = list(pool.map(lambda _: stage_report(tmp_path, "same.pdf", PDF).publish(), range(8)))
    assert len(set(paths)) == 8
    assert all(p.read_bytes() == PDF for p in paths)


@pytest.mark.parametrize("component", ["artifacts", "reports"])
def test_symlink_component_rejected(tmp_path, component):
    other = tmp_path / "elsewhere"; other.mkdir()
    if component == "artifacts": (tmp_path / "artifacts").symlink_to(other, target_is_directory=True)
    else:
        (tmp_path / "artifacts").mkdir()
        (tmp_path / "artifacts/reports").symlink_to(other, target_is_directory=True)
    with pytest.raises(OSError): stage_report(tmp_path, "report.pdf", PDF)
    assert list(other.iterdir()) == []


@pytest.mark.parametrize("kind", ["symlink", "directory"])
def test_unsafe_collision_not_overwritten_or_followed(tmp_path, kind):
    directory = tmp_path / "artifacts/reports"; directory.mkdir(parents=True)
    old = tmp_path / "old"; old.write_bytes(b"old")
    collision = directory / "report.pdf"
    if kind == "symlink": collision.symlink_to(old)
    elif kind == "directory": collision.mkdir()
    else: os.link(old, collision)
    with pytest.raises(ReportError): stage_report(tmp_path, "report.pdf", PDF).publish()
    assert old.read_bytes() == b"old"
    assert not list(directory.glob("*.tmp"))


def test_directory_replacement_cannot_redirect_publication(tmp_path):
    stage = stage_report(tmp_path, "report.pdf", PDF)
    old = tmp_path / "artifacts/old-reports"
    stage.directory.rename(old)
    stage.directory.mkdir()
    with pytest.raises(ReportError): stage.publish()
    assert list(old.iterdir()) == [] and list(stage.directory.iterdir()) == []


def test_stage_replacement_cleans_only_owned_inode(tmp_path):
    stage = stage_report(tmp_path, "report.pdf", PDF)
    path = stage.directory / stage.name
    moved = stage.directory / "owned-old"
    path.rename(moved); path.write_bytes(b"other")
    with pytest.raises(ReportError): stage.publish()
    assert path.read_bytes() == b"other" and moved.read_bytes() == PDF


@pytest.mark.parametrize("failure", ["write", "fsync", "link"])
def test_failure_cleans_only_owned_stage_and_preserves_collision(tmp_path, monkeypatch, failure):
    from src.report import output
    directory = tmp_path / "artifacts/reports"; directory.mkdir(parents=True)
    previous = directory / "report.pdf"; previous.write_bytes(b"previous")
    def fail(*args, **kwargs): raise OSError(errno.ENOSPC, "unsafe-exception-sentinel")
    if failure == "write": monkeypatch.setattr(output.os, "fdopen", fail)
    elif failure == "fsync": monkeypatch.setattr(output.os, "fsync", fail)
    else: monkeypatch.setattr(output.os, "link", fail)
    with pytest.raises(OSError): stage_report(tmp_path, "report.pdf", PDF).publish()
    assert previous.read_bytes() == b"previous"
    assert not list(directory.glob("*.tmp"))


def test_incomplete_pdf_never_creates_directory(tmp_path):
    with pytest.raises(ReportError): stage_report(tmp_path, "report.pdf", b"%PDF-1.4 partial")
    assert list(tmp_path.iterdir()) == []


def test_existing_hardlink_collision_is_preserved(tmp_path):
    directory = tmp_path / "artifacts/reports"; directory.mkdir(parents=True)
    old = tmp_path / "old"; old.write_bytes(b"old")
    os.link(old, directory / "report.pdf")
    final = stage_report(tmp_path, "report.pdf", PDF).publish()
    assert final.name == "report-2.pdf" and old.read_bytes() == b"old"


def test_exclusive_stage_collision_does_not_delete_previous_file(tmp_path, monkeypatch):
    from src.report import output
    directory = tmp_path / "artifacts/reports"; directory.mkdir(parents=True)
    collision = directory / ".report-predictable.tmp"; collision.write_bytes(b"previous")
    monkeypatch.setattr(output.secrets, "token_hex", lambda n: "predictable")
    with pytest.raises(FileExistsError): stage_report(tmp_path, "report.pdf", PDF)
    assert collision.read_bytes() == b"previous"


def test_publication_uses_verified_inode_after_stage_name_replacement(tmp_path, monkeypatch):
    from src.report import output
    stage = stage_report(tmp_path, "report.pdf", PDF)
    real_link = output.os.link
    def replace_and_link(src, dst, **kwargs):
        path = stage.directory / stage.name
        path.rename(stage.directory / "original-owned")
        path.write_bytes(b"replacement")
        return real_link(src, dst, **kwargs)
    monkeypatch.setattr(output.os, "link", replace_and_link)
    final = stage.publish()
    assert final.read_bytes() == PDF
    assert (stage.directory / stage.name).read_bytes() == b"replacement"


def test_stage_cleanup_failure_rolls_back_only_new_publication(tmp_path, monkeypatch):
    from src.report import output
    stage = stage_report(tmp_path, "report.pdf", PDF)
    real_unlink = output.os.unlink
    calls = 0
    def fail_once(path, **kwargs):
        nonlocal calls
        if path == stage.name and calls == 0:
            calls += 1
            raise OSError(errno.EACCES, "injected stage cleanup failure")
        return real_unlink(path, **kwargs)
    monkeypatch.setattr(output.os, "unlink", fail_once)
    with pytest.raises(OSError): stage.publish()
    assert list(stage.directory.iterdir()) == []
