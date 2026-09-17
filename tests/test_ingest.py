from __future__ import annotations

import json
import os
import shutil
import tarfile

import pytest

from pathlib import Path

from ifda import ingest
from ifda.ingest import identify_and_extract, moria_available, moria_path, _merge_regions


def _no_moria_anywhere(monkeypatch, tmp_path):
    """Neutralizes all three sources moria_path() consults.

    Stubbing shutil.which alone is not enough any more: the in-tree build of
    the pinned submodule is checked before PATH, so on a machine that has run
    scripts/build-moria.sh a which-only stub still resolves to a real binary.
    """
    monkeypatch.delenv("IFDA_MORIA", raising=False)
    monkeypatch.setattr(ingest, "_VENDORED", tmp_path / "absent" / "moria")
    monkeypatch.setattr(shutil, "which", lambda name: None)


def test_moria_unavailable_degrades_cleanly(monkeypatch, tmp_path):
    _no_moria_anywhere(monkeypatch, tmp_path)
    assert moria_available() is False
    result = identify_and_extract(str(tmp_path / "whatever.bin"), str(tmp_path / "out"))
    assert result["regions"] == []
    assert "moria not installed" in result["error"]


def test_vendored_build_wins_over_path(monkeypatch, tmp_path):
    """A checkout that pinned a moria commit must run that commit, not
    whatever version the host happens to have installed."""
    monkeypatch.delenv("IFDA_MORIA", raising=False)
    vendored = tmp_path / "moria" / "build" / "moria"
    vendored.parent.mkdir(parents=True)
    vendored.write_text("#!/bin/sh\n")
    vendored.chmod(0o755)
    monkeypatch.setattr(ingest, "_VENDORED", vendored)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/local/bin/moria")
    assert moria_path() == str(vendored)


def test_env_override_wins_over_vendored_build(monkeypatch, tmp_path):
    override = tmp_path / "elsewhere-moria"
    override.write_text("#!/bin/sh\n")
    override.chmod(0o755)
    vendored = tmp_path / "moria" / "build" / "moria"
    vendored.parent.mkdir(parents=True)
    vendored.write_text("#!/bin/sh\n")
    vendored.chmod(0o755)
    monkeypatch.setattr(ingest, "_VENDORED", vendored)
    monkeypatch.setenv("IFDA_MORIA", str(override))
    assert moria_path() == str(override)


def test_env_override_pointing_at_nothing_is_unavailable(monkeypatch, tmp_path):
    """An override that resolves to nothing is a configuration mistake. Falling
    back to a different binary than the one explicitly requested would hide it,
    and the whole point of the override is to control which build runs."""
    vendored = tmp_path / "moria" / "build" / "moria"
    vendored.parent.mkdir(parents=True)
    vendored.write_text("#!/bin/sh\n")
    vendored.chmod(0o755)
    monkeypatch.setattr(ingest, "_VENDORED", vendored)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/local/bin/moria")
    monkeypatch.setenv("IFDA_MORIA", str(tmp_path / "does-not-exist"))
    assert moria_path() is None
    assert moria_available() is False


def test_vendored_path_points_into_the_submodule():
    """Guards the parents[2] walk in ifda/ingest: if this module ever moves,
    _VENDORED silently starts pointing somewhere harmless-looking and the
    in-tree build is quietly never used again."""
    assert ingest._VENDORED == Path(ingest.__file__).resolve().parents[2] / "moria" / "build" / "moria"
    assert ingest._VENDORED.parents[2].name != "ifda"


def test_merge_regions_marks_error_status_unusable():
    """A region moria attempted but couldn't actually unpack (status
    "error:*") must not be offered as a usable analyze/re-extract target,
    even though moria still reports *something* at that offset."""
    doc = {
        "findings": [
            {"offset": 100, "type": "squashfs", "category": "filesystem",
             "confidence": 85, "description": "SquashFS"},
        ],
        "extraction": {"extracted": [
            {"offset": 100, "type": "squashfs", "root": "0x64-squashfs",
             "status": "error:undecodable-payload", "files": 0, "dirs": 0, "bytes": 0,
             "warnings": ["xz payload did not decode"]},
        ]},
    }
    regions = _merge_regions(doc, "/out")
    assert len(regions) == 1
    assert regions[0]["usable"] is False
    assert regions[0]["path"] == ""
    assert regions[0]["warnings"] == ["xz payload did not decode"]


def test_merge_regions_ok_status_is_usable_with_joined_path():
    doc = {
        "findings": [
            {"offset": 0, "type": "tar", "category": "archive", "confidence": 85,
             "description": "tar archive", "size": 2560},
        ],
        "extraction": {"extracted": [
            {"offset": 0, "type": "tar", "root": "0x0-tar", "status": "ok",
             "files": 3, "dirs": 1, "bytes": 500},
        ]},
    }
    regions = _merge_regions(doc, "/out")
    assert regions[0]["usable"] is True
    assert regions[0]["path"] == os.path.join("/out", "0x0-tar")
    assert regions[0]["category"] == "archive"


def test_merge_regions_keeps_region_size_and_extracted_bytes_distinct():
    """region_size (the compressed footprint moria found in the source
    image) and bytes (the sum of everything moria actually decompressed)
    are legitimately different numbers for a compressed filesystem --
    collapsing them into one "size" field is exactly what made the
    extracted-content total look like a wrong region size."""
    doc = {
        "findings": [
            {"offset": 0, "type": "squashfs", "category": "filesystem", "size": 1000},
        ],
        "extraction": {"extracted": [
            {"offset": 0, "type": "squashfs", "root": "0x0-squashfs", "status": "ok",
             "files": 50, "dirs": 10, "bytes": 5_000_000},
        ]},
    }
    regions = _merge_regions(doc, "/out")
    assert regions[0]["region_size"] == 1000
    assert regions[0]["bytes"] == 5_000_000


def test_merge_regions_ok_status_but_empty_is_not_usable():
    """status "ok" with zero files and zero dirs (an empty container) isn't
    worth offering as something to analyze or re-extract."""
    doc = {
        "findings": [{"offset": 0, "type": "zip", "category": "archive"}],
        "extraction": {"extracted": [
            {"offset": 0, "type": "zip", "root": "0x0-zip", "status": "ok", "files": 0, "dirs": 0, "bytes": 0},
        ]},
    }
    regions = _merge_regions(doc, "/out")
    assert regions[0]["usable"] is False


@pytest.mark.skipif(shutil.which("moria") is None, reason="moria not installed")
def test_identify_and_extract_directory_target_surfaces_morias_own_error(tmp_path):
    """moria only extracts a single raw image file, not an already-extracted
    directory tree -- confirms that specific, common misuse (pointing
    extract at a directory instead of the firmware image it came from)
    surfaces moria's own plain-English reason, not a generic "no valid
    JSON" wrapper around it."""
    (tmp_path / "some_dir").mkdir()
    result = identify_and_extract(str(tmp_path / "some_dir"), str(tmp_path / "out"))
    assert result["regions"] == []
    assert "directory" in result["error"]


@pytest.mark.skipif(shutil.which("moria") is None, reason="moria not installed")
def test_identify_and_extract_live_tar(tmp_path):
    """Real moria invocation against a small, self-contained tar (no
    external/local firmware fixtures) -- confirms the actual subprocess +
    JSON-parsing + region-merge path works end to end, not just the merge
    logic in isolation."""
    src_file = tmp_path / "hello.txt"
    src_file.write_text("hello moria")
    tar_path = tmp_path / "test.tar"
    with tarfile.open(tar_path, "w") as tf:
        tf.add(src_file, arcname="hello.txt")

    out_dir = tmp_path / "out"
    result = identify_and_extract(str(tar_path), str(out_dir))

    assert result.get("error") is None
    usable = [r for r in result["regions"] if r["usable"]]
    assert len(usable) == 1
    assert usable[0]["type"] == "tar"
    extracted_file = os.path.join(usable[0]["path"], "hello.txt")
    assert os.path.isfile(extracted_file)
    assert open(extracted_file).read() == "hello moria"
