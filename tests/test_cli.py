"""Tests for the `aegis` command-line entry point."""

from app import __version__
from app.cli import main


def test_help_lists_commands(capsys):
    assert main(["--help"]) == 0
    out = capsys.readouterr().out
    for cmd in ("replay", "benchmark", "train", "serve", "dashboard"):
        assert cmd in out


def test_version(capsys):
    assert main(["--version"]) == 0
    assert __version__ in capsys.readouterr().out


def test_unknown_command_exits_2(capsys):
    assert main(["definitely-not-a-command"]) == 2
    assert "unknown command" in capsys.readouterr().err


def test_subcommand_help_is_forwarded(capsys):
    assert main(["replay", "--help"]) == 0
    assert "--pcap" in capsys.readouterr().out


def test_replay_synthetic_stream(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["replay", "--synthetic", "--max-packets", "50", "--speed", "0"]) == 0
    assert "STREAMING INGEST COMPLETED" in capsys.readouterr().out
