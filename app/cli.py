"""
AEGIS command-line interface.

    aegis replay     Replay a PCAP (or synthetic stream) through the detection pipeline
    aegis benchmark  Measure pipeline throughput and latency
    aegis train      Train the ML detector models
    aegis serve      Run the REST API
    aegis dashboard  Run the Streamlit analyst dashboard

Each subcommand forwards its remaining arguments to the existing module entry
point, so `aegis replay --help` shows the full option list.
"""

import subprocess
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

DASHBOARD_APP = Path(__file__).resolve().parent.parent / "dashboard" / "streamlit_app.py"


def _replay(argv: List[str]) -> int:
    from app.ingest.replay import main
    return _run_argparse_main(main, "aegis replay", argv)


def _benchmark(argv: List[str]) -> int:
    from app.benchmark import main
    return _run_argparse_main(main, "aegis benchmark", argv)


def _train(argv: List[str]) -> int:
    from training.train import main
    return _run_argparse_main(main, "aegis train", argv)


def _serve(argv: List[str]) -> int:
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(prog="aegis serve", description="Run the AEGIS REST API")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    args = parser.parse_args(argv)
    uvicorn.run("app.api.main:app", host=args.host, port=args.port)
    return 0


def _dashboard(argv: List[str]) -> int:
    cmd = [sys.executable, "-m", "streamlit", "run", str(DASHBOARD_APP), *argv]
    return subprocess.call(cmd)


COMMANDS: Dict[str, Tuple[Callable[[List[str]], int], str]] = {
    "replay": (_replay, "Replay a PCAP or synthetic stream through the detection pipeline"),
    "benchmark": (_benchmark, "Measure pipeline throughput and latency"),
    "train": (_train, "Train the ML detector models"),
    "serve": (_serve, "Run the REST API"),
    "dashboard": (_dashboard, "Run the Streamlit analyst dashboard"),
}


def _run_argparse_main(main: Callable[[], None], prog: str, argv: List[str]) -> int:
    saved = sys.argv
    sys.argv = [prog, *argv]
    try:
        main()
    except SystemExit as exc:
        code = exc.code
        return code if isinstance(code, int) else (0 if code is None else 1)
    finally:
        sys.argv = saved
    return 0


def _usage() -> str:
    width = max(len(name) for name in COMMANDS)
    lines = ["usage: aegis <command> [options]", "", "commands:"]
    lines += [f"  {name:<{width}}  {desc}" for name, (_, desc) in COMMANDS.items()]
    lines += ["", "Run 'aegis <command> --help' for command options."]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(_usage())
        return 0
    if argv[0] in ("-V", "--version"):
        from app import __version__
        print(f"aegis {__version__}")
        return 0
    name, rest = argv[0], argv[1:]
    if name not in COMMANDS:
        print(f"aegis: unknown command '{name}'\n", file=sys.stderr)
        print(_usage(), file=sys.stderr)
        return 2
    handler, _ = COMMANDS[name]
    return handler(rest)


if __name__ == "__main__":
    sys.exit(main())
