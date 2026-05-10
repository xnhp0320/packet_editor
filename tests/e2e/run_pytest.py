#!/usr/bin/env python3
import argparse
import hashlib
import os
import subprocess
import sys
import venv
from pathlib import Path


def venv_python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def requirements_hash(requirements: Path) -> str:
    digest = hashlib.sha256()
    digest.update(requirements.read_bytes())
    return digest.hexdigest()


def ensure_venv(venv_dir: Path, requirements: Path) -> Path:
    python = venv_python(venv_dir)
    if not python.exists():
        venv.EnvBuilder(with_pip=True, clear=False).create(venv_dir)

    marker = venv_dir / ".requirements.sha256"
    current_hash = requirements_hash(requirements)
    if not marker.exists() or marker.read_text(encoding="utf-8") != current_hash:
        subprocess.check_call([
            str(python),
            "-m",
            "pip",
            "install",
            "-r",
            str(requirements),
        ])
        marker.write_text(current_hash, encoding="utf-8")
    return python


def main() -> int:
    parser = argparse.ArgumentParser(description="Run FlowForge e2e pytest suite in a venv.")
    parser.add_argument("--venv", required=True, type=Path)
    parser.add_argument("--requirements", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    python = ensure_venv(args.venv, args.requirements)
    env = os.environ.copy()
    env["FFG_RUNTIME"] = str(args.runtime)

    pytest_args = args.pytest_args
    if pytest_args and pytest_args[0] == "--":
        pytest_args = pytest_args[1:]
    if not pytest_args:
        pytest_args = [str(Path(__file__).resolve().parent)]

    return subprocess.call([str(python), "-m", "pytest", *pytest_args], env=env)


if __name__ == "__main__":
    raise SystemExit(main())
