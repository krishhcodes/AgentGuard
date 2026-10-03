"""The CLI module must import and parse (a syntax slip in cli.py once went unnoticed by every other test)."""

import subprocess
import sys

from agentguard.config import ROOT


def test_cli_imports_and_lists_eval_flags():
    out = subprocess.run([sys.executable, "-m", "agentguard", "eval", "--help"], cwd=ROOT,
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0 and "--freeze" in out.stdout and "--only" in out.stdout
