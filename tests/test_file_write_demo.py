"""The committed demo transcript is a regression fixture for the file-write pilot."""
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_demo_output_matches_golden_transcript():
    result = subprocess.run([sys.executable, str(REPO / "demo" / "file_write_pilot_demo.py")],
                            cwd=REPO, capture_output=True, text=True, timeout=300,
                            env={**__import__("os").environ, "PYTHONPATH": str(REPO)})
    assert result.returncode == 0, result.stderr
    expected = (REPO / "demo" / "expected_transcript.txt").read_text()
    assert result.stdout == expected
