"""Start both A2A agents and the conversation UI."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import httpx
import uvicorn
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
HUNTER = "http://127.0.0.1:10020/.well-known/agent-card.json"
ANALYZER = "http://127.0.0.1:10021/.well-known/agent-card.json"


def wait_for(url: str, name: str) -> None:
    for _ in range(40):
        try:
            response = httpx.get(url, timeout=1.0)
            if response.status_code == 200:
                print(f"{name} is up")
                return
        except httpx.HTTPError:
            time.sleep(0.25)
    raise RuntimeError(f"{name} did not start at {url}")


def main() -> None:
    load_dotenv(ROOT / ".env")
    python = sys.executable
    hunter = subprocess.Popen([python, "-m", "agents.red"], cwd=ROOT)
    analyzer = subprocess.Popen([python, "-m", "agents.blue"], cwd=ROOT)
    try:
        wait_for(HUNTER, "Gemini")
        wait_for(ANALYZER, "Claude")
        print("\nOpen http://127.0.0.1:8080")
        print("Or run: uv run python -m host.converse --repo PATH --bug FIX\n")
        uvicorn.run("host.web:app", host="127.0.0.1", port=8080, log_level="info")
    finally:
        hunter.terminate()
        analyzer.terminate()
        hunter.wait(timeout=5)
        analyzer.wait(timeout=5)


if __name__ == "__main__":
    main()
