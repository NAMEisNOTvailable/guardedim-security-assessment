from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Demo:
    number: str
    title: str
    script: Path


DEMOS = (
    Demo(
        number="01",
        title="Unauthenticated key exchange",
        script=Path("demos/mitm_key_replacement_demo.py"),
    ),
    Demo(
        number="02",
        title="Handshake desynchronisation",
        script=Path("demos/handshake_desync_demo.py"),
    ),
)


def run_demo(demo: Demo) -> bool:
    command = [sys.executable, str(ROOT / demo.script)]
    started = time.perf_counter()
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    elapsed = time.perf_counter() - started

    print()
    print(f"[{demo.number}] {demo.title}")
    print(f"Command: python {demo.script.as_posix()}")
    print("-" * 72)
    print(result.stdout.rstrip() or "(no stdout)")
    if result.stderr.strip():
        print()
        print("[stderr]")
        print(result.stderr.rstrip())
    print("-" * 72)

    passed = result.returncode == 0
    status = "PASS" if passed else "FAIL"
    print(f"Result: {status} ({elapsed:.2f}s)")
    return passed


def main() -> None:
    print("GuardedIM Local Vulnerability Demo Report")
    print("Scope: localhost and in-process sockets only; no third-party targets.")

    results = [run_demo(demo) for demo in DEMOS]
    passed = sum(1 for result in results if result)
    total = len(results)

    print()
    print("=" * 72)
    print(f"Summary: {passed}/{total} demos passed.")
    if passed == total:
        print("Overall result: PASS")
        return

    print("Overall result: FAIL")
    raise SystemExit(1)


if __name__ == "__main__":
    main()
