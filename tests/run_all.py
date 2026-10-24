"""Run every AirWarden test file and report a summary.

    python3 tests/run_all.py

Core tests need only the standard library. test_graph.py self-skips unless
`langgraph` is installed.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = ["test_detect.py", "test_agent.py", "test_new_attacks.py",
         "test_respond.py", "test_server.py", "test_graph.py"]


def main():
    failed = []
    for t in TESTS:
        print("=" * 56)
        print("RUN", t)
        print("-" * 56)
        r = subprocess.run([sys.executable, os.path.join(HERE, t)])
        if r.returncode != 0:
            failed.append(t)
    print("=" * 56)
    if failed:
        print("FAILED:", ", ".join(failed))
        sys.exit(1)
    print("ALL TEST FILES PASSED")


if __name__ == "__main__":
    main()
