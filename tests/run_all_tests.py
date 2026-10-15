"""Unified Test Runner for GreenLight.

Executes all test suites in sequence:
  1. tests/test_green_light.py  - Core contract unit tests
  2. tests/adversarial_suite.py   - Adversarial & exploit security suite
  3. tests/wallet.test.mjs       - EIP-6963 / EIP-1193 wallet integration tests

Usage:
  python3 tests/run_all_tests.py
"""
import os
import subprocess
import sys

GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

tests = [
    ("Contract Unit Tests", [sys.executable, "tests/test_green_light.py"]),
    ("Adversarial & Exploit Suite", [sys.executable, "tests/adversarial_suite.py"]),
    ("Wallet Layer Tests", ["node", "tests/wallet.test.mjs"]),
]

print(f"\n{BOLD}{CYAN}===================================================={RESET}")
print(f"{BOLD}{CYAN}    GreenLight Complete Verification Suite          {RESET}")
print(f"{BOLD}{CYAN}===================================================={RESET}\n")

all_passed = True
for name, cmd in tests:
    print(f"{BOLD}► Running {name}...{RESET}")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        print(f"  {GREEN}✔ {name} PASSED{RESET}\n")
        if res.stdout.strip():
            for line in res.stdout.strip().split("\n"):
                print(f"    {line}")
            print()
    else:
        print(f"  {RED}✘ {name} FAILED (Exit Code: {res.returncode}){RESET}\n")
        if res.stdout:
            print("STDOUT:\n", res.stdout)
        if res.stderr:
            print("STDERR:\n", res.stderr)
        all_passed = False
        break

print(f"{BOLD}{CYAN}===================================================={RESET}")
if all_passed:
    print(f"{BOLD}{GREEN}  🎉 ALL SUITES PASSED SUCCESSFULLY!                {RESET}")
    print(f"{BOLD}{CYAN}===================================================={RESET}\n")
    sys.exit(0)
else:
    print(f"{BOLD}{RED}  ❌ ONE OR MORE SUITES FAILED!                     {RESET}")
    print(f"{BOLD}{CYAN}===================================================={RESET}\n")
    sys.exit(1)
