"""
Comprehensive Test Runner for Password Security Essentials Microservice
Runs all unit tests, cryptographic verifications, and endpoint tests via pytest.
"""

import sys
import pytest

def run_tests():
    print("=" * 70)
    print("  Password Security Essentials Microservice — Full Test Suite")
    print("=" * 70)

    exit_code = pytest.main(["tests", "-v"])

    print("\n" + "=" * 70)
    if exit_code == 0:
        print("  SUCCESS: All tests passed successfully!")
    else:
        print(f"  FAILED: Pytest exited with code {exit_code}")
    print("=" * 70)

    return exit_code

if __name__ == "__main__":
    sys.exit(run_tests())
