import os

# Keep the default test run fast and deterministic: without this, the
# end-to-end analyze() tests in test_core.py would each shell out to the real
# cve-bin-tool binary (and its multi-GB local CVE database) for every seeded
# fixture tree, adding tens of seconds per test for a heavy external tool
# whose own entry-parsing logic is already covered by a fixture-driven unit
# test. Mirrors IFDA_GHIDRA_TEST's opt-in-for-slow pattern, just inverted:
# cve-bin-tool is normally on in real usage, opt-in-for-live in tests (see
# IFDA_CVE_BIN_TOOL_TEST for the live wiring smoke test).
if os.environ.get("IFDA_CVE_BIN_TOOL_TEST") != "1":
    os.environ.setdefault("IFDA_DISABLE_CVE_BIN_TOOL", "1")
