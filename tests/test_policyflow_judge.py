#!/usr/bin/env python3
"""Judge the firewall rule without a live host."""

import importlib.util
import pathlib

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "plugins" / "modules" / "policyflow_check.py"
spec = importlib.util.spec_from_file_location("policyflow_check", MODULE_PATH)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def test_open_host_allows_https():
    result, observed = check.judge_rule(check.empty_filter(), "allow", 443, "any")
    assert result == "pass", observed
    assert "accept" in observed


def test_open_host_does_not_deny_https():
    result, observed = check.judge_rule(check.empty_filter(), "deny", 443, "any")
    assert result == "fail", observed


def test_explicit_drop_fails_an_allow():
    result, observed = check.judge_rule(check.parse_iptables("-P INPUT DROP\n"), "allow", 443, "any")
    assert result == "fail", observed


def test_explicit_accept_passes_an_allow():
    text = "-P INPUT DROP\n-A INPUT -p tcp --dport 443 -j ACCEPT\n"
    result, observed = check.judge_rule(check.parse_iptables(text), "allow", 443, "any")
    assert result == "pass", observed


def main():
    test_open_host_allows_https()
    test_open_host_does_not_deny_https()
    test_explicit_drop_fails_an_allow()
    test_explicit_accept_passes_an_allow()
    print("judge tests passed")


if __name__ == "__main__":
    main()
