#!/usr/bin/python
"""Read one host fact and compare it with the desired value. Never changes the host."""

DOCUMENTATION = r"""
---
module: policyflow_check
short_description: Compare one firewall rule with the live host
description:
  - Read the packet filter and return pass or fail with the observed value.
  - The module does not change the host.
options:
  kind:
    description: A firewall rule, or one host control.
    required: true
    choices: [rule, control]
  name:
    description: Rule name, or a control id.
    required: true
    type: str
  action:
    description: allow or deny. Used for a rule.
    type: str
  port:
    description: Destination port. Used for a rule.
    type: int
  source:
    description: any, an address, a range, or one hostname. Used for a rule.
    type: str
  desired:
    description: Expected observed value for a control.
    type: str
"""

EXAMPLES = r"""
- name: Test the https rule
  policyflow_check:
    kind: rule
    name: allow-https
    action: allow
    port: 443
    source: any
"""

RETURN = r"""
finding:
  description: Rule name, result, desired text, and observed text.
  returned: always
  type: dict
"""


def source_matches(entry_source, wanted_source):
    if entry_source == "any":
        return True
    return entry_source == wanted_source


def judge_rule(state, action, port, source):
    """Return pass or fail, plus the observed text.

    Entries are read from the top. The first entry whose port and source
    match is the one that counts.
    """
    desired = "allow" if action == "allow" else "deny"
    for entry in state.get("entries", []):
        if entry.get("port") not in (None, port):
            continue
        if not source_matches(entry.get("source", "any"), source):
            continue
        observed = "rule %s port %s from %s" % (
            entry["action"],
            entry.get("port"),
            entry.get("source"),
        )
        result = "pass" if entry["action"] == desired else "fail"
        return result, observed

    default = state.get("default", "accept")
    if state.get("present"):
        observed = "default %s" % default
    else:
        observed = "no packet filter; default %s" % default
    actual = "allow" if default == "accept" else "deny"
    result = "pass" if actual == desired else "fail"
    return result, observed


def parse_iptables(text):
    state = {"present": True, "default": "accept", "entries": []}
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("-P INPUT "):
            policy = line.split()[-1].upper()
            state["default"] = "drop" if policy in ("DROP", "REJECT") else "accept"
            continue
        if not line.startswith("-A INPUT "):
            continue
        action = None
        if line.endswith("-j ACCEPT"):
            action = "allow"
        elif line.endswith("-j DROP") or line.endswith("-j REJECT"):
            action = "deny"
        if action is None:
            continue
        parts = line.split()
        port = None
        if "--dport" in parts:
            port = int(parts[parts.index("--dport") + 1])
        source = "any"
        if "-s" in parts:
            source = parts[parts.index("-s") + 1]
        state["entries"].append({"action": action, "port": port, "source": source})
    return state


def empty_filter():
    return {"present": False, "default": "accept", "entries": []}


def command_exists(run, name):
    rc, out, err = run(["/bin/sh", "-c", "command -v %s" % name])
    return rc == 0 and bool(out.strip())


def sshd_value(run, key):
    rc, out, err = run(["sshd", "-T"])
    if rc != 0:
        rc, out, err = run(["sudo", "-n", "sshd", "-T"])
    if rc != 0:
        return "unavailable"
    prefix = key + " "
    for line in out.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return "absent"


def logging_state(run):
    rc, out, err = run(["ps", "-eo", "comm"])
    if rc != 0:
        return "unavailable"
    names = set(out.split())
    for name in ("auditd", "rsyslogd", "systemd-journald"):
        if name in names:
            return "running"
    return "not running"


def judge_control(run, name, desired):
    if name == "ssh_root_login":
        observed = sshd_value(run, "permitrootlogin")
    elif name == "ssh_password_auth":
        observed = sshd_value(run, "passwordauthentication")
    elif name == "firewall_default":
        state = observe_filter(run)
        observed = state.get("default", "accept")
    elif name == "logging_service":
        observed = logging_state(run)
    else:
        return "fail", "unknown control"
    result = "pass" if observed == desired else "fail"
    return result, observed


def observe_filter(run):
    if command_exists(run, "iptables"):
        rc, out, err = run(["iptables", "-S"])
        if rc == 0:
            return parse_iptables(out)
    if command_exists(run, "nft"):
        rc, out, err = run(["nft", "list", "ruleset"])
        if rc == 0 and out.strip():
            return {"present": True, "default": "accept", "entries": []}
    return empty_filter()


def main():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec=dict(
            kind=dict(type="str", required=True, choices=["rule", "control"]),
            name=dict(type="str", required=True),
            action=dict(type="str", choices=["allow", "deny"]),
            port=dict(type="int"),
            source=dict(type="str"),
            desired=dict(type="str"),
        ),
        required_if=[
            ("kind", "rule", ["action", "port", "source"]),
            ("kind", "control", ["desired"]),
        ],
        supports_check_mode=True,
    )
    params = module.params

    def run(argv):
        return module.run_command(argv, check_rc=False)

    if params["kind"] == "rule":
        state = observe_filter(run)
        result, observed = judge_rule(state, params["action"], params["port"], params["source"])
        desired = "%s port %s from %s" % (params["action"], params["port"], params["source"])
        kind = "rule"
    else:
        result, observed = judge_control(run, params["name"], params["desired"])
        desired = params["desired"]
        kind = "control"
    module.exit_json(
        changed=False,
        finding=dict(
            name=params["name"],
            kind=kind,
            result=result,
            desired=desired,
            observed=observed,
        ),
    )


if __name__ == "__main__":
    main()
