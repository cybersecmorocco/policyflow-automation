#!/usr/bin/python
"""Write a one-page PDF dashboard from check findings. Does not change remote hosts."""

DOCUMENTATION = r"""
---
module: policyflow_report
short_description: Write the check dashboard as a PDF
description:
  - Count pass, fail, and waived findings and write a one-page PDF.
options:
  dest:
    description: Path of the PDF on the control node.
    required: true
    type: path
  hosts:
    description: Machines and their findings.
    required: true
    type: list
"""


def dashboard_lines(hosts):
    findings = []
    for host in hosts:
        findings.extend(host.get("findings") or [])
    passed = sum(1 for item in findings if item.get("result") == "pass")
    failed = sum(1 for item in findings if item.get("result") == "fail")
    waived = sum(1 for item in findings if item.get("result") == "waived")
    decided = passed + failed
    score = int(round(100.0 * passed / decided)) if decided else 0
    lines = [
        "PolicyFlow",
        "Machines: %d" % len(hosts),
        "Score: %d" % score,
        "Pass: %d" % passed,
        "Fail: %d" % failed,
        "Waived: %d" % waived,
        "",
    ]
    for host in hosts:
        lines.append(host.get("host", ""))
        for finding in host.get("findings") or []:
            lines.append(
                "%s  %s  desired=%s  observed=%s"
                % (finding.get("name"), finding.get("result"), finding.get("desired"), finding.get("observed"))
            )
    return lines


def pdf_bytes(lines):
    commands = ["BT", "/F1 11 Tf", "48 780 Td"]
    for index, line in enumerate(lines):
        if index:
            commands.append("0 -16 Td")
        safe = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        commands.append("(%s) Tj" % safe)
    commands.append("ET")
    stream = ("\n".join(commands) + "\n").encode("latin-1", "replace")
    objects = []

    def add(body):
        objects.append(body)
        return len(objects)

    font = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    content = add("<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream.decode("latin-1")))
    page = add("<< /Type /Page /Parent 4 0 R /MediaBox [0 0 612 792] /Contents %d 0 R /Resources << /Font << /F1 %d 0 R >> >> >>" % (content, font))
    pages = add("<< /Type /Pages /Count 1 /Kids [%d 0 R] >>" % page)
    catalog = add("<< /Type /Catalog /Pages %d 0 R >>" % pages)
    out = ["%PDF-1.4\n"]
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(sum(len(part.encode("latin-1")) for part in out))
        out.append("%d 0 obj\n%s\nendobj\n" % (number, body))
    xref = sum(len(part.encode("latin-1")) for part in out)
    out.append("xref\n0 %d\n" % (len(objects) + 1))
    out.append("0000000000 65535 f \n")
    for offset in offsets[1:]:
        out.append("%010d 00000 n \n" % offset)
    out.append("trailer\n<< /Size %d /Root %d 0 R >>\n" % (len(objects) + 1, catalog))
    out.append("startxref\n%d\n%%%%EOF\n" % xref)
    return "".join(out).encode("latin-1")


def main():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec=dict(
            dest=dict(type="path", required=True),
            hosts=dict(type="list", required=True),
        ),
        supports_check_mode=True,
    )
    lines = dashboard_lines(module.params["hosts"])
    if module.check_mode:
        module.exit_json(changed=False, lines=lines)
    payload = pdf_bytes(lines)
    dest = module.params["dest"]
    changed = True
    try:
        with open(dest, "rb") as handle:
            changed = handle.read() != payload
    except OSError:
        changed = True
    if changed:
        import os
        directory = os.path.dirname(dest)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(dest, "wb") as handle:
            handle.write(payload)
    module.exit_json(changed=changed, dest=dest, lines=lines)


if __name__ == "__main__":
    main()
