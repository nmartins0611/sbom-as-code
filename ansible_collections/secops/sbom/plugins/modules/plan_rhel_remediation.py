#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+

DOCUMENTATION = """
---
module: plan_rhel_remediation
short_description: Build targeted RHSA/CVE remediation plan from Grype JSON
options:
  grype_file:
    type: str
    required: true
  output_file:
    type: str
    required: true
  host:
    type: str
    required: true
  policy_file:
    type: str
    default: ""
  policy:
    type: dict
  write_findings_preview:
    type: bool
    default: true
"""

import json
import os
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.secops.sbom.plugins.module_utils.grype_rhel import (
    build_findings_preview,
    build_remediation_plan,
    load_yaml_file,
    parse_grype_file,
)


def main():
    module = AnsibleModule(
        argument_spec={
            "grype_file": {"type": "str", "required": True},
            "output_file": {"type": "str", "required": True},
            "host": {"type": "str", "required": True},
            "policy_file": {"type": "str", "required": False, "default": ""},
            "policy": {"type": "dict", "required": False},
            "write_findings_preview": {"type": "bool", "required": False, "default": True},
        },
        supports_check_mode=True,
    )
    grype_file = module.params["grype_file"]
    output_file = module.params["output_file"]
    host = module.params["host"]
    if not os.path.isfile(grype_file):
        module.fail_json(msg="Grype file not found: %s" % grype_file)
    policy = module.params["policy"] or {}
    policy_file = module.params["policy_file"]
    if not policy and policy_file:
        if not os.path.isfile(policy_file):
            module.fail_json(msg="Policy file not found: %s" % policy_file)
        try:
            policy = load_yaml_file(policy_file)
        except Exception as exc:
            module.fail_json(msg="Failed to load policy file %s: %s" % (policy_file, exc))
    try:
        parsed = parse_grype_file(grype_file, policy)
        plan = build_remediation_plan(host, parsed, policy)
    except Exception as exc:
        module.fail_json(msg="Failed to build remediation plan from %s: %s" % (grype_file, exc))
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.isdir(output_dir):
        os.makedirs(output_dir, mode=0o750)
    findings_preview_file = ""
    if module.params["write_findings_preview"]:
        findings_preview_file = os.path.join(output_dir, "findings-preview.json")
        preview = {"host": host, "findings": build_findings_preview(plan)}
        with open(findings_preview_file, "w", encoding="utf-8") as handle:
            json.dump(preview, handle, indent=2)
    if not module.check_mode:
        with open(output_file, "w", encoding="utf-8") as handle:
            json.dump(plan, handle, indent=2)
    module.exit_json(
        changed=not module.check_mode,
        plan=plan,
        output_file=output_file,
        findings_preview_file=findings_preview_file,
        advisory_count=plan["summary"]["advisory_count"],
        cve_fallback_count=plan["summary"]["cve_fallback_count"],
    )


if __name__ == "__main__":
    main()
