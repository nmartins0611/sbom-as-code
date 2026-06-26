#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+

DOCUMENTATION = """
---
module: parse_grype_rhel
short_description: Parse Grype JSON and filter RHEL-relevant RPM/kernel CVE matches
options:
  grype_file:
    type: str
    required: true
  policy_file:
    type: str
    default: ""
  policy:
    type: dict
"""

EXAMPLES = """
- secops.sbom.parse_grype_rhel:
    grype_file: /tmp/artifacts/rhel1/grype-report.json
"""

RETURN = """
matches:
  type: list
skipped:
  type: list
relevant_match_count:
  type: int
"""

import os
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.secops.sbom.plugins.module_utils.grype_rhel import load_yaml_file, parse_grype_file


def main():
    module = AnsibleModule(
        argument_spec={
            "grype_file": {"type": "str", "required": True},
            "policy_file": {"type": "str", "required": False, "default": ""},
            "policy": {"type": "dict", "required": False},
        },
        supports_check_mode=True,
    )
    grype_file = module.params["grype_file"]
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
    except Exception as exc:
        module.fail_json(msg="Failed to parse Grype file %s: %s" % (grype_file, exc))
    module.exit_json(changed=False, **parsed)


if __name__ == "__main__":
    main()
