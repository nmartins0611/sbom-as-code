#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+

DOCUMENTATION = """
---
module: verify_grype_diff
short_description: Diff two Grype reports and summarize resolved CVEs
"""

import json
import os
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.secops.sbom.plugins.module_utils.grype_rhel import diff_grype_reports, load_yaml_file


def main():
    module = AnsibleModule(
        argument_spec={
            "before_file": {"type": "str", "required": True},
            "after_file": {"type": "str", "required": True},
            "output_file": {"type": "str", "required": True},
            "policy_file": {"type": "str", "required": False, "default": ""},
            "policy": {"type": "dict", "required": False},
        },
        supports_check_mode=True,
    )
    before_file = module.params["before_file"]
    after_file = module.params["after_file"]
    output_file = module.params["output_file"]
    for path in (before_file, after_file):
        if not os.path.isfile(path):
            module.fail_json(msg="Grype file not found: %s" % path)
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
        diff = diff_grype_reports(before_file, after_file, policy)
    except Exception as exc:
        module.fail_json(msg="Failed to diff Grype reports: %s" % exc)
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.isdir(output_dir):
        os.makedirs(output_dir, mode=0o750)
    if not module.check_mode:
        with open(output_file, "w", encoding="utf-8") as handle:
            json.dump(diff, handle, indent=2)
    module.exit_json(changed=not module.check_mode, diff=diff, output_file=output_file)


if __name__ == "__main__":
    main()
