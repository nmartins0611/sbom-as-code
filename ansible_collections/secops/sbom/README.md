# secops.sbom Ansible Collection

SBOM-driven RHEL CVE discovery and targeted security remediation.

New to the project? Start with the repo [project overview](../../../docs/OVERVIEW.md).

## Playbooks

| Playbook | Hosts | Purpose |
|----------|-------|---------|
| `playbooks/scan.yml` | targets | Syft + Grype scan, fetch artifacts to controller |
| `playbooks/plan_remediation.yml` | localhost | Build `remediation-plan.json` per host |
| `playbooks/remediate.yml` | targets | Apply `dnf update-minimal --advisory` / `--cve` |
| `playbooks/verify.yml` | targets + localhost | Re-scan and diff CVE counts |
| `playbooks/ingest_external.yml` | localhost | External SBOM/Grype → plan |
| `playbooks/aap_assessment.yml` | targets + localhost | AAP assessment JT entry point |
| `playbooks/aap_remediate.yml` | targets | AAP remediate JT (approval gate) |
| `playbooks/aap_verify.yml` | targets + localhost | AAP verify JT entry point |

See [`aap/README.md`](../../../aap/README.md) for Controller setup, EE build, and surveys.

## Quick start

```bash
cd /path/to/sbom-as-code
export ANSIBLE_COLLECTIONS_PATH="$(pwd)/ansible_collections"

ansible-playbook ansible_collections/secops/sbom/playbooks/scan.yml
ansible-playbook ansible_collections/secops/sbom/playbooks/plan_remediation.yml
ansible-playbook ansible_collections/secops/sbom/playbooks/remediate.yml
ansible-playbook ansible_collections/secops/sbom/playbooks/verify.yml
```

## Scan scope

Set `sbom_scan_scope` in inventory (`minimal` default, `medium`, or `full`). See `examples/inventory/scan-scopes.yml` and `roles/sbom_scan/defaults/main.yml` for timeout maps.

Optional dedicated scan node: set `sbom_scan_node` to an inventory hostname (see `examples/inventory/scan-node.yml`).

Grype tuning: `sbom_grype_slim_output` (default true), `sbom_grype_distro` (auto from RHEL version), fixed minimal Syft cataloger exclusions.

## Tags

Remediation tasks are tagged `advisory-RHSA-YYYY:NNNN`, `cve-CVE-YYYY-NNNN`, and `pkg-<name>`.
