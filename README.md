# sbom-as-code

Ansible collection **`secops.sbom`**: SBOM inventory, Grype CVE matching, controller-side remediation planning, and targeted RHEL security updates.

## Quick start

```bash
git clone https://github.com/YOUR_ORG/sbom-as-code.git
cd sbom-as-code
export ANSIBLE_COLLECTIONS_PATH="$(pwd)/ansible_collections"

# Optional: local inventory overlay (keeps example hosts.yml unchanged)
cp inventory/hosts.local.yml.example inventory/hosts.local.yml
# edit inventory/hosts.local.yml with your hostnames and addresses

ansible-playbook ansible_collections/secops/sbom/playbooks/scan.yml -l rhel1
```

Credentials (if needed): copy [`inventory/secrets.yml.example`](inventory/secrets.yml.example) to `inventory/secrets.yml` — that file is gitignored.

Scan output lands in `artifacts/<hostname>/` (also gitignored).

## Documentation

| Doc | Audience |
|-----|----------|
| [docs/OVERVIEW.md](docs/OVERVIEW.md) | New users — what the project does, pipeline, input modes, AAP |
| [CLAUDE.md](CLAUDE.md) | Contributors and agents — architecture, locked decisions, commands |
| [ansible_collections/secops/sbom/README.md](ansible_collections/secops/sbom/README.md) | Collection usage — playbooks, scan scope, tags |
| [aap/README.md](aap/README.md) | AAP job templates, execution environment, surveys |

## Security

Do **not** commit:

- `inventory/secrets.yml` — passwords, vault content, tokens
- `inventory/hosts.local.yml` — real hostnames/IPs for your environment
- `artifacts/` — SBOM and vulnerability reports from your infrastructure

The committed [`inventory/hosts.yml`](inventory/hosts.yml) uses placeholder `*.example.com` hostnames only.

## License

GPL-3.0-or-later — see [`ansible_collections/secops/sbom/LICENSE`](ansible_collections/secops/sbom/LICENSE).
