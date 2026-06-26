# -*- coding: utf-8 -*-

import json
import sys
from pathlib import Path

COLLECTION = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(COLLECTION))

from plugins.module_utils.grype_rhel import (  # noqa: E402
    build_remediation_plan,
    diff_grype_reports,
    extract_rhsa_ids,
    parse_grype_file,
)


def test_extract_rhsa_from_urls():
    match = {
        "vulnerability": {
            "urls": [
                "https://access.redhat.com/errata/RHSA-2023:7370",
            ]
        }
    }
    assert extract_rhsa_ids(match) == ["RHSA-2023:7370"]


def test_parse_and_plan_with_sample_policy(tmp_path):
    sample = {
        "matches": [
            {
                "artifact": {
                    "name": "kernel",
                    "version": "5.14.0-570.el9",
                    "type": "rpm",
                },
                "vulnerability": {
                    "id": "CVE-2024-1086",
                    "severity": "High",
                    "fix": {"state": "fixed", "versions": ["5.14.0-611.el9"]},
                    "urls": ["https://access.redhat.com/errata/RHSA-2024:1234"],
                },
            },
            {
                "artifact": {
                    "name": "openssl",
                    "version": "1.1.1k",
                    "type": "rpm",
                },
                "vulnerability": {
                    "id": "CVE-2024-9999",
                    "severity": "Low",
                    "fix": {"state": "fixed", "versions": ["1.1.1k-9.el9"]},
                },
            },
        ]
    }
    grype_path = tmp_path / "grype-report.json"
    grype_path.write_text(json.dumps(sample))
    policy = {
        "min_severity": "high",
        "actionable_only": True,
        "ignore_cves": [],
        "ignore_packages": [],
        "remediation_method": "advisory_then_cve",
    }
    parsed = parse_grype_file(str(grype_path), policy)
    assert parsed["relevant_match_count"] == 1
    plan = build_remediation_plan("rhel1", parsed, policy)
    assert plan["summary"]["advisory_count"] == 1
    assert plan["advisories"][0]["id"] == "RHSA-2024:1234"
    assert plan["summary"]["cve_fallback_count"] == 0


def test_diff_grype_reports(tmp_path):
    policy = {"min_severity": "high", "actionable_only": True}
    before = {
        "matches": [
            {
                "artifact": {"name": "kernel", "type": "rpm", "version": "1"},
                "vulnerability": {
                    "id": "CVE-2024-0001",
                    "severity": "High",
                    "fix": {"state": "fixed", "versions": ["2"]},
                },
            }
        ]
    }
    after = {"matches": []}
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(json.dumps(before))
    after_path.write_text(json.dumps(after))
    diff = diff_grype_reports(str(before_path), str(after_path), policy)
    assert diff["resolved_count"] == 1
    assert diff["after_count"] == 0


def test_slim_grype_report_reduces_payload():
    from importlib.machinery import SourceFileLoader

    script = COLLECTION / "roles" / "sbom_scan" / "files" / "slim_grype_report.py"
    module = SourceFileLoader("slim_grype_report", str(script)).load_module()
    sample = {
        "matches": [
            {
                "artifact": {"name": "openssl", "version": "1.1.1k", "type": "rpm", "language": "python"},
                "vulnerability": {
                    "id": "CVE-2024-0001",
                    "severity": "High",
                    "namespace": "redhat:distro:redhat:9",
                    "dataSource": "https://access.redhat.com/errata/RHSA-2024:1234",
                    "urls": ["https://access.redhat.com/errata/RHSA-2024:1234"],
                    "description": "x" * 5000,
                    "fix": {"state": "fixed", "versions": ["1.1.1k-9.el9"]},
                },
            }
        ]
    }
    slim = module.slim_grype_report(sample)
    assert len(slim["matches"]) == 1
    assert "description" not in slim["matches"][0]["vulnerability"]
    assert slim["matches"][0]["artifact"]["name"] == "openssl"
