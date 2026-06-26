# -*- coding: utf-8 -*-
# GNU General Public License v3.0+

from __future__ import annotations

import json
import re
from typing import Any

RHSA_PATTERN = re.compile(r"RHSA-\d{4}:\d+")
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)

SEVERITY_RANK: dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Negligible": 4,
    "Unknown": 5,
}

KERNEL_PACKAGES: frozenset[str] = frozenset({
    "kernel",
    "kernel-core",
    "kernel-modules",
    "kernel-modules-core",
    "kernel-devel",
    "kernel-headers",
    "kernel-uki-virt",
    "linux-kernel",
})

RHEL_ARTIFACT_TYPES: frozenset[str] = frozenset({"rpm", "linux-kernel"})


def load_json_file(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_yaml_file(path: str) -> dict[str, Any]:
    import yaml

    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"Policy file must be a mapping: {path}")
    return data


def severity_meets_minimum(severity: str, minimum: str) -> bool:
    current = SEVERITY_RANK.get(severity, SEVERITY_RANK["Unknown"])
    floor = SEVERITY_RANK.get(minimum, SEVERITY_RANK["High"])
    return current <= floor


def extract_rhsa_ids(match: dict[str, Any]) -> list[str]:
    blob = json.dumps(match)
    found = RHSA_PATTERN.findall(blob)
    unique: list[str] = []
    for item in found:
        if item not in unique:
            unique.append(item)
    return unique


def normalize_package_name(artifact: dict[str, Any]) -> str:
    name = artifact.get("name", "unknown")
    artifact_type = artifact.get("type", "")
    if artifact_type == "linux-kernel":
        return "kernel"
    return name


def is_rhel_relevant_artifact(artifact: dict[str, Any]) -> bool:
    return artifact.get("type", "") in RHEL_ARTIFACT_TYPES


def package_requires_reboot(package_name: str) -> bool:
    if package_name in KERNEL_PACKAGES:
        return True
    return package_name.startswith("kernel-")


def build_tags(advisory_id: str | None, cve_id: str, package_name: str) -> list[str]:
    tags: list[str] = [f"cve-{cve_id.upper()}", f"pkg-{package_name}"]
    if advisory_id is not None:
        tags.insert(0, f"advisory-{advisory_id}")
    return tags


def parse_grype_file(grype_path: str, policy: dict[str, Any]) -> dict[str, Any]:
    data = load_json_file(grype_path)
    matches = data.get("matches", [])
    ignore_cves = {c.upper() for c in policy.get("ignore_cves", [])}
    ignore_packages = set(policy.get("ignore_packages", []))
    min_severity = policy.get("min_severity", "high")
    actionable_only = bool(policy.get("actionable_only", True))

    parsed_matches: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for match in matches:
        artifact = match.get("artifact", {})
        vulnerability = match.get("vulnerability", {})
        if not is_rhel_relevant_artifact(artifact):
            continue

        cve_id = vulnerability.get("id", "")
        if not CVE_PATTERN.match(cve_id):
            continue

        cve_upper = cve_id.upper()
        package_name = normalize_package_name(artifact)
        severity = vulnerability.get("severity", "Unknown")
        fix = vulnerability.get("fix", {})
        fix_state = fix.get("state", "unknown")
        fix_versions = fix.get("versions", [])

        if cve_upper in ignore_cves:
            skipped.append({"cve": cve_upper, "package": package_name, "reason": "ignored_by_policy"})
            continue

        if package_name in ignore_packages:
            skipped.append({"cve": cve_upper, "package": package_name, "reason": "ignored_package"})
            continue

        if not severity_meets_minimum(severity, min_severity):
            skipped.append({"cve": cve_upper, "package": package_name, "reason": "below_min_severity"})
            continue

        if actionable_only and fix_state != "fixed":
            skipped.append({"cve": cve_upper, "package": package_name, "reason": fix_state})
            continue

        if actionable_only and not fix_versions:
            skipped.append({"cve": cve_upper, "package": package_name, "reason": "no_fix_versions"})
            continue

        parsed_matches.append({
            "cve": cve_upper,
            "severity": severity,
            "package": package_name,
            "installed_version": artifact.get("version", ""),
            "fix_state": fix_state,
            "fix_versions": fix_versions,
            "rhsa_ids": extract_rhsa_ids(match),
            "reboot_required": package_requires_reboot(package_name),
        })

    return {
        "matches": parsed_matches,
        "skipped": skipped,
        "source_match_count": len(matches),
        "relevant_match_count": len(parsed_matches),
    }


def build_remediation_plan(host: str, parsed: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    remediation_method = policy.get("remediation_method", "advisory_then_cve")
    advisories: dict[str, dict[str, Any]] = {}
    cve_fallback: dict[str, dict[str, Any]] = {}

    for item in parsed["matches"]:
        cve_id = item["cve"]
        package_name = item["package"]
        rhsa_ids = item["rhsa_ids"]
        primary_rhsa = rhsa_ids[0] if rhsa_ids else None

        use_advisory = remediation_method in ("advisory", "advisory_then_cve") and primary_rhsa is not None
        if use_advisory:
            entry = advisories.setdefault(primary_rhsa, {
                "id": primary_rhsa,
                "cves": [],
                "packages": [],
                "severities": [],
                "reboot_required": False,
                "tags": [],
            })
            if cve_id not in entry["cves"]:
                entry["cves"].append(cve_id)
            if package_name not in entry["packages"]:
                entry["packages"].append(package_name)
            if item["severity"] not in entry["severities"]:
                entry["severities"].append(item["severity"])
            entry["reboot_required"] = entry["reboot_required"] or item["reboot_required"]
            for tag in build_tags(primary_rhsa, cve_id, package_name):
                if tag not in entry["tags"]:
                    entry["tags"].append(tag)
            continue

        if remediation_method in ("cve", "advisory_then_cve"):
            entry = cve_fallback.setdefault(cve_id, {
                "cve": cve_id,
                "packages": [],
                "severities": [],
                "reboot_required": False,
                "tags": [],
            })
            for tag in build_tags(None, cve_id, package_name):
                if tag not in entry["tags"]:
                    entry["tags"].append(tag)
            if package_name not in entry["packages"]:
                entry["packages"].append(package_name)
            if item["severity"] not in entry["severities"]:
                entry["severities"].append(item["severity"])
            entry["reboot_required"] = entry["reboot_required"] or item["reboot_required"]

    advisory_list = sorted(advisories.values(), key=lambda x: x["id"])
    cve_list = sorted(cve_fallback.values(), key=lambda x: x["cve"])

    plan = {
        "host": host,
        "advisories": advisory_list,
        "cve_fallback": cve_list,
        "skipped": parsed["skipped"],
        "summary": {
            "advisory_count": len(advisory_list),
            "cve_fallback_count": len(cve_list),
            "skipped_count": len(parsed["skipped"]),
            "relevant_match_count": parsed["relevant_match_count"],
        },
    }
    return plan


def build_findings_preview(plan: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for advisory in plan.get("advisories", []):
        rule_id = f"advisory-{advisory['id']}"
        findings.append({
            "rule_id": rule_id,
            "title": f"{advisory['id']} affects {', '.join(advisory['packages'])}",
            "severity": advisory["severities"],
            "cves": advisory["cves"],
            "remediation_available": True,
            "tags": advisory["tags"],
        })
    for item in plan.get("cve_fallback", []):
        rule_id = f"cve-{item['cve']}"
        findings.append({
            "rule_id": rule_id,
            "title": f"{item['cve']} affects {', '.join(item['packages'])}",
            "severity": item["severities"],
            "cves": [item["cve"]],
            "remediation_available": True,
            "tags": item["tags"],
        })
    return findings


def diff_grype_reports(before_path: str, after_path: str, policy: dict[str, Any]) -> dict[str, Any]:
    before = parse_grype_file(before_path, policy)
    after = parse_grype_file(after_path, policy)
    before_cves = {m["cve"] for m in before["matches"]}
    after_cves = {m["cve"] for m in after["matches"]}
    resolved = sorted(before_cves - after_cves)
    remaining = sorted(after_cves)
    new_cves = sorted(after_cves - before_cves)
    return {
        "before_count": len(before_cves),
        "after_count": len(after_cves),
        "resolved_cves": resolved,
        "remaining_cves": remaining,
        "new_cves": new_cves,
        "resolved_count": len(resolved),
    }
