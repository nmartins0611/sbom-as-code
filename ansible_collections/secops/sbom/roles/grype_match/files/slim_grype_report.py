#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reduce Grype JSON reports to fields required by secops.sbom planning."""

from __future__ import annotations

import json
import sys
from typing import Any


def slim_grype_report(data: dict[str, Any]) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for match in data.get("matches", []):
        artifact = match.get("artifact", {})
        vulnerability = match.get("vulnerability", {})
        fix = vulnerability.get("fix") or {}
        matches.append({
            "artifact": {
                "name": artifact.get("name", ""),
                "version": artifact.get("version", ""),
                "type": artifact.get("type", ""),
            },
            "vulnerability": {
                "id": vulnerability.get("id", ""),
                "severity": vulnerability.get("severity", ""),
                "namespace": vulnerability.get("namespace", ""),
                "dataSource": vulnerability.get("dataSource", ""),
                "urls": vulnerability.get("urls") or [],
                "fix": {
                    "state": fix.get("state", "unknown"),
                    "versions": fix.get("versions") or [],
                },
            },
        })
    return {"matches": matches}


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: slim_grype_report.py INPUT.json OUTPUT.json")
    with open(sys.argv[1], "r", encoding="utf-8") as handle:
        data = json.load(handle)
    slim = slim_grype_report(data)
    with open(sys.argv[2], "w", encoding="utf-8") as handle:
        json.dump(slim, handle, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
