#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import sys


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: count_json_matches.py FILE.json ARRAY_KEY")
    with open(sys.argv[1], "r", encoding="utf-8") as handle:
        data = json.load(handle)
    items = data.get(sys.argv[2], [])
    if not isinstance(items, list):
        raise SystemExit(f"expected list at key {sys.argv[2]!r}")
    print(len(items))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
