#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys


def load_config(path: pathlib.Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("trusted credential config must be a JSON object")
    return data


def str_list(value: object, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ValueError(f"{field} must be an array of strings")
    return [x for x in value if x]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Validate runtime credentials against trusted inventory.")
    parser.add_argument("--config", required=True, help="Path to trusted credential JSON file")
    args = parser.parse_args(argv)

    config_path = pathlib.Path(args.config)
    if not config_path.exists():
        print(f"[cred-check] config not found: {config_path}", file=sys.stderr)
        return 1

    cfg = load_config(config_path)
    required = str_list(cfg.get("required"), "required")
    optional = str_list(cfg.get("optional"), "optional")
    prefixes = str_list(cfg.get("credential_prefixes"), "credential_prefixes")

    trusted = set(required) | set(optional)

    missing = [name for name in required if not os.environ.get(name, "").strip()]
    if missing:
        print("[cred-check] missing required credentials:", ", ".join(missing), file=sys.stderr)
        return 1

    if os.environ.get("SIGN_REPO_INDEX", "0").strip() == "1":
        signing_key_b64 = os.environ.get("APK_REPO_SIGNING_KEY_B64", "").strip()
        if not signing_key_b64:
            print(
                "[cred-check] SIGN_REPO_INDEX=1 but APK_REPO_SIGNING_KEY_B64 is missing",
                file=sys.stderr,
            )
            return 1

    unexpected: list[str] = []
    for key, value in os.environ.items():
        if not value:
            continue
        if prefixes and not any(key.startswith(prefix) for prefix in prefixes):
            continue
        if key not in trusted:
            unexpected.append(key)

    if unexpected:
        unexpected.sort()
        print(
            "[cred-check] unexpected credential-like environment variables found. "
            "Add them to .github/trusted-credentials.json if intentional:",
            file=sys.stderr,
        )
        for key in unexpected:
            print(f"  - {key}", file=sys.stderr)
        return 1

    print(
        f"[cred-check] trusted credential validation passed "
        f"(required={len(required)}, optional={len(optional)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
