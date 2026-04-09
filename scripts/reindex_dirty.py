#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections import defaultdict
from dataclasses import dataclass

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

INDEX_NAME = "APKINDEX.tar.gz"


@dataclass
class S3Object:
    key: str
    size: int
    etag: str
    last_modified: dt.datetime


@dataclass
class DownloadedObject:
    obj: S3Object
    local_path: pathlib.Path


@dataclass
class Target:
    repo_path: str
    marker_key: str
    marker_etag: str | None
    forced: bool = False


@dataclass
class SigningConfig:
    private_key_file: str
    public_key_name: str | None


def normalize_prefix(prefix: str) -> str:
    out = prefix.strip().strip("/")
    if not out:
        return ""
    return f"{out}/"


def normalize_repo_path(raw: str, repo_prefix: str) -> str:
    path = raw.strip().strip("/")
    if not path:
        raise ValueError("empty path")
    if path.endswith(".apk"):
        path = path.rsplit("/", 1)[0]
    if ".." in path.split("/"):
        raise ValueError(f"invalid path: {raw}")

    repo_root = repo_prefix.rstrip("/")
    if repo_root and not (path == repo_root or path.startswith(f"{repo_root}/")):
        path = f"{repo_root}/{path}"

    return path


def marker_key_for_path(repo_path: str, state_prefix: str) -> str:
    return f"{state_prefix}{repo_path}.dirty"


def path_for_marker_key(marker_key: str, state_prefix: str) -> str | None:
    if not marker_key.startswith(state_prefix):
        return None
    if not marker_key.endswith(".dirty"):
        return None
    return marker_key[len(state_prefix) : -len(".dirty")]


def parse_event_targets(event_path: str | None) -> list[str]:
    if not event_path:
        return []
    p = pathlib.Path(event_path)
    if not p.exists():
        return []

    with p.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)

    candidates: list[str] = []

    def extend_value(value: object) -> None:
        if isinstance(value, str):
            if value.strip():
                candidates.append(value.strip())
            return
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.strip():
                    candidates.append(item.strip())

    client_payload = payload.get("client_payload")
    if isinstance(client_payload, dict):
        for key in ("path", "paths", "prefix", "prefixes", "target", "targets"):
            extend_value(client_payload.get(key))

    for key in ("path", "paths", "prefix", "prefixes", "target", "targets"):
        extend_value(payload.get(key))

    return candidates


def s3_client(account_id: str):
    endpoint = f"https://{account_id}.r2.cloudflarestorage.com"
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name="auto",
        config=Config(retries={"max_attempts": 10, "mode": "standard"}),
    )


def list_objects(client, bucket: str, prefix: str) -> list[S3Object]:
    paginator = client.get_paginator("list_objects_v2")
    results: list[S3Object] = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            results.append(
                S3Object(
                    key=obj["Key"],
                    size=int(obj["Size"]),
                    etag=str(obj.get("ETag", "")).strip('"'),
                    last_modified=obj["LastModified"],
                )
            )
    return results


def list_dirty_markers(client, bucket: str, state_prefix: str) -> dict[str, S3Object]:
    markers: dict[str, S3Object] = {}
    for obj in list_objects(client, bucket, state_prefix):
        path = path_for_marker_key(obj.key, state_prefix)
        if path:
            markers[path] = obj
    return markers


def parse_local_apk_filename(local_name: str) -> tuple[str, str] | None:
    base = os.path.basename(local_name)
    if not base.endswith(".apk"):
        return None

    stem = base[: -len(".apk")]
    match = re.match(r"^(?P<left>.+)-r(?P<release>[0-9]+)$", stem)
    if not match:
        return None

    left = match.group("left")
    release = match.group("release")
    if "-" not in left:
        return None

    pkg_name, version = left.rsplit("-", 1)
    if not pkg_name or not version:
        return None

    return pkg_name, f"{version}-r{release}"


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_packages(client, bucket: str, objects: list[S3Object], dest_dir: pathlib.Path) -> list[DownloadedObject]:
    downloaded: list[DownloadedObject] = []
    seen_names: set[str] = set()

    for obj in objects:
        local_name = os.path.basename(obj.key)
        if local_name in seen_names:
            raise RuntimeError(
                f"duplicate package filename within target path is unsupported: {local_name}"
            )
        seen_names.add(local_name)

        local_path = dest_dir / local_name
        client.download_file(bucket, obj.key, str(local_path))
        downloaded.append(DownloadedObject(obj=obj, local_path=local_path))

    return downloaded


def _trusted_key_files(trusted_keys_dir: str) -> list[pathlib.Path]:
    key_dir = pathlib.Path(trusted_keys_dir).resolve()
    if not key_dir.exists() or not key_dir.is_dir():
        raise RuntimeError(f"trusted keys directory not found: {key_dir}")

    key_files = sorted(key_dir.glob("*.pub"))
    if not key_files:
        raise RuntimeError(f"trusted keys directory has no .pub files: {key_dir}")
    return key_files


def _package_signature_key_name(apk_path: pathlib.Path) -> str:
    try:
        with tarfile.open(apk_path, "r:*") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                match = re.match(r"^\.SIGN\.[^.]+\.(?P<keyname>.+\.pub)$", member.name)
                if match:
                    return match.group("keyname")
    except tarfile.TarError as err:
        raise RuntimeError(f"failed to read package signature metadata: {apk_path}") from err

    raise RuntimeError(f"package has no .SIGN entry and cannot be verified: {apk_path}")


def _pkg_dir_for_downloaded(downloaded: list[DownloadedObject]) -> pathlib.Path:
    if not downloaded:
        raise RuntimeError("cannot resolve package directory for empty download set")

    pkg_dir = downloaded[0].local_path.parent.resolve()
    for item in downloaded[1:]:
        if item.local_path.parent.resolve() != pkg_dir:
            raise RuntimeError("downloaded package directory mismatch; cannot run key verification safely")
    return pkg_dir


@contextlib.contextmanager
def prepare_effective_trusted_keyring(downloaded: list[DownloadedObject], trusted_keys_dir: str):
    key_dir = pathlib.Path(trusted_keys_dir).resolve()
    key_files = _trusted_key_files(trusted_keys_dir)
    if not downloaded:
        yield str(key_dir)
        return

    required_key_names: set[str] = set()
    for item in downloaded:
        required_key_names.add(_package_signature_key_name(item.local_path))

    existing_names = {path.name for path in key_files}
    missing = sorted(name for name in required_key_names if name not in existing_names)
    if not missing:
        yield str(key_dir)
        return

    by_key_id: dict[str, list[pathlib.Path]] = defaultdict(list)
    for path in key_files:
        match = re.search(r"-(?P<keyid>[0-9a-fA-F]{8})\.rsa\.pub$", path.name)
        if match:
            by_key_id[match.group("keyid").lower()].append(path)

    unresolved: list[str] = []
    alias_pairs: list[tuple[str, str]] = []

    with tempfile.TemporaryDirectory(prefix="apk-keyring-") as tmp:
        staged_dir = pathlib.Path(tmp)
        for src in key_files:
            shutil.copy2(src, staged_dir / src.name)

        for expected_name in missing:
            match = re.search(r"-(?P<keyid>[0-9a-fA-F]{8})\.rsa\.pub$", expected_name)
            if not match:
                unresolved.append(f"{expected_name} (missing key-id suffix)")
                continue

            key_id = match.group("keyid").lower()
            matches = by_key_id.get(key_id, [])
            if len(matches) == 1:
                src = matches[0]
                shutil.copy2(src, staged_dir / expected_name)
                alias_pairs.append((expected_name, src.name))
                continue

            if not matches:
                unresolved.append(f"{expected_name} (no trusted key with id {key_id})")
            else:
                match_list = ", ".join(path.name for path in matches)
                unresolved.append(f"{expected_name} (ambiguous key id {key_id}: {match_list})")

        if unresolved:
            joined = "; ".join(unresolved)
            raise RuntimeError(
                "trusted keyring is missing required signature key filenames: "
                f"{joined}. Add matching .pub files to {key_dir}"
            )

        for alias_name, source_name in alias_pairs:
            print(f"[verify] added key filename alias: {alias_name} -> {source_name}")

        yield str(staged_dir)


def verify_downloaded_with_trusted_keys(downloaded: list[DownloadedObject], trusted_keys_dir: str) -> None:
    _trusted_key_files(trusted_keys_dir)
    if not downloaded:
        return

    key_dir = pathlib.Path(trusted_keys_dir).resolve()
    pkg_dir = _pkg_dir_for_downloaded(downloaded)

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{pkg_dir}:/work:ro",
        "-v",
        f"{key_dir}:/trusted-keys:ro",
        "-w",
        "/work",
        "alpine:3.20",
        "sh",
        "-euc",
        (
            "set -- ./*.apk; "
            "if [ \"$1\" = './*.apk' ]; then set --; fi; "
            "if [ \"$#\" -eq 0 ]; then exit 0; fi; "
            "apk --no-network --keys-dir /trusted-keys verify \"$@\""
        ),
    ]
    print(f"[verify] running trusted key verification: {' '.join(shlex.quote(x) for x in cmd)}")
    subprocess.run(cmd, check=True)


def build_apkindex(work_dir: pathlib.Path, trusted_keys_dir: str | None) -> pathlib.Path:
    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{work_dir}:/work",
        "-w",
        "/work",
    ]

    apk_cmd = "apk index -o APKINDEX.tar.gz \"$@\""
    if trusted_keys_dir:
        key_dir = pathlib.Path(trusted_keys_dir).resolve()
        if not key_dir.exists() or not key_dir.is_dir():
            raise RuntimeError(f"trusted keys directory not found: {key_dir}")
        cmd.extend(["-v", f"{key_dir}:/trusted-keys:ro"])
        apk_cmd = "apk --no-network --keys-dir /trusted-keys index -o APKINDEX.tar.gz \"$@\""

    cmd.extend(
        [
            "alpine:3.20",
            "sh",
            "-euc",
            (
                "set -- ./*.apk; "
                "if [ \"$1\" = './*.apk' ]; then set --; fi; "
                f"{apk_cmd}"
            ),
        ]
    )
    print(f"[index] running: {' '.join(shlex.quote(x) for x in cmd)}")
    subprocess.run(cmd, check=True)

    out = work_dir / INDEX_NAME
    if not out.exists():
        raise RuntimeError("apk index did not produce APKINDEX.tar.gz")
    return out


def sign_apkindex(work_dir: pathlib.Path, signing: SigningConfig) -> None:
    key_path = pathlib.Path(signing.private_key_file).resolve()
    if not key_path.exists():
        raise FileNotFoundError(f"signing key file not found: {key_path}")

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{work_dir}:/work",
        "-v",
        f"{key_path}:/signing/private.rsa:ro",
        "-w",
        "/work",
        "alpine:3.20",
        "sh",
        "-euc",
        (
            "apk add --no-cache abuild >/dev/null; "
            "if [ -n \"$1\" ]; then "
            "abuild-sign -k /signing/private.rsa -p \"$1\" /work/APKINDEX.tar.gz; "
            "else "
            "abuild-sign -k /signing/private.rsa /work/APKINDEX.tar.gz; "
            "fi"
        ),
        "sign",
        signing.public_key_name or "",
    ]
    print(f"[sign] running: {' '.join(shlex.quote(x) for x in cmd)}")
    subprocess.run(cmd, check=True)


def parse_apkindex(index_path: pathlib.Path) -> list[dict[str, str]]:
    with tarfile.open(index_path, "r:gz") as archive:
        member = archive.getmember("APKINDEX")
        file_obj = archive.extractfile(member)
        if file_obj is None:
            raise RuntimeError("APKINDEX entry is missing from APKINDEX.tar.gz")
        data = file_obj.read().decode("utf-8", errors="replace")

    entries: list[dict[str, str]] = []
    current: dict[str, str] = {}

    for line in data.splitlines():
        if not line.strip():
            if current:
                entries.append(current)
                current = {}
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if len(key) == 1:
            current[key] = value

    if current:
        entries.append(current)

    return entries


class ApkVersionComparator:
    def __init__(self) -> None:
        self._cache: dict[tuple[str, str], int] = {}

    def compare(self, left: str, right: str) -> int:
        if left == right:
            return 0

        cached = self._cache.get((left, right))
        if cached is not None:
            return cached

        cmd = [
            "docker",
            "run",
            "--rm",
            "alpine:3.20",
            "sh",
            "-euc",
            'apk version -t "$1" "$2"',
            "compare",
            left,
            right,
        ]
        result = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        symbol = result.stdout.strip()
        mapping = {"<": -1, "=": 0, ">": 1}
        if symbol not in mapping:
            raise RuntimeError(
                "unexpected output from apk version compare: "
                f"{symbol!r} (left={left!r}, right={right!r})"
            )

        value = mapping[symbol]
        self._cache[(left, right)] = value
        self._cache[(right, left)] = -value
        return value


def choose_latest_versions(entries: list[dict[str, str]], comparator: ApkVersionComparator) -> tuple[dict[str, str], dict[str, list[str]]]:
    versions_by_pkg: dict[str, list[str]] = defaultdict(list)

    for entry in entries:
        pkg = entry.get("P", "").strip()
        version = entry.get("V", "").strip()
        if pkg and version:
            versions_by_pkg[pkg].append(version)

    latest_by_pkg: dict[str, str] = {}
    duplicates: dict[str, list[str]] = {}

    for pkg, versions in versions_by_pkg.items():
        unique_versions = list(dict.fromkeys(versions))
        if not unique_versions:
            continue

        best = unique_versions[0]
        for candidate in unique_versions[1:]:
            if comparator.compare(candidate, best) > 0:
                best = candidate

        latest_by_pkg[pkg] = best
        if len(unique_versions) > 1:
            duplicates[pkg] = unique_versions

    return latest_by_pkg, duplicates


def prune_local_packages(downloaded: list[DownloadedObject], latest_by_pkg: dict[str, str]) -> tuple[list[DownloadedObject], list[DownloadedObject], list[DownloadedObject]]:
    keep: list[DownloadedObject] = []
    delete: list[DownloadedObject] = []
    unparsed: list[DownloadedObject] = []

    for item in downloaded:
        parsed = parse_local_apk_filename(item.local_path.name)
        if not parsed:
            keep.append(item)
            unparsed.append(item)
            continue

        pkg_name, full_version = parsed
        latest = latest_by_pkg.get(pkg_name)
        if latest and full_version != latest:
            delete.append(item)
        else:
            keep.append(item)

    return keep, delete, unparsed


def head_index_sha(client, bucket: str, index_key: str) -> str | None:
    try:
        resp = client.head_object(Bucket=bucket, Key=index_key)
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code")
        if code in {"404", "NoSuchKey", "NotFound"}:
            return None
        raise

    metadata = resp.get("Metadata", {}) or {}
    value = metadata.get("content-sha256")
    return value.strip() if isinstance(value, str) and value.strip() else None


def upload_index(client, bucket: str, index_key: str, index_path: pathlib.Path, content_sha: str, run_id: str | None):
    metadata = {"content-sha256": content_sha}
    if run_id:
        metadata["indexed-run-id"] = run_id

    with index_path.open("rb") as fh:
        client.put_object(
            Bucket=bucket,
            Key=index_key,
            Body=fh,
            ContentType="application/gzip",
            Metadata=metadata,
        )


def delete_keys(client, bucket: str, keys: list[str]):
    if not keys:
        return

    for i in range(0, len(keys), 1000):
        chunk = keys[i : i + 1000]
        payload = {"Objects": [{"Key": key} for key in chunk], "Quiet": True}
        client.delete_objects(Bucket=bucket, Delete=payload)


def marker_etag(client, bucket: str, marker_key: str) -> str | None:
    try:
        resp = client.head_object(Bucket=bucket, Key=marker_key)
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code")
        if code in {"404", "NoSuchKey", "NotFound"}:
            return None
        raise
    return str(resp.get("ETag", "")).strip('"') or None


def maybe_clear_marker(client, bucket: str, target: Target, dry_run: bool):
    if not target.marker_etag:
        return

    current = marker_etag(client, bucket, target.marker_key)
    if current is None:
        print(f"[dirty] marker already absent: {target.marker_key}")
        return

    if current != target.marker_etag:
        print(
            f"[dirty] marker changed while processing, leaving dirty set: {target.marker_key} "
            f"(start={target.marker_etag} now={current})"
        )
        return

    if dry_run:
        print(f"[dry-run] would clear marker: {target.marker_key}")
        return

    client.delete_object(Bucket=bucket, Key=target.marker_key)
    print(f"[dirty] cleared marker: {target.marker_key}")


def select_targets(
    marker_map: dict[str, S3Object],
    explicit_paths: list[str],
    repo_prefix: str,
    state_prefix: str,
    explicit_only: bool,
) -> list[Target]:
    selected: dict[str, Target] = {}

    def add_marker_path(path: str):
        marker = marker_map[path]
        selected[path] = Target(
            repo_path=path,
            marker_key=marker.key,
            marker_etag=marker.etag,
            forced=False,
        )

    if not explicit_only:
        for path in sorted(marker_map.keys()):
            add_marker_path(path)

    for raw in explicit_paths:
        normalized = normalize_repo_path(raw, repo_prefix)
        marker = marker_map.get(normalized)
        selected[normalized] = Target(
            repo_path=normalized,
            marker_key=marker.key if marker else marker_key_for_path(normalized, state_prefix),
            marker_etag=marker.etag if marker else None,
            forced=True,
        )

    return sorted(selected.values(), key=lambda item: item.repo_path)


def process_target(
    client,
    bucket: str,
    target: Target,
    run_id: str | None,
    dry_run: bool,
    trusted_keys_dir: str | None,
    signing: SigningConfig | None,
):
    repo_prefix = f"{target.repo_path.rstrip('/')}/"
    index_key = f"{target.repo_path.rstrip('/')}/{INDEX_NAME}"

    print(f"[target] {target.repo_path}")
    objects = list_objects(client, bucket, repo_prefix)
    apks = [obj for obj in objects if obj.key.endswith(".apk")]

    print(f"[pull] {target.repo_path}: remote_apk_count={len(apks)}")

    with tempfile.TemporaryDirectory(prefix="apk-reindex-") as tmp:
        tmp_dir = pathlib.Path(tmp)

        downloaded: list[DownloadedObject] = []
        if apks:
            if dry_run:
                for obj in sorted(apks, key=lambda x: x.key):
                    print(f"[dry-run] would download package: {obj.key}")
            downloaded = download_packages(client, bucket, apks, tmp_dir)
            print(f"[pull] downloaded {len(downloaded)} packages")

        keyring_ctx = (
            prepare_effective_trusted_keyring(downloaded, trusted_keys_dir)
            if trusted_keys_dir is not None and downloaded
            else contextlib.nullcontext(trusted_keys_dir)
        )
        with keyring_ctx as effective_keys_dir:
            if trusted_keys_dir is not None and downloaded and not dry_run:
                verify_downloaded_with_trusted_keys(downloaded, effective_keys_dir)
                print("[verify] package signatures matched trusted keyring")

            initial_index = build_apkindex(tmp_dir, trusted_keys_dir=effective_keys_dir)
            entries = parse_apkindex(initial_index)
            comparator = ApkVersionComparator()
            latest_by_pkg, duplicates = choose_latest_versions(entries, comparator)

            print(
                f"[scan] index_entries={len(entries)} duplicate_packages={len(duplicates)}"
            )

            keep_local, delete_local, unparsed_local = prune_local_packages(downloaded, latest_by_pkg)
            print(
                f"[prune] local_keep={len(keep_local)} local_delete={len(delete_local)} "
                f"local_unparsed={len(unparsed_local)}"
            )

            for item in delete_local:
                if dry_run:
                    print(f"[dry-run] would delete local old package: {item.local_path.name}")
                else:
                    item.local_path.unlink(missing_ok=True)

            final_index = build_apkindex(tmp_dir, trusted_keys_dir=effective_keys_dir)
            if not dry_run and signing is not None:
                sign_apkindex(tmp_dir, signing)
            elif dry_run and signing is not None:
                print("[dry-run] would sign APKINDEX.tar.gz with repository signing key")
            final_sha = sha256_file(final_index)

            if dry_run:
                print(f"[dry-run] would upload index: {index_key} sha256={final_sha}")
            else:
                remote_sha = head_index_sha(client, bucket, index_key)
                if remote_sha == final_sha:
                    print(f"[index] unchanged hash for {index_key}; skipping upload")
                else:
                    upload_index(client, bucket, index_key, final_index, final_sha, run_id)
                    print(f"[index] uploaded {index_key} sha256={final_sha}")

            remote_delete_keys = [item.obj.key for item in delete_local]
            if dry_run:
                for key in remote_delete_keys:
                    print(f"[dry-run] would delete remote old package: {key}")
            else:
                delete_keys(client, bucket, remote_delete_keys)
                if remote_delete_keys:
                    print(f"[cleanup] deleted {len(remote_delete_keys)} remote old packages")

    maybe_clear_marker(client, bucket, target, dry_run=dry_run)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rebuild dirty Alpine indexes in Cloudflare R2 and prune older package versions."
    )
    parser.add_argument("--bucket", required=True, help="R2 bucket name")
    parser.add_argument("--account-id", required=True, help="Cloudflare account ID for R2 endpoint")
    parser.add_argument("--repo-prefix", default="alpine/", help="Repository root prefix")
    parser.add_argument("--state-prefix", default="_state/dirty/", help="Dirty marker prefix")
    parser.add_argument(
        "--targets",
        default="",
        help="Comma-separated explicit repo paths (relative or under repo prefix)",
    )
    parser.add_argument("--event-json", default="", help="Optional GitHub event JSON path")
    parser.add_argument(
        "--trusted-keys-dir",
        default="",
        help="Optional directory containing trusted apk public keys (*.pub) for apk verify.",
    )
    parser.add_argument(
        "--signing-key-file",
        default="",
        help="Optional private key file used to sign generated APKINDEX.tar.gz.",
    )
    parser.add_argument(
        "--signing-key-public-name",
        default="",
        help="Optional public key name passed to abuild-sign -p.",
    )
    parser.add_argument(
        "--explicit-only",
        action="store_true",
        help="Process only explicit targets from --targets/--event-json",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print planned actions only")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    repo_prefix = normalize_prefix(args.repo_prefix)
    state_prefix = normalize_prefix(args.state_prefix)

    explicit_targets: list[str] = []
    if args.targets.strip():
        explicit_targets.extend([x.strip() for x in args.targets.split(",") if x.strip()])
    explicit_targets.extend(parse_event_targets(args.event_json or None))

    run_id = os.environ.get("GITHUB_RUN_ID")
    trusted_keys_dir = args.trusted_keys_dir.strip() or None
    signing = (
        SigningConfig(
            private_key_file=args.signing_key_file.strip(),
            public_key_name=args.signing_key_public_name.strip() or None,
        )
        if args.signing_key_file.strip()
        else None
    )
    if trusted_keys_dir is not None:
        print(f"[verify] using trusted apk keyring dir: {trusted_keys_dir}")
    if signing is not None:
        print(f"[sign] enabled repository index signing with key file: {signing.private_key_file}")
        if signing.public_key_name:
            print(f"[sign] using APKINDEX signature public key name: {signing.public_key_name}")
        else:
            print("[sign] using default APKINDEX signature public key name derived from private key")

    client = s3_client(args.account_id)
    marker_map = list_dirty_markers(client, args.bucket, state_prefix)
    targets = select_targets(
        marker_map=marker_map,
        explicit_paths=explicit_targets,
        repo_prefix=repo_prefix,
        state_prefix=state_prefix,
        explicit_only=args.explicit_only,
    )

    if not targets:
        print("[noop] no dirty targets found")
        return 0

    print(f"[targets] selected {len(targets)} paths")
    for target in targets:
        process_target(
            client=client,
            bucket=args.bucket,
            target=target,
            run_id=run_id,
            dry_run=args.dry_run,
            trusted_keys_dir=trusted_keys_dir,
            signing=signing,
        )

    print("[done] processing complete")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        raise SystemExit(130)
