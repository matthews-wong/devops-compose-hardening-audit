#!/usr/bin/env python3
"""Audit a rendered Docker Compose project for missing container hardening."""
import json
import sys
from typing import Callable, Iterator, NamedTuple

ROOT_USERS = {"", "0", "root", "0:0", "root:root"}


class Finding(NamedTuple):
    rule: str
    service: str
    message: str


Check = Callable[[dict], Iterator[str]]


def check_image_tag(svc: dict) -> Iterator[str]:
    image = svc.get("image")
    if not image:
        return  # build-only service, nothing to pin
    if "@sha256:" in image:
        return
    name = image.rsplit("/", 1)[-1]
    if ":" not in name:
        yield f"image '{image}' has no tag or digest"
    elif name.endswith(":latest"):
        yield f"image '{image}' uses the moving :latest tag"


def check_non_root(svc: dict) -> Iterator[str]:
    user = str(svc.get("user", ""))
    if user in ROOT_USERS:
        yield "runs as root; set a non-zero `user`"


def check_read_only(svc: dict) -> Iterator[str]:
    if svc.get("read_only") is not True:
        yield "root filesystem is writable; set `read_only: true`"


CHECKS: dict[str, Check] = {
    "CH001": check_image_tag,
    "CH002": check_non_root,
    "CH003": check_read_only,
}


def audit(project: dict) -> list[Finding]:
    findings = []
    for name, svc in sorted(project.get("services", {}).items()):
        for rule, check in CHECKS.items():
            findings.extend(Finding(rule, name, msg) for msg in check(svc))
    return findings


def load(path: str | None) -> dict:
    raw = open(path).read() if path else sys.stdin.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        sys.exit(f"audit: input is not JSON (pipe `docker compose config --format json`): {exc}")


def main(argv: list[str]) -> int:
    findings = audit(load(argv[1] if len(argv) > 1 else None))
    for f in findings:
        print(f"{f.rule} {f.service}: {f.message}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
