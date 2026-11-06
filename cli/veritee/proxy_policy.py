"""Measured DApp route policy, shared by CLI validation and guest setup."""

import json
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import unquote_to_bytes


PROXY_POLICY_PATH = Path("/run/temenos/dapp-proxy.json")
MAX_PROXY_PATHS = 64
MAX_PROXY_PATH_BYTES = 1024
MAX_PROXY_POLICY_BYTES = 65536


def _policy_bytes(paths: list[str]) -> bytes:
    return json.dumps(
        {"version": 1, "allowed_paths": paths},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def validate_proxy_allowed_paths(metadata: dict) -> list[str]:
    paths = metadata.get("proxy_allowed_paths", [])
    if not isinstance(paths, list) or len(paths) > MAX_PROXY_PATHS:
        raise ValueError("proxy_allowed_paths must be an array of at most 64 paths")
    seen = set()
    for path in paths:
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path.startswith("//")
            or len(path.encode("utf-8")) > MAX_PROXY_PATH_BYTES
            or any(char in path for char in ("?", "#", "\\", "://"))
            or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in path)
            or re.search(r"%(?![0-9a-fA-F]{2})", path)
        ):
            raise ValueError("proxy_allowed_paths contains an invalid application path")
        for segment in path.split("/"):
            decoded = unquote_to_bytes(segment)
            if decoded in (b".", b"..") or b"/" in decoded or b"\\" in decoded:
                raise ValueError("proxy_allowed_paths contains traversal or an encoded separator")
        if path in seen:
            raise ValueError("proxy_allowed_paths contains a duplicate path")
        seen.add(path)
    if len(_policy_bytes(paths)) > MAX_PROXY_POLICY_BYTES:
        raise ValueError("proxy_allowed_paths exceeds the runtime policy size limit")
    return list(paths)


def install_proxy_policy(metadata: dict, output: Path = PROXY_POLICY_PATH) -> None:
    """Publish only validated routes, atomically, after successful DApp setup."""
    content = _policy_bytes(validate_proxy_allowed_paths(metadata))
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(content)
        os.replace(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
