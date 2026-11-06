"""Read the published scratch carrier without running it or trusting its paths."""
import argparse
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import socket
import tarfile
import tempfile
import time
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .http_helpers import ResolvedHttpsConnection

CARRIER_ARTIFACT_PREFIX = "temenos/"


class RegistryRedirect(ValueError):
    def __init__(self, location):
        super().__init__("registry redirect requires validation")
        self.location = location


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RegistryRedirect(newurl)


def public_address(host, port):
    addresses = list(dict.fromkeys(item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
    if not addresses or any(not ipaddress.ip_address(ip).is_global or ip == "168.63.129.16" for ip in addresses):
        raise ValueError("carrier endpoint must resolve only to public addresses")
    return addresses[0]


class PublicHTTPSHandler(HTTPSHandler):
    def https_open(self, request):
        # The configured egress proxy resolves and enforces public destinations;
        # direct connections pin the checked IP while preserving TLS/Host names.
        if getattr(request, "_tunnel_host", None):
            return super().https_open(request)
        target = urlsplit(request.full_url)
        ip = public_address(target.hostname, target.port or 443)
        return self.do_open(lambda host, **kwargs: ResolvedHttpsConnection(host, ip, **kwargs),
                            request, context=self._context)


def acr_blob_redirect(registry, location):
    target = urlsplit(location)
    if (not registry.endswith(".azurecr.io") or target.scheme != "https" or
            target.username is not None or target.password is not None or target.fragment or
            target.port not in (None, 443)):
        return False
    name = target.hostname or ""
    return bool(re.fullmatch(r"[a-z0-9]{3,24}\.blob\.core\.windows\.net", name) or
                re.fullmatch(re.escape(registry.removesuffix(".azurecr.io")) + r"\.[a-z0-9-]+\.data\.azurecr\.io", name))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def read_json(data):
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")))


class BoundedReader:
    def __init__(self, stream, maximum, deadline):
        self.stream, self.remaining, self.deadline = stream, maximum, deadline

    def read(self, size=-1):
        if time.monotonic() >= self.deadline:
            raise TimeoutError("OS carrier deadline")
        data = self.stream.read(min(size if size >= 0 else self.remaining + 1, self.remaining + 1))
        self.remaining -= len(data)
        if self.remaining < 0:
            raise ValueError("OS carrier size limit")
        return data


class CarrierTarInfo(tarfile.TarInfo):
    @classmethod
    def frombuf(cls, buf, encoding, errors):
        member = super().frombuf(buf, encoding, errors)
        # tarfile processes extension headers before yielding a member. Bound
        # them here so a PAX/long-name header cannot allocate disk-sized RAM.
        if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE,
                               tarfile.XHDTYPE, tarfile.XGLTYPE):
            raise ValueError("unsupported carrier tar member type")
        if member.type in (tarfile.XHDTYPE, tarfile.XGLTYPE) and member.size > 64 * 1024:
            raise ValueError("carrier metadata size limit")
        return member


def verify_files(manifest, directory):
    report = []
    for descriptor in manifest["artifacts"]:
        name = descriptor["name"]
        if name not in ("disk.raw", "pcrs.json"):
            raise ValueError("unsupported artifact path")
        path = Path(directory) / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"missing regular artifact: {name}")
        size = path.stat().st_size
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if str(size) != descriptor["size"] or digest.hexdigest() != descriptor["sha256"]:
            raise ValueError(f"published artifact mismatch: {name}")
        report.append({"name": name, "size": str(size), "sha256": digest.hexdigest()})
    if (Path(directory) / "pcrs.json").stat().st_size > 2 * 1024 * 1024:
        raise ValueError("measurement file size limit")
    pcrs = read_json((Path(directory) / "pcrs.json").read_bytes().decode("utf-8"))
    if pcrs.get("measurements", {}).get("4") != manifest["measurements"]["pcr4"]:
        raise ValueError("published measurement file disagrees with manifest PCR4")
    return report


def fetch_carrier(manifest, output, max_download, max_extracted, timeout, deadline_ms=None):
    reference = manifest["publication"]["reference"]
    if not re.fullmatch(r"[a-z0-9.-]+/[a-z0-9_./-]+(?::[A-Za-z0-9_.-]+)?(?:@sha256:[0-9a-f]{64})?", reference):
        raise ValueError("invalid carrier reference")
    host, image = reference.split("/", 1)
    if "@" in image:
        repository, version = image.split("@", 1)
        repository = repository.split(":", 1)[0]
    elif ":" in image:
        repository, version = image.rsplit(":", 1)
    else:
        raise ValueError("carrier must have an explicit tag or digest")
    if ".." in repository:
        raise ValueError("invalid carrier repository")
    expected = {a["name"]: a for a in manifest["artifacts"]}
    if sorted(expected) != ["disk.raw", "pcrs.json"] or len(manifest["artifacts"]) != 2:
        raise ValueError("unsupported artifact set")
    declared = sum(int(a["size"]) for a in expected.values())
    if declared > max_extracted or any(int(a["size"]) <= 0 for a in expected.values()):
        raise ValueError("declared extraction size limit")
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=False)
    opener = build_opener(NoRedirect(), PublicHTTPSHandler())
    available_time = timeout if deadline_ms is None else min(timeout, deadline_ms / 1000 - time.time())
    if available_time <= 0:
        raise TimeoutError("OS carrier deadline elapsed")
    deadline, remaining = time.monotonic() + available_time, max_download
    token = None

    def request(url, accept="application/json", authenticate=True, *, blob=False):
        nonlocal token
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != host or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("unapproved registry endpoint")
        headers = {"Accept": accept, "Accept-Encoding": "identity"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            target = url
            for redirects in range(4):
                if time.monotonic() >= deadline:
                    raise TimeoutError("OS carrier deadline")
                try:
                    return opener.open(Request(target, headers=headers), timeout=max(0.1, min(30, deadline - time.monotonic())))
                except RegistryRedirect as redirect:
                    if (redirects == 3 or not blob or
                            not acr_blob_redirect(host, redirect.location)):
                        raise ValueError("unapproved carrier redirect") from None
                    target = redirect.location
                    headers.pop("Authorization", None)
        except HTTPError as error:
            challenge = error.headers.get("WWW-Authenticate", "")
            if (target != url or error.code != 401 or not authenticate or not challenge.startswith("Bearer ")):
                raise
            fields = dict(re.findall(r'(\w+)="([^"\r\n]*)"', challenge))
            realm = fields.get("realm", "")
            endpoint = urlsplit(realm)
            if endpoint.scheme != "https" or endpoint.netloc != host or endpoint.query or endpoint.fragment or endpoint.username:
                raise ValueError("unapproved registry token endpoint")
            query = urlencode({"service": host, "scope": f"repository:{repository}:pull"})
            response = request(f"{realm}?{query}", authenticate=False)
            with response:
                token_data = read_json(BoundedReader(response, 64 * 1024, deadline).read())
            token = token_data.get("token") or token_data.get("access_token")
            if not isinstance(token, str) or not token or len(token) > 32768 or "\r" in token or "\n" in token:
                raise ValueError("invalid registry token")
            return request(url, accept, authenticate=False, blob=blob)

    accept = ",".join(["application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json",
                       "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.docker.distribution.manifest.v2+json"])

    def metadata(kind, identifier, expected_digest=None):
        nonlocal remaining
        with request(f"https://{host}/v2/{repository}/{kind}/{identifier}", accept, blob=kind == "blobs") as response:
            data = BoundedReader(response, min(2 * 1024 * 1024, remaining), deadline).read()
        remaining -= len(data)
        actual = "sha256:" + hashlib.sha256(data).hexdigest()
        if expected_digest and actual != expected_digest:
            raise ValueError("carrier descriptor digest mismatch")
        return read_json(data), actual

    image_manifest, resolved = metadata("manifests", version, version if version.startswith("sha256:") else None)
    if "manifests" in image_manifest:
        candidates = [m for m in image_manifest["manifests"] if m.get("platform", {}).get("os") == "linux"
                      and m.get("platform", {}).get("architecture") == "amd64" and not m.get("platform", {}).get("variant")]
        if len(candidates) != 1:
            raise ValueError("ambiguous/missing linux/amd64 carrier")
        image_manifest, resolved = metadata("manifests", candidates[0]["digest"], candidates[0]["digest"])
    if image_manifest.get("schemaVersion") != 2 or not 1 <= len(image_manifest.get("layers", [])) <= 16:
        raise ValueError("unsupported carrier manifest")
    config, _ = metadata("blobs", image_manifest["config"]["digest"], image_manifest["config"]["digest"])
    if config.get("os") != "linux" or config.get("architecture") != "amd64":
        raise ValueError("carrier platform mismatch")
    seen = set()
    for layer in image_manifest["layers"]:
        layer_digest, size = layer["digest"], layer["size"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", layer_digest) or type(size) is not int or not 0 < size <= remaining:
            raise ValueError("carrier download size/digest limit")
        with tempfile.TemporaryFile(dir=directory.parent) as compressed:
            h, length = hashlib.sha256(), 0
            with request(f"https://{host}/v2/{repository}/blobs/{layer_digest}", "application/octet-stream", blob=True) as response:
                reader = BoundedReader(response, size, deadline)
                for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                    h.update(chunk)
                    length += len(chunk)
                    compressed.write(chunk)
            remaining -= length
            if length != size or "sha256:" + h.hexdigest() != layer_digest:
                raise ValueError("carrier layer mismatch")
            compressed.seek(0)
            media = layer.get("mediaType", "")
            if media not in ("application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip",
                             "application/vnd.docker.image.rootfs.diff.tar.gzip"):
                raise ValueError("unsupported carrier compression")
            compressed_reader = BoundedReader(compressed, size, deadline)
            raw = gzip.GzipFile(fileobj=compressed_reader) if media.endswith("gzip") else compressed_reader
            bounded = BoundedReader(raw, max_extracted + 1024 * 1024, deadline)
            with tarfile.open(fileobj=bounded, mode="r|", tarinfo=CarrierTarInfo) as archive:
                for member in archive:
                    name = member.name.removeprefix("./")
                    if member.isdir() and name.rstrip("/") in ("", ".", CARRIER_ARTIFACT_PREFIX.rstrip("/")):
                        continue
                    if not name.startswith(CARRIER_ARTIFACT_PREFIX):
                        raise ValueError("carrier member is outside the published artifact directory")
                    name = name.removeprefix(CARRIER_ARTIFACT_PREFIX)
                    if name not in expected or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or member.sparse or name in seen:
                        raise ValueError("unexpected/unsafe/duplicate carrier member")
                    if member.size != int(expected[name]["size"]):
                        raise ValueError("carrier member size mismatch")
                    seen.add(name)
                    with archive.extractfile(member) as source, (directory / name).open("xb") as destination:
                        for chunk in iter(lambda: source.read(1024 * 1024), b""):
                            destination.write(chunk)
    report = verify_files(manifest, directory)
    return {"version": 1, "carrier_digest": resolved, "platform": "linux/amd64", "artifacts": report,
            "pcr4": manifest["measurements"]["pcr4"], "validation": "published_files_checked_not_reproduced"}


def main():
    parser = argparse.ArgumentParser()
    for name in ("manifest", "output", "max-download", "max-extracted", "timeout"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--deadline-ms", type=int)
    args = parser.parse_args()
    manifest = read_json(Path(args.manifest).read_bytes())
    report = fetch_carrier(manifest, args.output, int(args.max_download), int(args.max_extracted), int(args.timeout), args.deadline_ms)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except HTTPError as error:
        print("registry HTTP failure", file=sys.stderr)
        sys.exit(75 if error.code == 429 or error.code >= 500 else 1)
    except (URLError, TimeoutError, ConnectionError, socket.gaierror):
        print("registry transport unavailable", file=sys.stderr)
        sys.exit(75)
