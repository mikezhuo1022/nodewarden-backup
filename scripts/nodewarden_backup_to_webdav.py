#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import re
import ssl
import sys
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Dict, List, Optional, Tuple
from urllib import error, parse, request
from urllib.parse import urljoin, urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


DEFAULT_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "120"))
DEFAULT_WEBDAV_BASE_URL = "https://dav.jianguoyun.com/dav"
DEFAULT_WEBDAV_REMOTE_DIR = "nodewarden/github-actions"
DEFAULT_TIMEZONE = "Asia/Shanghai"
DEFAULT_RETENTION_COUNT = 60
DEFAULT_BACKUP_PREFIX = "nodewarden_backup"
FILENAME_RE = re.compile(r"^nodewarden_backup_(\d{12})\.zip$", re.I)
CTX = ssl.create_default_context()


def log(message: str) -> None:
    print(message, flush=True)


def fail(message: str, code: int = 1) -> None:
    print(f"ERROR: {message}", file=sys.stderr, flush=True)
    raise SystemExit(code)


def getenv_required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        fail(f"Missing required environment variable: {name}")
    return value


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        fail(f"{name} must be an integer, got: {raw}")
        raise exc


def normalize_path(path: str) -> str:
    value = str(path or "").replace("\\", "/").strip().strip("/")
    if not value:
        return ""
    parts = [part for part in value.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        fail(f"Invalid path: {path}")
    return "/".join(parts)


def join_path(*parts: str) -> str:
    return "/".join(filter(None, (normalize_path(part) for part in parts)))


def encode_segments(path: str) -> str:
    normalized = normalize_path(path)
    if not normalized:
        return ""
    return "/".join(parse.quote(part, safe="") for part in normalized.split("/"))


def webdav_url(base_url: str, relative_path: str = "") -> str:
    base = base_url.rstrip("/")
    encoded = encode_segments(relative_path)
    return f"{base}/{encoded}" if encoded else base


def http_request(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    allowed_error_statuses: Optional[set[int]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[int, Dict[str, str], bytes]:
    req = request.Request(url, data=data, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with request.urlopen(req, context=CTX, timeout=timeout) as resp:
            return resp.status, dict(resp.headers.items()), resp.read()
    except error.HTTPError as exc:
        body = exc.read()
        if allowed_error_statuses and exc.code in allowed_error_statuses:
            return exc.code, dict(exc.headers.items()), body
        snippet = body.decode("utf-8", "replace")[:500]
        raise RuntimeError(f"{method} {url} -> HTTP {exc.code}: {snippet}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"{method} {url} failed: {exc.reason}") from exc


def json_request(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    payload: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    merged_headers = {"Accept": "application/json", "User-Agent": "NodeWarden-Jianguoyun-Backup/1.0"}
    if headers:
        merged_headers.update(headers)
    if body is not None:
        merged_headers["Content-Type"] = "application/json; charset=utf-8"
    _, _, response_body = http_request(url, method=method, headers=merged_headers, data=body, timeout=timeout)
    return json.loads(response_body.decode("utf-8"))


def form_request(
    url: str,
    form: Dict[str, str],
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    merged_headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "NodeWarden-Jianguoyun-Backup/1.0",
    }
    if headers:
        merged_headers.update(headers)
    _, _, response_body = http_request(
        url,
        method="POST",
        headers=merged_headers,
        data=parse.urlencode(form).encode("utf-8"),
        timeout=timeout,
    )
    return json.loads(response_body.decode("utf-8"))


def derive_master_password_hash(email: str, password: str, iterations: int) -> str:
    salt = email.strip().lower().encode("utf-8")
    master_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
    password_hash = hashlib.pbkdf2_hmac("sha256", master_key, password.encode("utf-8"), 1, dklen=32)
    return base64.b64encode(password_hash).decode("ascii")


def login_nodewarden(base_url: str, email: str, password: str) -> str:
    prelogin = json_request(
        urljoin(base_url, "/identity/accounts/prelogin"),
        method="POST",
        payload={"email": email.strip().lower()},
    )
    iterations = int(prelogin.get("kdfIterations") or 600000)
    password_hash = derive_master_password_hash(email, password, iterations)
    token = form_request(
        urljoin(base_url, "/identity/connect/token"),
        {
            "grant_type": "password",
            "username": email.strip().lower(),
            "password": password_hash,
            "scope": "api offline_access",
            "deviceIdentifier": str(uuid.uuid4()),
            "deviceName": "GitHub Actions Backup",
            "deviceType": "14",
        },
        headers={"X-NodeWarden-Web-Session": "1"},
    )
    access_token = str(token.get("access_token") or "").strip()
    if not access_token:
        fail("NodeWarden login succeeded but no access_token was returned")
    return access_token


def export_backup_archive(base_url: str, token: str, include_attachments: bool) -> bytes:
    status, _, body = http_request(
        urljoin(base_url, "/api/admin/backup/export"),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/zip,application/json",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "NodeWarden-Jianguoyun-Backup/1.0",
        },
        data=json.dumps({"includeAttachments": include_attachments}).encode("utf-8"),
    )
    if status != 200:
        fail(f"Unexpected export status: {status}")
    return body


def backup_filename(prefix: str, timezone_name: str) -> str:
    now = datetime.now(resolve_timezone(timezone_name))
    return f"{prefix}_{now.strftime('%Y%m%d%H%M')}.zip"


def resolve_timezone(timezone_name: str):
    normalized = str(timezone_name or "").strip() or DEFAULT_TIMEZONE
    try:
        return ZoneInfo(normalized)
    except ZoneInfoNotFoundError:
        if normalized in {"Asia/Shanghai", "PRC", "CST-8"}:
            return timezone(timedelta(hours=8), name="Asia/Shanghai")
        if normalized in {"UTC", "Etc/UTC", "GMT"}:
            return timezone.utc
        raise


def basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def ensure_webdav_directory(base_url: str, directory: str, auth_header: str) -> None:
    current = ""
    for segment in normalize_path(directory).split("/"):
        if not segment:
            continue
        current = join_path(current, segment)
        status, _, _ = http_request(
            webdav_url(base_url, current),
            method="MKCOL",
            headers={"Authorization": auth_header, "User-Agent": "NodeWarden-Jianguoyun-Backup/1.0"},
            allowed_error_statuses={200, 201, 204, 301, 302, 405},
        )
        if status not in {200, 201, 204, 301, 302, 405}:
            fail(f"WebDAV directory creation failed for {current}: HTTP {status}")


def put_webdav_file(base_url: str, remote_path: str, data: bytes, auth_header: str) -> None:
    remote_path = normalize_path(remote_path)
    parent = "/".join(remote_path.split("/")[:-1])
    if parent:
        ensure_webdav_directory(base_url, parent, auth_header)
    status, _, _ = http_request(
        webdav_url(base_url, remote_path),
        method="PUT",
        headers={
            "Authorization": auth_header,
            "Content-Type": "application/zip",
            "Content-Length": str(len(data)),
            "User-Agent": "NodeWarden-Jianguoyun-Backup/1.0",
        },
        data=data,
    )
    if status not in {200, 201, 204}:
        fail(f"WebDAV upload failed for {remote_path}: HTTP {status}")


def parse_http_date(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except Exception:
        return None


def webdav_relative_from_href(base_url: str, href: str) -> str:
    base_path = normalize_path(parse.unquote(urlparse(base_url).path))
    target_path = normalize_path(parse.unquote(urlparse(urljoin(base_url, href)).path))
    if not base_path:
        return target_path
    if target_path == base_path:
        return ""
    prefix = f"{base_path}/"
    if target_path.startswith(prefix):
        return target_path[len(prefix):]
    return target_path


def list_webdav_files(base_url: str, directory: str, auth_header: str) -> List[dict]:
    directory = normalize_path(directory)
    _, _, body = http_request(
        webdav_url(base_url, directory),
        method="PROPFIND",
        headers={
            "Authorization": auth_header,
            "Depth": "1",
            "Content-Type": "text/xml; charset=utf-8",
            "User-Agent": "NodeWarden-Jianguoyun-Backup/1.0",
        },
        data=b'<?xml version="1.0" encoding="utf-8"?><propfind xmlns="DAV:"><prop><resourcetype/><getlastmodified/><getcontentlength/></prop></propfind>',
    )
    root = ET.fromstring(body)
    ns = {"d": "DAV:"}
    items: List[dict] = []
    for response_node in root.findall("d:response", ns):
        href_node = response_node.find("d:href", ns)
        if href_node is None or not href_node.text:
            continue
        rel = webdav_relative_from_href(base_url, href_node.text)
        if not rel or rel == directory:
            continue
        if directory and not rel.startswith(directory + "/"):
            continue
        name = rel.split("/")[-1]
        is_dir = response_node.find(".//d:collection", ns) is not None
        modified_raw = response_node.findtext(".//d:getlastmodified", default="", namespaces=ns)
        size_raw = response_node.findtext(".//d:getcontentlength", default="0", namespaces=ns)
        try:
            size = int(size_raw)
        except Exception:
            size = 0
        items.append(
            {
                "name": name,
                "path": rel,
                "is_dir": is_dir,
                "modified": parse_http_date(modified_raw),
                "size": size,
            }
        )
    return items


def delete_webdav_file(base_url: str, remote_path: str, auth_header: str) -> None:
    status, _, _ = http_request(
        webdav_url(base_url, remote_path),
        method="DELETE",
        headers={"Authorization": auth_header, "User-Agent": "NodeWarden-Jianguoyun-Backup/1.0"},
        allowed_error_statuses={200, 204, 404},
    )
    if status not in {200, 204, 404}:
        fail(f"WebDAV delete failed for {remote_path}: HTTP {status}")


def prune_remote_backups(base_url: str, directory: str, keep_count: int, auth_header: str) -> int:
    if keep_count <= 0:
        return 0
    items = [
        item
        for item in list_webdav_files(base_url, directory, auth_header)
        if not item["is_dir"] and FILENAME_RE.match(item["name"])
    ]
    items.sort(
        key=lambda item: (
            FILENAME_RE.match(item["name"]).group(1) if FILENAME_RE.match(item["name"]) else "",
            item["modified"] or datetime.min.replace(tzinfo=resolve_timezone("UTC")),
        ),
        reverse=True,
    )
    deleted = 0
    for item in items[keep_count:]:
        delete_webdav_file(base_url, item["path"], auth_header)
        deleted += 1
    return deleted


def main() -> None:
    nodewarden_base_url = getenv_required("NODEWARDEN_BASE_URL").rstrip("/")
    nodewarden_email = getenv_required("NODEWARDEN_EMAIL")
    nodewarden_password = getenv_required("NODEWARDEN_MASTER_PASSWORD")
    webdav_base_url = os.getenv("WEBDAV_BASE_URL", DEFAULT_WEBDAV_BASE_URL).strip().rstrip("/")
    webdav_username = getenv_required("WEBDAV_USERNAME")
    webdav_password = getenv_required("WEBDAV_PASSWORD")
    webdav_remote_dir = normalize_path(os.getenv("WEBDAV_REMOTE_DIR", DEFAULT_WEBDAV_REMOTE_DIR))
    include_attachments = env_bool("NODEWARDEN_INCLUDE_ATTACHMENTS", True)
    retention_count = env_int("REMOTE_RETENTION_COUNT", DEFAULT_RETENTION_COUNT)
    timezone_name = os.getenv("BACKUP_TIMEZONE", DEFAULT_TIMEZONE).strip() or DEFAULT_TIMEZONE
    backup_prefix = os.getenv("BACKUP_PREFIX", DEFAULT_BACKUP_PREFIX).strip() or DEFAULT_BACKUP_PREFIX

    archive_name = backup_filename(backup_prefix, timezone_name)
    auth_header = basic_auth_header(webdav_username, webdav_password)

    log("Logging in to NodeWarden...")
    access_token = login_nodewarden(nodewarden_base_url, nodewarden_email, nodewarden_password)

    log(f"Exporting backup from {nodewarden_base_url} (include attachments: {include_attachments})...")
    archive_bytes = export_backup_archive(nodewarden_base_url, access_token, include_attachments)

    remote_path = join_path(webdav_remote_dir, archive_name)
    log(f"Uploading {archive_name} to WebDAV path: {remote_path}")
    put_webdav_file(webdav_base_url, remote_path, archive_bytes, auth_header)

    deleted = prune_remote_backups(webdav_base_url, webdav_remote_dir, retention_count, auth_header)

    log("Backup complete.")
    log(f"- file: {archive_name}")
    log(f"- bytes: {len(archive_bytes)}")
    log(f"- remote path: {remote_path}")
    log(f"- retention kept: {retention_count}")
    log(f"- pruned old backups: {deleted}")


if __name__ == "__main__":
    main()
