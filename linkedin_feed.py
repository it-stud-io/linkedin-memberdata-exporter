#!/usr/bin/env python3
"""Export the posts/activity of your own LinkedIn profile.

Uses LinkedIn's official Member Data Portability API (self-serve, EU/EEA/CH
members), so no password scraping is involved. App credentials, the profile
label and OAuth tokens are kept in a vault encrypted with AES-256-GCM, using a
key derived from a master passphrase via scrypt.

Usage:
    python linkedin_feed.py configure      # store app credentials + profile
    python linkedin_feed.py login          # OAuth consent, stores token
    python linkedin_feed.py export -f csv  # export your posts
    python linkedin_feed.py interactions   # posts you liked/commented on
    python linkedin_feed.py changelog      # activity since consent (last 28 days)
    python linkedin_feed.py show           # show (redacted) vault contents
"""

from __future__ import annotations

import argparse
import base64
import csv
import getpass
import http.server
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

DEFAULT_VAULT = Path.home() / ".linkedin_feed_reader" / "vault.json"
AUTH_URL = "https://www.linkedin.com/oauth/v2/authorization"
TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
API_BASE = "https://api.linkedin.com"
SCOPE = "r_dma_portability_self_serve"
# The DMA snapshot/changelog endpoints only accept this LinkedIn-Version (per docs).
DEFAULT_API_VERSION = "202312"
DEFAULT_PORT = 8765
PASSPHRASE_ENV = "LFR_PASSPHRASE"


# --------------------------------------------------------------------------- vault

class Vault:
    """JSON document encrypted with AES-256-GCM, key derived via scrypt."""

    KDF = {"n": 2**15, "r": 8, "p": 1}

    def __init__(self, path: Path):
        self.path = path

    @staticmethod
    def _derive(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
        return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode())

    def exists(self) -> bool:
        return self.path.exists()

    def load(self, passphrase: str) -> dict:
        blob = json.loads(self.path.read_text(encoding="utf-8"))
        salt = base64.b64decode(blob["salt"])
        key = self._derive(passphrase, salt, **blob["kdf"])
        try:
            plain = AESGCM(key).decrypt(
                base64.b64decode(blob["nonce"]), base64.b64decode(blob["data"]), b"lfr-v1"
            )
        except InvalidTag:
            sys.exit("Wrong passphrase or corrupted vault.")
        return json.loads(plain)

    def save(self, passphrase: str, data: dict) -> None:
        salt, nonce = os.urandom(16), os.urandom(12)
        key = self._derive(passphrase, salt, **self.KDF)
        cipher = AESGCM(key).encrypt(nonce, json.dumps(data).encode(), b"lfr-v1")
        blob = {
            "version": 1,
            "kdf": self.KDF,
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "data": base64.b64encode(cipher).decode(),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(blob, indent=2), encoding="utf-8")
        tmp.replace(self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass


def get_passphrase(confirm: bool = False) -> str:
    if env := os.environ.get(PASSPHRASE_ENV):
        return env
    pw = getpass.getpass("Vault passphrase: ")
    if confirm:
        if len(pw) < 8:
            sys.exit("Passphrase must be at least 8 characters.")
        if pw != getpass.getpass("Repeat passphrase: "):
            sys.exit("Passphrases do not match.")
    return pw


def open_vault(args) -> tuple[Vault, str, dict]:
    vault = Vault(args.vault)
    if not vault.exists():
        sys.exit(f"No vault at {vault.path}. Run 'configure' first.")
    pw = get_passphrase()
    return vault, pw, vault.load(pw)


# --------------------------------------------------------------------------- http

def http_json(url: str, *, data: dict | None = None, json_body: dict | None = None,
              headers: dict | None = None) -> dict:
    if json_body is not None:
        body, ctype = json.dumps(json_body).encode(), "application/json"
    elif data is not None:
        body, ctype = urllib.parse.urlencode(data).encode(), "application/x-www-form-urlencoded"
    else:
        body, ctype = None, None
    req = urllib.request.Request(url, data=body, headers=headers or {})
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code} for {url.split('?')[0]}: {detail}") from None


# --------------------------------------------------------------------------- oauth

def run_oauth(cfg: dict) -> dict:
    port = cfg.get("redirect_port", DEFAULT_PORT)
    redirect_uri = f"http://localhost:{port}/callback"
    state = secrets.token_urlsafe(24)
    result: dict = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if urllib.parse.urlparse(self.path).path != "/callback":
                self.send_response(404)
                self.end_headers()
                return
            result.update({k: v[0] for k, v in qs.items()})
            ok = "code" in result and result.get("state") == state
            self.send_response(200 if ok else 400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            msg = "Login successful - you can close this tab." if ok else "Login failed."
            self.wfile.write(f"<html><body><h3>{msg}</h3></body></html>".encode())

        def log_message(self, *_):
            pass

    server = http.server.HTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()

    url = AUTH_URL + "?" + urllib.parse.urlencode({
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": redirect_uri,
        "state": state,
        "scope": SCOPE,
    })
    print(f"Opening browser for LinkedIn consent. If nothing opens, visit:\n{url}\n")
    webbrowser.open(url)
    thread.join(timeout=300)
    server.server_close()

    if result.get("state") != state:
        sys.exit("OAuth failed: state mismatch or timeout.")
    if "error" in result:
        sys.exit(f"OAuth failed: {result['error']}: {result.get('error_description', '')}")

    token = http_json(TOKEN_URL, data={
        "grant_type": "authorization_code",
        "code": result["code"],
        "redirect_uri": redirect_uri,
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
    })
    return _stamp(token)


def _stamp(token: dict) -> dict:
    now = int(time.time())
    token["expires_at"] = now + int(token.get("expires_in", 0))
    if "refresh_token_expires_in" in token:
        token["refresh_expires_at"] = now + int(token["refresh_token_expires_in"])
    return token


def ensure_token(vault: Vault, pw: str, data: dict) -> str:
    token = data.get("token")
    if not token:
        sys.exit("No access token stored. Run 'login' first.")
    if token["expires_at"] - 300 > time.time():
        return token["access_token"]
    if token.get("refresh_token") and token.get("refresh_expires_at", 0) > time.time():
        print("Access token expired, refreshing...")
        new = _stamp(http_json(TOKEN_URL, data={
            "grant_type": "refresh_token",
            "refresh_token": token["refresh_token"],
            "client_id": data["client_id"],
            "client_secret": data["client_secret"],
        }))
        new.setdefault("refresh_token", token["refresh_token"])
        new.setdefault("refresh_expires_at", token["refresh_expires_at"])
        data["token"] = new
        vault.save(pw, data)
        return new["access_token"]
    sys.exit("Access token expired. Run 'login' again.")


# --------------------------------------------------------------------------- api

class VersionNotActive(RuntimeError):
    """LinkedIn rejected the LinkedIn-Version header (HTTP 426)."""


def version_candidates(*preferred: str | None, months: int = 18) -> list[str]:
    """Preferred versions first, then every month from now backwards.

    LinkedIn normalizes YYYYMM to YYYYMMDD (202608 -> 20260801) and only keeps
    versions active for about a year; not every month gets a release.
    """
    today = datetime.now(timezone.utc)
    year, month = today.year, today.month
    out = list(dict.fromkeys(p for p in preferred if p))
    for _ in range(months):
        v = f"{year}{month:02d}"
        if v not in out:
            out.append(v)
        year, month = (year, month - 1) if month > 1 else (year - 1, 12)
    return out


def api_headers(access_token: str, api_version: str) -> dict:
    return {
        "Authorization": f"Bearer {access_token}",
        "LinkedIn-Version": api_version,
        "X-Restli-Protocol-Version": "2.0.0",
    }


def api_get(path: str, params: dict, access_token: str, api_version: str) -> dict:
    try:
        return http_json(f"{API_BASE}{path}?{urllib.parse.urlencode(params)}",
                         headers=api_headers(access_token, api_version))
    except RuntimeError as e:
        if "HTTP 426" in str(e):
            raise VersionNotActive(str(e)) from None
        raise


def fetch_domain(access_token: str, domain: str, api_version: str) -> list[dict]:
    """Fetch all snapshot records of one data domain.

    Each page holds exactly one element; LinkedIn's docs say to keep paging
    until a 404 "No data found" (the "total" field is unreliable).
    """
    records: list[dict] = []
    for start in range(10_000):
        try:
            page = api_get("/rest/memberSnapshotData",
                           {"q": "criteria", "domain": domain, "start": start},
                           access_token, api_version)
        except RuntimeError as e:
            if "HTTP 404" not in str(e):
                raise
            if start == 0:
                print(f"  LinkedIn has no {domain} data (yet). The snapshot is built once after "
                      "consent and some domains take hours to days; posts made after consent "
                      "appear in 'changelog' instead.")
            break
        elements = page.get("elements", [])
        if not elements:
            break
        for el in elements:
            records.extend(el.get("snapshotData", []))
    return records


def fetch_with_version(access_token: str, domain: str, *preferred: str) -> tuple[list[dict], str]:
    """Fetch a domain, falling back to older API versions if LinkedIn rejects one."""
    for version in version_candidates(*preferred):
        try:
            return fetch_domain(access_token, domain, version), version
        except VersionNotActive:
            print(f"  LinkedIn-Version {version} not active, trying another...")
    raise RuntimeError("No active LinkedIn-Version found; pass one with --api-version.")


# --------------------------------------------------------------------------- export

def write_export(records: list[dict], fmt: str, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        out.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
        return
    columns: list[str] = []
    for r in records:
        columns += [k for k in r if k not in columns]
    with out.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for r in records:
            writer.writerow({k: v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
                             for k, v in r.items()})


# --------------------------------------------------------------------------- commands

def cmd_configure(args) -> None:
    vault = Vault(args.vault)
    data: dict = {}
    if vault.exists():
        print(f"Updating existing vault at {vault.path}")
        pw = get_passphrase()
        data = vault.load(pw)
    else:
        print(f"Creating new vault at {vault.path}")
        pw = get_passphrase(confirm=True)

    def ask(key: str, prompt: str, secret: bool = False, default=None):
        current = data.get(key, default)
        hint = " [keep current]" if current and secret else f" [{current}]" if current else ""
        value = (getpass.getpass if secret else input)(f"{prompt}{hint}: ").strip()
        return value or current

    data["profile"] = ask("profile", "Profile (your LinkedIn vanity name or URL)")
    data["client_id"] = ask("client_id", "LinkedIn app Client ID")
    data["client_secret"] = ask("client_secret", "LinkedIn app Client Secret", secret=True)
    data["redirect_port"] = int(ask("redirect_port", "Local redirect port", default=DEFAULT_PORT))
    data["api_version"] = ask("api_version", "LinkedIn-Version (YYYYMM)", default=DEFAULT_API_VERSION)
    if not all(data.get(k) for k in ("profile", "client_id", "client_secret")):
        sys.exit("Profile, Client ID and Client Secret are required.")
    vault.save(pw, data)
    print(f"Saved. Register this redirect URL in your LinkedIn app: "
          f"http://localhost:{data['redirect_port']}/callback")


def cmd_login(args) -> None:
    vault, pw, data = open_vault(args)
    data["token"] = run_oauth(data)
    vault.save(pw, data)
    exp = datetime.fromtimestamp(data["token"]["expires_at"], timezone.utc)
    print(f"Logged in as profile '{data['profile']}'. Token valid until {exp:%Y-%m-%d %H:%M} UTC.")


def remember_version(vault: Vault, pw: str, data: dict, api_version: str) -> None:
    if api_version != data.get("api_version"):
        print(f"  Using LinkedIn-Version {api_version} (saved to vault)")
        data["api_version"] = api_version
        vault.save(pw, data)


def fetch_domains(args, domains: list[str]):
    """Yield (domain, records) for each domain; persists a working API version."""
    vault, pw, data = open_vault(args)
    access_token = ensure_token(vault, pw, data)
    preferred = [args.api_version, DEFAULT_API_VERSION, data.get("api_version")]
    for domain in domains:
        print(f"Fetching {domain} for '{data['profile']}'...")
        records, api_version = fetch_with_version(access_token, domain, *preferred)
        remember_version(vault, pw, data, api_version)
        preferred = [api_version]
        yield domain, records, data


def output_path(args, data: dict, name: str) -> Path:
    profile = data["profile"].rstrip("/").split("/")[-1]
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return args.output_dir / f"{profile}_{name}_{stamp}.{args.format}"


def cmd_export(args) -> None:
    for domain, records, data in fetch_domains(args, args.domain):
        out = output_path(args, data, domain.lower())
        write_export(records, args.format, out)
        print(f"  {len(records)} records -> {out}")


# --------------------------------------------------------------------------- interactions

POST_URN = re.compile(r"urn(?::|%3A)li(?::|%3A)(activity|ugcPost|share)(?::|%3A)(\d+)", re.I)


def _field(record: dict, *names: str) -> str:
    """Case-insensitive lookup of the first non-empty matching field."""
    lower = {k.lower(): v for k, v in record.items()}
    for n in names:
        if v := lower.get(n.lower()):
            return v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
    return ""


def _link(record: dict) -> str:
    link = _field(record, "Link", "Url", "URL", "PostLink", "ShareLink")
    if not link:  # fall back to any LinkedIn URL in the record
        link = next((v for v in record.values()
                     if isinstance(v, str) and "linkedin.com/" in v), "")
    return link


def canonical_post(link: str) -> tuple[str, str]:
    """Map post/comment links to (post_urn, canonical feed URL) so they group together."""
    if m := POST_URN.search(link):
        urn = f"urn:li:{m.group(1)}:{m.group(2)}"
        return urn, f"https://www.linkedin.com/feed/update/{urn}/"
    return link, link


def aggregate_interactions(likes: list[dict], comments: list[dict],
                           since: datetime | None = None) -> list[dict]:
    posts: dict[str, dict] = {}

    def add(record: dict, kind: str) -> None:
        link = _link(record)
        if not link:
            return
        date = _field(record, "Date", "Created", "CreatedAt", "Timestamp")
        if since and (parsed := _parse_date(date)) and parsed < since:
            return
        urn, url = canonical_post(link)
        p = posts.setdefault(urn, {
            "post_url": url, "post_urn": urn if urn.startswith("urn:") else "",
            "first_interaction": date, "last_interaction": date,
            "reaction_count": 0, "reactions": [], "comment_count": 0, "comments": [],
        })
        if date:
            p["first_interaction"] = min(filter(None, [p["first_interaction"], date]))
            p["last_interaction"] = max(p["last_interaction"] or "", date)
        if kind == "like":
            p["reaction_count"] += 1
            if (t := _field(record, "Type", "ReactionType")) and t not in p["reactions"]:
                p["reactions"].append(t)
        else:
            p["comment_count"] += 1
            if msg := _field(record, "Message", "Comment", "Text", "Commentary"):
                p["comments"].append(msg)

    for r in likes:
        add(r, "like")
    for r in comments:
        add(r, "comment")

    rows = sorted(posts.values(), key=lambda p: p["last_interaction"] or "", reverse=True)
    for p in rows:
        p["reactions"] = ", ".join(p["reactions"])
        p["comments"] = " | ".join(p["comments"])
    return rows


def _parse_date(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value.strip().replace(" UTC", ""))
    except ValueError:
        return None
    return dt.replace(tzinfo=None)


def cmd_interactions(args) -> None:
    since = datetime.fromisoformat(args.since) if args.since else None
    fetched = {d: (r, data) for d, r, data in fetch_domains(args, ["ALL_LIKES", "ALL_COMMENTS"])}
    likes, data = fetched["ALL_LIKES"]
    comments, _ = fetched["ALL_COMMENTS"]
    rows = aggregate_interactions(likes, comments, since)
    out = output_path(args, data, "interactions")
    write_export(rows, args.format, out)
    print(f"{len(likes)} reactions + {len(comments)} comments -> {len(rows)} posts -> {out}")


# --------------------------------------------------------------------------- changelog

def ensure_archiving(access_token: str, api_version: str) -> int | None:
    """Return the epoch-ms since when LinkedIn archives changelog events; enable if off."""
    auth = api_get("/rest/memberAuthorizations", {"q": "memberAndApplication"},
                   access_token, api_version)
    if elements := auth.get("elements"):
        return elements[0].get("regulatedAt")
    print("Changelog archiving was not enabled for this app - enabling it now.")
    http_json(f"{API_BASE}/rest/memberAuthorizations", json_body={},
              headers=api_headers(access_token, api_version))
    return None


def fetch_changelog(access_token: str, api_version: str, since_ms: int) -> list[dict]:
    """All changelog events since `since_ms` (LinkedIn keeps 28 days).

    startTime is inclusive, so we page by the latest processedAt and dedupe by id.
    """
    events: dict = {}
    start_time = since_ms
    while True:
        page = api_get("/rest/memberChangeLogs",
                       {"q": "memberAndApplication", "count": 50, "startTime": start_time},
                       access_token, api_version)
        elements = page.get("elements", [])
        new = [e for e in elements if e.get("id") not in events]
        if not new:
            break
        events.update((e.get("id"), e) for e in new)
        start_time = max(e.get("processedAt", start_time) for e in elements)
    return sorted(events.values(), key=lambda e: e.get("capturedAt", 0))


def _deep_find(obj, key: str):
    """First value stored under `key` anywhere in a nested JSON structure."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        children = obj.values()
    elif isinstance(obj, list):
        children = obj
    else:
        return None
    for child in children:
        if (found := _deep_find(child, key)) is not None:
            return found
    return None


def summarize_event(event: dict) -> dict:
    activity = event.get("processedActivity") or event.get("activity") or {}
    text = ""
    for key in ("commentary", "shareCommentary", "message", "text"):
        value = _deep_find(activity, key)
        if isinstance(value, dict):
            value = value.get("text")
        if isinstance(value, str) and value:
            text = value
            break
    resource_id = str(event.get("resourceId", ""))
    urn_match = POST_URN.search(resource_id) or POST_URN.search(json.dumps(activity))
    captured = event.get("capturedAt")
    return {
        "captured_at": datetime.fromtimestamp(captured / 1000, timezone.utc)
                       .strftime("%Y-%m-%d %H:%M:%S") if captured else "",
        "method": event.get("method", ""),
        "resource": event.get("resourceName", ""),
        "resource_id": resource_id,
        "post_url": canonical_post(urn_match.group(0))[1] if urn_match else "",
        "reaction": _deep_find(activity, "reactionType") or "",
        "text": text,
    }


def cmd_changelog(args) -> None:
    vault, pw, data = open_vault(args)
    access_token = ensure_token(vault, pw, data)
    since = datetime.fromisoformat(args.since).replace(tzinfo=timezone.utc) if args.since \
        else datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=28)
    print(f"Fetching changelog for '{data['profile']}' since {since:%Y-%m-%d}...")
    for version in version_candidates(args.api_version, DEFAULT_API_VERSION, data.get("api_version")):
        try:
            regulated_at = ensure_archiving(access_token, version)
            events = fetch_changelog(access_token, version, int(since.timestamp() * 1000))
            break
        except VersionNotActive:
            print(f"  LinkedIn-Version {version} not active, trying another...")
    else:
        raise RuntimeError("No active LinkedIn-Version found; pass one with --api-version.")
    remember_version(vault, pw, data, version)

    if regulated_at:
        start = datetime.fromtimestamp(regulated_at / 1000, timezone.utc)
        print(f"  LinkedIn archives your activity since {start:%Y-%m-%d %H:%M} UTC.")
    if args.resource:
        events = [e for e in events if e.get("resourceName") in args.resource]
    rows = events if args.format == "json" else [summarize_event(e) for e in events]
    out = output_path(args, data, "changelog")
    write_export(rows, args.format, out)
    kinds = ", ".join(f"{k}: {v}" for k, v in
                      sorted(Counter(e.get("resourceName") for e in events).items())) or "none"
    print(f"  {len(events)} events ({kinds}) -> {out}")


def cmd_show(args) -> None:
    _, _, data = open_vault(args)
    token = data.get("token") or {}
    print(f"Vault:        {args.vault}")
    print(f"Profile:      {data.get('profile')}")
    print(f"Client ID:    {data.get('client_id')}")
    print(f"Secret:       {'*' * 8 if data.get('client_secret') else '-'}")
    print(f"Redirect:     http://localhost:{data.get('redirect_port')}/callback")
    print(f"API version:  {data.get('api_version')}")
    if token:
        exp = datetime.fromtimestamp(token["expires_at"], timezone.utc)
        print(f"Token:        present, expires {exp:%Y-%m-%d %H:%M} UTC"
              f"{', refreshable' if token.get('refresh_token') else ''}")
    else:
        print("Token:        none (run 'login')")


def main() -> None:
    parser = argparse.ArgumentParser(description="Export your own LinkedIn posts/activity.")
    parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT,
                        help=f"encrypted vault file (default: {DEFAULT_VAULT})")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("configure", help="store profile and app credentials").set_defaults(func=cmd_configure)
    sub.add_parser("login", help="authorize via LinkedIn OAuth").set_defaults(func=cmd_login)
    sub.add_parser("show", help="show redacted configuration").set_defaults(func=cmd_show)

    exp = sub.add_parser("export", help="export feed data")
    exp.add_argument("-f", "--format", choices=["json", "csv"], default="json")
    exp.add_argument("-o", "--output-dir", type=Path, default=Path("export"))
    exp.add_argument("-d", "--domain", nargs="+", default=["MEMBER_SHARE_INFO"],
                     help="snapshot domains, e.g. MEMBER_SHARE_INFO (posts), ARTICLES, "
                          "ALL_COMMENTS, ALL_LIKES (default: MEMBER_SHARE_INFO)")
    exp.add_argument("--api-version", help="override LinkedIn-Version header (YYYYMM)")
    exp.set_defaults(func=cmd_export)

    inter = sub.add_parser("interactions",
                           help="network posts you liked or commented on, one row per post")
    inter.add_argument("-f", "--format", choices=["json", "csv"], default="json")
    inter.add_argument("-o", "--output-dir", type=Path, default=Path("export"))
    inter.add_argument("--since", help="only interactions on/after this date (YYYY-MM-DD)")
    inter.add_argument("--api-version", help="override LinkedIn-Version header (YYYYMM)")
    inter.set_defaults(func=cmd_interactions)

    chg = sub.add_parser("changelog",
                         help="your activity since consent (posts, comments, reactions; last 28 days)")
    chg.add_argument("-f", "--format", choices=["json", "csv"], default="json")
    chg.add_argument("-o", "--output-dir", type=Path, default=Path("export"))
    chg.add_argument("--since", help="start date (YYYY-MM-DD), default: 28 days ago")
    chg.add_argument("--resource", nargs="+",
                     help="only these resource names, e.g. ugcPosts socialActions/comments")
    chg.add_argument("--api-version", help="override LinkedIn-Version header (YYYYMM)")
    chg.set_defaults(func=cmd_changelog)

    args = parser.parse_args()
    try:
        args.func(args)
    except RuntimeError as e:
        sys.exit(str(e))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
