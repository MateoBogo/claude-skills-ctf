#!/usr/bin/env python3
"""ctfd.py — CTFd client: sync challenges, organise workspace, submit flags.

Subcommands:
  init   --url URL --token TOKEN [--out DIR]   Configure workspace (writes .ctfd.json)
  sync   [--dir DIR] [--force]                 Download/refresh all challenge files
  triage [--dir DIR] [--chal NAME]             Run triage.sh on each challenge dir
  submit FLAG --chal NAME [--dir DIR]          Submit a flag
  status [--dir DIR] [--category CAT]          Show solve progress table
  next   [--dir DIR] [--category CAT]          Print next unsolved challenge path (lowest pts)

Workspace layout after sync:
  DIR/
    .ctfd.json            ← URL, token, challenge metadata cache
    {category}/
      {slug}/
        {files...}
        .triage.json      ← written by: ctfd.py triage
        .solved           ← JSON written on correct flag submit
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

CONFIG_FILE = ".ctfd.json"
TRIAGE_SH = Path(__file__).resolve().parent / "triage.sh"


# ── helpers ──────────────────────────────────────────────────────────────────


def slug(name: str) -> str:
    return re.sub(r"[^\w-]", "_", name.lower()).strip("_")


def load_config(workspace: Path) -> dict:
    cfg_path = workspace / CONFIG_FILE
    if not cfg_path.exists():
        sys.exit(f"[ctfd] workspace not initialised — run: ctfd.py init --url URL --token TOKEN --out {workspace}")
    return json.loads(cfg_path.read_text())


def save_config(workspace: Path, cfg: dict) -> None:
    (workspace / CONFIG_FILE).write_text(json.dumps(cfg, indent=2))


def api_get(base_url: str, token: str, path: str) -> Any:
    url = base_url.rstrip("/") + path
    req = urllib.request.Request(url, headers={"Authorization": f"Token {token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def api_post(base_url: str, token: str, path: str, data: dict) -> Any:
    url = base_url.rstrip("/") + path
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers={"Authorization": f"Token {token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def download_file(url: str, dest: Path, token: str) -> None:
    req = urllib.request.Request(url, headers={"Authorization": f"Token {token}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        dest.write_bytes(r.read())


# ── subcommands ───────────────────────────────────────────────────────────────


def cmd_init(args: argparse.Namespace) -> None:
    workspace = Path(args.out).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    cfg = {"url": args.url.rstrip("/"), "token": args.token, "challenges": {}}
    save_config(workspace, cfg)
    print(f"[ctfd] workspace initialised → {workspace}")


def cmd_sync(args: argparse.Namespace) -> None:
    workspace = Path(args.dir).resolve()
    cfg = load_config(workspace)
    base_url, token = cfg["url"], cfg["token"]

    print("[ctfd] fetching challenge list …")
    result = api_get(base_url, token, "/api/v1/challenges")
    chals = result.get("data", [])
    print(f"[ctfd] {len(chals)} challenges found")

    for chal in chals:
        cid = chal["id"]
        detail = api_get(base_url, token, f"/api/v1/challenges/{cid}")["data"]
        cat = slug(detail.get("category") or "misc")
        name = slug(detail["name"])
        chal_dir = workspace / cat / name
        chal_dir.mkdir(parents=True, exist_ok=True)

        # Download attached files
        for file_url in detail.get("files", []):
            if not file_url.startswith("http"):
                file_url = base_url + "/" + file_url.lstrip("/")
            fname = Path(urllib.parse.urlparse(file_url).path).name
            dest = chal_dir / fname
            if dest.exists() and not args.force:
                continue
            print(f"  ↓ {cat}/{name}/{fname}")
            try:
                download_file(file_url, dest, token)
            except Exception as e:
                print(f"  [warn] could not download {file_url}: {e}", file=sys.stderr)

        # Write challenge metadata
        meta = {
            "id": cid,
            "name": detail["name"],
            "category": detail.get("category", "misc"),
            "points": detail.get("value", 0),
            "description": detail.get("description", ""),
            "connection_info": detail.get("connection_info") or "",
            "solves": detail.get("solves", 0),
            "synced_at": int(time.time()),
        }
        (chal_dir / ".meta.json").write_text(json.dumps(meta, indent=2))

        # Update config cache
        cfg["challenges"][str(cid)] = {"cat": cat, "slug": name, "points": meta["points"]}

    save_config(workspace, cfg)
    print("[ctfd] sync complete")


def cmd_triage(args: argparse.Namespace) -> None:
    workspace = Path(args.dir).resolve()
    cfg = load_config(workspace)

    if not TRIAGE_SH.exists():
        sys.exit(f"[ctfd] triage.sh not found at {TRIAGE_SH}")

    targets: list[Path] = []
    if args.chal:
        # Search by slug across all categories
        for cat_dir in workspace.iterdir():
            if not cat_dir.is_dir() or cat_dir.name.startswith("."):
                continue
            match = cat_dir / slug(args.chal)
            if match.is_dir():
                targets.append(match)
        if not targets:
            sys.exit(f"[ctfd] challenge not found: {args.chal}")
    else:
        for cat_dir in sorted(workspace.iterdir()):
            if not cat_dir.is_dir() or cat_dir.name.startswith("."):
                continue
            for chal_dir in sorted(cat_dir.iterdir()):
                if chal_dir.is_dir():
                    targets.append(chal_dir)

    for chal_dir in targets:
        triage_out = chal_dir / ".triage.json"
        print(f"[triage] {chal_dir.relative_to(workspace)} …")
        try:
            result = subprocess.run(
                ["bash", str(TRIAGE_SH), str(chal_dir), "--json"],
                capture_output=True, text=True, timeout=60,
            )
            # triage.sh writes .ctf-triage.json inside the dir; copy to .triage.json
            auto_json = chal_dir / ".ctf-triage.json"
            if auto_json.exists():
                shutil.copy(auto_json, triage_out)
            elif result.stdout.strip().startswith("{"):
                triage_out.write_text(result.stdout)
            if result.returncode not in (0, 3):
                print(f"  [warn] exit {result.returncode}: {result.stderr[:120]}", file=sys.stderr)
            else:
                # Print skill hint if available
                hints_file = chal_dir / ".ctf-triage.md"
                if hints_file.exists():
                    first_hint = next((l for l in hints_file.read_text().splitlines() if "SKILL" in l or "→" in l), "")
                    if first_hint:
                        print(f"  → {first_hint.strip()}")
        except subprocess.TimeoutExpired:
            print(f"  [warn] triage timed out for {chal_dir.name}", file=sys.stderr)


def cmd_submit(args: argparse.Namespace) -> None:
    workspace = Path(args.dir).resolve()
    cfg = load_config(workspace)
    base_url, token = cfg["url"], cfg["token"]

    # Find challenge id by name slug
    chal_slug = slug(args.chal)
    cid = None
    chal_dir = None
    for cat_dir in workspace.iterdir():
        if not cat_dir.is_dir() or cat_dir.name.startswith("."):
            continue
        candidate = cat_dir / chal_slug
        if candidate.is_dir():
            meta_path = candidate / ".meta.json"
            if meta_path.exists():
                cid = json.loads(meta_path.read_text())["id"]
                chal_dir = candidate
                break

    if cid is None:
        sys.exit(f"[ctfd] challenge not found locally: {args.chal} — run sync first")

    solved_path = chal_dir / ".solved"
    if solved_path.exists() and not args.force:
        prev = json.loads(solved_path.read_text())
        print(f"[ctfd] already solved with flag: {prev['flag']}")
        return

    flag = args.flag
    print(f"[ctfd] submitting flag for '{args.chal}' …")
    try:
        resp = api_post(base_url, token, "/api/v1/challenges/attempt", {"challenge_id": cid, "submission": flag})
    except urllib.error.HTTPError as e:
        sys.exit(f"[ctfd] HTTP {e.code}: {e.read().decode()[:200]}")

    status = resp.get("data", {}).get("status", "unknown")
    message = resp.get("data", {}).get("message", "")
    print(f"[ctfd] status={status}  message={message}")

    if status == "correct":
        meta = json.loads((chal_dir / ".meta.json").read_text())
        solved_path.write_text(json.dumps({"flag": flag, "ts": int(time.time()), "points": meta.get("points")}))
        print(f"[ctfd] ✓ solved! {meta['points']} pts  →  {chal_dir.relative_to(workspace)}")
    elif status == "incorrect":
        print("[ctfd] ✗ wrong flag")
    elif status == "already_solved":
        solved_path.write_text(json.dumps({"flag": flag, "ts": int(time.time()), "note": "already_solved"}))
        print("[ctfd] already solved on platform")


def cmd_status(args: argparse.Namespace) -> None:
    workspace = Path(args.dir).resolve()
    load_config(workspace)  # validate workspace

    rows = []
    for cat_dir in sorted(workspace.iterdir()):
        if not cat_dir.is_dir() or cat_dir.name.startswith("."):
            continue
        if args.category and cat_dir.name != slug(args.category):
            continue
        for chal_dir in sorted(cat_dir.iterdir()):
            if not chal_dir.is_dir():
                continue
            meta_path = chal_dir / ".meta.json"
            if not meta_path.exists():
                continue
            meta = json.loads(meta_path.read_text())
            solved = (chal_dir / ".solved").exists()
            triage_done = (chal_dir / ".triage.json").exists()
            rows.append((cat_dir.name, meta["name"], meta.get("points", 0), solved, triage_done))

    total = len(rows)
    solved_n = sum(1 for r in rows if r[3])
    print(f"\n  {'CAT':<15} {'CHALLENGE':<30} {'PTS':>5}  {'TRIAGE':<7}  STATUS")
    print("  " + "-" * 68)
    for cat, name, pts, solved, triage_done in rows:
        status_str = "✓ solved" if solved else "·"
        triage_str = "✓" if triage_done else "·"
        print(f"  {cat:<15} {name:<30} {pts:>5}  {triage_str:<7}  {status_str}")
    print(f"\n  {solved_n}/{total} solved\n")


def cmd_next(args: argparse.Namespace) -> None:
    workspace = Path(args.dir).resolve()
    load_config(workspace)

    candidates = []
    for cat_dir in workspace.iterdir():
        if not cat_dir.is_dir() or cat_dir.name.startswith("."):
            continue
        if args.category and cat_dir.name != slug(args.category):
            continue
        for chal_dir in cat_dir.iterdir():
            if not chal_dir.is_dir():
                continue
            if (chal_dir / ".solved").exists():
                continue
            meta_path = chal_dir / ".meta.json"
            if not meta_path.exists():
                continue
            meta = json.loads(meta_path.read_text())
            candidates.append((meta.get("points", 9999), cat_dir.name, meta["name"], chal_dir))

    if not candidates:
        print("[ctfd] all challenges solved!")
        return

    candidates.sort()
    pts, cat, name, chal_dir = candidates[0]
    triage_hint = ""
    md = chal_dir / ".ctf-triage.md"
    if md.exists():
        triage_hint = next((l.strip() for l in md.read_text().splitlines() if "→" in l or "SKILL" in l), "")
    print(f"\n  Next: [{cat}] {name} ({pts} pts)")
    print(f"  Dir:  {chal_dir}")
    if triage_hint:
        print(f"  Hint: {triage_hint}")
    # Print connection info if present
    meta = json.loads((chal_dir / ".meta.json").read_text())
    if meta.get("connection_info"):
        print(f"  Conn: {meta['connection_info']}")
    print()


# ── main ──────────────────────────────────────────────────────────────────────


def main() -> None:
    p = argparse.ArgumentParser(prog="ctfd.py", description="CTFd platform client")
    p.add_argument("--dir", default="./ctf_workspace", metavar="DIR", help="Workspace directory (default: ./ctf_workspace)")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="Configure workspace")
    pi.add_argument("--url", required=True, help="CTFd base URL (e.g. https://ctf.example.com)")
    pi.add_argument("--token", required=True, help="CTFd API token")
    pi.add_argument("--out", default="./ctf_workspace", metavar="DIR", help="Workspace directory to create")

    ps = sub.add_parser("sync", help="Download/refresh all challenge files")
    ps.add_argument("--force", action="store_true", help="Re-download existing files")

    pt = sub.add_parser("triage", help="Run triage.sh on challenge dirs")
    pt.add_argument("--chal", metavar="NAME", help="Triage one challenge only")

    psu = sub.add_parser("submit", help="Submit a flag")
    psu.add_argument("flag", help="The flag string")
    psu.add_argument("--chal", required=True, metavar="NAME", help="Challenge name (or slug)")
    psu.add_argument("--force", action="store_true", help="Re-submit even if already marked solved")

    pst = sub.add_parser("status", help="Show solve progress")
    pst.add_argument("--category", metavar="CAT", help="Filter by category")

    pn = sub.add_parser("next", help="Print next unsolved challenge")
    pn.add_argument("--category", metavar="CAT", help="Filter by category")

    args = p.parse_args()
    dispatch = {"init": cmd_init, "sync": cmd_sync, "triage": cmd_triage,
                "submit": cmd_submit, "status": cmd_status, "next": cmd_next}
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
