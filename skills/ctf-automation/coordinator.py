#!/usr/bin/env python3
"""coordinator.py — multi-worker exploit loop dispatcher (stretch goal).

Each worker is an independent invocation of exploit_loop.py on a disjoint
slice of hypothesis space. All workers share one `.state.json` file in
the challenge dir, protected by `fcntl.flock`, and their per-attempt
rows are appended to the common `.struggle.jsonl`. Because `exploit_loop`
already auto-invokes `learn.py` on flag, the coordinator's only extra job
is spawning, monitoring, and reaping.

This is a deliberate skeleton, not a full scheduler. The priorities the
mission calls out — status sweeps every 10 min, kill stalled workers after
20 min, reallocate budget — are implemented as a single poll loop with
tunable `--sweep-s` and `--stall-s`. Production would want this reworked
around asyncio or a proper process supervisor; we keep it synchronous
and obvious so a human can reason about it in one read.

Status: SKELETON. Validated only with --mock. Real-binary coordination
is deferred to a future round because the single-worker loop already
solves the validation targets fast enough.
"""
from __future__ import annotations
import argparse, fcntl, json, os, signal, subprocess, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOOP = HERE / "exploit_loop.py"


class SharedState:
    """One JSON file, fcntl-locked for every read/write."""

    def __init__(self, path: Path):
        self.path = path
        if not path.exists():
            path.write_text(json.dumps({"workers": {}, "flag": None}))

    def update(self, fn):
        with self.path.open("r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                state = json.loads(f.read() or "{}")
                fn(state)
                f.seek(0); f.truncate()
                f.write(json.dumps(state))
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    def read(self) -> dict:
        with self.path.open("r") as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                return json.loads(f.read() or "{}")
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)


def spawn_worker(wid: str, cmd: list[str], log_dir: Path) -> subprocess.Popen:
    log_dir.mkdir(parents=True, exist_ok=True)
    outp = (log_dir / f"{wid}.out").open("w")
    errp = (log_dir / f"{wid}.err").open("w")
    return subprocess.Popen(cmd, stdout=outp, stderr=errp,
                            start_new_session=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chal-dir", required=True)
    ap.add_argument("--exploit", required=True)
    ap.add_argument("--local", default=None)
    ap.add_argument("--remote", default=None)
    ap.add_argument("--workers", type=int, default=2,
                    help="number of parallel workers")
    ap.add_argument("--offset-space", default="0:256",
                    help="outer range to partition across workers")
    ap.add_argument("--sweep-s", type=int, default=600,
                    help="status poll interval (default 10 min)")
    ap.add_argument("--stall-s", type=int, default=1200,
                    help="kill a worker that hasn't produced new attempts "
                         "in this many seconds (default 20 min)")
    ap.add_argument("--mock", action="store_true",
                    help="skip real spawning; print the plan as JSON")
    args = ap.parse_args()

    chal = Path(args.chal_dir).resolve()
    chal.mkdir(parents=True, exist_ok=True)
    state = SharedState(chal / ".state.json")

    a, b = (int(x, 0) for x in args.offset_space.split(":"))
    if args.workers < 1 or b <= a:
        print(json.dumps({"error": "bad partition"})); return 2
    slice_size = max(1, (b - a) // args.workers)
    plan = []
    for i in range(args.workers):
        lo = a + i * slice_size
        hi = b if i == args.workers - 1 else lo + slice_size
        plan.append({"wid": f"w{i}", "offset_range": f"{lo}:{hi}"})

    if args.mock:
        print(json.dumps({"mode": "mock", "plan": plan,
                          "state_file": str(chal / ".state.json")}, indent=2))
        return 0

    procs: dict[str, subprocess.Popen] = {}
    for p in plan:
        wid = p["wid"]
        cmd = [sys.executable, str(LOOP), args.exploit,
               "--sweep-offset", p["offset_range"],
               "--dir", str(chal),
               "--worker-id", wid,
               # No --no-learn: workers still trigger learn.py individually
               # on flag. learn.py deduplicates via near-match, so redundant
               # flag discoveries are safe.
               ]
        if args.local:  cmd += ["--local", args.local]
        if args.remote: cmd += ["--remote", args.remote]
        procs[wid] = spawn_worker(wid, cmd, chal / ".workers")
        state.update(lambda s, w=wid, sl=p["offset_range"]: s["workers"].update(
            {w: {"pid": procs[w].pid, "slice": sl,
                 "started": time.time(), "last_progress": time.time(),
                 "attempts": 0}}))

    struggle = chal / ".struggle.jsonl"
    last_seen_per_worker: dict[str, int] = {w: 0 for w in procs}
    t_sweep = time.time()
    try:
        while procs:
            time.sleep(min(args.sweep_s, 5))  # tight poll, log every sweep_s
            if time.time() - t_sweep >= args.sweep_s:
                t_sweep = time.time()
                # Per-worker progress: count struggle lines tagged with each worker_id.
                per_worker: dict[str, int] = {w: 0 for w in procs}
                if struggle.is_file():
                    for line in struggle.read_text().splitlines():
                        try:
                            e = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        w = e.get("worker_id")
                        if w in per_worker:
                            per_worker[w] += 1
                for wid, p in list(procs.items()):
                    if p.poll() is not None:
                        del procs[wid]
                        continue
                    delta = per_worker.get(wid, 0) - last_seen_per_worker.get(wid, 0)
                    last_seen_per_worker[wid] = per_worker.get(wid, 0)
                    if delta > 0:
                        state.update(lambda s, w=wid, n=per_worker[w]: s["workers"][w].update(
                            {"last_progress": time.time(), "attempts": n}))
                    # stall check uses per-worker last_progress
                    info = state.read()["workers"].get(wid, {})
                    if time.time() - info.get("last_progress", time.time()) > args.stall_s:
                        print(f"[coord] stalled worker {wid} — sending SIGTERM",
                              file=sys.stderr)
                        try: os.killpg(p.pid, signal.SIGTERM)
                        except ProcessLookupError: pass
            # Flag? workers now write .state.json under fcntl lock when they find one.
            s = state.read()
            if s.get("flag"):
                print(f"[coord] flag reported by {s.get('flag_worker_id','?')}: "
                      f"{s['flag']} — terminating siblings", file=sys.stderr)
                for p in procs.values():
                    try: os.killpg(p.pid, signal.SIGTERM)
                    except ProcessLookupError: pass
                break
    finally:
        # Parallelised cleanup: SIGTERM every worker first, sleep once, then
        # SIGKILL any survivor. Previously we waited 3s per worker, so N
        # stuck workers took N*3s minimum.
        for p in procs.values():
            try: os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError: pass
        deadline = time.time() + 3
        while time.time() < deadline and any(p.poll() is None for p in procs.values()):
            time.sleep(0.1)
        for p in procs.values():
            if p.poll() is None:
                try: os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError: pass

    final = state.read()
    print(json.dumps({"plan": plan, "final_state": final}, indent=2))
    return 0 if final.get("flag") else 1


if __name__ == "__main__":
    sys.exit(main())
