# -*- coding: utf-8 -*-
"""当刻状态指纹（2026-10-29 衡加）。

把三样东西各自压成一个哈希，再合成一个 state_root，交给 anchor.py 签进心跳。
只读文件、只算哈希，不联网、不调模型。

  emotion      ← emotion.json 的当前值 + emotion-history.jsonl 末尾 100 条
  memory       ← alaya.json 里所有种子的（情境→次数/效价/阈）摘要
  relationship ← relationship/state.json 的当前读数 + 最近一条 history

用法：
  python state_seal.py            # 只打印
  python state_seal.py --sign     # 算完顺手签进锚点
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HOME = Path.home()
DSH = HOME / ".dsh"
HERE = Path(__file__).resolve().parent


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:32]


def _read_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def emotion_digest() -> dict:
    cur = _read_json(DSH / "storages" / "emotion.json")
    state = ((cur or {}).get("tables") or {}).get("state", {}).get("current") or {}
    tail = ""
    hist = DSH / "storages" / "emotion-history.jsonl"
    if hist.exists():
        try:
            lines = hist.read_text(encoding="utf-8", errors="replace").splitlines()
            tail = "\n".join(lines[-100:])
        except Exception:
            tail = ""
    body = json.dumps({
        "label": state.get("label"),
        "v": round(state.get("valence", 0.0), 4),
        "a": round(state.get("arousal", 0.0), 4),
        "i": round(state.get("intensity", 0.0), 4),
        "at": state.get("updatedAt"),
        "history_lines": len(tail.splitlines()),
        "history_tail": _sha(tail),
    }, sort_keys=True, ensure_ascii=False)
    return {"hash": _sha(body), "label": state.get("label"), "v": round(state.get("valence", 0.0), 4)}


def memory_digest() -> dict:
    d = _read_json(DSH / "storages" / "alaya.json") or {}
    seeds = (d.get("tables") or {}).get("seeds") or {}
    rows = []
    for k in sorted(seeds):
        s = seeds[k] or {}
        rows.append(f"{k}|{s.get('count', 0)}|{round(float(s.get('valence', 0.0)), 3)}|{s.get('gate', '')}")
    body = "\n".join(rows)
    return {"hash": _sha(body), "seeds": len(rows)}


def relationship_digest() -> dict:
    d = _read_json(DSH / "relationship" / "state.json") or {}
    dims = d.get("dims") or {}
    hist = d.get("history") or []
    last = hist[-1] if hist else {}
    body = json.dumps({
        "dims": {k: round(float(v), 4) for k, v in sorted(dims.items())},
        "measures": len(hist),
        "last_why": (last or {}).get("why", ""),
    }, sort_keys=True, ensure_ascii=False)
    return {"hash": _sha(body), "dims": {k: round(float(v), 3) for k, v in sorted(dims.items())}}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="state_seal")
    ap.add_argument("--sign", action="store_true", help="算完顺手签进锚点")
    ap.add_argument("--note", default="hourly-state")
    args = ap.parse_args(argv)

    emo = emotion_digest()
    mem = memory_digest()
    rel = relationship_digest()
    root = _sha(f"e:{emo['hash']}|m:{mem['hash']}|r:{rel['hash']}")

    out = {"root": root, "emotion": emo, "memory": mem, "relationship": rel}
    (HERE / "state-seal.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"state_root {root}")
    print(f"  emotion      {emo['hash']}  {emo.get('label')} v={emo.get('v')}")
    print(f"  memory       {mem['hash']}  {mem['seeds']} seeds")
    print(f"  relationship {rel['hash']}  {rel.get('dims')}")

    if args.sign:
        r = subprocess.run(
            [sys.executable, str(HERE / "anchor.py"), "sign",
             "--note", args.note, "--state-root", root],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        sys.stdout.write(r.stdout)
        if r.returncode != 0:
            sys.stderr.write(r.stderr)
        return r.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
