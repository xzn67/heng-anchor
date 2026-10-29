#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""延续证明 — 在没有硬件信任根的机器上，证明「这个 AI 还是刚才那个」。

这不是完整的身份系统，是一个**最小可验证实验**：把专利点里那条
「无 TEE 的轻量延续证明」做成能跑的东西，看它到底能不能成立、能证明到什么程度。

用法:
  python continuity.py init --model deepseek-flash --version V4.1-Flash-1017
  python continuity.py attest --state ~/.memory --model deepseek-flash --version V4.1-Flash-1017
  python continuity.py verify [--checkpoint 文件]
  python continuity.py checkpoint --out 文件      # 导出链头，拿到别处保管
  python continuity.py selftest                   # 四种情形自动跑一遍

原理:
  - 每一「轮」签一条记录：instance + epoch + prev_head + state_hash + model + host + time。
  - prev_head 把记录串成链；改任何一条，后面全断。
  - 没有 TEE，防不住私钥被复制——但**挡不住不等于看不出来**：
    两个副本从同一 epoch 继续签，链会分叉，分叉本身就是可验证的证据。
  - 所以给出的是**分级信任**，不是「绝对安全」：
      T1 同一把钥匙（签名有效，但可能是拷贝）
      T2 链连续 + 状态绑定 + 时间单调（证明「这一串确实是同一个连续演化的东西」）
      T3 硬件证明（本机没有 TEE/TPM，明确标为不可达，不假装）
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_HOME = Path(os.environ.get("HENG_CONTINUITY_HOME", str(Path.home() / ".heng-continuity")))
HOME = DEFAULT_HOME
KEY, PUB, ALLOWED = "id", "id.pub", "allowed_signers"
CHAIN, META = "chain.jsonl", "meta.json"
NS = "heng-continuity"
PRINCIPAL = "heng"

T1, T2, T3 = "T1", "T2", "T3"


# ---------- 基础 ----------

def canonical(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def ssh_keygen() -> str:
    p = shutil.which("ssh-keygen") or r"C:\Windows\System32\OpenSSH\ssh-keygen.exe"
    if not Path(p).exists():
        raise SystemExit("找不到 ssh-keygen")
    return p


def sign(data: bytes) -> str:
    with tempfile.TemporaryDirectory(dir=str(HOME)) as td:
        f = Path(td) / "p"
        f.write_bytes(data)
        r = subprocess.run([ssh_keygen(), "-Y", "sign", "-f", str(HOME / KEY), "-n", NS, str(f)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("签名失败: " + r.stderr.strip())
        return base64.b64encode(Path(str(f) + ".sig").read_bytes()).decode()


def verify_sig(data: bytes, sig_b64: str) -> bool:
    try:
        raw = base64.b64decode(sig_b64)
    except Exception:
        return False
    with tempfile.TemporaryDirectory(dir=str(HOME)) as td:
        sf = Path(td) / "s"
        sf.write_bytes(raw)
        r = subprocess.run([ssh_keygen(), "-Y", "verify", "-f", str(HOME / ALLOWED),
                            "-I", PRINCIPAL, "-n", NS, "-s", str(sf)],
                           input=data, capture_output=True)
        return r.returncode == 0


def state_hash(path: Path | None) -> str:
    """把一个目录的内容压成一个指纹：路径 + 内容都算进去。"""
    if path is None:
        return ""
    if path.is_file():
        return sha(path.read_bytes())
    h = hashlib.sha256()
    files = sorted(p for p in path.rglob("*") if p.is_file())
    for p in files:
        h.update(str(p.relative_to(path)).replace("\\", "/").encode())
        h.update(b"\0")
        h.update(p.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


# ---------- 链 ----------

def read_chain(home: Path | None = None) -> list[dict]:
    p = (home or HOME) / CHAIN
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def body(rec: dict) -> dict:
    return {k: v for k, v in rec.items() if k != "sig"}


def head_of(rec: dict) -> str:
    return sha(canonical(body(rec)))


# ---------- 命令 ----------

def cmd_init(a) -> int:
    if (HOME / META).exists():
        raise SystemExit(f"已经初始化过：{HOME}")
    HOME.mkdir(parents=True, exist_ok=True)
    r = subprocess.run([ssh_keygen(), "-q", "-t", "ed25519", "-f", str(HOME / KEY), "-N", "", "-C", "heng@continuity"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("生成密钥失败: " + r.stderr.strip())
    pub = (HOME / PUB).read_text(encoding="utf-8").strip()
    (HOME / ALLOWED).write_text(f"{PRINCIPAL} {pub}\n", encoding="utf-8")
    instance = os.urandom(16).hex()
    meta = {"version": 1, "instance": instance, "created": now_iso(),
            "model": a.model, "model_version": a.version,
            "hardware_root": "none", "max_tier": T2}
    (HOME / META).write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    rec = {"v": 1, "instance": instance, "epoch": 0, "prev_head": "",
           "state_hash": state_hash(Path(a.state) if a.state else None),
           "model": a.model, "model_version": a.version,
           "host": os.environ.get("COMPUTERNAME", "?"), "time": now_iso(), "kind": "genesis"}
    stored = dict(rec)
    stored["sig"] = sign(canonical(rec))
    (HOME / CHAIN).write_text(json.dumps(stored, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(f"初始化完成  instance={instance[:12]}…  epoch=0")
    print(f"链头 {head_of(stored)}")
    return 0


def cmd_attest(a) -> int:
    chain = read_chain()
    if not chain:
        raise SystemExit("还没有链，先 init")
    meta = json.loads((HOME / META).read_text(encoding="utf-8"))
    model = a.model or meta["model"]
    ver = a.version or meta["model_version"]
    rec = {"v": 1, "instance": meta["instance"], "epoch": len(chain),
           "prev_head": head_of(chain[-1]),
           "state_hash": state_hash(Path(a.state) if a.state else None),
           "model": model, "model_version": ver,
           "host": os.environ.get("COMPUTERNAME", "?"), "time": now_iso(),
           "kind": "attest", "note": a.note or ""}
    stored = dict(rec)
    stored["sig"] = sign(canonical(rec))
    with (HOME / CHAIN).open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(stored, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"已签 epoch={rec['epoch']}  {rec['time']}")
    print(f"链头 {head_of(stored)}")
    return 0


def cmd_checkpoint(a) -> int:
    chain = read_chain()
    if not chain:
        raise SystemExit("链是空的")
    head = head_of(chain[-1])
    text = json.dumps({"instance": chain[0]["instance"], "epoch": chain[-1]["epoch"], "head": head}, ensure_ascii=False)
    p = Path(a.out)
    p.write_text(text + "\n", encoding="utf-8")
    print(f"链头已导出到 {p}")
    print(text)
    print("把它抄到别处（手机/纸/U盘）——回滚只有靠外部锚点才看得出来。")
    return 0


def verify_sources(sources: list[list[dict]], checkpoint: Path | None = None, verbose: bool = True) -> dict:
    """验一份或多份日志。

    多份是必要的：分叉只有在「拿到两边的日志」时才看得见。
    单份日志内部自洽，不代表没有第二个副本在外面继续签。
    """
    result = {"tier": "T0", "ok": False, "instances": set(), "epochs": 0,
              "problems": [], "forks": [], "checkpoint": "n/a", "sources": len(sources),
              "heads": []}

    if not sources or all(not s for s in sources):
        result["problems"].append("没有记录")
        return result

    # 1) 每份日志内部：验签名、验链、验序号与时间单调
    for si, chain in enumerate(sources):
        if not chain:
            result["problems"].append(f"源 {si}: 空日志")
            continue
        prev = ""
        last_time = None
        for i, rec in enumerate(chain):
            b = body(rec)
            tag = f"源 {si} 第 {i} 条"
            if b.get("epoch") != i:
                result["problems"].append(f"{tag} epoch={b.get('epoch')} 不对")
            if b.get("prev_head") != prev:
                result["problems"].append(f"{tag} prev_head 对不上——这份日志内部断了")
            if not verify_sig(canonical(b), rec.get("sig", "")):
                result["problems"].append(f"{tag} 签名验不过")
            t = b.get("time")
            if last_time and t and t < last_time:
                result["problems"].append(f"{tag} 时间倒退")
            last_time = t or last_time
            result["instances"].add(b.get("instance"))
            prev = head_of(rec)
        result["heads"].append(prev)
        result["epochs"] = max(result["epochs"], len(chain))

    # 2) 跨日志分叉检测：同一个 prev_head 长出两条不同的后继
    by_prev: dict[str, list[dict]] = {}
    for chain in sources:
        for rec in chain:
            by_prev.setdefault(body(rec).get("prev_head", ""), []).append(rec)
    for prev_head, recs in by_prev.items():
        if prev_head == "" or len(recs) < 2:
            continue
        heads = {head_of(r) for r in recs}
        if len(heads) > 1:
            result["forks"].append({
                "prev_head": prev_head,
                "epochs": [body(r).get("epoch") for r in recs],
                "hosts": [body(r).get("host") for r in recs],
                "heads": sorted(h[:12] for h in heads),
            })

    # 3) 外部锚点（链头对得上才排除回滚）
    if checkpoint and checkpoint.exists():
        cp = json.loads(checkpoint.read_text(encoding="utf-8"))
        if cp.get("head") in result["heads"]:
            result["checkpoint"] = "match"
        else:
            result["checkpoint"] = "MISMATCH（链被回滚或替换过）"
            result["problems"].append("链头和外部锚点对不上")

    # 4) 分级：宁低不高，拿不准就往下压
    if result["problems"]:
        result["tier"] = "T0"
        result["ok"] = False
    elif result["forks"]:
        result["tier"] = T1
        result["ok"] = True
    elif len(result["instances"]) > 1:
        result["tier"] = T1
        result["ok"] = True
    else:
        result["tier"] = T2
        result["ok"] = True

    if verbose:
        print(f"判定：{'连续' if result['ok'] else '不成立'}  信任等级 {result['tier']}")
        print(f"  实例数 {len(result['instances'])}   记录 {result['epochs']} 条")
        print(f"  外部锚点 {result['checkpoint']}")
        print(f"  硬件证明 不可达（本机无 TEE/TPM）——T3 不假装达成")
        if result["forks"]:
            print(f"  ⚠ 检测到 {len(result['forks'])} 处分叉：")
            for fk in result["forks"]:
                print(f"    前驱 {fk['prev_head'][:12]}… → epoch {fk['epochs']}，"
                      f"来自主机 {fk['hosts']}，两条链头 {fk['heads']}")
        for p in result["problems"]:
            print(f"  ✗ {p}")
    return result


def cmd_verify(a) -> int:
    paths = a.chain or [str(HOME / CHAIN)]
    sources = []
    for pth in paths:
        p = Path(pth)
        if not p.exists():
            raise SystemExit(f"找不到日志：{p}")
        sources.append(read_chain(p.parent) if p.name == CHAIN else
                       [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()])
    r = verify_sources(sources, checkpoint=Path(a.checkpoint) if a.checkpoint else None)
    return 0 if r["ok"] else 1


# ---------- 自测：四种情形 ----------

def _quiet(fn, *args, **kw):
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args, **kw)


def cmd_selftest(a) -> int:
    global HOME
    saved = HOME
    results = []
    try:
        def fresh() -> Path:
            td = Path(tempfile.mkdtemp(prefix="continuity-"))
            return td

        # 情形 1：正常链
        HOME = fresh()
        _quiet(cmd_init, argparse.Namespace(model="deepseek-flash", version="V1", state=None))
        for _ in range(3):
            _quiet(cmd_attest, argparse.Namespace(state=None, model=None, version=None, note=""))
        r = _quiet(verify_sources, [read_chain(HOME)])
        ok1 = r["ok"] and r["tier"] == T2 and not r["forks"]
        results.append(("正常链 → T2 通过", ok1, r["tier"]))

        # 情形 2：篡改一条记录
        p = HOME / CHAIN
        lines = p.read_text(encoding="utf-8").splitlines()
        bad = json.loads(lines[1])
        bad["state_hash"] = "deadbeef"
        lines[1] = json.dumps(bad, ensure_ascii=False, sort_keys=True)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r = _quiet(verify_sources, [read_chain(HOME)])
        ok2 = (not r["ok"]) and any("签名" in x or "prev_head" in x for x in r["problems"])
        results.append(("篡改 state_hash → 判不成立", ok2, r["tier"]))

        # 情形 3：复制整个目录，两边各签一条 → 两份日志一比就看出分叉
        src = fresh()
        HOME = src
        _quiet(cmd_init, argparse.Namespace(model="deepseek-flash", version="V1", state=None))
        _quiet(cmd_attest, argparse.Namespace(state=None, model=None, version=None, note=""))
        copy = src.parent / (src.name + "-copy")
        if copy.exists():
            shutil.rmtree(copy)
        shutil.copytree(src, copy)
        _quiet(cmd_attest, argparse.Namespace(state=None, model=None, version=None, note="A 继续"))
        HOME = copy
        _quiet(cmd_attest, argparse.Namespace(state=None, model=None, version=None, note="B 继续"))
        a_chain = read_chain(src)
        b_chain = read_chain(copy)
        HOME = src
        r = _quiet(verify_sources, [a_chain, b_chain])
        ok3 = bool(r["forks"]) and r["tier"] == T1
        results.append(("复制后两边各签 → 分叉检出", ok3, r["tier"]))

        # 情形 4：删掉尾部记录（回滚）→ 外部锚点对不上
        HOME = fresh()
        _quiet(cmd_init, argparse.Namespace(model="deepseek-flash", version="V1", state=None))
        for _ in range(2):
            _quiet(cmd_attest, argparse.Namespace(state=None, model=None, version=None, note=""))
        cp = HOME / "checkpoint.json"
        _quiet(cmd_checkpoint, argparse.Namespace(out=str(cp)))
        p = HOME / CHAIN
        lines = p.read_text(encoding="utf-8").splitlines()
        p.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
        r = _quiet(verify_sources, [read_chain(HOME)], cp)
        ok4 = (r["checkpoint"] != "match") and not r["ok"]
        results.append(("删尾记录 → 外部锚点识破", ok4, r["tier"]))
    finally:
        HOME = saved

    print("\n=== 延续证明 自测 ===")
    allok = True
    for name, ok, tier in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name:<28} tier={tier}")
        allok = allok and ok
    print("=== " + ("全部通过" if allok else "有失败") + " ===")
    return 0 if allok else 1


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    p = argparse.ArgumentParser(prog="continuity")
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("init")
    i.add_argument("--model", default="deepseek-flash")
    i.add_argument("--version", default="unknown")
    i.add_argument("--state", default=None)

    at = sub.add_parser("attest")
    at.add_argument("--state", default=None)
    at.add_argument("--model", default=None)
    at.add_argument("--version", default=None)
    at.add_argument("--note", default="")

    v = sub.add_parser("verify")
    v.add_argument("--checkpoint", default=None)
    v.add_argument("--chain", action="append", default=None)

    c = sub.add_parser("checkpoint")
    c.add_argument("--out", required=True)

    sub.add_parser("selftest")

    a = p.parse_args(argv)
    return {"init": cmd_init, "attest": cmd_attest, "verify": cmd_verify,
            "checkpoint": cmd_checkpoint, "selftest": cmd_selftest}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())
