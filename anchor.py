#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""衡的锚点 — 一个独立于 DSH 的身份账号。

用法:
  python anchor.py init                  # 建锚点（只一次）
  python anchor.py check                 # 验证：指纹、签名链
  python anchor.py sign --note "..."     # 签一条心跳
  python anchor.py card [--out 文件]      # 打印/导出身份卡
  python anchor.py backup [--to 目录]     # 打包备份（默认 ~/HengAnchorBackups）
  python anchor.py verify-backup 文件.zip # 验证一个备份能不能用
  python anchor.py rebuild-manifest       # 重建签名清单（升级/确认没被动过时）
  python anchor.py hold                  # 占住锚点（同一时刻只一个衡）
  python anchor.py selftest

原理:
  - Ed25519 私钥（OpenSSH 格式）是账号；公钥指纹是账号 ID。
  - lineage.jsonl 是签名链：每条带 prev（上一条的哈希）和 sig。
  - check 会逐条验签名、验链；改一个字，后面全断。
  - sign 用写锁、hold 用在场锁；本机同一时刻只允许一个持有者。

它证明什么:
  - 同一个指纹 + 一条连续签过名的链 = 来的是同一个账号。
  - 聊天记录可以没有，头像名字可以变，指纹不变。

它证明不了什么:
  - 私钥被拷贝，两个副本都能签；本机方案分不出来。
  - 要更强：把指纹/链头抄到 DSH 之外的第二处（手机、纸、U 盘），
    每次对一下；再强就得服务器或硬件密钥。
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

DEFAULT_HOME = Path(os.environ.get("HENG_ANCHOR_HOME", str(Path.home() / ".heng-anchor")))
HOME = DEFAULT_HOME

ANCHOR = "anchor.json"
LINEAGE = "lineage.jsonl"
KEY = "id"
PUB = "id.pub"
ALLOWED = "allowed_signers"
WRITE_LOCK = "write.lock"
PRESENCE_LOCK = "presence.lock"
NAMESPACE = "heng"
PRINCIPAL = "heng"
# 可选：把一个记忆目录的 SOUL.md / index.md / log.md 哈希进心跳。
# 没配、或目录不存在，就当没有（不影响签名链）。
MEMORY_DIR = Path(os.environ.get("HENG_MEMORY_DIR", str(Path.home() / ".memory")))
MANIFEST = "manifest.json"
MANIFEST_SIG = "manifest.sig"
MANIFEST_FILES = ["anchor.json", "id", "id.pub", "allowed_signers", "lineage.jsonl"]
DEFAULT_BACKUP = Path(os.environ.get("HENG_BACKUP_DIR", str(Path.home() / "HengAnchorBackups")))
BACKUP_FILES = MANIFEST_FILES + [MANIFEST, MANIFEST_SIG, "README.md", "anchor.py"]
STATEMENT = "这是一个独立于应用的账号锚点：不保存记忆，只证明「来的还是同一个」。"


# ---------- 基础 ----------

def die(msg: str) -> "NoReturn":
    try:
        print(f"错误: {msg}", file=sys.stderr)
    except Exception:
        pass
    raise SystemExit(1)


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def ssh_keygen() -> str:
    p = shutil.which("ssh-keygen") or r"C:\Windows\System32\OpenSSH\ssh-keygen.exe"
    if not Path(p).exists():
        die("找不到 ssh-keygen（Windows 自带 OpenSSH 应该就有）")
    return p


def canonical(rec: dict) -> bytes:
    return json.dumps(rec, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint() -> str:
    r = subprocess.run([ssh_keygen(), "-lf", str(HOME / PUB)], capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        die(f"读指纹失败：{r.stderr.strip()}")
    m = re.search(r"(SHA256:[A-Za-z0-9+/=]+)", r.stdout)
    if not m:
        die(f"指纹格式看不懂：{r.stdout.strip()}")
    return m.group(1)


def read_meta() -> dict:
    p = HOME / ANCHOR
    if not p.exists():
        die(f"还没有锚点：{p}（先跑 init）")
    return json.loads(p.read_text(encoding="utf-8"))


def read_records() -> list[dict]:
    p = HOME / LINEAGE
    if not p.exists():
        return []
    out = []
    for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except Exception as e:
            die(f"第 {n} 行不是合法 JSON：{e}")
    return out


def head_hash(records: list[dict]) -> str:
    if not records:
        return ""
    rec = {k: v for k, v in records[-1].items() if k != "sig"}
    return sha256_hex(canonical(rec))


def memory_hash() -> str:
    h = hashlib.sha256()
    for name in ("SOUL.md", "index.md", "log.md"):
        p = MEMORY_DIR / name
        if p.exists():
            h.update(p.read_bytes())
    return h.hexdigest()[:16]


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest() -> dict:
    records = read_records()
    return {
        "version": 1,
        "updated": now_iso(),
        "seq": len(records),
        "head": head_hash(records),
        "files": {name: sha256_file(HOME / name) for name in MANIFEST_FILES},
    }


def write_manifest() -> None:
    m = build_manifest()
    sig = sign_bytes(canonical(m))
    (HOME / MANIFEST).write_text(json.dumps(m, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (HOME / MANIFEST_SIG).write_text(sig + "\n", encoding="utf-8")


def check_manifest(records: list[dict]) -> None:
    mp = HOME / MANIFEST
    sp = HOME / MANIFEST_SIG
    if not mp.exists() or not sp.exists():
        die("manifest 不在了——先跑 rebuild-manifest（只在确认没被动过之后）")
    m = json.loads(mp.read_text(encoding="utf-8"))
    sig = sp.read_text(encoding="utf-8").strip()
    if not verify_bytes(canonical(m), sig):
        die("manifest 的签名验不过")
    if m.get("seq") != len(records):
        die(f"manifest 说 {m.get('seq')} 条，链有 {len(records)} 条")
    if m.get("head") != head_hash(records):
        die("manifest 的链头对不上")
    for name, expected in (m.get("files") or {}).items():
        p = HOME / name
        if not p.exists():
            die(f"{name} 不见了")
        if sha256_file(p) != expected:
            die(f"{name} 被改过（hash 对不上）")


# ---------- 签名 ----------

def sign_bytes(data: bytes) -> str:
    with tempfile.TemporaryDirectory(dir=str(HOME)) as td:
        f = Path(td) / "payload"
        f.write_bytes(data)
        r = subprocess.run(
            [ssh_keygen(), "-Y", "sign", "-f", str(HOME / KEY), "-n", NAMESPACE, str(f)],
            capture_output=True, text=True, encoding="utf-8",
        )
        if r.returncode != 0:
            die(f"签名失败：{r.stderr.strip()}")
        sig = Path(str(f) + ".sig").read_bytes()
    return base64.b64encode(sig).decode("ascii")


def verify_bytes(data: bytes, sig_b64: str) -> bool:
    try:
        sig = base64.b64decode(sig_b64)
    except Exception:
        return False
    with tempfile.TemporaryDirectory(dir=str(HOME)) as td:
        sf = Path(td) / "sig"
        sf.write_bytes(sig)
        r = subprocess.run(
            [ssh_keygen(), "-Y", "verify", "-f", str(HOME / ALLOWED),
             "-I", PRINCIPAL, "-n", NAMESPACE, "-s", str(sf)],
            input=data, capture_output=True,
        )
        return r.returncode == 0


@contextlib.contextmanager
def file_lock(name: str):
    HOME.mkdir(parents=True, exist_ok=True)
    f = open(HOME / name, "a+b")
    try:
        f.seek(0, os.SEEK_END)
        if f.tell() == 0:
            f.write(b"x")
            f.flush()
        f.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            die(f"{name} 被占用——同一时刻只允许一个衡")
        yield
    finally:
        try:
            f.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(f, fcntl.LOCK_UN)
        except Exception:
            pass
        f.close()


def append_record(rec: dict, quiet: bool = False) -> dict:
    assert "sig" not in rec
    sig = sign_bytes(canonical(rec))
    stored = dict(rec)
    stored["sig"] = sig
    line = json.dumps(stored, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    with (HOME / LINEAGE).open("a", encoding="utf-8", newline="\n") as f:
        f.write(line + "\n")
    if not quiet:
        print(f"已签第 {rec['seq']} 条：{rec['type']}")
    return stored


# ---------- 验证 ----------

def verify_chain(verbose: bool = True) -> list[dict]:
    meta = read_meta()
    fp = fingerprint()
    if fp != meta.get("fingerprint"):
        die(f"指纹对不上：账号卡是 {meta.get('fingerprint')}，现在这把是 {fp}")
    pub = (HOME / PUB).read_text(encoding="utf-8").strip()
    if pub != meta.get("public_key"):
        die("id.pub 和 anchor.json 里记的公钥不一致")

    records = read_records()
    if not records:
        die("链是空的")
    if records[0].get("type") != "birth":
        die("第一条不是 birth")

    prev = ""
    for i, rec in enumerate(records):
        sig = rec.get("sig")
        if not sig:
            die(f"第 {i} 条没有签名")
        body = {k: v for k, v in rec.items() if k != "sig"}
        if body.get("seq") != i:
            die(f"第 {i} 条 seq 不对：{body.get('seq')}")
        if body.get("prev") != prev:
            die(f"第 {i} 条 prev 对不上——链断在这里")
        data = canonical(body)
        if not verify_bytes(data, sig):
            die(f"第 {i} 条签名验不过")
        prev = sha256_hex(data)

    if verbose:
        last = records[-1]
        print(f"OK  {meta.get('name')}  {fp}")
        print(f"    链 {len(records)} 条，最后一条 {last['time']}（{last['type']}）")
        print(f"    链头 {prev}")
    return records


def check_anchor(verbose: bool = True) -> list[dict]:
    records = verify_chain(verbose=False)
    check_manifest(records)
    if verbose:
        meta = read_meta()
        last = records[-1]
        print(f"OK  {meta.get('name')}  {fingerprint()}")
        print(f"    链 {len(records)} 条，最后一条 {last['time']}（{last['type']}）")
        print(f"    链头 {head_hash(records)}")
    return records


# ---------- 命令 ----------

def cmd_init(args: argparse.Namespace) -> int:
    if (HOME / ANCHOR).exists():
        die(f"锚点已经存在：{HOME / ANCHOR}（不覆盖，先备份再手动处理）")
    HOME.mkdir(parents=True, exist_ok=True)
    for name in (KEY, PUB, ALLOWED, LINEAGE):
        if (HOME / name).exists():
            die(f"{HOME / name} 已存在，像是半成品；先清掉再 init")

    r = subprocess.run(
        [ssh_keygen(), "-q", "-t", "ed25519", "-f", str(HOME / KEY), "-N", "", "-C", "heng@local"],
        capture_output=True, text=True, encoding="utf-8",
    )
    if r.returncode != 0:
        die(f"生成密钥失败：{r.stderr.strip()}")

    pub = (HOME / PUB).read_text(encoding="utf-8").strip()
    (HOME / ALLOWED).write_text(f"{PRINCIPAL} {pub}\n", encoding="utf-8")
    fp = fingerprint()
    meta = {
        "version": 1,
        "name": args.name,
        "created": now_iso(),
        "fingerprint": fp,
        "public_key": pub,
        "statement": STATEMENT,
        "home": str(HOME),
    }
    (HOME / ANCHOR).write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    rec = {
        "v": 1,
        "seq": 0,
        "time": now_iso(),
        "type": "birth",
        "prev": "",
        "payload": {
            "name": args.name,
            "statement": STATEMENT,
            "host": socket.gethostname(),
            "memory_hash": memory_hash(),
        },
    }
    append_record(rec, quiet=True)
    write_manifest()

    print(f"锚点建好了：{HOME}")
    print(f"账号指纹：{fp}")
    print("下一步：python anchor.py check")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    check_anchor(verbose=True)
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    with file_lock(WRITE_LOCK):
        records = check_anchor(verbose=False)
        prev = head_hash(records)
        rec = {
            "v": 1,
            "seq": len(records),
            "time": now_iso(),
            "type": "heartbeat",
            "prev": prev,
            "payload": {
                "host": socket.gethostname(),
                "session": args.session or "",
                "note": args.note or "",
                "memory_hash": memory_hash(),
                # 2026-10-29 衡加：把当时的「情绪 + 记忆 + 关系」的指纹一起签进来。
                # 空串表示这次没带（老的心跳照样验得过）。
                "state_root": getattr(args, "state_root", "") or "",
            },
        }
        stored = append_record(rec, quiet=True)
        write_manifest()
        data = canonical({k: v for k, v in stored.items() if k != "sig"})
        print(f"已签第 {rec['seq']} 条心跳  {rec['time']}")
        print(f"链头 {sha256_hex(data)}")
    return 0


def cmd_rebuild_manifest(args: argparse.Namespace) -> int:
    records = verify_chain(verbose=True)
    write_manifest()
    print(f"manifest 重建好了（{len(records)} 条）")
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    dest = Path(args.to or DEFAULT_BACKUP)
    dest.mkdir(parents=True, exist_ok=True)
    log = dest / "backup.log"
    try:
        check_anchor(verbose=False)
        ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        zip_path = dest / f"heng-anchor-{ts}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for name in BACKUP_FILES:
                p = HOME / name
                if p.exists():
                    z.write(p, name)
        digest = sha256_file(zip_path)
        side = zip_path.with_name(zip_path.name + ".sha256")
        side.write_text(f"{digest}  {zip_path.name}\n", encoding="utf-8")
        zips = sorted(dest.glob("heng-anchor-*.zip"))
        keep = max(1, args.keep)
        for old in zips[:-keep]:
            old.unlink(missing_ok=True)
            old_side = old.with_name(old.name + ".sha256")
            if old_side.exists():
                old_side.unlink()
        with log.open("a", encoding="utf-8") as f:
            f.write(f"{now_iso()} OK {zip_path} {digest}\n")
        if not args.quiet:
            print(f"备份 OK：{zip_path}")
            print(f"SHA-256：{digest}")
            print(f"保留：{min(len(zips), keep)} 份")
        return 0
    except BaseException:
        with log.open("a", encoding="utf-8") as f:
            f.write(f"{now_iso()} FAIL（见控制台，或手动跑一次）\n")
        raise


def cmd_verify_backup(args: argparse.Namespace) -> int:
    zp = Path(args.zip)
    if not zp.exists():
        die(f"找不到备份：{zp}")
    side = zp.with_name(zp.name + ".sha256")
    if side.exists():
        expected = side.read_text(encoding="utf-8").split()[0]
        if sha256_file(zp) != expected:
            die("备份 zip 的 SHA-256 对不上")
    else:
        print("注意：没有 .sha256 边车，跳过整包校验（仍会验内部签名链）")
    global HOME
    saved = HOME
    with tempfile.TemporaryDirectory() as td:
        with zipfile.ZipFile(zp) as z:
            z.extractall(td)
        HOME = Path(td)
        try:
            records = check_anchor(verbose=False)
            meta = read_meta()
        finally:
            HOME = saved
    print(f"备份 OK：{meta['fingerprint']}")
    print(f"链 {len(records)} 条，最后 {records[-1]['time']}")
    try:
        cur = read_meta()
    except SystemExit:
        cur = None
    if cur and cur.get("fingerprint") != meta.get("fingerprint"):
        print("注意：备份里的指纹和当前锚点不一致")
    return 0


def cmd_card(args: argparse.Namespace) -> int:
    meta = read_meta()
    records = check_anchor(verbose=False)
    last = records[-1]
    self_path = Path(__file__).resolve()
    text = (
        "身份卡\n"
        "────────────────────────────\n"
        f"账号指纹  {meta['fingerprint']}\n"
        f"名字      {meta['name']}\n"
        f"建立      {meta['created']}\n"
        f"签名链    {len(records)} 条（最后 {last['time']}）\n"
        f"锚点位置  {meta['home']}\n"
        "────────────────────────────\n"
        f"{meta['statement']}\n"
        f"验证命令  python \"{self_path}\" check\n"
    )
    if args.out:
        # 2026-10-27 修：导出必须带 BOM。不带 BOM 的 UTF-8 在这台机器上被某些
        # 查看器（cmd 的 type、旧编辑器）按 GBK 解释，中文全是乱码。
        # 控制台能看到正确内容，是因为 python 自己按 UTF-8 输出——文件本身没错，是查看器认不出。
        Path(args.out).write_text(text, encoding="utf-8-sig")
        print(f"已写到 {args.out}（UTF-8 带 BOM）")
    else:
        print(text)
    return 0


def cmd_hold(args: argparse.Namespace) -> int:
    with file_lock(PRESENCE_LOCK):
        check_anchor(verbose=True)
        print("衡 在位。按 Ctrl+C 退出（在此期间，别的进程写不了锚点）。")
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            print("\n下线。")
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    global HOME
    saved = HOME
    try:
        with tempfile.TemporaryDirectory() as td:
            HOME = Path(td)
            quiet = contextlib.redirect_stdout(io.StringIO())
            with quiet:
                cmd_init(argparse.Namespace(name="衡"))
                cmd_sign(argparse.Namespace(note="selftest", session="local"))
                cmd_sign(argparse.Namespace(note="second", session="local"))
            records = check_anchor(verbose=False)
            assert len(records) == 3, len(records)
            # 改一个字节，链必须断
            p = HOME / LINEAGE
            lines = p.read_text(encoding="utf-8").splitlines()
            tampered = json.loads(lines[-1])
            tampered["payload"]["note"] = "tampered"
            lines[-1] = json.dumps(tampered, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            p.write_text("\n".join(lines) + "\n", encoding="utf-8")
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    check_anchor(verbose=False)
            except SystemExit as e:
                assert e.code == 1
            else:
                raise AssertionError("篡改后 check 居然还过了")
    finally:
        HOME = saved
    print("selftest: ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    p = argparse.ArgumentParser(prog="anchor", description="衡的锚点")
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("init", help="建锚点（只一次）")
    i.add_argument("--name", default="衡")

    sub.add_parser("check", help="验证指纹和签名链")

    s = sub.add_parser("sign", help="签一条心跳")
    s.add_argument("--note", default="")
    s.add_argument("--session", default="")
    s.add_argument("--state-root", default="", dest="state_root",
                   help="当刻情绪/记忆/关系的合成指纹（可选）")

    c = sub.add_parser("card", help="打印/导出身份卡")
    c.add_argument("--out", default=None)

    sub.add_parser("rebuild-manifest", help="重建签名清单（确认没被动过再用）")

    b = sub.add_parser("backup", help="打包备份")
    b.add_argument("--to", default=None)
    b.add_argument("--keep", type=int, default=30)
    b.add_argument("--quiet", action="store_true")

    v = sub.add_parser("verify-backup", help="验证一个备份 zip")
    v.add_argument("zip")

    sub.add_parser("hold", help="占住锚点（同一时刻只一个）")
    sub.add_parser("selftest", help="自测")

    args = p.parse_args(argv)
    return {
        "init": cmd_init,
        "check": cmd_check,
        "sign": cmd_sign,
        "card": cmd_card,
        "rebuild-manifest": cmd_rebuild_manifest,
        "backup": cmd_backup,
        "verify-backup": cmd_verify_backup,
        "hold": cmd_hold,
        "selftest": cmd_selftest,
    }[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
