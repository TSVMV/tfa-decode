#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""2FA 一键解码工具 — 自动识别 TOTP/HOTP/otpauth URI/Base32/URL 编码/HTML 实体/Base64/明文。

无第三方依赖，Python 3.9+。
"""

import argparse
import base64
import hmac
import html
import re
import struct
import sys
import time
import urllib.parse
from dataclasses import dataclass
from hashlib import sha1, sha256, sha512
from typing import List, Optional

# ---------- 基础解码器 ----------

def base32_decode(s: str) -> Optional[bytes]:
    """标准 Base32（RFC 4648）解码，容忍缺失的填充、大小写与空格/连字符分组。失败返回 None。"""
    s = re.sub(r"[-\s]", "", s.strip().upper())
    if not s or len(s) < 5:
        return None
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    if not all(c in allowed for c in s):
        return None
    try:
        return base64.b32decode(s + "=" * ((-len(s)) % 8))
    except Exception:
        return None

def base64_url_decode(s: str) -> Optional[bytes]:
    s = s.strip()
    if not s:
        return None
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-+_=")
    if not all(c in allowed for c in s):
        return None
    pad = (-len(s)) % 4
    try:
        return base64.urlsafe_b64decode(s + "=" * pad)
    except Exception:
        return None

def is_url_encoded(s: str) -> bool:
    # 形如 %3C %22 的 %XX 序列
    return bool(re.search(r"%[0-9A-Fa-f]{2}", s))

def is_html_entity(s: str) -> bool:
    return bool(re.search(r"&(?:[a-zA-Z][a-zA-Z0-9]+|#\d+|#x[0-9a-fA-F]+);", s))

def parse_kv_string(s: str) -> dict:
    """解析形如 secret=ABC&period=60&digits=8 的内联参数（按 & 分对，& 为普通字符）"""
    out = {}
    for part in s.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out

def _safe_int(v, default):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default

# ---------- RFC 6238 / RFC 4226 ----------

_DIGESTS = {"SHA1": sha1, "SHA256": sha256, "SHA512": sha512}

def hotp(secret: bytes, counter: int, digits: int, algo: str = "SHA1") -> str:
    if not 1 <= digits <= 10:
        digits = 6
    if counter < 0:
        counter = 0
    digest = _DIGESTS.get(algo.upper(), sha1)
    data = struct.pack(">Q", counter)
    h = hmac.new(secret, data, digest).digest()
    off = h[-1] & 0x0F
    code = (struct.unpack(">I", h[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)

def totp(secret: bytes, period: int = 30, digits: int = 6, algo: str = "SHA1", ts: Optional[float] = None) -> str:
    ts = time.time() if ts is None else ts
    if period <= 0:
        period = 30
    return hotp(secret, int(ts // period), digits, algo)

# ---------- otpauth:// URI ----------

@dataclass
class OtpAuth:
    type: str = "totp"
    issuer: str = ""
    account: str = ""
    secret_b32: str = ""
    period: int = 30
    digits: int = 6
    algorithm: str = "SHA1"
    counter: Optional[int] = None
    raw: str = ""

    @property
    def secret(self) -> bytes:
        return base32_decode(self.secret_b32) or b""

def parse_otpauth(uri: str) -> OtpAuth:
    uri = uri.strip()
    if "://" not in uri:
        scheme, rest = "", uri
    else:
        scheme, rest = uri.split("://", 1)
    rest = rest.split("?", 1)
    head, query = rest[0], rest[1] if len(rest) > 1 else ""
    # head 形如 "hotp/Acme:bob" → 第一段是 type，剩下的按第一个 ":" 分出 account
    type_seg, _, rest_seg = head.partition("/")
    otype = type_seg.lower()
    label = rest_seg.split(":", 1)[1] if ":" in rest_seg else rest_seg
    q = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
    issuer = q.get("issuer", "")
    if issuer:
        label = f"{issuer} {label}"
    period = _safe_int(q.get("period", "30"), 30)
    if period <= 0:
        period = 30
    digits = _safe_int(q.get("digits", "6"), 6)
    if not 1 <= digits <= 10:
        digits = 6
    counter = _safe_int(q.get("counter"), None) if q.get("counter") is not None else None
    cfg = OtpAuth(
        type=otype if otype in ("totp", "hotp") else "totp",
        issuer=issuer,
        account=label,
        secret_b32=(q.get("secret") or "").upper(),
        period=period,
        digits=digits,
        algorithm=(q.get("algorithm", "SHA1") or "SHA1").upper(),
        counter=counter,
        raw=uri,
    )
    return cfg

# ---------- 结果 ----------

@dataclass
class DecodeResult:
    kind: str
    value: str
    details: str = ""
    ok: bool = True
    warning: str = ""

# ---------- 自动识别 ----------

def detect_and_decode(raw: str, args) -> List[DecodeResult]:
    s = raw.strip()
    if not s:
        return []

    # 1. otpauth:// URI
    if s.lower().startswith("otpauth://"):
        return [_decode_otpauth(s, args)]

    # 2. 内联键值对 secret=ABC&period=60&digits=8（先于 Base32，因为含 = 与 &）
    if re.match(r"^(secret|key)\s*=", s, flags=re.I):
        kv = parse_kv_string(s)
        sec_raw = kv.get("secret") or kv.get("key") or ""
        sec_bytes = base32_decode(sec_raw) or sec_raw.encode("utf-8")
        period = _safe_int(kv.get("period"), args.period or 30) or 30
        digits = _safe_int(kv.get("digits"), args.digits or 6) or 6
        algo = (kv.get("algorithm") or args.algorithm or "SHA1").upper()
        code = totp(sec_bytes, period, digits, algo)
        code8 = totp(sec_bytes, period, 8, algo)
        res = [DecodeResult(
            kind="TOTP (内联 key=value)",
            value=code,
            details=f"secret={sec_raw}  period={period}s  digits={digits}  algo={algo}  "
                    f"(同时 8 位: {code8})",
        )]
        res.append(DecodeResult(
            kind="secret → bytes",
            value=sec_bytes.hex(),
            details=f"Base32 解码为 {len(sec_bytes)} 字节: {sec_bytes!r}"
                    if base32_decode(sec_raw) is not None
                    else f"非 Base32，按 UTF-8 字节处理: {sec_bytes!r}",
        ))
        return res

    # 3. 纯 Base32 密钥 → 计算当前 TOTP
    b32 = base32_decode(s)
    if b32 is not None and len(b32) >= 8:
        period = args.period or 30
        digits = args.digits or 6
        algo = args.algorithm or "SHA1"
        code = totp(b32, period, digits, algo)
        code8 = totp(b32, period, 8, algo)
        res = [DecodeResult(
            kind="TOTP (RFC 6238)",
            value=code,
            details=f"secret={s}  period={period}s  digits={digits}  algo={algo}  "
                    f"(同时 8 位: {code8})",
        )]
        res.append(DecodeResult(
            kind="Base32 → bytes",
            value=b32.hex(),
            details=f"Base32 解码为 {len(b32)} 字节: {b32!r}",
        ))
        return res

    # 3. URL 编码
    if is_url_encoded(s):
        try:
            out = urllib.parse.unquote(s)
            return [DecodeResult(kind="URL 编码", value=out, details=f"URLDecode 结果: {out!r}")]
        except Exception as e:
            return [DecodeResult(kind="URL 编码", value="", details=f"解码失败: {e}", ok=False)]

    # 4. HTML 实体
    if is_html_entity(s):
        out = html.unescape(s)
        return [DecodeResult(kind="HTML 实体", value=out, details=f"unescape: {out!r}")]

    # 5. URL 安全 Base64（含 - / _ 视为 b64url 标志；或解码结果 ≥60% 可打印）
    b64 = base64_url_decode(s)
    if b64 is not None and len(b64) > 0:
        has_b64url_char = ("-" in s or "_" in s)
        printable = sum(1 for b in b64 if 32 <= b < 127)
        if has_b64url_char or printable / len(b64) >= 0.6:
            return [DecodeResult(kind="Base64 (URL 安全)", value=b64.decode("utf-8", "replace"),
                                 details=f"base64url 解码: {b64!r}")]

    # 6. 明文
    return [DecodeResult(kind="明文 / 密码", value=s,
                         warning="未匹配 TOTP/Base32/URL/Base64 特征，按明文输出")]

def _decode_otpauth(uri: str, args) -> DecodeResult:
    cfg = parse_otpauth(uri)
    if cfg.type == "totp":
        period = args.period or cfg.period
        digits = args.digits or cfg.digits
        algo = args.algorithm or cfg.algorithm
        code = totp(cfg.secret, period, digits, algo)
        return DecodeResult(
            kind=f"TOTP [{cfg.type.upper()}]",
            value=code,
            details=f"issuer={cfg.issuer or '-'}  account={cfg.account or '-'}  "
                    f"period={period}s  digits={digits}  algo={algo}  "
                    f"secret_b32={cfg.secret_b32}",
            warning="" if cfg.secret else "secret 缺失，无法计算",
        )
    else:
        counter = args.counter if args.counter is not None else (cfg.counter or 0)
        digits = args.digits or cfg.digits
        algo = args.algorithm or cfg.algorithm
        code = hotp(cfg.secret, counter, digits, algo)
        return DecodeResult(
            kind="HOTP [RFC 4226]",
            value=code,
            details=f"issuer={cfg.issuer or '-'}  account={cfg.account or '-'}  "
                    f"counter={counter}  digits={digits}  algo={algo}",
            warning="" if cfg.secret else "secret 缺失，无法计算",
        )

# ---------- 输出 ----------

BAR = "=" * 64

def render(res_list: List[DecodeResult]) -> None:
    if not res_list:
        print("(空输入)")
        return
    print(BAR)
    for r in res_list:
        flag = "  " if r.ok else "!"
        print(f"[{r.kind}] {flag} {r.value}")
        if r.details:
            print(f"   └ {r.details}")
        if r.warning:
            print(f"   ⚠ {r.warning}")
    print(BAR)

# ---------- CLI ----------

def add_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("inputs", nargs="*", help="待解码字符串（可多个），或文件路径")
    p.add_argument("--sha1", action="store_true", help="强制 SHA1")
    p.add_argument("--sha256", action="store_true", help="强制 SHA256")
    p.add_argument("--sha512", action="store_true", help="强制 SHA512")
    p.add_argument("--digits", type=int, choices=[6, 7, 8], default=None, help="强制位数（默认 6，显式指定时覆盖 URI）")
    p.add_argument("--period", type=int, default=None, help="TOTP 周期秒数（默认 30，显式指定时覆盖 URI）")
    p.add_argument("--counter", type=int, default=None, help="HOTP 计数器（默认取 URI 或 0）")
    p.add_argument("--file", action="store_true", help="把 inputs 视为文件路径")

def resolve_algorithm(args) -> Optional[str]:
    if args.sha256:
        return "SHA256"
    if args.sha512:
        return "SHA512"
    if args.sha1:
        return "SHA1"
    return None  # 未显式指定，交由各分支回退到 URI 或 SHA1

def load_inputs(args) -> List[str]:
    if args.file:
        out = []
        for p in args.inputs:
            with open(p, "r", encoding="utf-8") as f:
                out.extend(line for line in (ln.strip() for ln in f) if line)
        return out
    out = list(args.inputs)
    # 非 --file 时，如果单个参数是存在的文件，也按文件读
    if len(out) == 1:
        p = out[0]
        try:
            with open(p, "r", encoding="utf-8") as f:
                out = [ln for ln in (ln.strip() for ln in f) if ln]
        except OSError:
            pass
    return out

def main() -> int:
    p = argparse.ArgumentParser(description="2FA 一键解码工具（自动识别 TOTP/HOTP/URI/Base32/URL/HTML/Base64/明文）")
    add_args(p)
    args = p.parse_args()
    args.algorithm = resolve_algorithm(args)

    inputs = load_inputs(args)
    if not inputs:
        print("未提供输入。用法示例：\n"
              "  python decode.py JBSWY3DPPHPDXV6T\n"
              "  python decode.py otpauth://totp/Acme:alice?secret=JBSWY3DPPHPDXV6T\n"
              "  python decode.py secrets.txt --file")
        return 2

    for s in inputs:
        render(detect_and_decode(s, args))
    return 0

if __name__ == "__main__":
    # 模块别名：保持 detect_and_decode 在 -m 入口下也可用
    import __main__
    sys.exit(main())
