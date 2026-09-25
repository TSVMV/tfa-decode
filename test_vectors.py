"""针对 RFC 6238 / RFC 4226 的已知测试向量验证（TOTP 时间戳固定）。

可作 pytest 用例收集，亦可 ``python test_vectors.py`` 独立运行。
"""
from __future__ import annotations

import struct
import sys

from decode import hotp, parse_otpauth, totp

_SECRET = b"12345678901234567890"


def test_hotp_known_vectors():
    assert hotp(_SECRET, 0, 6, "SHA1") == "755224"
    assert hotp(_SECRET, 1, 6, "SHA1") == "287082"


def test_rfc6238_totp_sha1():
    assert hotp(_SECRET, 59 // 30, 6, "SHA1") == "287082"
    assert totp(_SECRET, 30, 6, "SHA1", ts=11111111095) == "442993"


def test_sha256_sha512_cross_validation():
    def _ref(secret, period, digits, algo, ts):
        import hashlib
        import hmac
        digest = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}[algo]
        data = struct.pack(">Q", ts // period)
        h = hmac.new(secret, data, digest).digest()
        off = h[-1] & 0x0F
        return str((struct.unpack(">I", h[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)).zfill(digits)

    ts = 11111111095
    assert totp(_SECRET, 30, 6, "SHA256", ts=ts) == _ref(_SECRET, 30, 6, "SHA256", ts)
    assert totp(_SECRET, 30, 6, "SHA512", ts=ts) == _ref(_SECRET, 30, 6, "SHA512", ts)


def test_parse_otpauth_uri():
    cfg = parse_otpauth(
        "otpauth://totp/Acme:alice@example.com?secret=JBSWY3DPPHPDXV6T"
        "&issuer=Acme&digits=8&algorithm=SHA1&period=30"
    )
    assert cfg.issuer == "Acme"
    assert cfg.account == "Acme alice@example.com"
    assert cfg.digits == 8
    assert cfg.type == "totp"


def main() -> int:
    failures = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            print(f"[OK] {name}")
        except AssertionError as e:
            failures += 1
            print(f"[FAIL] {name}: {e}")
    print(f"\n失败 {failures} 项。")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
