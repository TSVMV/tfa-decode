"""针对 RFC 6238 / RFC 4226 的已知测试向量验证（TOTP 时间戳固定）。"""
import sys
import struct
from decode import hotp, totp, parse_otpauth, base32_decode

def main() -> int:
    failures = 0

    # RFC 6238 测试向量：secret = ASCII "12345678901234567890"（20 字节），T=59s 期望 TOTP(SHA1,6)=287082
    secret = b"12345678901234567890"
    rfc = hotp(secret, 59 // 30, 6, "SHA1")
    print(f"[RFC 6238 T=59s 期望 287082]  {rfc}")
    if rfc != "287082":
        failures += 1

    # HOTP 独立验证（hmac.new + SHA1）向量：counter=0→755224，counter=1→287082
    h0 = hotp(secret, 0, 6, "SHA1")
    print(f"[HOTP counter=0 期望 755224] {h0}")
    if h0 != "755224":
        failures += 1

    h1 = hotp(secret, 1, 6, "SHA1")
    print(f"[HOTP counter=1 期望 287082] {h1}")
    if h1 != "287082":
        failures += 1

    # TOTP 时间戳向量：T=11111111095 期望 442993（SHA1,6）
    t6 = totp(secret, 30, 6, "SHA1", ts=11111111095)
    print(f"[RFC 6238 T=11111111095 期望 442993] {t6}")
    if t6 != "442993":
        failures += 1

    # SHA256 / SHA512 交叉验证（与独立实现比对）
    def _ref_totp(secret, period, digits, algo, ts):
        import hmac, hashlib
        digest = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}[algo]
        data = struct.pack(">Q", ts // period)
        h = hmac.new(secret, data, digest).digest()
        off = h[-1] & 0x0F
        return str((struct.unpack(">I", h[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)).zfill(digits)

    ts2 = 11111111095
    t256 = totp(secret, 30, 6, "SHA256", ts=ts2)
    t512 = totp(secret, 30, 6, "SHA512", ts=ts2)
    print(f"[SHA256 交叉]  {t256}   [SHA512 交叉]  {t512}")
    exp256 = _ref_totp(secret, 30, 6, "SHA256", ts2)
    exp512 = _ref_totp(secret, 30, 6, "SHA512", ts2)
    print(f"[SHA256 独立]  {exp256}   [SHA512 独立]  {exp512}")
    if t256 != exp256 or t512 != exp512:
        failures += 1

    # otpauth URI 解析
    cfg = parse_otpauth("otpauth://totp/Acme:alice@example.com?secret=JBSWY3DPPHPDXV6T&issuer=Acme&digits=8&algorithm=SHA1&period=30")
    assert cfg.issuer == "Acme", cfg.issuer
    assert cfg.account == "Acme alice@example.com", cfg.account
    assert cfg.digits == 8, cfg.digits
    assert cfg.type == "totp"
    print("[otpauth URI 解析]  OK")

    # otpauth URI 解析
    cfg = parse_otpauth("otpauth://totp/Acme:alice@example.com?secret=JBSWY3DPPHPDXV6T&issuer=Acme&digits=8&algorithm=SHA1&period=30")
    assert cfg.issuer == "Acme", cfg.issuer
    assert cfg.account == "Acme alice@example.com", cfg.account
    assert cfg.digits == 8, cfg.digits
    assert cfg.type == "totp"
    print("[otpauth URI 解析]  OK")

    print(f"\n失败 {failures} 项。")
    return 1 if failures else 0

if __name__ == "__main__":
    sys.exit(main())
