# 2FA 一键解码工具

自动识别并解码各类 2FA 相关内容，一行命令出结果。

## 支持的解码类型（自动识别）

| 类型 | 说明 | 示例输入 |
|------|------|----------|
| TOTP | RFC 6238 动态验证码 | `secret: JBSWY3DPPHPDXV6T` 或含 `otpauth://totp/` 的 URI |
| HOTP | RFC 4226 计数器验证码 | 同上 + 计数器 |
| otpauth URI | 2FA 应用二维码内容 | `otpauth://totp/Example:alice?secret=...&period=30` |
| Base32 | 密钥 Base32 解码 | `JBSWY3DPPHPDXV6T` → 原始字节 |
| URL 编码 | URLDecoder | `%3Cscript%3E` → `<script>` |
| HTML 实体 | HTML 实体解码 | `&lt;a&gt;` → `<a>` |
| URL 安全 Base64 | URL 安全 Base64 解码 | `ABCD-_` 形式 |
| 明文密码 | 直接输出（供人工比对） | `JBSWY3DPPHPDXV6T` |

自动识别规则：
1. 以 `otpauth://` 开头 → 解析为 TOTP/HOTP，计算当前有效验证码
2. 纯 Base32 且长度对齐 → 解码为 TOTP secret，输出当前 6/8 位验证码
3. URL 编码特征（含 `%XX`）→ URLDecode
4. HTML 实体特征（含 `&xxx;`）→ HTML 解码
5. URL 安全 Base64 特征 → Base64 解码
6. 都不匹配 → 作为明文密码展示

## 快速开始

```powershell
# 一键解码（自动识别类型）
python decode.py JBSWY3DPPHPDXV6T

# 指定 TOTP 算法与位数
python decode.py JBSWY3DPPHPDXV6T --sha256 --digits 8

# 从文件批量解码（每行一个）
python decode.py secrets.txt

# 交互式模式
python decode.py
```

## 文件说明

- `decode.py` — 主程序（Python 3，无第三方依赖）
- `secrets.txt` — 示例密钥文件（每行一个待解码项）

## 安全提醒

- 解码结果中包含明文验证码与明文密码，请勿将输出提交到代码仓库或粘贴到公共渠道。
- 建议仅在本地、已加密的终端使用。
