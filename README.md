# FastPassword

一个 **可推导、不存储** 的密码生成器，Windows 桌面版（.NET 10 + WinUI 3）。

你只需要记住一个主密码；每个站点用「区分代号 + 账号」推导出各自的密码。
程序不联网、不上传、不保存任何站点密码——它根本不知道你的密码是什么，只是每次现算。

> 思路源自 [kenmick/FlowerPassword](https://github.com/kenmick/FlowerPassword)（花密），
> 但**算法完全不同、不兼容**：本项目用 Argon2id 重做了派生，并以此为基础增加了加密清单、
> 备份密钥恢复等能力。用花密算出来的密码在这里算不出来，反之亦然。

---

## 它解决什么问题

「每个站点一个独立密码」最难的不是生成，是**记住**。密码管理器把密码存进一个库，
库本身就成了新的单点故障和攻击目标。这个程序走另一条路：

```
站点密码 = KDF(主密码, 站点代号, 账号, 长度, 字符集)
```

- 不存密码 → 库文件泄露也拿不到任何站点密码
- 不联网 → 没有云端泄露面
- 可重算 → 换电脑、重装系统，只要有主密码就能算出全部密码

代价是：**主密码忘了就是全部作废**，没有任何找回手段（备份密钥除外，见下）。

## 算法

| 环节 | 做法 |
|---|---|
| 派生 | **Argon2id**，64 MiB / t=3 / p=1，输出 32 字节（单次约 200 ms，故意慢） |
| salt | `SHA256("FastPassword/v2" ‖ 站点 ‖ 账号 ‖ 长度 ‖ 字符集 ‖ 严格标志)`，参数即身份 |
| 编码 | 32 字节 → Base-N 映射到 62 或 70 字符集 |
| 严格模式 | 保证至少 1 个大写、1 个小写、1 个数字（70 档还要求 1 个符号），最多重试 17 次 |

参数全部硬编码为常量，**改动任意一个都会换掉所有已生成的密码**，因此它们不是配置项。

保险库（可选的账号清单）另走一套独立常量：

| 环节 | 做法 |
|---|---|
| 解锁密钥 | Argon2id 同上 → 32 字节根密钥 |
| 用途隔离 | HKDF-SHA256 用不同 info 派生出「校验钥匙」与「清单钥匙」 |
| 加密 | AES-256-GCM，AAD 绑定记录 id（把 A 行的密文挪到 B 行会直接解不开） |
| 备份密钥 | 160 bit 随机 → HKDF → 用 KEK 包裹「主密码」本身 |

## 功能

- 选中记录后 **Ctrl+C 复制密码 / Ctrl+B 复制账号**（仅窗口内生效，不占用全局快捷键）
- 复制密码后倒计时自动清除剪贴板，且**不进入 Win+V 历史**
- 全局热键 **Ctrl+Alt+P** 呼出 / 收起窗口，常驻托盘
- 防截屏（`WDA_EXCLUDEFROMCAPTURE`）、失焦自动隐藏、隐藏后自动锁定
- 忘记主密码时可用**备份密钥**解锁并取回主密码
- 首次使用弹出「使用须知」，把「密码不可找回」这类致命提醒放在最前面

## 构建

需要 **.NET 10 SDK**（WinUI 3 项目还需要 Windows App SDK，NuGet 会自动还原）。

```bat
dotnet build src\FastPassword.App -c Release -p:Platform=x64
```

一键出两个分发包（会自动排除 `data\`，见下）：

```bat
打包.bat
```

| 产物 | 说明 |
|---|---|
| `dist\FastPassword-v1.1.0-win-x64.zip` | 自包含，约 64 MB，目标机什么都不用装 |
| `dist\FastPassword-v1.1.0-win-x64-lite.zip` | 精简，约 11 MB，需先装 .NET 10 Desktop Runtime + Windows App Runtime 2.5.x |

运行测试：

```bat
dotnet test FastPassword.slnx -c Release
```

141 项单元测试覆盖派生向量、NFC 归一化、边界输入、严格模式确定性、保险库加解密、
并发写入、损坏行跳过、schema 版本降级拒绝等。

## 数据在哪

全部在程序目录下的 `data\`：

```
data\
  fastpassword.db       保险库（AES-GCM 加密；没有主密码打不开）
  fastpassword.db-wal   SQLite WAL，可能含已提交但未合并的数据
  settings.json         开关配置（不含秘密）
  selfcheck.json        环境指纹，用于发现算法漂移
  logs\app.log          运行日志
```

⚠️ **备份必须整个 `data\` 目录一起拷**。WAL 模式下只拷 `.db` 会丢掉最近的改动。
`打包.bat` 会把 `data\` 排除在分发包之外，也不会删除它。

## 安全边界（请先读这段）

**它防的**：库文件被单独拷走、云端同步泄露、忘记密码导致的连锁重置、
剪贴板被历史记录回溯、截图/录屏意外拍到密码。

**它防不了**：主密码本身太弱（8 位随手密码在显卡面前撑不过一周）、
机器已被恶意程序控制（内存里的明文、键盘记录都拦不住）、
物理接触 + 冷启动攻击。

所以：**主密码请用长口令或随机短语**，程序启动时的强度条就是给这件事用的。

## 目录结构

```
src/FastPassword.Core/     派生算法、加密、编码（无 UI 依赖，可单测）
src/FastPassword.Storage/  SQLite 保险库（无 WinUI 依赖，可单测）
src/FastPassword.App/      WinUI 3 界面
tests/                     单元测试
docs/                      算法规范、使用说明、截图
```

Core 与 Storage 刻意不依赖 WinUI——历史上最危险的两个 bug（连接泄漏、
按 (site, account) 合并覆盖记录）都发生在存储层，放在 App 里就只能靠手工点界面验证。

## 许可

[MIT](LICENSE)。算法思路致谢 [kenmick/FlowerPassword](https://github.com/kenmick/FlowerPassword)。
