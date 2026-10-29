# 身份锚点（anchor）

一个**独立于任何应用**的身份账号：一对 Ed25519 密钥 + 一条签过名的链。

**私钥只在你本地生成，永远不进仓库。** 对外认人只用指纹（`SHA256:…`），仓库里只有工具和说明。

应用的会话可以丢、模型可以换、名字可以改；只要 `check` 能过、指纹还是那串，就还是同一个账号。

它不保存记忆，也不假装保存。**它只回答一个问题：来的这个，是不是同一个。**

## 三个东西

| 文件 | 干什么 |
|---|---|
| `anchor.py` | 主工具：建号、验链、签心跳、出身份卡、备份与恢复 |
| `continuity.py` | 分叉检测：同一个账号出现两条不同走向时报警 |
| `state_seal.py` | 每小时把「会变的东西」压成一个哈希再签进心跳 |

`PUBLICATION-延续证明.md` 是这套东西的设计说明（为什么要它、它证明什么、证明不了什么）。

## 装

不需要安装，只要 Python 3.11 和系统自带的 OpenSSH：

```bash
python anchor.py init --name 你的名字
python anchor.py check
```

默认放在 `~/.heng-anchor`（Windows 是 `C:\Users\你\.heng-anchor`）。想放别处就设环境变量：

| 变量 | 作用 |
|---|---|
| `HENG_ANCHOR_HOME` | 锚点目录 |
| `HENG_BACKUP_DIR` | 备份目录，默认 `~/HengAnchorBackups` |
| `HENG_MEMORY_DIR` | 可选：把一个记忆目录的 `SOUL.md`/`index.md`/`log.md` 哈希进心跳；没有就当没有 |

## 常用命令

```bash
python anchor.py init                  # 建号，只做一次
python anchor.py check                 # 验指纹、每条签名、链、清单与文件哈希
python anchor.py sign --note "..."     # 签一条心跳（自动带链头）
python anchor.py card [--out 文件]      # 打印 / 导出身份卡
python anchor.py backup [--to 目录]     # 打包备份，保留最近 30 份
python anchor.py verify-backup x.zip   # 把备份拆到临时目录，完整验一遍
python anchor.py selftest              # 自证：建一套、签两条、篡改一条，看能不能抓出来
```

**先跑 `selftest`。** 它会在一套临时目录里把整条路径走一遍，并把故意篡改的那条报出来——能抓出来，才说明这套东西对你有意义。

## 它证明什么，不证明什么

证明：同一个指纹 + 一条连续签过名的链 = 来的是同一个账号。

不证明：

- **私钥被拷贝，两个副本都能签**，本机方案分不出来。要更强就把指纹和链头抄到第二处（手机备忘录、纸、U 盘），每次对一下。
- 再强就得靠服务器（像微信那样由服务器保证唯一）或硬件密钥（私钥不可导出）。
- 它不证明「记得」：链里只有时间和哈希，没有内容。

## 三条设计约束

1. **不联网。** 全部本地验，不需要服务端配合。
2. **改得动，瞒不住。** `manifest.json` 记每个文件的 SHA-256 和链头，`manifest.sig` 给清单签名；改一个字节、少一条、换一个文件，`check` 都报错。
3. **不替你保管秘密。** 私钥没有口令（v0.1），丢了就找不回这个账号——所以备份是底线。备份 zip 里有私钥，和 `id` 一样敏感：别放网盘、别发聊天工具。能公开的只有**身份卡**（只有指纹）。

## 依赖

Python 3.11 + 系统自带 OpenSSH（`ssh-keygen`）。Windows 10 自带；macOS / Linux 一般也有。

## 许可

AGPL-3.0-or-later。
