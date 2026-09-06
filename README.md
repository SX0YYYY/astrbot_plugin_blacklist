# astrbot_plugin_blacklist · 黑名单管家

AstrBot 插件：纯手动 QQ 黑名单管理。管理员拉黑谁，bot 就完全无视谁——没有 LLM 参与，稳定、零误伤、零额外开销。

![AstrBot](https://img.shields.io/badge/AstrBot-v4.x%20%3E%3D4.16-blue) ![Platform](https://img.shields.io/badge/平台-aiocqhttp%20(NapCat)-green) ![License](https://img.shields.io/badge/License-MIT-yellow)

## ✨ 功能特色

- **完全拦截**：被拉黑用户的消息在进入任何插件/LLM 处理之前被彻底拦截，bot 完全无视。
- **提示策略可选**：提示一次 / 每次提示 / 完全静默，文案自定义。
- **屏蔽范围可选**：私聊+群聊都屏蔽 / 仅私聊 / 仅群聊。
- **纯手动管理**：无 LLM 参与，没有误举报、没有提示词开销、没有模型行为的不确定性。
- **配置体检**：`/black status` 逐项检查配置与平台，"装完没反应"一眼定位。

## 📸 效果展示

> TODO：此处放截图

## 📦 环境要求

| 项 | 要求 |
|---|---|
| AstrBot | v4，`>=4.16,<5` |
| 消息平台 | **aiocqhttp（NapCat / OneBot v11）** |
| LLM | 无要求（本插件不使用 LLM） |

## 🚀 安装

- **插件市场（推荐）**：AstrBot WebUI → 插件市场 → 搜索「黑名单管家」→ 安装。
- **手动**：把本仓库下载后，将整个 `astrbot_plugin_blacklist` 目录放入 AstrBot 的 `data/plugins/` 下，WebUI → 插件管理 → 重载。

> 本插件无第三方依赖，仅使用 AstrBot 自身 API 与 Python 标准库。

## ⚡ 快速上手

1. 管理员对 bot 发 `/black status` —— 确认「配置体检」全部 ✅。
2. `/black add <QQ号或@某人> 原因` 拉黑 → 对方消息从此被完全无视。
3. `/black remove <QQ号>` 随时解除。

## 📖 命令（仅 AstrBot 全局管理员可用，别名 `/拉黑`）

| 命令 | 说明 |
|---|---|
| `/black help` | 查看帮助（别名 帮助） |
| `/black add <QQ号\|@用户> [原因]` | 拉黑（群聊可直接 @ 对方） |
| `/black remove <QQ号\|@用户>` | 解除拉黑（别名 del / delete / 解除 / 解禁） |
| `/black list` | 查看黑名单 |
| `/black check <QQ号\|@用户>` | 查询某人是否在黑名单 |
| `/black status` | 运行状态 + 配置体检 |

## ⚙️ 配置（WebUI 插件配置页）

| 配置项 | 默认 | 说明 |
|---|---|---|
| block_scope | all | 拉黑屏蔽范围：all / private_only / group_only |
| notice_mode | once | 被拉黑者提示：once / always / never |
| notice_text | （见面板） | 拉黑提示文案 |
| protect_admins | true | 管理员名单内的 QQ 无法被拉黑 |
| admin_ids | 空 | 管理员名单；空则用 AstrBot 全局管理员(admins_id)。非空时「管理员保护」的覆盖对象随之变为该名单 |

## ❓ FAQ

**Q：装完测试了，什么反应都没有？**
先发 `/black status` 看配置体检；插件加载日志也会输出体检警告（可在 AstrBot 日志中搜索 `astrbot_plugin_blacklist`）。注意本插件是**手动拉黑**工具——只有你 `/black add` 过的人会被拦截，没有自动识别功能。

**Q：和我的其他插件冲突吗？**
本插件只占用 `/black` 命令组，不向 LLM 注入任何内容、不注册任何工具，对其他插件零影响。

**Q：被拉黑的人换个 QQ 号回来怎么办？**
黑名单按 QQ 号生效，换号无法自动识别（这是拉黑类插件的普遍局限）。

**Q：从旧版「黑名单守卫」升级？**
黑名单数据（`blacklist.json`）完全兼容，升级后原样保留；旧版的举报记录（`reports.json`）不再使用，可手动删除。

## ⚠️ 注意

- `/black` 命令组仅 AstrBot **全局管理员**（admins_id）可用；`admin_ids` 配置项在非空时是「管理员保护」的保护对象名单。
- 命令输出包含完整 QQ 与拉黑原因，建议在私聊中操作，避免在群里泄露。
- 卸载插件会连带删除 AstrBot 中的插件配置与 `plugin_data/astrbot_plugin_blacklist/` 数据（黑名单），卸载前请自行备份。

## 📄 License

[MIT](LICENSE) © 2025 SX0YYYY

 Issues 反馈：[GitHub Issues](https://github.com/SX0YYYY/astrbot_plugin_blacklist/issues)
