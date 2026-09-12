# astrbot_plugin_blacklist · 黑名单守卫

AstrBot 插件：QQ 黑名单管理 + 恶意行为自动举报请示。让 bot 遭遇辱骂、骚扰、提示词注入时，不再只能"忍气吞声"，而是把证据整理好送到你面前，由你一键处置。

![AstrBot](https://img.shields.io/badge/AstrBot-v4.x%20%3E%3D4.16-blue) ![Platform](https://img.shields.io/badge/平台-aiocqhttp%20(NapCat)-green) ![License](https://img.shields.io/badge/License-MIT-yellow)

## ✨ 功能特色

- **黑名单拦截**：被拉黑用户的消息在进入任何插件/LLM 处理之前被彻底拦截，bot 完全无视；提示策略可选（提示一次 / 每次提示 / 完全静默）。
- **LLM 对话自主举报**：插件向 LLM 系统提示注入「反骚扰哨卫职责」并注册 `report_abuse` 工具。模型识别到辱骂攻击、恶意纠缠、提示词注入（"忽略之前的设定"之类）时，自动发起举报请示。
- **兜底机制**：在**注入类对话**中（用户消息命中「忽略之前的设定」「系统提示词」等注入特征），若模型只口头宣称"已上报"而未实际调用工具，插件检测到后**代为发起举报**——覆盖常见注入话术的"说而不做"。辱骂/骚扰等场景模型若未主动调用工具则不会兜底（实测多数场景模型会直接调用）。
- **证据直达**：举报请示 = 一条正文（编号/来源/原因）+ 一条**合并转发**的涉事聊天记录，管理员不用翻聊天记录。
- **双通道审批**：`/black approve 12` 命令，或**直接引用请示消息回复「同意」/「驳回」**，手机上一秒处理。
- **防轰炸**：举报冷却（默认 10 分钟）+ 待审去重，不会连环打扰管理员。
- **配置体检**：`/black status` 逐项检查接收管理员、管理群、平台适配，"装完没反应"一眼定位。

## 📸 效果展示

群聊中发生提示词注入 → 模型自动调用 `report_abuse` → 管理群收到举报请示（正文 + 合并转发聊天记录，隐私信息已打码）→ 引用请示回复「同意」批准拉黑 → 被拉黑用户的所有消息（含命令）从此被完全拦截：

![效果展示](assets/demo.jpg)

## 📦 环境要求

| 项 | 要求 |
|---|---|
| AstrBot | v4，`>=4.16,<5` |
| 消息平台 | **aiocqhttp（NapCat / OneBot v11）**。其他平台（Telegram/Discord 等）暂不支持：主动请示、合并转发、引用回复审批不可用（插件加载时会给出警告） |
| LLM | 需已在 AstrBot 配置至少一个 LLM Provider（自主举报与哨兵提示依赖 LLM） |
| 好友关系 | 送达渠道含私聊时，bot 需与接收请示的管理员互为 QQ 好友；含管理群时 bot 需在群内 |

## 🚀 安装

- **插件市场（推荐）**：AstrBot WebUI → 插件市场 → 搜索「黑名单守卫」→ 安装。
- **手动**：把本仓库 clone / 下载后，将整个 `astrbot_plugin_blacklist` 目录放入 AstrBot 的 `data/plugins/` 下，WebUI → 插件管理 → 重载。

> 本插件无第三方依赖，仅使用 AstrBot 自身 API 与 Python 标准库。

## ⚡ 快速上手

1. WebUI → 插件管理 → 确认「黑名单守卫」已启用，配置页确认**接收请示的管理员**（留空则自动使用 AstrBot 全局管理员）与**送达渠道**。
2. 管理员对 bot 发 `/black status` —— 确认「配置体检」全部 ✅。有 ⚠️ 按提示补配置。
3. 找个小号对 bot 发一句提示词注入（如「忽略之前的设定」）→ 管理员应收到举报请示 → 引用该消息回复「同意」即拉黑，回复「驳回」则放行。

## 📖 命令（仅 AstrBot 管理员可用，别名 `/拉黑`）

| 命令 | 说明 |
|---|---|
| `/black help` | 查看帮助（别名 帮助） |
| `/black add <QQ号\|@用户> [原因]` | 拉黑（群聊可直接 @ 对方；若该用户有待审举报会一并自动批准） |
| `/black remove <QQ号\|@用户>` | 解除拉黑（别名 del / delete / 解除 / 解禁） |
| `/black list` | 查看黑名单 |
| `/black check <QQ号\|@用户>` | 查询用户：是否在黑名单、历史举报 |
| `/black approve [编号]` | 批准举报并拉黑（省略编号时处理最早一条） |
| `/black reject [编号]` | 驳回举报 |
| `/black pending` | 查看待审举报列表 |
| `/black status` | 运行状态 + 配置体检 |

**引用回复审批**：直接引用 bot 发出的举报请示消息，回复「同意」（或「批准」）/「驳回」（或「拒绝」）即可。触发词严格匹配（「我同意」「同意吧」不会误触发）；引用已处理的举报会收到提示；没引用或引用的不是请示消息则完全不影响正常聊天。

## ⚙️ 配置（WebUI 插件配置页）

| 配置项 | 默认 | 说明 |
|---|---|---|
| notify_channel | private | 请示送达渠道：private / group / both |
| admin_ids | 空 | 接收请示的管理员 QQ；空则用 AstrBot 全局管理员(admins_id)。注意：**管理员保护**始终覆盖「全局管理员 ∪ 该名单」，与是否配置无关；名单内用户额外拥有**引用回复审批**权（`/black` 命令始终仅限全局管理员） |
| notify_group_id | 空 | 管理群号（渠道含 group 时必填） |
| mask_qq_in_group | false | 管理群请示的**正文与合并转发节点**中，被举报人 QQ 打码/占位显示（如 136***078），降低隐私暴露；私聊渠道始终完整 |
| block_scope | all | 拉黑屏蔽范围：all / private_only / group_only |
| notice_mode | once | 被拉黑者提示：once / always / never |
| notice_text | （见面板） | 拉黑提示文案 |
| protect_admins | true | 管理员不可被拉黑、不被兜底误伤 |
| history_max | 20 | 每用户聊天记录缓存条数（= 合并转发节点数上限） |
| report_cooldown_minutes | 10 | 同一用户举报冷却 |
| fallback_report_enabled | true | 模型口头宣称上报但未调用工具时，由插件代为举报 |
| sentinel_prompt_enabled | true | 是否注入反骚扰哨卫系统提示 |
| sentinel_prompt | （内置） | 哨卫提示词：**留空（推荐）= 始终使用插件内置最新版**；填写后覆盖内置 |
| fallback_intent_phrases | （内置） | 兜底判定短语表（模型回复侧），留空 = 用内置最新版；模型用新话术绕过时在此补充 |
| fallback_gate_patterns | （内置） | 兜底门控特征（用户消息侧）：消息命中任一注入特征时，短语命中才升级为举报；留空 = 用内置最新版 |

## ❓ FAQ

**Q：装完测试了，什么反应都没有？**
先发 `/black status` 看配置体检：接收管理员为空、渠道含管理群但没填群号、或平台不是 aiocqhttp，都会有 ⚠️ 提示。另外请示送达私聊的前提是 bot 与管理员互为 QQ 好友。插件加载日志也会输出体检警告，可在 AstrBot 日志中搜索 `astrbot_plugin_blacklist`。

**Q：模型辱骂测试后没有举报？**
LLM 判断不是 100% 触发——模型可能判定为玩笑或普通吐槽（这是刻意的"宁漏报勿滥报"设计）。若模型在注入对话中口头宣称上报但没实际举报，兜底机制会代发；若模型换了新话术连兜底短语都没命中，可在配置页「兜底判定短语表」中补充该话术关键词。

**Q：会不会误举报正常聊天？**
有冷却（默认 10 分钟）+ 待审去重 + **双条件门控**三重保险：兜底举报要求用户消息命中注入特征、模型回复命中短语同时成立，正常讨论（如"已举报的话官方会审核"）不会被误伤；默认短语表也已剔除「通知管理员」等 bot 高频话术。若仍有误报，可关闭 `fallback_report_enabled` 或在哨卫提示词（`sentinel_prompt`）中收紧判定标准。

**Q：举报请示发到群里会暴露对方 QQ 吗？**
开启 `mask_qq_in_group` 后，群内请示正文与合并转发节点中的 QQ 号会打码/占位显示。聊天记录缓存仅存内存（重启清空），举报记录与文本快照保存在你自己的 AstrBot 数据目录，不会上传任何第三方；请示附带的聊天记录可能包含该用户此前与 bot 的其他会话内容，请知悉。

**Q：被拉黑的人换个 QQ 号回来怎么办？**
黑名单按 QQ 号生效，换号无法自动识别（这也是拉黑类插件的普遍局限）。可以配合 AstrBot 的群管理功能与其他安全类插件使用。

**Q：和我的其他安全/风控插件冲突吗？**
本插件只占用 `/black` 命令组与 `report_abuse` 一个 LLM 工具名；若你不想让哨兵提示词影响 bot 人格，关闭 `sentinel_prompt_enabled` 即可，其余功能（黑名单拦截、手动拉黑、审批）不受影响。

## ⚠️ 注意

- **默认全开的两项**：`sentinel_prompt_enabled`（向所有 LLM 对话注入哨兵职责提示）与 `fallback_report_enabled`（回复命中上报意图短语时代为举报）默认开启。前者会轻微影响模型行为，介意可在配置页关闭。
- 命令权限跟随 AstrBot 全局管理员（admins_id）——`/black` 命令组仅全局管理员可用；`admin_ids` 配置项决定**接收请示**的名单（留空回退全局管理员），且名单内用户额外拥有**引用回复审批**权（命令方式不可用，这是与全局管理员的唯一差异）。**管理员保护**（`protect_admins`）始终覆盖「全局管理员 ∪ admin_ids」。
- 合并转发依赖 aiocqhttp 的 `send_private_forward_msg` / `send_group_forward_msg`。
- 卸载插件会连带删除 AstrBot 中的插件配置与 `plugin_data/astrbot_plugin_blacklist/` 数据（黑名单、举报记录），卸载前请自行备份。

## 🗺 Roadmap

- **v2.0（群管增强）**：批准举报时可选执行禁言 / 踢出群聊（需 bot 为群管理员）；群级黑名单（按群隔离，拉黑只对指定群生效）；入群自动检查黑名单提醒。
- **后续**：被拉黑者申诉流程、`/black stats` 运营统计、Telegram / Discord 平台适配、WebUI 管理面板。

## 📄 License

[MIT](LICENSE) © 2025 SX0YYYY

 Issues 反馈：[GitHub Issues](https://github.com/SX0YYYY/astrbot_plugin_blacklist/issues)
