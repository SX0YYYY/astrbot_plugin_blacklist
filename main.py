"""astrbot_plugin_blacklist：黑名单管家——QQ 黑名单手动管理。

功能：
1. 管理员命令组 /black：拉黑、解除、列表、查询、状态、帮助。
2. 全量消息实时监听：被拉黑用户的消息在最高优先级被拦截，
   bot 完全无视；提示策略可配置（提示一次/每次/静默）。

纯手动管理，无 LLM 参与——稳定、零误伤、零额外开销。
"""

from __future__ import annotations

import re
from sys import maxsize

import astrbot.api.message_components as Comp
from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, StarTools
from astrbot.core.star.filter.command import GreedyStr

from .core.storage import Storage

PLUGIN_NAME = "astrbot_plugin_blacklist"


def clean_at_reason(text: str, at_qq: str) -> str:
    """从原因文本中剔除 At 组件被框架文本化产生的「@昵称(QQ号)」片段。

    用真实 QQ 构造精确模式（昵称本身可能含括号与数字，通配 \\d+ 会提前
    截断），全局剔除后压缩连续空格——「@」在文本开头或中后段均能清干净。
    """
    cleaned = re.sub(rf"@.+?\({re.escape(str(at_qq))}\)", "", text or "")
    return re.sub(r"\s{2,}", " ", cleaned).strip()


class BlacklistGuard(Star):
    def __init__(self, context: Context, config: AstrBotConfig) -> None:
        super().__init__(context)
        self.config = config
        self.storage = Storage(StarTools.get_data_dir(PLUGIN_NAME))
        logger.info(
            f"[{PLUGIN_NAME}] 已加载：黑名单 {len(self.storage.get_blacklist())} 人。"
        )
        for name, ok, note in self._config_checkup():
            if not ok:
                logger.warning(f"[{PLUGIN_NAME}] 配置体检未通过：{name} — {note}")

    async def terminate(self) -> None:
        logger.info(f"[{PLUGIN_NAME}] 已卸载。")

    # ==================== 配置与管理员工具方法 ====================

    def _conf_str(self, key: str, default: str, allowed: set[str] | None = None) -> str:
        raw = self.config.get(key, default)
        value = str(raw if raw not in (None, "") else default).strip().lower()
        if allowed is not None and value not in allowed:
            return default
        return value

    def _conf_bool(self, key: str, default: bool) -> bool:
        value = self.config.get(key, default)
        return default if value is None else bool(value)

    def _admin_ids(self) -> list[str]:
        """管理员 QQ 名单：配置项优先，回退 AstrBot 全局管理员（admins_id），仅保留纯数字。"""
        ids = [str(x).strip() for x in (self.config.get("admin_ids") or []) if str(x).strip()]
        if not ids:
            try:
                ids = [
                    str(x).strip()
                    for x in self.context.get_config().get("admins_id", [])
                ]
            except Exception as e:  # noqa: BLE001
                logger.warning(f"[{PLUGIN_NAME}] 读取全局管理员列表失败: {e}")
                ids = []
        return [i for i in ids if i.isdigit()]

    def _is_admin(self, event: AstrMessageEvent) -> bool:
        try:
            if event.is_admin():
                return True
        except Exception:  # noqa: BLE001
            pass
        return str(event.get_sender_id() or "") in self._admin_ids()

    def _blocked_here(self, is_group: bool) -> bool:
        scope = self._conf_str("block_scope", "all", {"all", "private_only", "group_only"})
        if scope == "private_only":
            return not is_group
        if scope == "group_only":
            return is_group
        return True

    @staticmethod
    def _extract_at_qq(event: AstrMessageEvent) -> str | None:
        """从消息链中提取第一个 @ 的目标 QQ。"""
        try:
            for comp in event.get_messages():
                if isinstance(comp, Comp.At):
                    qq = str(getattr(comp, "qq", "") or "")
                    if qq and qq != "all":
                        return qq
        except Exception:  # noqa: BLE001
            pass
        return None

    def _config_checkup(self) -> list[tuple[str, bool, str]]:
        """配置体检：返回 (检查项, 是否正常, 说明) 列表，加载日志与 /black status 共用。"""
        items: list[tuple[str, bool, str]] = []

        admins = self._admin_ids()
        items.append(
            (
                "管理员名单",
                bool(admins),
                "、".join(admins)
                if admins
                else "未配置 admin_ids 且全局管理员(admins_id)为空，命令权限仍以 AstrBot 全局管理员为准，管理员保护将无生效对象",
            )
        )

        try:
            has_aiocqhttp = any(
                inst.meta().name == "aiocqhttp"
                for inst in self.context.platform_manager.platform_insts
            )
        except Exception:  # noqa: BLE001
            has_aiocqhttp = True  # 检测失败时不误报
        items.append(
            (
                "平台适配",
                has_aiocqhttp,
                "aiocqhttp(NapCat) 已接入"
                if has_aiocqhttp
                else "未检测到 aiocqhttp 平台实例：本插件为 aiocqhttp(NapCat) 设计，当前平台可能不可用",
            )
        )
        return items

    # ==================== 消息监听：拦截 ====================

    @filter.event_message_type(filter.EventMessageType.ALL, priority=maxsize)
    async def on_any_message(self, event: AstrMessageEvent) -> None:
        """全量消息监听：被拉黑用户的消息在最高优先级被拦截。"""
        try:
            sender = str(event.get_sender_id() or "").strip()
            if not sender or sender == str(event.get_self_id() or ""):
                return

            is_group = bool(str(event.get_group_id() or "").strip())
            if self.storage.is_blacklisted(sender) and self._blocked_here(is_group):
                await self._notify_blocked(event, sender)
                event.stop_event()
                return
        except Exception as e:  # noqa: BLE001 - 监听器绝不能向外抛异常
            logger.error(f"[{PLUGIN_NAME}] 消息监听处理异常: {e}")

    async def _notify_blocked(self, event: AstrMessageEvent, sender: str) -> None:
        """按提示策略告知被拉黑用户，然后消息被拦截。"""
        mode = self._conf_str("notice_mode", "once", {"once", "always", "never"})
        if mode == "never":
            return
        if mode == "once" and self.storage.has_noticed(sender):
            return
        text = str(
            self.config.get("notice_text") or "你已被管理员拉黑，消息不会被接收。"
        )
        try:
            # 先落盘再发送（宁少勿多）：并发消息同过检查窗口的竞态下，
            # 至多提示一次，不会因为 send 耗时导致连环提示
            self.storage.mark_noticed(sender)
            await event.send(event.plain_result(text))
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[{PLUGIN_NAME}] 发送拉黑提示失败: {e}")

    # ==================== 管理员命令组 ====================

    @filter.command_group("black", alias={"拉黑"})
    def black_group(self):
        """黑名单管家：拉黑管理、状态查询。"""
        pass

    @filter.permission_type(filter.PermissionType.ADMIN)
    @black_group.command("status", alias={"状态"})
    async def black_status(self, event: AstrMessageEvent):
        """查看黑名单管家运行状态。"""
        blacklist = self.storage.get_blacklist()
        scope_label = {
            "all": "私聊+群聊",
            "private_only": "仅私聊",
            "group_only": "仅群聊",
        }[self._conf_str("block_scope", "all", {"all", "private_only", "group_only"})]
        mode_label = {
            "once": "提示一次",
            "always": "每次提示",
            "never": "完全静默",
        }[self._conf_str("notice_mode", "once", {"once", "always", "never"})]
        yield event.plain_result(
            f"🛡 黑名单管家状态\n"
            f"黑名单人数：{len(blacklist)}\n"
            f"屏蔽范围：{scope_label}\n"
            f"被拉黑者提示：{mode_label}\n"
            f"管理员保护：{'开' if self._conf_bool('protect_admins', True) else '关'}\n"
            f"━━━ 配置体检 ━━━\n"
            + "\n".join(
                f"{'✅' if ok else '⚠️'} {name}：{note}" for name, ok, note in self._config_checkup()
            )
        )

    @filter.permission_type(filter.PermissionType.ADMIN)
    @black_group.command("help", alias={"帮助"})
    async def black_help(self, event: AstrMessageEvent):
        """查看黑名单管家的命令与用法帮助。"""
        yield event.plain_result(
            "🛡 黑名单管家 · 帮助\n"
            "拉黑：/black add <QQ号|@用户> [原因]\n"
            "解除：/black remove <QQ号|@用户>\n"
            "列表：/black list\n"
            "查询：/black check <QQ号|@用户>\n"
            "状态：/black status（含配置体检）\n"
            "纯手动管理，无 LLM 参与；拉黑后对方消息将被完全拦截。"
        )

    @filter.permission_type(filter.PermissionType.ADMIN)
    @black_group.command("add", alias={"添加", "ban"})
    async def black_add(self, event: AstrMessageEvent, qq: str = "", *, reason: GreedyStr):
        """拉黑用户：/black add <QQ号|@用户> [原因]"""
        target, reason_text = self._resolve_target(event, qq, str(reason))
        if not target:
            yield event.plain_result(
                "用法：/black add <QQ号|@用户> [原因]\n"
                "示例：/black add 123456 恶意刷屏骚扰\n"
                "群聊中也可以直接 @ 对方：/black add @某人 恶意骚扰"
            )
            return

        if self._conf_bool("protect_admins", True) and target in self._admin_ids():
            yield event.plain_result(f"❌ {target} 是管理员，受管理员保护，无法拉黑。")
            return

        if self.storage.is_blacklisted(target):
            entry = self.storage.get_entry(target) or {}
            yield event.plain_result(
                f"⚠ {target} 已在黑名单中"
                f"（{entry.get('added_at', '')}，原因：{entry.get('reason', '')}）。"
            )
            return

        entry = self.storage.add_blacklist(
            target, reason_text or "管理员手动拉黑", str(event.get_sender_id() or "admin")
        )
        yield event.plain_result(
            f"✅ 已拉黑 {entry['qq']}（{entry.get('added_at')}）\n"
            f"原因：{entry.get('reason')}"
        )

    @filter.permission_type(filter.PermissionType.ADMIN)
    @black_group.command("remove", alias={"del", "delete", "解除", "解禁"})
    async def black_remove(self, event: AstrMessageEvent, qq: str = ""):
        """解除拉黑：/black remove <QQ号|@用户>"""
        target = self._extract_at_qq(event) or str(qq).strip()
        if not target or not target.isdigit():
            yield event.plain_result("用法：/black remove <QQ号|@用户>")
            return
        entry = self.storage.remove_blacklist(target)
        if entry is None:
            yield event.plain_result(f"⚠ {target} 不在黑名单中。")
            return
        yield event.plain_result(
            f"✅ 已解除 {target} 的拉黑。\n"
            f"原拉黑信息：{entry.get('added_at', '')}，原因：{entry.get('reason', '')}"
        )

    @filter.permission_type(filter.PermissionType.ADMIN)
    @black_group.command("list", alias={"列表"})
    async def black_list(self, event: AstrMessageEvent):
        """查看黑名单。"""
        blacklist = self.storage.get_blacklist()
        if not blacklist:
            yield event.plain_result("黑名单为空。")
            return
        lines = []
        entries = sorted(blacklist.items(), key=lambda kv: str(kv[1].get("added_at", "")))
        for i, (qq, entry) in enumerate(entries, 1):
            if i > 30:
                lines.append(f"... 等共 {len(blacklist)} 人")
                break
            lines.append(f"{i}. {qq}｜{entry.get('reason', '')}｜{entry.get('added_at', '')}")
        yield event.plain_result("🛡 黑名单：\n" + "\n".join(lines))

    @filter.permission_type(filter.PermissionType.ADMIN)
    @black_group.command("check", alias={"查询"})
    async def black_check(self, event: AstrMessageEvent, qq: str = ""):
        """查询用户状态：/black check <QQ号|@用户>"""
        target = self._extract_at_qq(event) or str(qq).strip()
        if not target or not target.isdigit():
            yield event.plain_result("用法：/black check <QQ号|@用户>")
            return
        entry = self.storage.get_entry(target)
        if entry:
            yield event.plain_result(
                f"👤 用户 {target}：\n"
                f"黑名单：是（{entry.get('added_at')}，原因：{entry.get('reason')}，"
                f"操作人：{entry.get('operator')}）"
            )
        else:
            yield event.plain_result(f"👤 用户 {target}：\n黑名单：否")

    def _resolve_target(
        self,
        event: AstrMessageEvent,
        qq: str,
        greedy_text: str,
    ) -> tuple[str, str]:
        """解析命令的目标用户与原因文本。返回 (target_qq, reason)。

        At 组件被框架文本化为「@昵称(12345)」且位置参数 qq 会吃进这段文本，
        用真实 QQ 精确剔除（详见 clean_at_reason）。
        """
        at_qq = self._extract_at_qq(event)
        if at_qq:
            reason = clean_at_reason(
                " ".join(x for x in (str(qq).strip(), str(greedy_text).strip()) if x),
                str(at_qq),
            )
            return at_qq, reason
        target = str(qq).strip()
        if target.isdigit():
            return target, str(greedy_text).strip()
        # 无 @ 且非数字：视为只给了原因没给 QQ
        return "", ""
