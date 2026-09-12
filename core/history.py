"""每用户最近消息的内存缓存，用于举报时附上聊天记录。"""

from __future__ import annotations

import time
from collections import deque
from datetime import datetime
from typing import Any

# 内存上限：最多缓存多少个用户的消息记录
_MAX_USERS = 1000
# 单条消息文本截断长度
_MAX_TEXT_LEN = 200


class MessageHistory:
    """按用户缓存最近消息（环形队列），举报时格式化输出。"""

    def __init__(self, max_per_user: int = 20) -> None:
        self._max_per_user = max(1, int(max_per_user))
        self._users: dict[str, deque] = {}

    def record(
        self,
        qq: str | int,
        name: str,
        is_group: bool,
        group_id: str,
        text: str,
    ) -> None:
        qq = str(qq)
        dq = self._users.get(qq)
        if dq is None:
            if len(self._users) >= _MAX_USERS:
                self._evict()
            dq = deque(maxlen=self._max_per_user)
            self._users[qq] = dq
        dq.append(
            {
                "time": time.time(),
                "qq": qq,
                "name": name or qq,
                "is_group": is_group,
                "group_id": str(group_id or ""),
                "text": (text or "")[:_MAX_TEXT_LEN],
            },
        )

    def get_entries(self, qq: str | int, limit: int | None = None) -> list[dict[str, Any]]:
        """返回某用户缓存记录的列表副本（构造合并转发用）；无记录时返回空列表。"""
        dq = self._users.get(str(qq))
        if not dq:
            return []
        entries: list[dict[str, Any]] = list(dq)
        if limit:
            entries = entries[-limit:]
        return entries

    def format(self, qq: str | int, limit: int | None = None, max_chars: int = 1500) -> str:
        """把某用户最近的缓存消息格式化为多行文本；无记录时返回占位说明。"""
        dq = self._users.get(str(qq))
        if not dq:
            return "（启动后未缓存到该用户的消息）"
        entries: list[dict[str, Any]] = list(dq)
        if limit:
            entries = entries[-limit:]
        lines = []
        for e in entries:
            ts = datetime.fromtimestamp(e["time"]).strftime("%m-%d %H:%M:%S")
            scope = f"群{e['group_id']}" if e["is_group"] else "私聊"
            text = e["text"] or "（非文本消息）"
            lines.append(f"[{ts}][{scope}] {e['name']}: {text}")
        output = "\n".join(lines)
        if len(output) > max_chars:
            output = output[:max_chars] + "\n...（记录过长已截断）"
        return output

    def _evict(self) -> None:
        """超出用户数上限时，淘汰最近最不活跃的一半用户。"""
        if not self._users:
            return
        ranked = sorted(
            self._users.items(),
            key=lambda item: item[1][-1]["time"] if item[1] else 0.0,
        )
        for qq, _ in ranked[: len(ranked) // 2]:
            self._users.pop(qq, None)
