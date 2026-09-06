"""黑名单的持久化存储。

数据文件保存在 data/plugin_data/astrbot_plugin_blacklist/ 下：
- blacklist.json: 黑名单（QQ -> 拉黑信息）

所有写操作立即原子落盘，文件很小，无需批量写入。
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from astrbot.api import logger

PLUGIN_NAME = "astrbot_plugin_blacklist"


def _now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Storage:
    """黑名单的 JSON 持久化。"""

    def __init__(self, data_dir: Path | str) -> None:
        self._dir = Path(data_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._blacklist_file = self._dir / "blacklist.json"
        self._blacklist: dict[str, dict[str, Any]] = {}
        self._load()

    # ---------- 加载 / 保存 ----------

    def _load(self) -> None:
        try:
            if self._blacklist_file.exists():
                data = json.loads(self._blacklist_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._blacklist = data
        except Exception as e:  # noqa: BLE001 - 损坏时重置而不是让插件崩溃
            logger.error(f"[{PLUGIN_NAME}] 读取 {self._blacklist_file.name} 失败: {e}")
            # 坏文件改名保留现场，便于人工恢复，避免后续保存直接覆盖唯一证据；
            # Windows 下 rename 不覆盖已存在文件，先删旧 .bak 防止二次损坏时失效
            try:
                bak = self._blacklist_file.with_suffix(self._blacklist_file.suffix + ".bak")
                if bak.exists():
                    bak.unlink()
                self._blacklist_file.rename(bak)
                logger.error(f"[{PLUGIN_NAME}] 已将损坏文件保留为 {bak.name}")
            except Exception:  # noqa: BLE001
                pass
            self._blacklist = {}

    def _atomic_write(self, path: Path, data: dict[str, Any]) -> None:
        """原子写入：先写临时文件再 os.replace，避免崩溃/断电留下半截 JSON。"""
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        os.replace(tmp, path)

    def _save_blacklist(self) -> None:
        try:
            self._atomic_write(self._blacklist_file, self._blacklist)
        except Exception as e:  # noqa: BLE001
            logger.error(f"[{PLUGIN_NAME}] 写入黑名单文件失败: {e}")

    # ---------- 黑名单 ----------

    def is_blacklisted(self, qq: str | int) -> bool:
        return str(qq) in self._blacklist

    def get_entry(self, qq: str | int) -> dict[str, Any] | None:
        return self._blacklist.get(str(qq))

    def add_blacklist(self, qq: str | int, reason: str, operator: str) -> dict[str, Any]:
        entry = {
            "qq": str(qq),
            "reason": reason or "未填写原因",
            "operator": operator,
            "added_at": _now_iso(),
            "noticed": False,
        }
        self._blacklist[str(qq)] = entry
        self._save_blacklist()
        return entry

    def remove_blacklist(self, qq: str | int) -> dict[str, Any] | None:
        entry = self._blacklist.pop(str(qq), None)
        if entry is not None:
            self._save_blacklist()
        return entry

    def get_blacklist(self) -> dict[str, dict[str, Any]]:
        return self._blacklist

    # ---------- 提示标记 ----------

    def has_noticed(self, qq: str | int) -> bool:
        entry = self._blacklist.get(str(qq))
        return bool(entry and entry.get("noticed"))

    def mark_noticed(self, qq: str | int) -> None:
        entry = self._blacklist.get(str(qq))
        if entry is not None:
            entry["noticed"] = True
            self._save_blacklist()
