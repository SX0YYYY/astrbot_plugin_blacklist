"""黑名单与举报记录的持久化存储。

数据文件保存在 data/plugin_data/astrbot_plugin_blacklist/ 下：
- blacklist.json: 黑名单（QQ -> 拉黑信息）
- reports.json:   举报记录（id -> 举报详情）

所有写操作立即落盘，文件很小，无需批量写入。
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from astrbot.api import logger

PLUGIN_NAME = "astrbot_plugin_blacklist"

REPORT_PENDING = "pending"
REPORT_APPROVED = "approved"
REPORT_REJECTED = "rejected"


def _now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Storage:
    """黑名单与举报记录的 JSON 持久化。"""

    def __init__(self, data_dir: Path | str) -> None:
        self._dir = Path(data_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._blacklist_file = self._dir / "blacklist.json"
        self._reports_file = self._dir / "reports.json"

        self._blacklist: dict[str, dict[str, Any]] = {}
        self._reports: dict[str, dict[str, Any]] = {}
        self._next_report_id = 1

        self._load()

    # ---------- 加载 / 保存 ----------

    def _load(self) -> None:
        for path, attr in (
            (self._blacklist_file, "_blacklist"),
            (self._reports_file, "_reports"),
        ):
            try:
                if path.exists():
                    data = json.loads(path.read_text(encoding="utf-8"))
                    if not isinstance(data, dict):
                        # 可解析但顶层不是对象（如被写成 []/"x"）：按损坏处理，保留现场
                        raise ValueError(f"顶层结构不是对象（{type(data).__name__}）")
                    setattr(self, attr, data)
            except Exception as e:  # noqa: BLE001 - 损坏时重置而不是让插件崩溃
                logger.error(f"[{PLUGIN_NAME}] 读取 {path.name} 失败: {e}")
                # 坏文件改名保留现场，便于人工恢复，避免后续保存直接覆盖唯一证据；
                # Windows 下 rename 不覆盖已存在文件，先删旧 .bak 防止二次损坏时失效
                try:
                    bak = path.with_suffix(path.suffix + ".bak")
                    if bak.exists():
                        bak.unlink()
                    path.rename(bak)
                    logger.error(f"[{PLUGIN_NAME}] 已将损坏文件保留为 {bak.name}")
                except Exception:  # noqa: BLE001
                    pass
                setattr(self, attr, {})

        try:
            self._next_report_id = max(int(rid) for rid in self._reports) + 1
        except ValueError:
            self._next_report_id = 1

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

    def _save_reports(self) -> None:
        try:
            self._atomic_write(self._reports_file, self._reports)
        except Exception as e:  # noqa: BLE001
            logger.error(f"[{PLUGIN_NAME}] 写入举报记录文件失败: {e}")

    # ---------- 黑名单 ----------

    def is_blacklisted(self, qq: str | int) -> bool:
        return str(qq) in self._blacklist

    def get_entry(self, qq: str | int) -> dict[str, Any] | None:
        return self._blacklist.get(str(qq))

    def add_blacklist(
        self,
        qq: str | int,
        reason: str,
        operator: str,
        report_id: int | None = None,
    ) -> dict[str, Any]:
        entry = {
            "qq": str(qq),
            "reason": reason or "未填写原因",
            "operator": operator,
            "report_id": report_id,
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

    def has_noticed(self, qq: str | int) -> bool:
        entry = self._blacklist.get(str(qq))
        return bool(entry and entry.get("noticed"))

    def mark_noticed(self, qq: str | int) -> None:
        entry = self._blacklist.get(str(qq))
        if entry is not None and not entry.get("noticed"):
            entry["noticed"] = True
            self._save_blacklist()

    # ---------- 举报 ----------

    # reports.json 最大记录数：超出时自动清理最旧的「已处理」举报（待审永不清理）
    MAX_REPORTS = 500

    def _cleanup_reports(self) -> None:
        """记录数超上限时，按创建时间从旧到新删除已处理举报，防止文件无限膨胀。"""
        if len(self._reports) <= self.MAX_REPORTS:
            return
        decided = sorted(
            (
                (key, r.get("created_ts", 0.0))
                for key, r in self._reports.items()
                if r.get("status") != REPORT_PENDING
            ),
            key=lambda kv: kv[1],
        )
        excess = len(self._reports) - self.MAX_REPORTS
        for key, _ in decided[:excess]:
            del self._reports[key]

    def create_report(
        self,
        target_qq: str,
        target_name: str,
        reason: str,
        source: str,
        severity: str = "medium",
        review_note: str = "",
        history_text: str = "",
    ) -> dict[str, Any]:
        report = {
            "id": self._next_report_id,
            "target_qq": str(target_qq),
            "target_name": target_name or str(target_qq),
            "reason": reason,
            "source": source,
            "severity": severity,
            "review_note": review_note,
            "history": history_text,
            "created_at": _now_iso(),
            "created_ts": time.time(),
            "status": REPORT_PENDING,
            "decided_at": "",
            "decided_by": "",
        }
        self._next_report_id += 1
        self._reports[str(report["id"])] = report
        self._cleanup_reports()
        self._save_reports()
        return report

    def get_report(self, report_id: int | str) -> dict[str, Any] | None:
        return self._reports.get(str(report_id))

    def pending_reports(self) -> list[dict[str, Any]]:
        reports = [r for r in self._reports.values() if r.get("status") == REPORT_PENDING]
        reports.sort(key=lambda r: r.get("id", 0))
        return reports

    def pending_report_for(self, qq: str | int) -> dict[str, Any] | None:
        qq = str(qq)
        for report in self.pending_reports():
            if report.get("target_qq") == qq:
                return report
        return None

    def last_report_ts(self, qq: str | int) -> float:
        qq = str(qq)
        timestamps = [
            r.get("created_ts", 0.0) for r in self._reports.values() if r.get("target_qq") == qq
        ]
        return max(timestamps, default=0.0)

    def reports_for(self, qq: str | int) -> list[dict[str, Any]]:
        qq = str(qq)
        reports = [r for r in self._reports.values() if r.get("target_qq") == qq]
        reports.sort(key=lambda r: r.get("id", 0), reverse=True)
        return reports

    def decide_report(
        self,
        report_id: int | str,
        status: str,
        decided_by: str,
    ) -> dict[str, Any] | None:
        report = self._reports.get(str(report_id))
        if report is None:
            return None
        if report.get("status") != REPORT_PENDING:
            return report
        report["status"] = status
        report["decided_at"] = _now_iso()
        report["decided_by"] = decided_by
        self._save_reports()
        return report
