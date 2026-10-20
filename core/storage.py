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


def _safe_int(value: Any, default: int = 0) -> int:
    """把任意值安全转换为 int，失败时返回默认值。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    """把任意值安全转换为 float，失败时返回默认值。"""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any, default: bool = False) -> bool:
    """解析布尔值，兼容 WebUI/手工编辑产生的字符串形式。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "enable", "enabled"}:
            return True
        if normalized in {"0", "false", "no", "off", "disable", "disabled"}:
            return False
        return default
    if value is None:
        return default
    return bool(value)


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
        for path, attr, sanitizer in (
            (self._blacklist_file, "_blacklist", self._sanitize_blacklist),
            (self._reports_file, "_reports", self._sanitize_reports),
        ):
            try:
                if path.exists():
                    raw_text = path.read_text(encoding="utf-8")
                    data = json.loads(raw_text)
                    if not isinstance(data, dict):
                        # 可解析但顶层不是对象（如被写成 []/"x"）：按损坏处理，保留现场
                        raise ValueError(f"顶层结构不是对象（{type(data).__name__}）")
                    cleaned, repaired = sanitizer(data)
                    setattr(self, attr, cleaned)
                    if repaired:
                        # 合法 JSON 但条目损坏：保留原始文件现场，再落盘清洗后的数据
                        self._backup_original(path, raw_text)
                        logger.warning(
                            f"[{PLUGIN_NAME}] {path.name} 有 {repaired} 条异常记录，"
                            f"已自动修复/跳过；原始文件已备份为 {path.name}.bak"
                        )
                        if attr == "_blacklist":
                            self._save_blacklist()
                        else:
                            self._save_reports()
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

        numeric_ids = [int(rid) for rid in self._reports if str(rid).isdigit()]
        self._next_report_id = max(numeric_ids, default=0) + 1

    def _backup_original(self, path: Path, raw_text: str) -> None:
        """把清洗前的原始文件写到 .bak，便于人工恢复。"""
        try:
            bak = path.with_suffix(path.suffix + ".bak")
            bak.write_text(raw_text, encoding="utf-8")
        except Exception as e:  # noqa: BLE001
            logger.error(f"[{PLUGIN_NAME}] 备份 {path.name} 失败: {e}")

    @staticmethod
    def _sanitize_blacklist(data: dict[str, Any]) -> tuple[dict[str, Any], int]:
        """清洗黑名单：非对象条目修复为可拦截的最小记录，保证不因坏数据放行。"""
        cleaned: dict[str, Any] = {}
        repaired = 0
        for key, value in data.items():
            qq = str(key).strip()
            if not qq:
                repaired += 1
                continue
            if isinstance(value, dict):
                entry = dict(value)
            else:
                entry = {
                    "qq": qq,
                    "reason": "数据损坏，已自动修复",
                    "operator": "system",
                    "report_id": None,
                    "added_at": _now_iso(),
                    "noticed": False,
                }
                repaired += 1
            entry["qq"] = qq
            entry.setdefault("reason", "未填写原因")
            entry.setdefault("operator", "system")
            entry.setdefault("report_id", None)
            entry.setdefault("added_at", _now_iso())
            entry["noticed"] = _as_bool(entry.get("noticed"), False)
            cleaned[qq] = entry
        return cleaned, repaired

    @staticmethod
    def _sanitize_reports(data: dict[str, Any]) -> tuple[dict[str, Any], int]:
        """清洗举报记录：跳过非对象/无有效 id 的条目，统一数字 id 并去重。"""
        cleaned: dict[str, Any] = {}
        repaired = 0
        for key, value in data.items():
            if not isinstance(value, dict):
                repaired += 1
                continue
            entry = dict(value)
            rid = _safe_int(entry.get("id"), -1)
            if rid < 0:
                rid = _safe_int(key, -1)
                if rid >= 0:
                    repaired += 1
            if rid < 0:
                repaired += 1
                continue
            entry["id"] = rid
            try:
                entry["created_ts"] = float(entry.get("created_ts") or 0.0)
            except (TypeError, ValueError):
                entry["created_ts"] = 0.0
                repaired += 1
            if not entry.get("status"):
                entry["status"] = REPORT_PENDING
            if not isinstance(entry.get("target_qq"), str):
                entry["target_qq"] = str(entry.get("target_qq") or "")
            if not entry.get("target_name"):
                entry["target_name"] = entry["target_qq"]
            entry.setdefault("reason", "")
            entry.setdefault("source", "")
            entry.setdefault("severity", "medium")
            entry.setdefault("review_note", "")
            entry.setdefault("history", "")
            entry.setdefault("created_at", "")
            entry.setdefault("decided_at", "")
            entry.setdefault("decided_by", "")
            key_str = str(rid)
            if key_str in cleaned:
                # 重复 id：保留 created_ts 较新的一条
                if float(entry.get("created_ts") or 0.0) >= float(
                    cleaned[key_str].get("created_ts") or 0.0
                ):
                    cleaned[key_str] = entry
                repaired += 1
            else:
                cleaned[key_str] = entry
        return cleaned, repaired

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
        entry = self._blacklist.get(str(qq))
        return entry if isinstance(entry, dict) else None

    def add_blacklist(
        self,
        qq: str | int,
        reason: str,
        operator: str,
        report_id: int | None = None,
    ) -> dict[str, Any]:
        existing = self._blacklist.get(str(qq))
        noticed = _as_bool(existing.get("noticed"), False) if isinstance(existing, dict) else False
        entry = {
            "qq": str(qq),
            "reason": reason or "未填写原因",
            "operator": operator,
            "report_id": report_id,
            "added_at": _now_iso(),
            "noticed": noticed,
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
        return bool(isinstance(entry, dict) and _as_bool(entry.get("noticed"), False))

    def mark_noticed(self, qq: str | int) -> None:
        entry = self._blacklist.get(str(qq))
        if isinstance(entry, dict) and not _as_bool(entry.get("noticed"), False):
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
                (key, _safe_float(r.get("created_ts")))
                for key, r in self._reports.items()
                if isinstance(r, dict) and r.get("status") != REPORT_PENDING
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
        while str(self._next_report_id) in self._reports:
            self._next_report_id += 1
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
        report = self._reports.get(str(report_id))
        return report if isinstance(report, dict) else None

    def pending_reports(self) -> list[dict[str, Any]]:
        reports = [
            r
            for r in self._reports.values()
            if isinstance(r, dict) and r.get("status") == REPORT_PENDING
        ]
        reports.sort(key=lambda r: _safe_int(r.get("id")))
        return reports

    def pending_report_for(self, qq: str | int) -> dict[str, Any] | None:
        qq = str(qq)
        for report in self.pending_reports():
            if report.get("target_qq") == qq:
                return report
        return None

    def last_report_ts(self, qq: str | int) -> float:
        qq = str(qq)
        timestamps: list[float] = []
        for report in self._reports.values():
            if isinstance(report, dict) and report.get("target_qq") == qq:
                try:
                    timestamps.append(float(report.get("created_ts") or 0.0))
                except (TypeError, ValueError):
                    continue
        return max(timestamps, default=0.0)

    def reports_for(self, qq: str | int) -> list[dict[str, Any]]:
        qq = str(qq)
        reports = [
            r
            for r in self._reports.values()
            if isinstance(r, dict) and r.get("target_qq") == qq
        ]
        reports.sort(key=lambda r: _safe_int(r.get("id")), reverse=True)
        return reports

    def decide_report(
        self,
        report_id: int | str,
        status: str,
        decided_by: str,
    ) -> dict[str, Any] | None:
        report = self._reports.get(str(report_id))
        if not isinstance(report, dict):
            return None
        if report.get("status") != REPORT_PENDING:
            return report
        report["status"] = status
        report["decided_at"] = _now_iso()
        report["decided_by"] = decided_by
        self._save_reports()
        return report
