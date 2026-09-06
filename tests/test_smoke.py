"""astrbot_plugin_blacklist（黑名单管家）冒烟测试。

运行方式：
- CI：pip install astrbot 后直接 `python tests/test_smoke.py`
- 本地开发：设置环境变量 ASTRBOT_SRC 指向 AstrBot 源码目录后运行；
  未设置时尝试直接 import astrbot

版本演进：v1.1.0 删规则层；v1.2.0 引用审批；v1.3.0 配置化；v1.4.x 打码/
体检/门控/迁移；v0.0.1 重生为纯手动黑名单管理（移除全部 LLM 举报链路）。
"""

import asyncio
import importlib.util
import inspect
import json
import os
import sys
import tempfile
from pathlib import Path

# ---------- 可移植路径解析 ----------
_HERE = Path(__file__).resolve().parent          # tests/
_PLUGIN_DIR = _HERE.parent                       # 仓库根 = 插件包目录
_ASTRBOT_SRC = os.environ.get("ASTRBOT_SRC")
if _ASTRBOT_SRC:
    sys.path.insert(0, _ASTRBOT_SRC)

try:
    import astrbot  # noqa: F401
    HAS_ASTRBOT = True
except ImportError:
    HAS_ASTRBOT = False

if not HAS_ASTRBOT:
    print("SKIP: 未安装 astrbot（设置 ASTRBOT_SRC 或 pip install astrbot），测试中止")
    sys.exit(1)

sys.path.insert(0, str(_PLUGIN_DIR))

import astrbot.api.message_components as Comp  # noqa: E402
from astrbot.core.star.filter.command import CommandFilter, GreedyStr  # noqa: E402

from core.storage import Storage  # noqa: E402

# ---------- 以包方式加载插件主模块（含相对导入） ----------
spec = importlib.util.spec_from_file_location(
    "astrbot_plugin_blacklist",
    str(_PLUGIN_DIR / "main.py"),
    submodule_search_locations=[str(_PLUGIN_DIR)],
)
main = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = main
spec.loader.exec_module(main)

# ============================================================
# Storage：黑名单增删查 / 提示标记 / 原子写 / 损坏恢复
# ============================================================
with tempfile.TemporaryDirectory() as td:
    s = Storage(td)
    assert not s.is_blacklisted("123")
    s.add_blacklist("123", "测试原因", "op")
    assert s.is_blacklisted(123)  # int 也应命中
    entry = s.get_entry("123")
    assert entry and entry["reason"] == "测试原因" and entry["operator"] == "op"

    assert not s.has_noticed("123")
    s.mark_noticed("123")
    assert s.has_noticed("123")

    entry = s.remove_blacklist("123")
    assert entry and entry["reason"] == "测试原因"
    assert not s.is_blacklisted("123")
    assert s.remove_blacklist("123") is None  # 重复解除

    # 原子写 + 持久化：新实例能读回，无 .tmp 残留
    s2 = Storage(td)
    assert not s2.is_blacklisted("123")
    assert not (Path(td) / "blacklist.json.tmp").exists()

    # 损坏处理：坏文件改名 .bak 且覆盖旧 .bak
    bad_dir = Path(td) / "bad"
    bad_dir.mkdir()
    (bad_dir / "blacklist.json").write_text("{corrupted!", encoding="utf-8")
    (bad_dir / "blacklist.json.bak").write_text("OLD_BAK", encoding="utf-8")
    s3 = Storage(bad_dir)
    assert s3.get_blacklist() == {}
    assert (bad_dir / "blacklist.json.bak").read_text(encoding="utf-8") == "{corrupted!"
print("Storage OK")

# ============================================================
# 纯逻辑：@ 拉黑原因清洗（真实 QQ 精确剔除）
# ============================================================
assert main.clean_at_reason("@小明(45678) 恶意刷屏骚扰", "45678") == "恶意刷屏骚扰"
assert main.clean_at_reason("骂人 @小明(45678) 的行为", "45678") == "骂人 的行为"
# 昵称内含 (数字) 也不截断（通配 \d+ 会在此翻车）
assert main.clean_at_reason("@小明(1)23(45678) 恶意刷屏", "45678") == "恶意刷屏"
assert main.clean_at_reason("正常原因不清洗", "45678") == "正常原因不清洗"
assert main.clean_at_reason("", "45678") == ""
print("CleanAtReason OK")

# ============================================================
# schema 一致性：仅剩 5 项拉黑管理配置
# ============================================================
with open(_PLUGIN_DIR / "_conf_schema.json", encoding="utf-8") as f:
    schema = json.load(f)
assert sorted(schema.keys()) == [
    "admin_ids", "block_scope", "notice_mode", "notice_text", "protect_admins"
], sorted(schema.keys())


async def black_add(self, event, qq: str = "", *, reason: GreedyStr):
    """仿真签名，与 main.py 中一致。"""


cf = CommandFilter("add")
cf.handler_params = {}
sig = inspect.signature(black_add, eval_str=True)
idx = 0
for k, v in sig.parameters.items():
    if idx < 2:
        idx += 1
        continue
    if v.default == inspect.Parameter.empty:
        cf.handler_params[k] = v.annotation
    else:
        cf.handler_params[k] = v.default

params = cf.validate_and_convert_params(["12345", "恶意", "刷屏", "骚扰"], cf.handler_params)
assert params == {"qq": "12345", "reason": "恶意 刷屏 骚扰"}, params
params = cf.validate_and_convert_params(["12345"], cf.handler_params)
assert params == {"qq": "12345", "reason": ""}, params
params = cf.validate_and_convert_params([], cf.handler_params)
assert params == {"qq": "", "reason": ""}, params
print("SchemaAndParams OK")

# ============================================================
# main 完整加载 + handler 注册（8 个：监听 + 7 命令）
# ============================================================
from astrbot.core.star.register.star_handler import star_handlers_registry  # noqa: E402

ours = [h for h in star_handlers_registry.get_handlers_by_module_name(main.__name__)]
assert len(ours) == 8, [getattr(h, "handler_name", "") for h in ours]
names = {getattr(h, "handler_name", "") for h in ours}
expected = {
    "on_any_message", "black_group", "black_status", "black_help",
    "black_add", "black_remove", "black_list", "black_check",
}
assert names == expected, names ^ expected
print("Handlers OK: 8")

print("\n=== 全部冒烟测试通过 ===")
