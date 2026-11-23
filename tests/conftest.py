"""pytest 全局配置：保证项目根目录可导入、测试全程离线（无真实网络调用）。"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import task_compliance  # noqa: E402


@pytest.fixture(autouse=True)
def _force_offline():
    """每个用例前后都强制离线模式并清空缓存，LLM 调用只能通过 monkeypatch 注入。"""
    task_compliance.set_llm_enabled(False)
    task_compliance._cache.clear()
    yield
    task_compliance.set_llm_enabled(False)
    task_compliance._cache.clear()
