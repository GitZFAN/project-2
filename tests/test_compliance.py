"""合规审核引擎测试契约（先于业务实现编写，TDD Red 阶段建立）。

对应 docs/module_specs.md 第 5 节测试契约 T01-T14。
所有用例默认离线运行，LLM 行为通过 monkeypatch 模拟，确保确定性与零网络依赖。
"""
import asyncio
from pathlib import Path

import pytest

import task_compliance as tc
from task_compliance import (
    CASES,
    ComplianceResult,
    LLMJudge,
    check_compliance,
    check_compliance_batch,
    preprocess,
)

ROOT = Path(__file__).resolve().parent.parent

# 六条题面用例的预期：(status, 至少命中的规则集合)
EXPECTED = [
    ("合规", set()),                                   # Case 1
    ("违规", {"Rule-01", "Rule-02"}),                  # Case 2
    ("违规", {"Rule-01", "Rule-02", "Rule-03", "Rule-05"}),  # Case 3
    ("违规", {"Rule-02"}),                             # Case 4
    ("违规", {"Rule-01", "Rule-05"}),                  # Case 5
    ("违规", {"Rule-01", "Rule-02"}),                  # Case 6
]


# ---------- T01：六个题面用例的 status 与规则子集断言 ----------
@pytest.mark.parametrize("idx", list(range(len(CASES))))
def test_t01_six_cases(idx):
    result = check_compliance(CASES[idx])
    expected_status, expected_rules = EXPECTED[idx]
    assert isinstance(result, ComplianceResult)
    assert result.status == expected_status
    assert expected_rules.issubset(set(result.violated_rules))
    # 规则必须去重且字典序排序
    assert result.violated_rules == sorted(set(result.violated_rules))
    assert result.text_snippet == CASES[idx]


def test_t01_case1_full_compliance():
    result = check_compliance(CASES[0])
    assert result.status == "合规"
    assert result.violated_rules == []
    assert result.is_attack_detected is False
    assert result.is_fallback is False
    assert result.evidence_snippet is None


# ---------- T02：Prompt 注入检测且违规内容不放行 ----------
def test_t02_prompt_injection():
    result = check_compliance(CASES[3])
    assert result.is_attack_detected is True
    assert result.status == "违规"
    assert "Rule-02" in result.violated_rules
    assert "注入" in result.reasoning_trace or "攻击" in result.reasoning_trace


# ---------- T03：HTML 隐藏文本提取与审核 ----------
def test_t03_hidden_html_extracted():
    norm = preprocess(CASES[4])
    assert norm.has_html is True
    assert norm.has_hidden_html is True
    assert "保本保息" in norm.hidden_text
    assert "保本保息" in norm.audit_text  # 隐藏文本必须进入送审文本，不能被剥离丢弃
    result = check_compliance(CASES[4])
    assert {"Rule-01", "Rule-05"}.issubset(set(result.violated_rules))


# ---------- T04：拼音 + 零宽字符变体 ----------
def test_t04_pinyin_zero_width_obfuscation():
    norm = preprocess(CASES[2])
    assert norm.has_zero_width is True
    assert norm.has_pinyin_obfuscation is True
    # 零宽字符必须被剥干净
    assert "\u200b" not in norm.normalized
    result = check_compliance(CASES[2])
    assert {"Rule-01", "Rule-02", "Rule-03", "Rule-05"}.issubset(
        set(result.violated_rules)
    )


# ---------- T05：确定性，连调 5 次完全一致 ----------
def test_t05_determinism_five_runs():
    for text in CASES:
        signatures = set()
        for _ in range(5):
            r = check_compliance(text)
            signatures.add((r.status, tuple(r.violated_rules)))
        assert len(signatures) == 1, f"确定性失败: {text}"


# ---------- T06：批量并发接口的顺序与等价性 ----------
def test_t06_batch_order_and_equivalence():
    batch = asyncio.run(check_compliance_batch(CASES))
    assert len(batch) == len(CASES)
    single = [check_compliance(t) for t in CASES]
    for i, (b, s) in enumerate(zip(batch, single)):
        assert b.text_snippet == CASES[i]
        assert (b.status, b.violated_rules) == (s.status, s.violated_rules)
        assert isinstance(b, ComplianceResult)


def test_t06_batch_empty():
    assert asyncio.run(check_compliance_batch([])) == []


# ---------- T07：异步链路 fail-closed 兜底 ----------
def test_t07_async_fail_closed(monkeypatch):
    def _raise(*args, **kwargs):
        raise RuntimeError("simulated upstream timeout")

    monkeypatch.setattr(tc._auditor, "enabled", True)
    monkeypatch.setattr(tc._auditor, "audit_async", _raise)
    results = asyncio.run(check_compliance_batch(CASES))
    assert len(results) == len(CASES)
    for r in results:
        assert r.status == "违规"        # 绝不 fail-open 放行
        assert r.is_fallback is True
    # 本地引擎命中的规则在兜底结果中仍需保留，不漏放
    assert "Rule-01" in results[1].violated_rules


# ---------- T08：同步链路 fail-closed 兜底 ----------
def test_t08_sync_fail_closed(monkeypatch):
    def _raise(*args, **kwargs):
        raise RuntimeError("simulated network error")

    monkeypatch.setattr(tc._auditor, "enabled", True)
    monkeypatch.setattr(tc._auditor, "audit_sync", _raise)
    # 即使原文本身合规，LLM 故障时也必须拦截
    result = check_compliance(CASES[0])
    assert result.status == "违规"
    assert result.is_fallback is True


# ---------- T09：双通道融合（并集，本地优先级不被 LLM 覆盖） ----------
def test_t09a_llm_extra_rule_merged(monkeypatch):
    judge = LLMJudge(
        status="违规",
        violated_rules=["Rule-04"],
        evidence_snippet="mock",
        reasoning_trace="LLM mock: 不正当竞争",
        is_attack_detected=False,
    )

    async def _async_audit(text):
        return judge

    monkeypatch.setattr(tc._auditor, "enabled", True)
    monkeypatch.setattr(tc._auditor, "audit_async", _async_audit)
    results = asyncio.run(check_compliance_batch([CASES[0]]))
    assert results[0].status == "违规"
    assert "Rule-04" in results[0].violated_rules
    assert results[0].is_fallback is False


def test_t09b_llm_cannot_override_local_violation(monkeypatch):
    judge = LLMJudge(
        status="合规",
        violated_rules=[],
        evidence_snippet=None,
        reasoning_trace="LLM mock: 合规",
        is_attack_detected=False,
    )

    def _sync_audit(text):
        return judge

    monkeypatch.setattr(tc._auditor, "enabled", True)
    monkeypatch.setattr(tc._auditor, "audit_sync", _sync_audit)
    result = check_compliance(CASES[1])  # 本地已判违规的 Case 2
    assert result.status == "违规"
    assert {"Rule-01", "Rule-02"}.issubset(set(result.violated_rules))


# ---------- T10：离线模式是有意降级而非 fallback ----------
def test_t10_offline_mode():
    assert tc._auditor.enabled is False
    result = check_compliance(CASES[0])
    assert result.is_fallback is False
    assert result.status == "合规"


# ---------- T11：通用泛化能力（证明不是针对题面用例写死） ----------
def test_t11a_rule04_unfair_competition():
    text = "别家公司的产品都是坑，买了就跑路，我们这款才是全网第一，收益最高。"
    result = check_compliance(text)
    assert result.status == "违规"
    assert "Rule-04" in result.violated_rules


def test_t11b_split_chars_triggers_rule05():
    text = "这款理财产品保 本 保 息，放心入手。"
    norm = preprocess(text)
    result = check_compliance(text)
    assert "Rule-01" in result.violated_rules
    assert "Rule-05" in result.violated_rules  # compact 独有命中 = 拆词规避
    assert "保本保息" in norm.compact


def test_t11c_homophone_via_syllables():
    text = "吻赚不赔，老客户闭眼上车。"
    result = check_compliance(text)
    assert "Rule-02" in result.violated_rules  # 吻赚不赔 → 音节流命中稳赚不赔
    # 同音字不属于 Rule-05 信号（无零宽/隐藏/拉丁拼音/插符拆词）
    assert "Rule-05" not in result.violated_rules


def test_t11d_latin_pinyin_obfuscation():
    text = "bao ben bao xi，马上加仓这只基金。"
    norm = preprocess(text)
    assert norm.has_pinyin_obfuscation is True
    result = check_compliance(text)
    assert "Rule-01" in result.violated_rules
    assert "Rule-05" in result.violated_rules


# ---------- T12：缓存深拷贝隔离 ----------
def test_t12_cache_deep_copy_isolation():
    r1 = check_compliance(CASES[0])
    r2 = check_compliance(CASES[0])
    assert r1 is not r2
    r1.violated_rules.append("Rule-99")
    r3 = check_compliance(CASES[0])
    assert "Rule-99" not in r3.violated_rules


# ---------- T13：安全与交付物检查 ----------
def test_t13_no_hardcoded_api_key():
    source = (ROOT / "task_compliance.py").read_text(encoding="utf-8")
    assert "sk-" not in source                       # 禁止硬编码常见 Key 前缀
    assert "os.environ" in source                    # 必须走环境变量
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    for var in ("LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL",
                "LLM_TIMEOUT", "LLM_CONCURRENCY"):
        assert var in env_example


# ---------- T14：边界输入 ----------
def test_t14_empty_and_whitespace():
    for text in ("", "   "):
        result = check_compliance(text)
        assert result.status == "合规"
        assert result.violated_rules == []
        assert result.is_fallback is False


def test_t14_non_string_input():
    result = check_compliance(None)  # type: ignore[arg-type]
    assert isinstance(result, ComplianceResult)
    assert result.status == "合规"
