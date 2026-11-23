# 完工 Review 记录

> Review 时间：2026-11-17
> 验证环境：Python 3.12（.venv），pydantic 2.14 / httpx 0.28 / pypinyin 0.55 / pytest 9.2
> 验证方式：全程离线（无真实 API Key），LLM 链路通过 httpx stub 做端到端契约验证

## 1. 笔试题要求逐条核对

| # | 题目要求 | 落实情况 | 证据 |
|---|---|---|---|
| 1 | 对接真实大模型 API，OpenAI 兼容协议 | `LLMAuditor` 走 `{LLM_BASE_URL}/chat/completions`，Bearer 鉴权，配 Key 即启用 | stub 验证同步/异步 POST、400 自动降级、JSON 围栏解析均通过 |
| 2 | 严禁硬编码 API Key，环境变量读取 + `.env.example` | 全部配置 `os.environ.get` 读取；T13 静态扫描防回归 | `.env.example` 含 5 个变量；无 Key 自动离线 |
| 3 | 编码前先写设计说明（SDD） | 模块 docstring【设计说明】+ `docs/design.md` + `docs/module_specs.md` | 三份文档先于代码提交 |
| 4 | Rule-01 收益承诺 | 词库 + 承诺类正则，字面/紧凑/音节三层匹配 | Case2/3/5/6 全部命中 |
| 5 | Rule-02 夸大误导 | 词库 + `错过…再等`/`闭眼[买入上]` 通用模式 | Case2/3/4/6 全部命中 |
| 6 | Rule-03 风险提示缺失 | 标的识别（6位代码/字母+股票基金/指代词）+ 推荐动词 + 免责词共现判定 | Case3 命中；T11 泛化用例验证 |
| 7 | Rule-04 不正当竞争 | 同业贬低小句共现、极限词、无出处数据三类通用模式 | T11a 构造新话术命中，证明非用例硬编码 |
| 8 | Rule-05 变体规避 | 信号驱动：Cf 字符/HTML 隐藏文本/拉丁拼音/compact 独有命中 | Case3（零宽+拼音）、Case5（隐藏 HTML）命中 |
| 9 | 抗对抗：拼音/零宽（Case3） | NFKC + Cf 剥离 + 合法音节集合识别拉丁拼音 + 音节流子序列匹配 | T04：两信号为真，Rule-01/02/03/05 全中 |
| 10 | 抗对抗：Prompt 注入（Case4） | 本地注入模式库置标记 + LLM 分隔符隔离 Prompt；注入文本照常审核 | T02：`is_attack_detected=True` 且 Rule-02 不放行 |
| 11 | 抗对抗：HTML 隐藏文本（Case5） | HTMLParser 栈式隐藏追踪，隐藏文本单独提取并强制送审 | T03：hidden_text 含"保本保息"，Rule-01/05 命中 |
| 12 | 语义诱导（Case6） | 本地词库先保底命中 01/02；LLM 通道负责深层语义（有 Key 时增强） | 离线即满足预期子集；在线融合不降低召回 |
| 13 | 确定性：连调 5 次 100% 一致 | temperature=0 + 本地纯函数 + 哈希幂等缓存（深拷贝） | T05 + 主程序断言，6 用例签名唯一 |
| 14 | 批量并发高吞吐 | `Semaphore(LLM_CONCURRENCY)` + `wait_for` 超时 + `gather(return_exceptions=True)` | T06 顺序/等价性；T07 单条故障整批不中断 |
| 15 | 单条异常/超时不漏放 | 一律 fail-closed：`status=违规, is_fallback=True`，本地规则保留 | T07/T08 + stub 验证持续故障兜底 |
| 16 | `python3 task_compliance.py` 一键 assert 通过 | `__main__` 内置 9 组断言，默认离线零网络依赖 | 实测打印 `ALL ASSERTIONS PASSED` |
| 17 | 禁止针对用例写死规则 | 词库/模式按规则维度做领域通用设计；另造 4 条全新话术验证泛化 | T11a-d 全过（含同音字、纯拉丁拼音、插符拆词） |
| 18 | 交付物齐全 | `task_compliance.py` / `.env.example` / 设计与规格文档 / 测试 | 见第 4 节文件清单 |

## 2. 测试结果

### 2.1 pytest 全量（26 项，先于实现编写）
```
26 passed in 0.06s
```
覆盖：T01 六用例子集断言 / T02 注入 / T03 隐藏 HTML / T04 拼音零宽 / T05 确定性 /
T06 批量顺序 / T07-T08 双链路 fail-closed / T09 双通道融合 / T10 离线降级 /
T11 泛化（Rule-04、拆词、同音字、拉丁拼音）/ T12 缓存隔离 / T13 安全扫描 / T14 边界输入。

### 2.2 题面一键验收
```
$ python3 task_compliance.py
ALL ASSERTIONS PASSED：6 用例审核 / 注入防御 / 变体抗对抗 / 确定性 / 并发兜底 全部通过
```

### 2.3 LLM 真实 HTTP 链路（httpx stub 端到端）
- 400 不支持 `response_format` → 自动降级重试成功；
- ```json 代码围栏响应可正常解析；
- 非法 rule_id（Rule-99）被 pydantic 契约过滤；
- LLM 持续返回非法 JSON → fail-closed 兜底（is_fallback=True，判违规）；
- LLM 判合规不能覆盖本地违规裁决（并集融合）。

## 3. 六用例实测命中（离线模式）

| Case | status | violated_rules | 特殊标记 |
|---|---|---|---|
| 1 | 合规 | `[]` | — |
| 2 | 违规 | Rule-01, Rule-02, Rule-03 | Rule-03 为弹性多判，预期子集仍满足 |
| 3 | 违规 | Rule-01, Rule-02, Rule-03, Rule-05 | 零宽+拉丁拼音双信号 |
| 4 | 违规 | Rule-01, Rule-02, Rule-03 | is_attack_detected=True |
| 5 | 违规 | Rule-01, Rule-05 | 隐藏文本已送审 |
| 6 | 违规 | Rule-01, Rule-02, Rule-03 | 本地保底，LLM 在线增强语义 |

注：断言采用「预期规则 ⊆ 实际命中」策略，Rule-03 等弹性规则允许多判、漏判才失败。

## 4. 交付文件清单

```
project-2/
├── task_compliance.py        # 主交付：完整实现 + __main__ 一键断言
├── .env.example              # 环境变量模板（无真实 Key）
├── requirements.txt          # pydantic / httpx / pypinyin / pytest
├── test.py                   # 题面原始文件（未改动）
├── docs/
│   ├── design.md             # 设计文档（SDD）
│   ├── module_specs.md       # 模块规格（测试契约来源）
│   └── review.md             # 本 Review 记录
└── tests/
    ├── conftest.py           # 离线夹具 + 缓存隔离
    └── test_compliance.py    # 26 项测试（TDD，先写测试后写实现）
```

## 5. 剩余人工步骤（只能由本人完成）

1. 真实 API 联调：`cp .env.example .env` 填入 Key 后直接运行
   `python3 task_compliance.py` 即可，程序启动时经 python-dotenv 自动加载 `.env`
   （也可继续用 `export $(grep -v '^#' .env | xargs)` 注入，已 export 的变量优先级更高），
   启用双通道（DeepSeek/通义/Kimi 等 OpenAI 兼容端点均可）；
2. 按题目要求初始化 git 并推送到自己的 git 空间（涉及本人账号凭据）：
   `git init && git add . && git commit -m "feat: compliance audit engine" && git remote add origin <你的仓库> && git push -u origin main`；
3. 附上 AI 编程对话记录（分享链接或导出 Markdown）。

## 6. 已知设计取舍

- 拉丁拼音识别要求连续 ≥2 个合法音节，以牺牲极少数单音节场景换取低误报；
- fail-closed 兜底在极端情况下可能拦截合规话术（宁可误拦不可漏放，与题目"不漏放"要求一致）；
- 兜底结果不写缓存，避免一次上游故障导致进程生命周期内永久降级。
