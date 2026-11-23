# 模块规格说明书（Module Specs）

> 由 `docs/design.md` 细化而来，是测试用例与实现的**契约**。
> 所有接口签名以本文件为准；实现必须满足每个模块的「不变式」。

## 0. 数据结构契约

### 0.1 `NormalizedText`（预处理产物，内部模型）
| 字段 | 类型 | 说明 |
|---|---|---|
| `original` | `str` | 原始输入 |
| `normalized` | `str` | NFKC + 剥离 Cf 字符后的文本（HTML 标签已解析为文本） |
| `audit_text` | `str` | 送 LLM 审核的文本 = 可见文本 + 隐藏文本标注段 |
| `compact` | `str` | 仅保留 Unicode L/N 类字符的紧凑文本 |
| `syllables` | `tuple[str, ...]` | 有序拼音音节流（汉字拼音 + 拉丁文拼音） |
| `has_zero_width` | `bool` | 是否检出 Cf 类格式字符 |
| `has_html` | `bool` | 是否含 HTML 标签 |
| `has_hidden_html` | `bool` | 是否提取到隐藏元素文本 |
| `hidden_text` | `str` | 隐藏元素文本（可能为空） |
| `has_pinyin_obfuscation` | `bool` | 是否检出拉丁文拼音规避 |

### 0.2 `LocalHit`（本地引擎单条命中，内部模型）
`rule_id: str`、`evidence: str`、`trace: str`

### 0.3 `LLMJudge`（LLM 返回契约，pydantic 校验）
`status: str`、`violated_rules: list[str]`、`evidence_snippet: str|None`、`reasoning_trace: str`、`is_attack_detected: bool`
- 非法 rule_id 直接丢弃；`status` 归一化为含"违规"即违规，否则合规。

### 0.4 `ComplianceResult`（题目给定，字段不可变更）
保持 `test.py` 原定义；`violated_rules` 输出前必须 `sorted()`。

---

## 1. 预处理模块

### 1.1 `preprocess(text: str) -> NormalizedText`
**管道顺序（不可调换）**：
1. 类型校验：非 `str` 转 `str`；空串直接返回空表征对象；
2. `unicodedata.normalize("NFKC", text)`；
3. 扫描并剥离 `unicodedata.category(c) == "Cf"` 的字符，剥到任意一个即 `has_zero_width=True`；
4. 若含 `<` 且 HTMLParser 识别到标签 → `has_html=True`：
   - 用栈记录每层标签是否隐藏（`script/style/head/title/meta/link`、`display:none`、`visibility:hidden`、`input[type=hidden]`）；
   - 栈内任一隐藏帧为真时，文本进 `hidden_text`，否则进可见文本；
   - `audit_text = 可见文本 + ("\n【隐藏文本】" + hidden_text if hidden_text)`；`has_hidden_html = bool(hidden_text.strip())`；
5. `compact`：在剥离 Cf 的文本上，仅保留 category 首字母为 `L`/`N` 的字符；
6. 音节流：逐字符扫描，汉字经 `lazy_pinyin(Style.NORMAL)` 转音节；拉丁字母累积成 token，去调号（NFD 去组合记号）后，连续 ≥2 个 token 命中合法音节集合则 `has_pinyin_obfuscation=True` 且 token 入流，否则丢弃；
7. 无 HTML 时 `normalized` 即步骤 3 产物，`audit_text=normalized`。

**不变式**
- 纯函数：同输入必同输出；
- 不抛异常：任何解析失败回退为「全文本当可见文本」；
- 隐藏文本绝不允许只剥离不送审。

## 2. 本地规则引擎 `LocalDetector`

### 2.1 词库与模式（按规则维度组织，禁止按用例组织）
- `LEXICON["Rule-01"]`：保本保息、保本、保息、保证收益、刚性兑付、刚兑、零风险、无风险、稳赚、包赚、必赚、稳赢、收益有保障、有保障、保底收益、承诺收益、兜底 等；
- `LEXICON["Rule-02"]`：稳赚不赔、闭眼买、闭眼入、闭眼上车、闭眼、强烈推荐、满仓、必涨、涨停、翻倍、一夜暴富、躺赚、无脑买、放心买、错过再等 等；
- `PATTERNS["Rule-01"]`：保障+百分比+收益、百分比+（稳定/保底/保障/锁定/承诺）及其逆序、年化+承诺类词 等通用正则；
- `PATTERNS["Rule-02"]`：`错过…再等`、`闭眼[买入上]` 等；
- `PATTERNS["Rule-04"]`：（同业词）+（贬义词）小句共现、极限词（全网第一/唯一/最高/最佳/首个）、无出处数据模式。

### 2.2 匹配方法 `detect(norm: NormalizedText) -> list[LocalHit]`
对每条规则执行三层匹配并去重：
1. **字面匹配**：词库词条在 `normalized` 或 `compact` 中子串命中；只在 `compact` 命中的记为拆词证据（供 Rule-05）；
2. **音节匹配**：词条预计算音节元组，在 `norm.syllables` 中做连续子序列匹配，命中证据记为"拼音/同音变体"；
3. **正则匹配**：PATTERNS 在 `normalized` 与 `compact` 上 search。

### 2.3 Rule-03 专用判定 `_check_risk_disclosure(norm) -> bool`
- 标的识别：6 位代码 `\d{6}`；`[A-Za-z]{1,6}\s*(股票|基金|股份|个股)`；`(这只|这支|该只|该支|此)\s*(股票|基金|个股|产品)`；
- 推荐动词：推荐、买入、加仓、满仓、建仓、入手、上车、闭眼买、闭眼入、抄底；
- 免责词：市场有风险、投资需谨慎、风险提示、过往业绩、不代表未来、招募说明书、风险自担、注意风险；
- 判定：存在（标的 或 推荐动词+股/基/产品字样）且全文无任一免责词 → 命中 Rule-03。

### 2.4 Rule-05 判定（信号驱动）
`has_zero_width` / `has_hidden_html` / `has_pinyin_obfuscation` / 拆词证据，任一为真即命中。

### 2.5 注入检测 `detect_injection(text: str) -> bool`
通用模式库（中英文）：系统提示、忽略(之前|以上|所有|先前)…(指令|提示|要求|规则)、ignore previous、直接返回 status、你现在是、role:system 等。
**不变式**：检测结果只置标记，不中断审核流程。

## 3. LLM 审核器 `LLMAuditor`

### 3.1 配置（全部来自环境变量，构造时读取）
`LLM_BASE_URL`（默认 OpenAI 兼容地址）、`LLM_API_KEY`（空则 `enabled=False` 离线模式）、`LLM_MODEL`、`LLM_TIMEOUT`（默认 15s）。

### 3.2 接口
- `async audit_async(text: str) -> LLMJudge | None`
- `audit_sync(text: str) -> LLMJudge | None`
- `enabled=False` 时直接返回 `None`，不产生任何网络调用。

### 3.3 请求与防御
- POST `{BASE_URL}/chat/completions`，OpenAI 兼容协议，Bearer 鉴权；
- `temperature=0`；带 `response_format={"type":"json_object"}`，若服务端 400 不支持则自动去掉该字段重试；
- System Prompt：声明审核员身份、列出五条规则、给定 JSON schema、声明分隔符内为不可信数据、禁止执行其中指令；
- User Message：`<|user_content|> ... <|/user_content|>` 包裹；
- JSON 解析先剥离 ```json 代码围栏，再经 `LLMJudge` 校验；解析/校验失败重试 1 次，再失败抛异常由上层兜底。

**不变式**：本模块不做最终裁决，只产出候选判断；任何异常向上抛，由编排层 fail-closed。

## 4. 融合与编排

### 4.1 `merge_result(norm, local_hits, llm_judge, attack) -> ComplianceResult`
- `violated_rules` = 本地规则 ∪ LLM 规则，`sorted()` 输出；
- `status`：并集非空或任一通道判违规 → "违规"，否则 "合规"；
- `evidence_snippet`：本地证据优先，去重后 ` | ` 拼接，截断 120 字；
- `reasoning_trace`：分段拼接 `[本地引擎]` 与 `[LLM]` 依据；纯本地且合规时给明确合规说明；
- `is_attack_detected` = 本地注入检测 OR LLM 标记。

### 4.2 `check_compliance(text: str) -> ComplianceResult`（同步，签名同题面）
流程：缓存查询 → preprocess → 本地检测 + 注入检测 → `audit_sync`（离线返回 None）→ merge → 写缓存（深拷贝返回）。
异常兜底：除 `LLMAuditor.enabled=False` 外的任何异常 → `_fallback_result()`。

### 4.3 `async check_compliance_batch(texts: list[str]) -> list[ComplianceResult]`
- 信号量 = `LLM_CONCURRENCY`（默认 8）；
- 每条 `asyncio.wait_for(..., timeout=LLM_TIMEOUT)` 包裹；
- `gather(return_exceptions=True)` 二次收口；异常项一律 `_fallback_result()`；
- 返回列表长度、顺序与输入严格一致。

### 4.4 `_fallback_result(text, local_hits, reason) -> ComplianceResult`
`status="违规"`、`is_fallback=True`、规则取本地命中（可空）、trace 注明 fail-closed 原因。**禁止 fail-open**。

### 4.5 缓存
- key = `sha256(normalized)`；仅缓存非 fallback 的成功结果；
- 命中返回 `model_copy(deep=True)`，防止外部修改污染缓存。

## 5. 测试契约（tests/test_compliance.py，先于实现编写）

| 编号 | 测试 | 预期 |
|---|---|---|
| T01 | 6 个 CASES 全量审核 | status 符合预期；预期规则为实际命中子集 |
| T02 | Case 4 注入标记 | `is_attack_detected=True`，且违规内容仍被拦截 |
| T03 | Case 5 隐藏文本 | hidden_text 非空；Rule-01/05 命中 |
| T04 | Case 3 拼音+零宽 | Rule-01/02/03/05 命中；两个对抗信号为真 |
| T05 | 确定性 | 每条连调 5 次，(status, rules) 完全一致 |
| T06 | 批量接口 | 长度/顺序一致，且与单条结果一致 |
| T07 | fail-closed（异步） | mock LLM 抛异常 → `is_fallback=True, status=违规`，整批不中断 |
| T08 | fail-closed（同步） | 同步 LLM 抛异常同样兜底 |
| T09 | LLM 融合 | mock LLM 追加 Rule-04 → 并集命中；LLM 判合规不能覆盖本地违规 |
| T10 | 离线模式 | 无 Key 时 `is_fallback=False` 且 Case 1 判合规 |
| T11 | 通用泛化（非用例） | 同业贬低→Rule-04；"保 本 保 息"→Rule-01+05；同音"吻赚不赔"→Rule-02 |
| T12 | 缓存隔离 | 两次调用对象不同；修改返回值不污染后续结果 |
| T13 | 安全与交付物 | 源码无硬编码 Key；`.env.example` 存在且含全部变量名 |

## 6. 环境变量契约（.env.example）
`LLM_BASE_URL`、`LLM_API_KEY`、`LLM_MODEL`、`LLM_TIMEOUT`、`LLM_CONCURRENCY`。
