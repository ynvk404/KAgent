# Token accounting + auto-compaction: independent verification and proposal

Ngày báo cáo: 06-10-2026. **AUDIT + VERIFY + PROPOSAL ONLY.**

**Verdict: MATERIAL ACCOUNTING/COMPACTION FIXES NEEDED.** Có lỗi làm sai quyết định compact và đánh giá hiệu quả compact, omission đối với Gemini replay, và thiếu Anthropic usage telemetry. Chưa chứng minh lỗi blocking/P1 trên một provider thật. Threshold hiện tại là soft trigger; vượt threshold không đồng nghĩa vượt context window. Không sửa production, tests cũ, Phase A/B, structured handoff hoặc auto-continue.

## A. Căn cứ và initial state

- Đã đọc `AGENTS.md` và request đính kèm. Source hiện tại là authority; số liệu trong tài liệu Phase B được xem là lịch sử, không nhận làm kết quả của audit này.
- Branch `main`, HEAD `4f7417e` (`fix: harden Phase B tool result offloading`); commit trước `4c4bb63` chứa Phase A hardening. `git status --short` ban đầu rỗng. `git worktree list` có workspace hiện tại và hai entry cũ prunable; không sửa chúng.
- Phase B đã nằm trong committed production: `ResultRetention`, session-bound reader, sanitized artifact store, preview/ref, continuation index, compaction/resume integration. Đây không phải Phase B draft cần implement tiếp.
- Gemini artifact có sẵn: `tests/agent/test_token_accounting_audit.py`, gồm bảy characterization tests. Không tìm thấy báo cáo token-accounting riêng trong `docs/`; chỉ biết severity P1 được nêu cho AC-GATE-01 trong request. Không tự gán severity Gemini cho các finding còn lại.
- Thêm một file **audit-only** `tests/agent/test_token_accounting_independent_verify.py` để kiểm tra production control paths, encoder/session replay và response parsing. Các assertion mô tả behavior hiện tại, không phải desired regression contract sau fix.

## B. Current architecture map

```text
PRE-TURN — Agent.run_inner
  reconcile history/tool calls + elide persisted workflow receipts
  → rebuild system prompt (static policy + skill list + state notices + Phase B index)
  → expand incoming @file
  → history estimate + expanded incoming estimate + enabled registry schemas
  → soft threshold AND minimum non-system history AND failure circuit breaker
  → optional auto_compact

WORKING REQUEST
  append RAW incoming user to history; save; deepcopy history
  → planner guidance (system), intelligence (user), curated recall (user)
  → SessionMemory observations (user), saved-memory catalog (user), WorkflowState (user)
  → replace latest working user with expanded @file text
  → guard: Phase B admission → Phase A eligible tool-output reduction
  → refresh whole-target/requested-goal guidance
  → ChatRequest + current tool schemas → provider-specific encoder → provider

MID-TURN
  provider assistant + tool calls → execute through existing Registry permissions
  → sanitized full UI event → sanitized tool message in working/history
  → Phase B eligible source admission: artifact + preview/ref OR inline fallback
  → guard before subsequent request: recompute current represented messages
  → bounded/elided text only in request; full artifact never implicitly hydrated

COMPACTION
  history snapshot (exclude primary system from summary input)
  → sanitized bounded serialized history, ≤22,000 chars + compaction system prompt
  → separate, tools-free summary ChatRequest, reasoning off where supported
  → parse/merge bounded SessionMemory; retain latest useful user/final answer
  → rebuild system + Phase B continuation; preserve structured ref descriptors
  → accept if HISTORY estimate saves max(64 tokens, 10%)
  → replace memory/history; learn/save/snapshot → restore on resume

USAGE
  OpenAI-compatible / Gemini parser → ChatResponse.usage
  → Agent._record_request_metrics → bounded MetricsCollector → explicit JSONL export
  Anthropic parser currently omits usage. Idle UI uses approximate history + schemas.
```

Source anchors: `src/agent/agent.py:3300`, `:3349`, `:3413`, `:3524`, `:3541`, `:4250`, `:4280`, `:4318`, `:4898`, `:5121`, `:5255`, `:5304`; `src/agent/tool_results.py:159`, `:189`; `src/session/store.py:246`, `:438`.

Một exception quan trọng: main-loop guidance được refresh **sau** guard (`agent.py:3529`), nên guard không phải điểm cuối cùng nhìn đúng request. Malformed-call retry có guard riêng. Whole-target final synthesis guard bằng registry đầy đủ dù request không có tools; synthesis retry thêm instruction sau guard. Không có mandatory hard-budget check ở `_chat_for_turn` hoặc `_chat_for_compaction`.

## C. Accounting table

Ký hiệu: **M** = `approximate_message_tokens` (`agent.py:5415`), từng content/reasoning và name+arguments dùng integer floor `/4`; **T** = `tools_token_estimate` (`:1605`), JSON registry `/4`; **G** = pre-turn compact gate; **W** = guard; **U** = idle status/UI; **B** = Phase B admission. W/B luôn đo represented `working`, không đo disk artifact. U ở `src/ui/core/app.py:1368`, status ratio ở `src/ui/widgets/status_bar.py:127`. Actual usage không tham gia G/W/U/B.

| Component / source | Gửi provider? | Estimator hiện tại | G | W | U | B | Cache / invalidation và sai lệch |
|---|---|---|---|---|---|---|---|---|
| System prompt: `system_prompt.py:361`, `agent.py:1756` | Có; Gemini/Anthropic gom system riêng | M(content); nằm trong history[0] | Có | Có | Có | Có | Rebuild mỗi turn, scope/profile/state thay đổi; bao gồm policy notices, skill catalog và Phase B index. Không đo adapter framing. |
| History content: `agent.py:1602`, `:3411` | Có nếu encoder giữ message | M(content) | Có | Có | Có | Có | Không token cache; W/B recompute sau replacement. Provider có thể bỏ empty assistant, merge tool turns; M không phản ánh các khác biệt này. |
| Role/message framing/envelope: `openai.py:390`, `anthropic.py:encode_request`, `gemini.py:encode_message` | Có dưới representation riêng từng provider | Không có per-message overhead | Không | Không | Không | Không | Undercount tích lũy theo số message; JSON schema envelope đã nằm một phần trong T nhưng message envelope chưa có. |
| Assistant `reasoning_content`: `types.py:55`, `openai.py:403` | Chỉ DeepSeek/Kimi hợp lệ cùng provider/model và request mode | M(reasoning_content), bất kể encoder có gửi hay không | Có nếu stored | Có | Có nếu stored | Có | Không cache. Có thể **overcount** sau switch/thinking-mode change; state của provider khác không được replay nhưng vẫn count. |
| Gemini ordered `gemini_parts`: `gemini.py:186`, `:250`, `:335`, `:443`; `store.py:246`, `:442` | Chỉ cùng Gemini/model provenance; `safe_replay_part` lọc lại | **Không**; chỉ visible content/tool calls có representation tương ứng được M tính | Không tính phần riêng | Không tính phần riêng | Không tính phần riêng | Không tính phần riêng | Unsigned thought text bị loại; signed thought text và signatures replay. Visible text/functions trong parts thay thế generic representation, không được cộng cả hai. |
| Assistant tool-call function name: `agent.py:5422` | Có | M: `(len(name)+len(args))//4` | Có | Có | Có | Có | Không lỗi precedence: cả tổng nằm trong ngoặc. Floor loss <1 token/call theo heuristic. |
| Assistant tool-call arguments: cùng anchor | Có, string hoặc provider parse thành JSON object | M cùng name | Có | Có | Có | Có | No cache. JSON whitespace/default normalization khác wire; arguments không có size budget ở estimator. |
| Tool-call ID, tool-message name/id, tool-call provider signature: `types.py:43`, `openai.py:397`, `gemini.py:477` | Tùy provider: OpenAI IDs/name, Anthropic tool_use IDs, Gemini function names/signatures | Không, trừ assistant function name ở row trên | Không | Không | Không | Không | Omits visible envelope identifiers và opaque signature trên fallback function-call path. Internal tool status/provenance/ref dict không tự gửi. |
| Incoming RAW user: `agent.py:3395` | Có trong history/resume; lượt hiện tại gửi expanded variant | M trong working; G dùng `len(expanded)//4` | Có, expanded | Có | Sau append: raw | Có, expanded | Không double-count incoming trong G: đo trước append. Idle U không có pending input. Raw history không giữ toàn bộ @file expansion. |
| Expanded @file/content: `mentions.py:165`, `:210`; `agent.py:3340`, `:3490` | Có trong current working | `len(expanded)//4`, rồi M | Có | Có | Không, ngoài mention text | Có | 64KiB/file, dedup resolved files; **không aggregate cap** cho nhiều files. Không có hard send ceiling khi input không reducible. |
| SessionMemory render: `system_prompt.py:466`, `agent.py:3467` | Có, user observation + short system notice | M khi trong working | **Không observation**; chỉ system notice | Có | Chỉ notice; không observation | Có | Render fresh mỗi turn, ≤10,000 chars + wrapper. Merge caps lists/240-char item. Sau compact, acceptance không đo observation này. |
| Curated memory recall: `agent.py:1309`, `:3455`; `memory/store.py:470` | Có nếu top-5 search có matches | M khi trong working | Không | Có | Không | Có | Fresh per-turn search; ≤12,000 chars. Có thể trùng kiến thức catalog nhưng đó là context thực sự được gửi, không phải accounting double-count. |
| Saved-memory catalog: `agent.py:3474`; `memory/store.py:325` | Có nếu memory store/index không rỗng | M khi trong working | Không, trừ system notice | Có | Chỉ system notice | Có | Index ≤200 rows và ≤8,000 chars, render fresh. Đây khác Phase B result index. |
| WorkflowState render: `system_prompt.py:515`, `agent.py:3480` | Có nếu state liên quan | M khi trong working | Không observation; chỉ notice | Có | Chỉ notice | Có | ≤6,000 chars + wrapper; smaller per-value caps. Injection là rendered snapshot cho lượt đó, không recount mutable workflow object ngoài messages. |
| Intelligence context: `agent.py:1360`, `:3444`; `intelligence/store.py:492` | Có nếu search score≥6, top-5 | M khi trong working | Không | Có | Không | Có | ≤10,000 chars. G omission thêm tối đa ~2.5k heuristic tokens, không được Gemini test cover. |
| Planner/whole-target/requested-goal/retry/synthesis guidance: `agent.py:3417`, `:2887`, `:2922`, `:3640`, `:4158` | Có | M nếu nằm trong list đang được đo | Initial guidance không | Có trước guard; **late refresh/retry sau guard chưa đo lại** | Chỉ guidance persisted vào history | Có khi admission nhìn list | Recomputed từng phase; no shared final estimate. Pure working guidance thường không persist. |
| Phase B preview/ref header: `tool_results.py:98`, `:228`; `agent.py:4364` | Có qua replacement.content | M(content) | Có nếu history đã thay | Có | Có nếu history đã thay | Có | Payload disk và transient original không cộng. W recount exact rendered replacement; descriptor metadata không phải request text. |
| Phase B result continuation index: `tool_results.py:164`; `agent.py:1778`, `:5391` | Có trong rebuilt primary system | M(system content) | Có khi rebuilt | Có nếu working system đã chứa | Có khi rebuilt | Có nếu working đã chứa | ≤32 refs; không lazy hydrate. New admission tăng reference map nhưng không update current working system; index xuất hiện khi rebuild/compact/next turn. Vì thế chưa gửi thì chưa count, không phải omission phantom catalog. |
| Tool schemas: `registry.py:139`, `agent.py:1605`, `:3550` | Có nếu `req.tools`; không có ở compaction/synthesis | T = generic JSON toàn registry; trace estimate dùng JSON supplied tools | Có, trừ opts.tools=False | Theo opts, synthesis overcounts | Registry đầy đủ mặc định | Theo caller schemas | Key chỉ sorted names. Register tên mới đổi key; duplicate bị reject; không unregister API. Exposed mutable map/schema gap chưa có production mutation chứng minh. Provider normalization chưa phản ánh hết. |
| Other provider continuation state: `Message`/`ToolProvider` fields | Không có response_id/Anthropic thinking-block continuation field hiện tại; DeepSeek/Kimi/Gemini như các row trên | Không thêm phần khác | Không | Không | Không | Không | Không suy diễn opaque fields không tồn tại. Generic status/ref/provenance controller-only không được encoder serialize. |
| Compaction summary: `agent.py:5283`, `:5304`, `:5328` | Structured: observation lượt sau; fallback: user summary in history; recent turn cũng gửi | M(history); structured observation chỉ M(working) | Fallback có; structured observation không | Có khi injected | Fallback có; structured notice/recent thôi | Có khi injected | Acceptance saves history tokens, không projected request; synthetic reproduction thấy next pressure tăng dù acceptance pass. Raw fallback summary không có explicit character cap ở apply method, ngoài response output budget. |
| Actual provider input/output/cache/thinking usage: `metrics.py:18`, `:29`, `:47`, `agent.py:4280` | Là RESPONSE telemetry, không request context | `openai_chat_usage`, `gemini_usage`; Anthropic thiếu | Không | Không | Không | Không | Bounded collector 2048 records; explicit JSONL export. Không nằm session messages/store serialization; idle UI không hiển thị billed usage. Cached/reasoning subset semantics được giữ cho OpenAI/Gemini. |

Các capped injection độc lập có tổng tối đa khoảng **46,000 chars ≈11,500 heuristic tokens**, chưa tính wrappers/planner. Đây là tổng các upper bounds, không khẳng định mọi invocation đều đạt tối đa. Phase B result index đã nằm trong pre-turn system; không gộp nhầm với saved-memory catalog bị omit.

## D. Gemini finding verification matrix

Severity ở đây: P1 cần evidence failure nghiêm trọng/blocking thực tế; P2 là sai control decision/telemetry/config đáng sửa; P3 là hardening lý thuyết. Không có external-provider overflow measurement.

| Finding | Gemini severity | Codex verdict | Actual severity | Evidence | Action |
|---|---|---|---|---|---|
| AC-GATE-01 | P1 theo request | **DESIGN CHOICE BUT NEEDS HARDENING**; deadband mechanism confirmed, exact 19.3k/severity overstated | P2 | `agent.py:3353`, `:5427`; existing production characterization deliberately expects no compact for modest history; new real-inventory path sends >soft threshold | Separate soft trigger, worthwhile-history gate, hard model budget; không chỉ xóa min gate |
| GROQ-BASE-01 | Không cung cấp | **Confirmed** baseline exceeds trigger; overflow severity overstated | P2 policy gap | Compact runtime-style registry: 10,398 fixed estimate >5,500; no provider API executed | Explain/validate unattainable trigger, model budget separate; không hardcode 8–10k |
| INJECT-CTX-01 | Không cung cấp | **Confirmed** materially incorrect projected pressure | P2 | Real Agent.run: pre 7,526 < threshold 8,526 < sent 10,013; history qualifies; 0 compact attempts | Shared projected request construction/count, include conditional injections |
| GEMINI-PARTS-01 | Không cung cấp | **Partially correct**; unsigned-thought proof false positive; signed replay/signatures omission confirmed | P2 | Real filter + save/load + encoder keeps signed 8,000-char text/4,000-char signature while estimate=1 | Count selected replay representation once; signatures separate uncertain estimate |
| ANTHROPIC-USAGE-01 | Không cung cấp | **Confirmed** telemetry bug | P2 telemetry, không context-control bug | Mock API JSON through actual `_chat_once` → Agent metrics usage=None | Parse input/output/cache semantics, không use previous usage as next budget |
| TOOLS-CACHE-01 | Không cung cấp | **Design gap / theoretical**; chưa confirmed production stale path | P3 | Names-only key + artificial tool/plugin mutation reproduce; no production same-name schema mutation/reload found | Optional encoded-schema digest/revision contract; no urgent schema refactor |
| CTX-WINDOW-01 | Không cung cấp | **Design gap**, partially provider/model-aware already | P2, model/config-dependent | Groq clamp, Kimi model map/default-only override, general 16k; switch callback recomputes | Model budget metadata + output reserve + override/fallback; preserve soft trigger |

### AC-GATE-01: intent, measurements, actual consequence

`auto_compact_threshold` đo **history including system + incoming expansion + schemas**, nên không phải history-only threshold. Code và `test_characterizes_auto_compact_trigger_components` thể hiện **heuristic request-pressure soft trigger**, phải có đủ non-system history để summary có ý nghĩa. `minimum_compactable_history_tokens(T)=max(2048, floor(T/3))` tránh summarize chủ yếu fixed overhead. Acceptance còn đòi ≥64 hoặc 10% history savings. Đây là intent có test support, không phải invariant “≥T thì compact bắt buộc chạy”.

Fixed overhead không giảm bằng summarize. Tuy nhiên minimum-history ratio dựa trên toàn T có thể trì hoãn compaction trong khi reducible history đã có ích; nó cũng không biết budget headroom, size các injections hay prospective savings. Giữ worthwhile-compaction policy, nhưng không dùng nó làm lý do gửi vượt **hard** budget nếu có budget đó.

Đo qua actual constructors/schema giống runtime, 18 built-in enabled skills, 32 schemas (31 startup tools + Phase B reader), target fixture `http://127.0.0.1:3000`, reasoning off, tooling minimal, không plugins/MCP/custom skills:

| Prompt profile | Prompt M | Schemas T | Fixed estimate | +minimum history ở T=16k |
|---|---:|---:|---:|---:|
| Full | 11,111 | 6,776 | 17,887 | 23,220 |
| Compact | 3,622 | 6,776 | 10,398 | 15,731 |

**19,312 không phải con số production hiện tại.** Gemini test hardcode 13,979 và không dựng registry. Với full fixture hiện tại, ~23,220 là baseline+5,333, **chưa** incoming/injections, không universal exact request threshold. Thêm 2,500-token history rồi chạy Agent.run full: gate không compact, fake provider nhận estimate **20,840**. Vì baseline đã >16k, ngay cả sau compact floor này vẫn có thể >soft trigger.

Guard nhìn working nhưng chỉ offload/reduce adaptive tool messages; user, assistant, system, preserved tool receipts không được arbitrary truncate. Floor 2,000 chars/tool và safety target `T-max(128, round(.02T))` cũng có thể không khả thi. Nó vẫn dispatch khi còn pressure; nếu không có tool messages, không emit residual warning. Existing Phase B documentation cũng nêu rõ không bảo đảm hard model ceiling (`docs/phase-b-tool-result-offloading.md:244`). Vì vậy **P1 chỉ từ “16k→19.3k” là không supported**. Fake dispatch >soft threshold được chứng minh; actual provider rejection không được thử.

### INJECT-CTX-01: materially wrong decision

SessionMemory, workflow, intelligence, recalled curated facts, saved-memory catalog và planner guidance được thêm sau G. Chúng đều conditional, không phải luôn inject. Short system notices được G count; observation data chưa. Bounds ghi trong table. ResultRetention continuation có trước G qua system rebuild, nên phần finding nói mọi catalog bị omit phải sửa.

Audit-only real Agent.run dùng production-shaped memory lists, history 6,000 tokens đáp ứng min gate, tools=False để cô lập injection khỏi planner/schema. G=7,526, T=8,526; working được gửi=10,013, delta=2,487; compaction probe không được gọi. Nếu G dùng projected working, condition pressure và min history đều true. Đây chứng minh control decision materially khác, không chỉ hai estimator khác nhau.

W nhận toàn injection nhưng không có reducible tools nên không sửa được request và không báo residual. Khi có eligible tools, omission có thể đẩy pressure sang Phase A/B tool degradation thay vì pre-turn compact; đó là consequence suy ra từ guard, chưa đo UX riêng. Actual overflow cần model budget/provider evidence, không suy từ soft crossing.

### GEMINI-PARTS-01: real encoder and provider semantics

Non-stream parser (`gemini.py:186`) và stream parser (`:250`) đều gọi `safe_replay_part`. Unsigned `thought=True,text=...` bị discard. Signed text/thought, visible text và function calls được retain theo thứ tự; session save/load lọc tương tự. `encode_message` ưu tiên toàn retained parts **thay cho** generic content/calls nếu provider/model match, gồm normalization `models/` prefix. Mismatch fallback sang visible content/functions, không gửi signatures.

Gemini audit original đưa **unsigned** thought vào Message bằng tay rồi chỉ assert M=3; production parser/session/encoder không replay phần đó. Kết luận rằng 2k thought-text tokens fixture đó vào request là **false positive**. Nhưng signed fixture trong verification thực sự round-trips và encoder gửi 8,000-char signed text + 4,000-char signature, M chỉ 1 visible token. Existing reasoning continuity test cũng chứng minh signed part có production-supported path.

Google mô tả returned thought text là summaries, không toàn hidden reasoning. Với Generate Content API mà KAgent dùng, signatures tăng input-token count khi replay; không lấy `thoughtsTokenCount` của response cũ làm replay token count. Nguồn đúng protocol: [Generate Content thinking](https://ai.google.dev/gemini-api/docs/generate-content/thinking), [Generate Content token counting](https://ai.google.dev/gemini-api/docs/generate-content/tokens). Các trang `/docs/thinking` mới nói Interactions API, không lấy ví dụ đó áp cho encoder REST hiện tại.

Minimal rule: lựa chọn replay representation theo cùng eligibility như encoder; estimate retained visible/private text, functions và opaque signature overhead **một lần**. Không cộng generic visible content/calls thêm khi chúng đã nằm trong replay parts. Không estimate unsigned discarded thoughts. Signature estimate phải ghi uncertainty; base64 length/4 là heuristic có thể dùng làm conservative reservation, **không phải verified conversion sang provider tokens**. Exact billing/context contribution của fixture signed text không được đo bằng API; privacy fields vẫn opaque, không log nội dung.

### GROQ-BASE-01: conservative trigger, not context size

Runtime backend Groq luôn compact prompt (`runtime.py:1558`) và `min(config_threshold,5500)`; nếu config≤0 thì vẫn 5500. Cap áp cho tất cả Groq models, default `openai/gpt-oss-120b`, không phải một model nhỏ có 5.5k window. Trong code không có Groq context-window metadata. Minimal/full tooling chọn prompt guidance/discovery behavior, **không filter schemas khỏi registry**; inactive skill permission gates cũng không loại schemas. Runtime thêm plugins/MCP khi configured, càng không thể suy registry nhỏ hơn chỉ do Groq.

Real-inventory compact baseline 10,398. Groq minimum-history gate=2,048, nên startup/modest history chưa compact; ≥2,048 history có thể request compact, nhưng summary không thể bỏ fixed prompt/schemas. Fixture 2,500 history tokens gọi compact probe một lần (probe trả False), gửi estimate 13,351. Không có endless same-turn compact loop: gate kiểm tra đầu mỗi turn; ineffective compaction có thể tăng failure counter đến3 và suppress những lượt sau.

[Groq model documentation](https://console.groq.com/docs/model/openai/gpt-oss-120b) ghi 131,072 context cho default model. Vượt 5,500 vì vậy không chứng minh overflow của model đó. Rate-limit quota hoặc service-tier limits là một budget khác; code không gắn 5,500 với một quota được xác minh, không invent lý do cho constant. Consequence confirmed là soft trigger luôn dưới fixed floor, compaction/guard pressure khó giải quyết, có thể degrade tool context không cần thiết. UI idle có thể hiện pressure cao; không đo cadence/noise live UI riêng. Không đề xuất một magic replacement 8–10k.

### ANTHROPIC-USAGE-01: dropped response telemetry

`AnthropicClient.chat` chỉ retry wrapper; omission nằm trong `_chat_once` (`anthropic.py:118`), return ChatResponse thiếu usage. Original source-inspection test nhìn wrapper, nên có thể pass ngay cả khi helper đã parse usage: đó không phải durable regression test. Verification dùng mocked HTTP transport returning realistic usage JSON, chạy actual Anthropic parser + Agent.run + metrics, successful request có usage=None.

Anthropic client không implement StreamingClient; bật streaming trong agent không tạo Anthropic SSE route, vẫn `chat`. Vì vậy không có streaming-parser khác cần sửa ở tree này. OpenAI/Gemini có cả non-stream/stream usage paths đã kiểm tra qua focused tests/source. OpenAI transport chỉ request `include_usage` khi label=`openai`; compatible/Groq streaming usage phụ thuộc endpoint trả, không khẳng định guaranteed complete telemetry ở mọi endpoint.

Anthropic fields: input_tokens, output_tokens, cache_read_input_tokens, cache_creation_input_tokens; cache creation có thể có lifetime breakdown. Total input phải cộng uncached+read+creation, thay vì gán raw input_tokens thành full input và xem read là subset của số đó. [Anthropic prompt-caching documentation](https://platform.claude.com/docs/en/build-with-claude/prompt-caching) xác nhận phép cộng. Minimal normalized TokenUsage có full input và cached-read subset; cần giữ cache-creation riêng nếu muốn export billing breakdown, không gộp thành cache hit. Không invent separate reasoning tokens nếu API không cung cấp. Usage phục vụ telemetry/calibration, không thay prospective estimation/control.

### TOOLS-CACHE-01: stale by construction, production path not established

Key sorted tool names bỏ description/schema content. Register tên mới làm key khác; duplicate name bị reject; không có unregister public API. Mutable registry map cho phép replacement, MCP schema trả mutable dict, plugin giữ mutable PluginConfig. Verification với actual CommandPluginTool + artificial cfg.description edit tái hiện stale estimate.

Search production không tìm thấy runtime same-name schema edits/replacement/hot tool-list reload: MCP list_tools dùng startup discovery; returned `_schema_obj`/`_desc` không cập nhật nội bộ. Plugin config transaction thay cfg fields/deepcopy, không mutate held plugin schema objects như fixture. Provider/model switch thay client/profile/threshold, không rebuild/filter registry; session-bound reader có scoped registry view riêng. Skill metadata hot reload làm system catalog khác, nhưng LoadSkill/ReadPayloads schemas vẫn generic names, không enumerate changing descriptions từ skill list.

Vì vậy không nâng artificial mutation thành confirmed production bug. Có design gap nếu future plugin/MCP mutation được hỗ trợ. Minimal digest của serialized schema hiện gửi hoặc revision bắt buộc cho every supported mutation đủ; revision tăng ở register-only **không** giải quyết in-place mutations nếu vẫn public mutable contract.

## E. New missed findings, limited to accounting

### TA-NEW-01 — compaction effectiveness checks history, omits new memory projection (P2)

Exact path: `apply_compaction_summary` (`agent.py:5304`) dựng `next_memory`, primary system chỉ chứa carried-state notice, structured summary không nằm trong next_history; compare `approximate_message_tokens(history_snap)` với `approximate_message_tokens(next_history)` ở `:5355`. Observation được inject sau đó tại `:3467`. Acceptance vì vậy đo hai representation khác với next working request.

Reproduction gọi **actual apply method**, không mock acceptance/merge/render/save. Old history estimate **2,991**, new history **1,527**, savings **1,464** vượt required10%/64. Rendered merged memory + wrapper **9,956 chars**; projected next context **4,016**, tăng **1,025** dù compact được accepted. Fixture summary là synthetic các mục observations theo headings có thật, items được production merge cắt ≤240 chars. Không cho rằng model thực tế luôn generate summary này; parser/acceptance chấp nhận loại output đó, và declared savings invariant không hold cho projected request.

Tối thiểu phải compare projected before/after **cùng request semantics**, gồm previous/next memory, catalog/workflow/ref state và cùng pending input/tools. Không chỉ bù tokens vào UI. History-only stats vẫn hữu ích nhưng không đủ để gọi compact hiệu quả. Compacted state có thể làm resumed request lớn hơn; existing session schema không cần đổi để sửa decision.

### TA-NEW-02 — tools-free synthesis guard counts full schemas (P2)

Exact path `_whole_target_synthesis` (`agent.py:4158`): append synthesis instruction → `guard_working_context(working, emit, None)` → ChatRequest không set tools. Guard opts=None dùng `tools_token_estimate`. Generic max-step synthesis (`:4052`) cũng có pattern guard opts của turn nhưng không attach tools vào synthesis request.

Actual synthesis method, actual runtime-style32 schemas, fake text response: messages before guard **6,622**, threshold **7,622** (headroom ~1k); guard cộng **6,776** schemas không gửi, shrink adaptive tool payload12,000 chars về floor. Fake provider nhận tools=None, messages estimate **4,128**. Đây là **unnecessary representation loss** chứng minh được, không chỉ telemetry mismatch. Không thay preserved semantics/permission hay normalization.

Fix: estimator/guard nhận actual request tool-set, tools-free synthesis=0; retry instructions và refreshed guidance phải có final measurement sau insertion. Không yêu cầu synthesis policy hoặc workflow rewrite.

Các observation khác được gộp vào existing gaps, không tạo thêm findings thiếu reproduction: tiny-message envelope floor, late guidance after guard, incompatible reasoning-state overcount, no aggregate @file cap. Không audit lại security findings Phase B.

## F. Correct invariants

1. **Projected pressure:** pre-turn dùng đúng projected next request: history+expanded input+conditional injections+actual request schemas+eligible provider-private replay+framing estimate. Không dùng current conversation history như full prospective request.
2. **Compactable history:** chỉ history mà summarization có thể giảm, không primary system, fixed schemas, unrelated fresh injected data. Không lấy fixed overhead để tự kết luận summary có savings. Minimum history vẫn có thể là policy, nhưng không hard-budget authorization.
3. **Soft versus hard budget:** compact threshold là proactive/economic trigger; model input ceiling là independent dispatch constraint. Exceed soft trigger có thể hợp lệ; khi known hard budget không khả thi thì explicit context-capacity outcome, không silently dispatch hoặc destructively trim authoritative/preserved context.
4. **Worthwhile compact:** acceptance so sánh projected before/after trong cùng context/provider/tool mode, kể cả memory render tăng sau summary; useful history savings được report riêng. Input vẫn oversize sau successful compact phải được phát hiện lại, không assume success làm request safe.
5. **Provider-private replay:** chỉ count thứ encoder sẽ gửi cho active provider/model/mode. Ordered Gemini parts thay generic content/functions khi eligible, signatures count riêng; discarded thought/private state không count. Không log/decode opaque state, không cộng response reasoning output như input replay.
6. **Represented tool results:** W/B count preview/ref/elision đang trong working, không full artifact/UI/original; sau replacements đo lại current content. Full artifact không phải input/evidence/approval. Preserved receipts không bị ép truncate để satisfy quota.
7. **Actual usage:** normalized response telemetry theo provider semantics, cache/reasoning không double-count; missing fields giữ None. Không lấy last actual usage làm next context estimate hoặc durable model-limit metadata.
8. **Every dispatch:** request context thay đổi cuối cùng phải được estimate trong actual request mode; final synthesis/compaction không tools, guidance/retry included. UI idle/Phase B marginal estimate có semantics riêng, không buộc equal cùng total.
9. **Recovery/switch:** failed summary không publish projected savings/threshold; failure counter là policy riêng. Supported provider/model transaction recompute budget/profile sau success; restored session dùng live config/model, không recalled authorization hoặc old provider quota.

## G. Minimal architecture proposal — shared primitives, separate semantics

**Nên có shared estimator primitives và projected-context builder. Không cần một framework/class lớn.** Separate consumers hiện tại có lý do: G prospective next turn, W current represented request, U idle conversation pressure, B marginal result representation. Lỗi nằm ở omissions/representation/tool-mode drift, không phải việc các số khác nhau.

Một helper module nhỏ, ví dụ `src/agent/context_estimate.py`, có hai trách nhiệm hẹp:

- Message/request estimate dùng active backend/model/mode và actual schemas, components có named breakdown. Reuse provider replay eligibility helper của encoder thay duplicating incompatible matching logic. Không estimate toàn JSON wire bằng `/4` rồi gọi đó “actual tokens”; JSON syntax/context tokenization không tương đương.
- Build projected working context qua cùng render/search primitives hiện có. Pre-turn build theo tentative history, expanded input và session state; sau compact rebuild theo next state. Recall/planner events chỉ emit khi turn thật chuẩn bị, tránh duplicate search side effects/UI events. Không đưa runtime workflows vào estimator.

Suggested breakdown (dataclass chỉ nếu có ích; dict/named result cũng đủ):

| Field | Semantics |
|---|---|
| system_tokens | Actual primary/additional system text cho request đang đo |
| history_tokens | Represented history text + eligible state, không incoming/injection |
| incoming_tokens | Expanded input cho turn, zero ở idle/synthesis nếu không có pending input riêng |
| injected_tokens | Conditional observations/catalog/recall/intelligence/guidance |
| tool_schema_tokens | Actual request tool-set; zero khi tools-free |
| provider_private_tokens | Selected replay-only fields chưa count trong other components |
| framing_tokens | Approximate per-message/call adapter overhead |
| estimated_total | Sum mutually exclusive components; conservative approximation |
| compactable_history_tokens | Non-system eligible history contribution; không fixed floor |
| reducible_tool_tokens / fixed_floor_tokens | Capacity và non-reducible contribution, dùng policy/diagnostics |
| soft_compact_threshold | Trigger policy, không model context window |
| hard_input_budget / reserved_output_tokens | Derived từ verified model metadata/explicit override; unknown có trạng thái riêng |
| available_budget / confidence | Hard headroom nếu biết; heuristic/unknown không giả làm verified |

Threshold/budget có thể là object/helper **khác** với raw estimate. Không cần nhét mọi config field vào estimate. Không cần persist per-message token fields hoặc tokenizer caches vào session.

Consumer contracts:

| Consumer | Dùng estimate nào | Decision |
|---|---|---|
| Pre-turn G | Prospective request với expanded user + actual conditional injections | Soft pressure + meaningful history → compact; independent hard check không bị min gate bypass |
| W | Actual current working và tools của request sắp gửi | Existing Phase B/A reduction + recount; report residual/fixed floor; dispatch hard-budget decision riêng |
| U | Idle history breakdown; optionally projected static carried context, incoming=0 | Label “hist/estimated req” và soft-pressure ratio rõ; active request snapshot riêng nếu muốn, không show billed usage như estimate |
| B | Marginal current result → preview+ref, actual schema delta; current pressure | Giữ selective trusted adapters/floor/proportional allocation; không hydrate/pay full artifact tokens |
| Compaction acceptance | Projected old/new với cùng pending input/provider/tools | Savings invariant; history stats separately |
| Provider metrics | Actual input/output/cache fields | Telemetry/export/calibration, không gate replacement |

UI cache hiện chỉ `(transcript length,busy)` nên nếu reuse breakdown/budget, thêm context/schema/runtime revision vào invalidation. Không khẳng định một stale live-UI sequence đã reproduced; đây là dependency cho proposed shared state. Giữ status bar compact, không copy provider details sang mọi widget.

### Model window / threshold choice

Current code:

- General configured default **16,000**, user field `Config.auto_compact_threshold`; `Agent.set_auto_compact_threshold` clamp≥0. Không có universal model hard limit.
- Groq provider-level **5,500 cap**, kể cả explicit0 reenabled. Current test deliberately validates behavior; changing0 semantics cần compatibility decision riêng.
- Kimi chỉ auto-derive khi config threshold **bằng default16k**: `KIMI_CONTEXT_WINDOWS[model] *3//4`. `moonshot-v1-8k`→6,144; `32k`→24,576; `kimi-k2.6`→196,608. Explicit nondefault giữ nguyên, unknown model fallback16k. Explicit16k không thể phân biệt default versus intentional override hiện tại.
- Normal UI model/provider switch dùng shared transaction+`commit_runtime_state` (`runtime.py:1195`, `model_picker.py:289`), recompute threshold/profile. Finding “switch không recompute” là **false** với supported path. `Agent.set_client` alone không recompute; đây là low-level setter, không chứng minh supported runtime switch stale.
- Manual/custom compatible endpoints có unknown contexts; custom display name không đổi transport identity/budget theo guessed brand. Tool registry không shrink theo model/tooling profile.
- Reserved generation output được adapter encode (`openai.py:522`, `gemini.py:405`, Anthropic max_tokens), nhưng estimator/guard không trừ output reserve. Kimi adapter defaults output2,048; 75% trigger không phải generic output-budget proof. Compaction request ≤22k chars cũng chưa model-aware.

**Chọn hybrid ở request-budget level, không biến soft threshold thành equal context window.** Minimal policy:

1. Verified static metadata cho supported known IDs (reuse Kimi map), normalize input-limit versus combined-context-limit. Chỉ thêm vendor IDs/windows khi verified; không infer display name. Có thể dùng provider model metadata từ discovery sẵn có khi trustworthy, nhưng không thêm network probes trên every turn.
2. Explicit per-model/profile/manual context-limit override và reserved-output setting khi metadata unknown; tách default sentinel `None` khỏi “user explicitly16k” nếu đổi config schema. Giữ storage domains Official/Custom/Manual như guide.
3. Nếu combined window known, illustrative budget `B=floor(W*safety_ratio)-reserved_output`; nếu provider công bố separate input/output limits, apply đúng semantics, không subtract output hai lần. Ratio là configurable conservative policy cần calibration, không arbitrary vendor claim.
4. Compare **full** estimate với B. Equivalent compactable headroom `B-fixed_overhead-injected_noncompactable` chỉ phục vụ compact/guard planning; **không** subtract fixed overhead từ B rồi compare full total lần nữa. Fixed floor≥B phải explicit infeasible context outcome.
5. Soft threshold S giữ operator/provider policy nhưng bound dưới B khi B known. Nếu S≤fixed floor, surface policy/floor mismatch; đừng silently raise hard budget. Có thể disable futile soft compact retries khi predicted savings không đủ, vẫn giảm eligible tool context khi hard pressure thật.
6. Unknown model fallback: giữ16k như **soft heuristic** để compatibility; optional explicitly labeled conservative assumed input cap nếu operator muốn local hard budgeting. Không gọi16k “safe real model limit” vì unknown model có thể chỉ4k/8k. Nếu goal yêu cầu strict provider-fit guarantee, cần metadata/explicit override thay vì fake guarantee; không hỏi operator authorization lại cho target/actions.

Công thức ratio/reserve chưa được implement hay calibrate. Groq default131,072 được verified từ vendor documentation, không dùng number đó hardcode proposal trong audit. Kimi map được đọc như current source metadata; không re-audit toàn bộ current provider catalog hoặc model availability.

## H. Minimal fix plan in dependency order — NOT IMPLEMENTED

| Step / dự kiến files | Behavior proposed | Focused regression tests required | Compatibility / Phase A-B / session-resume impact |
|---|---|---|---|
| 1. `src/agent/context_estimate.py` (optional new helper), `src/agent/agent.py`, `src/llm/providers/gemini.py`, `openai.py` | Shared text/framing/schema primitives + encoder-matching private replay eligibility; mutually exclusive breakdown | Same-model signed/unsigned Gemini, provenance/model mismatch, visible/functions exactly once; DeepSeek/Kimi mode mismatch excluded; many tiny messages/large args | Estimates change and pressure earlier; no protocol/state field changes. Recalibrate numeric boundary tests by behavioral invariant, không whitespace. No artifact/persist migration. |
| 2. `agent.py`, `system_prompt.py` if render orchestration needed | Shared projected turn rendering before G, rebuild after compact; acceptance compare full projected old/new | Real Agent.run memory/workflow/recall/intelligence/catalog conditional paths; G eligible-only boundary; NEW-01 rejected or bounded state; expanded @file count once; failure leaves previous state | Keep raw-versus-expanded history contract and untrusted role classification. Phase A/B receive same requests but correct pressure. Resume renders existing state; no new handoff. |
| 3. `agent.py`, `agent/tool_results.py`, `ui/core/app.py` | Pass actual request tools to guard/admission; final measurement after guidance/retry; UI semantics/invalidation explicit | tools=False, tools-free final synthesis and compaction schemas=0; NEW-02 no unnecessary loss; late guidance counted; UI idle/active labels; zero pending input | Guard/admission still preserve-class and trusted-source policy. Ref headers/full artifacts unchanged. No automatic tool enabling, permissions or workflow changes. |
| 4. `src/cli/runtime.py`, `src/config/config.py`, provider metadata/runtime helper, `agent.py` | Separate soft trigger from optional verified/assumed hard budget; output reserve, infeasible fixed floor, supported switch recompute | Default/explicit/disabled overrides, small8k versus baseline, unknown compatible model, profile identity, real prepared switches; summary failure/retry/circuit breaker; non-reducible input exceeds known budget | Highest compatibility risk: explicit context-capacity outcome instead of provider rejection. Groq0/clamp and Kimi explicit16k semantics need deliberate migration. Phase A/B cannot violate preserve contracts. Live config mutations require existing full transaction lock, rollback/failure/overlap/cancellation tests if persistence changes. Session uses active runtime metadata, never remembered authority. |
| 5. `src/llm/runtime/metrics.py`, `providers/anthropic.py` | Parse normalized Anthropic input/output/cache usage, optional cache-creation field; export unknown reasoning as None | Actual mocked API response through parser+Agent metric; missing/malformed usage, cached total/read/creation subsets, JSONL compatibility; no phantom Anthropic streaming path | Telemetry-only, no G/W/B policy change. Adding optional dataclass field requires positional-constructor/export review. Existing sessions do not persist metrics; no resume migration. |
| 6. `src/tools/common/registry.py`, `agent.py` (optional hardening) | Encoded-schema digest cache or supported mutation revision | Same-name schema/description edit, add/remove/replacement/scoped reader, provider/profile no-ops; unchanged schema cache stable | P3 follow-up, no need redesign plugins/MCP. Must not touch permission Registry gate. No session/artifact format changes. |

Không cần structured handoff, auto-continue, exact tokenizer dependency, whole provider refactor, registry permission bypass hay thay Phase A/B security policy. Dependency1–4 giải quyết context decisions;5 telemetry độc lập có thể làm riêng;6 không block material fixes.

## I. Approximation quality and Phase A/B interaction

`len(text)//4` là character heuristic, không byte/token measurement. Chưa có tiktoken installed trong `venv-linux` (`find_spec`=False), requirements không khai báo tokenizer. Không install/download tokenizer; vì vậy **không** báo error percentage hoặc exact billed-token accuracy.

Local deterministic sample outputs:

| Sample | Unicode chars | UTF-8 bytes | Current estimate |
|---|---:|---:|---:|
| English prose | 920 | 920 | 230 |
| Vietnamese | 760 | 980 | 190 |
| JSON | 591 | 591 | 147 |
| Code | 880 | 880 | 220 |
| URL-heavy | 960 | 960 | 240 |
| Repeated ASCII | 800 | 800 | 200 |
| Minified JS-like | 1,060 | 1,060 | 265 |
| Emoji/unicode | 300 | 1,100 | 75 |

Các số chỉ cho thấy heuristic hiện tại, không prove actual token counts. 50 user messages `ok` → **0 tokens**, dù content 100chars và messages tồn tại trên wire. Per-component floor mất <1 heuristic token/component; tổng floor loss tăng theo số content/reasoning/call entries. Framing omission riêng có thể lớn hơn, chưa có verified provider constants. Large tool args/name được cộng trước floor, expression precedence **đúng**; không sửa thành `len(name)+len(args)//4`.

Minimal hardening: ceil nonempty text components, small adapter-aware envelope allowance, Unicode/opaque-state uncertainty reservation và calibrated safety margin. Ceil không sửa framing hoặc Unicode model variation; 2%/minimum128 safety của guard là **reduction target**, không chứng minh overall tokenizer error<2%. Tokenizer có thể useful later nhưng không thay provider signatures/framing/schemas/model-budget contracts; không cần dependency mới để sửa omissions confirmed.

Phase B/A specific verification:

- Offload thay working content bằng **rendered preview+ref**. Artifact payload, transient `PendingResult.original`, `_bounded_results.original`, full UI event không ở estimator list. Source đọc lại qua gated reader khi operator/model yêu cầu; không hydrate trong guard/resume.
- Guard gọi admission trước size calculation, rồi size recompute `M(working)+T` sau từng Phase A replacement; markers/ref headers được count vì là current content. Repeated pressure dùng original sanitized source để rebound representation, nhưng estimate current replacement. Đây không phải stale-content estimate bug.
- B admission lấy total snapshot để proportional allocation cho batch, không recalibrate total giữa mỗi individual offload; W tiếp theo recount toàn current list. Có thể allocation dư so với exact floor, nhưng không chứng minh new harmful B bug; giữ scope.
- Result index không được append lại sau mỗi live admission vào current system. Current request đã có preview/ref; map growth chưa tự gửi catalog. Rebuild next turn/compaction xuất ≤32ref index và G/W/B tính như system content. Compaction `attach` giữ structured descriptors, không count descriptor dict như text; continuation text count once. Resume restore refs rồi rebuild system, không count/hydrate full artifacts.
- Reader schema được T count như mọi schema khi enabled registry includes reader; no-store Agent không có capability/schema. Profile/permission gates không silently hide schemas.
- Current tests đã rerun: selective pressure, distributed preview/reread, full UI versus preview history, real file execution/resume, sequential rebound, structured ref survives compact, Phase A proportional/metadata/preserved receipts, Phase B audit regressions. Không reopen evidence/authorization/store security audit.

## J. Compaction failure/recovery — limited check

Threshold là config state, không sửa trong `auto_compact`; failed/empty/ineffective summary tăng failure counter. Lượt kế tiếp recompute history/incoming/tools từ source, không reuse trigger tokens. Sau **3** failures gate suppressed cho subsequent turns đến reset hoặc successful compaction resets counter; đây là intentional circuit breaker, không token-cache stale.

`compact_in_place` false (nothing) không tăng failure counter; no successful summary stats. Auto-compaction error emits and normal turn continues, W vẫn best effort. Successful compact recompute **history** estimate để emit; subsequent working rebuild inject memory còn thiếu trong displayed savings. Đây là NEW-01, không threshold stale. Model/provider supported switch callback recompute threshold/profile sau transaction success; set_client alone không metadata policy.

Candidate next_memory/history được derive trước acceptance. Nếu summary request/parse/ineffective rejection trước commit, old state giữ. `apply_compaction_summary` publish memory/history rồi await learn/save/snapshot; late persistence failure không có full rollback trong method. Đó là lifecycle caveat từ source, không mở full cancellation/persistence audit hoặc tự nâng thành accounting finding ở đây. Nếu implement config/model budget persistence sau này phải tuân guide failure/overlap/cancellation tests.

## K. Review of all seven existing Gemini tests

| Existing test | Path/fixture quality | Proves / does not prove |
|---|---|---|
| `test_gemini_replayed_thought_parts_uncounted` | Hand-built Message, unsigned thought; không parser/filter/encoder | Proves estimator ignores field. Does **not** prove unsigned thought replay; production rejects that premise. Signed variant independently verified. |
| `test_injected_context_omitted_from_trigger_tokens` | Renders memory/workflow, không Agent.run/gate/guard | Proves rendered blocks have size. Không tự chứng minh wrong decision; independent eligible-history Agent.run now does. |
| `test_auto_compact_deadband_at_default_threshold` | Pure arithmetic, hard-coded fixed13,979, no current registry | Proves conjunction with5,333 minimum. Does not establish19,312 current production point, real context ceiling or P1. |
| `test_groq_baseline_fixed_overhead_exceeds_threshold` | Actual compact prompt but empty skill registry, schemas hardcode4,893 | Finding direction independently confirmed; fixture không runtime32tool/18skill overhead, không API failure. |
| `test_anthropic_client_drops_provider_usage` | `inspect.getsource(client.chat)` examines retry wrapper | Brittle proxy, could pass after helper fix. Independent mocked full parsing+metrics is actual proof. |
| `test_tools_token_estimate_cache_invalidation_gap` | Synthetic DynamicTool missing protocol run/requires_permission, mutable desc | Artificial stale reproduction valid for cache mechanism; không production mutation path, protocol issue already documented historically. File unchanged. |
| `test_integer_division_zeroes_out_short_messages` | Real estimator,50 tiny content messages | Correct heuristic/envelope omission evidence. Không exact tokenizer/billing/context-failure quantification. |

Original seven tests đều pass trên lần chạy độc lập; **không** đồng nghĩa audit narratives/severities đều đúng.

## L. Verification performed and final scope

Commands đã chạy (không full suite):

```bash
git status --short
git branch --show-current
git worktree list
git log -4 --oneline

venv-linux/bin/python -m pytest -q tests/agent/test_token_accounting_audit.py tests/agent/test_output_pipeline.py tests/agent/test_post_compaction.py tests/agent/test_resume_after_compaction.py tests/agent/test_tool_result_offloading.py tests/agent/test_phase_b_audit_regressions.py tests/llm/test_metrics.py tests/llm/test_reasoning_continuity.py tests/llm/test_anthropic.py tests/llm/test_gemini.py tests/integration/test_tool_schema_budget.py
# 193 passed in 21.78s

venv-linux/bin/python -m pytest -q tests/agent/test_agent.py -k 'compact or guard_working_context or tools_token_estimate or midturn'
# 26 passed, 154 deselected in 4.48s

venv-linux/bin/python -m pytest -q tests/runtime/test_cli_main.py -k 'effective_auto_compact or effective_prompt_profile' tests/ui/test_status_bar.py
# 9 passed, 53 deselected in 14.49s
# -k applied globally, so UI tests in this invocation were deselected.

venv-linux/bin/python -m pytest -q -s tests/agent/test_token_accounting_independent_verify.py::test_audit_final_synthesis_counts_tools_it_does_not_send tests/ui/test_status_bar.py
# 27 passed in 10.01s (1 synthesis verification + 26 UI tests)

venv-linux/bin/python -m pytest -q -s tests/agent/test_token_accounting_independent_verify.py
# Final: 10 passed in 9.35s; measurements above are from this execution.

venv-linux/bin/pyright tests/agent/test_token_accounting_independent_verify.py
# Final: 0 errors, 0 warnings, 0 informations.
```

Development of audit-only fixture có một intermediate test failure (ReasoningLevel import from runtime sai) và intermediate type-check errors. Đã sửa **chỉ new fixture**, rerun thành công như trên; không sửa production/old tests. Pyright runner còn in version-update advisory; không install/update gì. Không chạy global pyright; không nhận global clean claim của tree với existing Gemini protocol fixture.

Read/search commands dùng `rg` và focused `sed`/`cat`; một số guessed path không tồn tại được thay bằng symbol-discovered paths, không ảnh hưởng coverage claimed. Vendor web docs đã đọc để verify Gemini Generate Content replay/signature semantics, Anthropic cache fields và Groq default-model window. Không gọi inference/model-counting API.

Final handoff checks: `git diff --check`, `git diff`, `git status --short`, và `git diff --no-index --check /dev/null` cho hai new audit files (untracked files không nằm trong normal git diff). Chỉ hai files audit/report mới; production và tests Gemini cũ unchanged. Không stage/commit/push, dependency install, live pentest, full suite, unrelated benchmark, structured handoff hoặc auto-continue. Report và proposal hoàn tất; **dừng ở đây**.
