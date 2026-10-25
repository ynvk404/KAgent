# Lan-22 final remediation — validation và factual accuracy

Ngày: 25/10/2026. Đợt này triển khai thay đổi offline; không chạy target,
không gọi provider, không sửa dữ liệu thực nghiệm và không commit.

## Nguồn, Git và giới hạn điều tra

HEAD khi bắt đầu: `fd0c5bcdf0ea29b0968dd21f3e49fa88505543ba`.
Đã đọc `AGENTS.md`, implementation và tests liên quan trước khi sửa.
SQLi Skill sau sửa có SHA-256
`85c6c6e7ba881b620596beabe4f050275ba9d97e4f4f458d9e163a3049f42f73`.
Năm tệp đã modified trước nhiệm vụ được giữ nguyên:
`src/ui/core/app.py`, `src/ui/core/state.py`, `tests/ui/test_input_rendering.py`,
`tests/ui/test_outcomes.py`, `tests/ui/test_pending_phase.py`. Diff có sẵn bỏ
dialog Continue/Stop và deferred presentation sau max-steps; đây không phải
thành quả remediation này. Không stage, reset, revert, cài package hoặc push.

Các nguồn sau tồn tại và đọc được:

| Nguồn | Đường dẫn/định danh đã mở |
|---|---|
| Repository | `/home/khainguyen/kagent` |
| Run | `experiments/scenario3/runs/lan-22/` — 28 tệp, gồm tệp ẩn |
| Session | `profile-home/.kagent/sessions/45a4dc59-7999-4497-9713-adcaf581865b.json` |
| Debug/runtime logs | `logs/session.jsonl`, `logs/kagent.log` |
| Observations | `project/.kagent/observations/45a4dc59-7999-4497-9713-adcaf581865b.json` |
| Workflow, memory, transcript | Workflow và messages trong session; context snapshot trong `profile-home/.kagent/context/` |
| Artifacts | Recon summary, enumeration inventory, candidates và `q-search-proof.md`; đã đối chiếu immutable `.proof` |
| Skill snapshot | `project/skills/`; toàn bộ snapshot khớp checkout trước sửa |
| Forensic audit | `/mnt/c/Users/ThinkPad T480s/.codex/visualizations/2026/10/25/01a17100-3ac4-7f00-ae04-08546b3ae709/lan-22-factual-accuracy-audit.md` |
| Forensic manifest | Cùng thư mục trên, `lan-22-forensic-integrity.json` |

Đường dẫn Windows được giải quyết bằng mount `/mnt/c`, không giả định đã đọc
file Windows chưa mở được. Đã đọc bảng 52 nhận định. Các hàng audit tự ghi là
giả thuyết cần loại trừ không bị tính thành phát biểu nguyên văn của model.

SHA-256 audit: `79c021dd6ede0ad3fb3058cf6a457e0f07e177e6aa68aae489b7bd8399883d27`.
SHA-256 manifest: `61abd2924deb737ca738c942c9f0507dd029cb1ca1e1ca122258160397fecc40`.

Manifest lịch sử không hoàn toàn khớp bộ dữ liệu hiện tại: `kagent.log`,
`session.jsonl` và context snapshot khác cả mốc before/after của audit. Runtime
log hiện có ghi shutdown/debug-writer warning về 622 dropped records sau thời
điểm lập manifest. Không khôi phục hoặc viết lại các tệp đó. Các tệp session,
observations, artifacts, proof và Skill còn khớp manifest. Đã lấy hash/mode
riêng cho cả 28 tệp khi bắt đầu remediation để so sánh trước bàn giao.

Nguồn còn thiếu: standalone TUI attachment/video được audit nhắc đến, immutable
runtime-source snapshot của lần chạy, session trước compaction, packet/server
capture và provider-request archive. Có transcript persisted cùng debug deltas,
nhưng không thể khôi phục từng context gửi provider từ debug log bị dropped và
tool-result metadata view. Không tạo lại hoặc đoán nội dung các nguồn thiếu.

Kiểm tra độc lập trên dữ liệu còn giữ:

- 7/7 validation captures complete, không truncated; response hash, retained
  hash và Candidate/Attempt ownership khớp; Search có 5, Login có 2 sources.
- 2/2 result seals và Candidate bindings khớp; cả hai là `insufficient-evidence`.
- Search source proof bằng immutable snapshot; có 1 registered proof.
- Login không có registered proof nhưng vẫn có 2 raw observations.
- Hai Candidates deferred, hai Attempts unresolved, goal SQLi deferred,
  không có persisted finding.

## Nguyên nhân Search `GET /rest/products/search`, `q`

Analysis đã quan sát quote gây SQLite parser diagnostic với fragment wildcard;
đây là planning context, không phải owned terminal proof. Trong attempt:

| Thứ tự | Request/diễn giải của model | Kết quả và quyết định phù hợp |
|---|---|---|
| 1 | `q=apple`, chọn known match | 200 JSON, 921 byte, 3 records: control hữu ích, chưa là Boolean oracle |
| 2 | `apple') AND '1'='1`, gọi TRUE | 500 near `)`; model kết luận query không có parentheses. Error position không quyết định toàn bộ balance; probe chưa phải TRUE được xác lập |
| 3 | `apple' AND '1'='1` | 200 JSON, 30 byte, `data:[]`; model giải thích suffix làm predicate false như fact. Oracle dự đoán giữ known match đã thất bại; cơ chế suffix chỉ là giả thuyết |
| 4 | `apple'--` | 500 incomplete input; chưa xác định quote/grouping/suffix nào bị ảnh hưởng |
| 5 | `apple'-- ` | Cùng incomplete input, cùng response hash với bước 4; không phân biệt thêm giả thuyết SQLite line-comment hiện có |

Không có FALSE request. Không có cặp equal TRUE/FALSE thực thi. Không có controlled
evaluation đủ SQLI-2. Verdict unresolved của Search phù hợp với evidence.

Nguyên nhân chứng minh được là suy luận quá chắc từ parser position, không kiểm
tra truth value sau khi ghép prefix/expression/suffix, và thử biến thể có cùng
dự đoán thay vì chọn phép thử phân biệt. Model biết cần oracle nhưng không áp dụng
điều đó vào request cụ thể. Capture không thiếu các response cần cho nhận định này.

Bookkeeping cũng lệch: request confirmation đầu có đổi cấu trúc nhưng không được
model đếm ngay; proof tự gọi request cuối là fourth shape sau ba adjustments.
Thực tế có bốn non-control requests, còn whitespace cuối không tự tạo một SQL
shape mới. Không suy mọi khác biệt byte thành semantic adjustment. Không tăng
allowance, max_steps hoặc thêm runtime counter để che lỗi này.

Skill hiện tại đã có nhiều cảnh báo đúng và khớp snapshot run; vì vậy đây không
đơn thuần là thiếu Skill. Giả thuyết còn lại gồm anchoring bởi tri thức Juice Shop
và việc guidance dài làm model bỏ sót điều kiện; không có controlled model trial
để chứng minh mức đóng góp của chúng. Không khôi phục implementation SQL thật từ
các parser errors. Counterexamples SQLite trong memory chỉ chứng minh inference
đó không duy nhất, không tái dựng server.

## Artifact, Workflow prose và TUI/final

Luồng hiện có đã phân biệt response và request: native HTTP giữ bounded body,
ObservationStore giữ hash/ownership, HTTP tool đặt evidence envelope trước body,
sau đó có marker kết thúc response và redacted request preview. Agent cấp body
đủ điều kiện vào model/history; debug/TUI tool-result dùng metadata view.
Không có bằng chứng cần sửa HTTP adapter hoặc ObservationStore cho các sai lệch
factual dưới đây. Điều này mô tả source path được kiểm chứng offline, không chứng
minh byte outbound của từng provider request lịch sử.

| Sai lệch | Kết luận từ nguồn |
|---|---|
| robots không reveal paths | Capture đủ 28 byte có `Disallow: /ftp`; inventory/coverage prose trái dữ liệu |
| GraphQL không tồn tại | Không có test/source review đủ hỗ trợ; thiếu kiểm tra bị đổi thành kết luận vắng mặt |
| Reset-password POST | Nguồn là GET/500/text-html; tên route không xác lập POST hoặc body schema |
| Không tải main.js lần hai | Hai GET retained 4096 và 65536 byte, đều truncated; narrative lịch sử sai |
| Đếm operation/path/request | 48 discovery paths + 2 wildcard baselines = 50 discovery requests; 37 direct HTTP calls + 50 = 87 native HTTP sources; 1 shell source riêng. Chúng không phải một operation total |
| LIKE/concatenation thành fact | Parser diagnostic không lộ full query; Candidate signals và proof explanation đã nâng giả thuyết thành implementation |
| Express request preview trong body | Preview là controller metadata; retained response là HTML stack trace |
| Candidate ID/status | Có typo ID trong candidates artifact. Queued/no-attempt đúng ở checkpoint trước validation, stale nếu dùng cho final |
| “No data was read” | Control đã trả product records; chỉ có thể nói chưa chứng minh additional extraction qua injection |

Typed Runtime status không tự biến SQLi suspected thành confirmed. Prose của model
mới là nơi nói có equal pair chưa chạy, nói Login chỉ còn narrative hoặc gọi stack
trace là SQL-injectable. Proof registration xác nhận snapshot/links, không xác nhận
vulnerability meaning. Đây là lý do sửa guidance và presentation context thay vì
thêm bộ kiểm duyệt phát biểu vào Runtime.

Login mở attempt bước 88, control bước 89 trả 401; intended TRUE bước 90 trả
200 với marker authentication token. Max_steps đóng unresolved trước compaction,
trước khi model làm FALSE/repetition/proof. Không kết luận model chắc chắn hoàn tất
nếu tăng budget. Câu single-login limitation của model không phải giới hạn runtime
đã công bố. Skill có wording “do not request [token] again” dễ xung đột với yêu cầu
repetition; đã làm rõ mà vẫn giữ cấm replay/decoding/characterization ngoài workflow.
Hướng dẫn cũ gọi token là valid administrative cũng vượt evidence; đã sửa.

Lỗi TUI thuần túy được sửa là label `Reason:` rỗng khi deferred_reason không có
nội dung. Chỉ ẩn label rỗng; không suy reason mới từ notes và không đổi outcome.

## Compaction

Persisted summary tự thêm beyond-SQLi goals dù objective chỉ yêu cầu SQLi, coi
redacted password placeholder là bytes đã gửi, và mô tả parser/query-shape quá chắc.
Final tiếp đó đồng nhất empty proof refs với không còn raw evidence. Canonical
objective, Attempts, Results, seals và ownership vẫn đúng. Compaction không gây
closure max-steps hay làm mất Login observations.

Runtime đã đưa canonical requested goals vào compaction prompt; không cần thêm
schema/filter. Thay đổi chỉ làm rõ: `whole_target` là traversal mode, không thêm
vulnerability classes; không lấy assistant plans/TODOs làm goal mới; không sửa
Candidate/Attempt/Result qua summary; giữ unresolved references và phân biệt
raw observations, registered proof, accepted result, persisted finding. Redacted
representation không cho phép suy actual request bytes. Resume/recovery giữ
cơ chế cũ, được kiểm tra bằng FakeClient và save/fresh resume.

## Các thay đổi

| Tệp | Nội dung |
|---|---|
| `skills/sql-injection/SKILL.md` | Decision check Observation → Hypothesis → Oracle → Expected Result → Falsifier → Next Decision; một ví dụ ngắn; phân biệt competing shapes và equivalent variations; rõ incidental token/repetition; bỏ khẳng định token validity/admin chưa kiểm chứng |
| `src/agent/validation_guidance.py` | Đưa decision check ngắn vào start/resume hints; không thêm probe trước finalization hay ledger/action mới |
| `src/agent/system_prompt.py` | Claim/source checkpoint cho full và compact target-assessment prompts; recent result có current Candidate status, Attempt status, finding persistence; giải thích empty refs |
| `src/agent/agent.py` | Final synthesis đối chiếu executed/intended, raw/proof/result/finding và current goal/state; compaction guidance giữ scope, uncertainty và redacted-byte distinction |
| `src/ui/core/outcomes.py` | Ẩn `Reason:` khi reason null/rỗng/whitespace, giữ nguyên blocker/outcome |
| `tests/agent/test_lan22_accuracy.py` | Regression offline cho guidance delivery, status projection, final synthesis, compaction/resume, metadata domains, SQLite counterexamples và blank reason |
| `tests/skills/test_sql_injection.py` | Thay assertion bảo vệ wording cấm request token again bằng kiểm tra repetition đúng và cấm token characterization bổ sung |
| `benchmarks/fixtures/lan22_accuracy.json` | 8 sanitized reference cases cùng human-review rubric |
| `benchmarks/docs/lan22-accuracy.md` | Cách đánh giá reference/model và giới hạn kết luận |
| Báo cáo này | Nguồn, root causes, kiểm chứng, phạm vi và readiness |

Guidance testing không được chèn vào empty coding sessions không có target origin.
Đã rút gọn prompt/hint sau khi phát hiện token overhead làm một số test fixture
auto-compact sớm. Không tăng context allowance và không sửa tests để né context
guards. Continuation hint vẫn phải qua giới hạn chiều dài hiện có.

## Regression và kiểm chứng

RED ban đầu: 15 failed, 3 passed trong regression mới, trước production edits.
Gồm thiếu explicit decision chain/claim/synthesis/compaction distinctions và ba
ca TUI empty reason. Các test guidance chứng minh policy được cấp cho model,
không chứng minh model tuân thủ. Test synthesis giữ nguyên scripted Whole-target
prose; Direct vẫn dùng incomplete-goal projection vốn có. Không có validator mới.

Sau sửa và rút gọn: Agent core + regression mới **209 passed**; nhóm context estimate,
validation continuation, artifact guidance và regression mới **101 passed**.
Lượt rộng đầu phát hiện 10 failures do prompt/hint size; đã sửa nguyên nhân và chạy
lại các nhóm liên quan, không nới assertion, budget hoặc skip semantics.

Pyright bằng `venv-linux`, trên bốn tệp Python production sửa và hai tệp test:
**0 errors, 0 warnings**. Không cài/cập nhật Pyright theo thông báo phiên bản mới.

Lượt responsibility check rộng cuối: **4551 passed, 1 failed, 441.61s**.
Failure duy nhất là
`tests/ui/test_persistence_responsiveness.py::test_async_wait_control_keeps_textual_responsive[evidence_snapshot]`:
control path có 1 recovery tick trong khi harness yêu cầu ít nhất 2, heartbeat
gap 152.24ms và Escape delivery 2.28ms. Chưa có bằng chứng quy nguyên nhân cho
remediation hoặc kết luận tất cả UI responsiveness đều ổn định.

Chạy lại **toàn bộ** `tests/ui/test_persistence_responsiveness.py` bằng cùng offline
plugin: **11 passed, 7.74s**. Không sửa test, nới threshold hoặc thêm skip. Đây là
failure đo thời gian không tái hiện trong lượt chạy riêng, được giữ làm limitation
về độ lặp lại của harness; không mở rộng thành đợt sửa scheduling/persistence.
Không cộng hai lượt thành một unique-test total hoặc gọi lượt rộng là toàn bộ GREEN.

Đã kiểm tra `git diff --check`, đọc diff và `git status --short` trước bàn giao.
HEAD cuối không đổi. Worktree giữ 5 tệp có sẵn, thêm 6 modified và 4 tệp mới của
nhiệm vụ này; không có commit. **28/28 tệp lan-22 giữ nguyên hash và mode** so với
mốc remediation bắt đầu. Các thay đổi log/context so với manifest audit đã tồn
tại trước nhiệm vụ này, không phải do remediation.

Lệnh responsibility check rộng (offline socket boundary hiện có, không bật opt-in):

```sh
venv-linux/bin/pytest -q -p tests.system.offline_suite \
  tests/agent tests/skills tests/ui tests/integration tests/state \
  tests/security/test_http_body_fidelity.py \
  tests/security/test_http_observation_reader.py \
  tests/security/test_observation_grounding.py \
  tests/security/test_observation_publication.py \
  tests/security/test_evidence_source_binding.py \
  tests/security/test_http_readback_lifecycle.py --tb=short
```

Không chạy toàn bộ repository suite, live/external-model/opt-in tests hoặc target
retest. Phạm vi đã bao phủ các responsibility bị ảnh hưởng: Agent prompts/context,
Skill, Workflow integration/state, TUI, HTTP body/readback/publication và evidence
binding. Không cần chạy provider/config/backend groups vì không sửa các hợp đồng đó.

## Benchmark, hạn chế và tác động

Đã tạo 8-case reference pack: search oracle, robots/absence, method/body, counting,
download history, Login evidence, metadata provenance, canonical goal/checkpoint.
Đã kiểm tra offline reference arithmetic và SQLite counterexamples. Chưa chạy
model benchmark; không báo accuracy score hoặc behavioral improvement từ FakeClient.
Mọi tuyên bố cải thiện suy luận/viết factual vẫn ở mức guidance/context cho đến khi
có thử nghiệm model thực với cùng case/build/config được ghi nhận.

Các hạn chế được giữ và báo riêng:

- Raw bounded target bodies có thể chứa token trong private ObservationStore và
  model/history/session path theo lab policy hiện tại; 0600 và hex không phải
  credential redaction. Đây là vấn đề data-handling nghiêm trọng đã có test bảo vệ
  fidelity. Không đổi retention/redaction/provenance contract trong nhiệm vụ này,
  không sửa token lịch sử hoặc tuyên bố đã chứng minh outbound leak của run.
- Mâu thuẫn Continue/reload-first handoff và actionable projection được forensic
  audit tái hiện là vấn đề continuation ngoài phạm vi factual guidance. Worktree
  có sẵn bỏ dialog max-steps không được coi là đã sửa cơ chế retest này.
- Cleanup heuristic có thể nhầm HTTP error-page prose với cleanup failure theo
  audit; chưa sửa validation admission/cleanup contract trong đợt này.
- Known enumeration omissions và chi phí iterations không được tối ưu; không
  dùng run đơn lẻ để quy lỗi năng lực hoặc hứa tăng budget sẽ sửa reasoning.
- Model vẫn có thể bỏ qua guidance hoặc làm sai prose; Runtime không chấm ngữ
  nghĩa từng câu. Canonical records cũng có phần prose do model khai báo.
- Broad check có một failure timing của UI control; chạy riêng nhóm 11 tests
  GREEN không chứng minh đã loại được mọi scheduling variation của harness.

Direct: không thêm prerequisite discovery, không đổi Candidate/Attempt admission;
target-bound synthesis có guidance mới, typed incomplete fallback giữ nguyên.
Whole-target: không thêm goal, không thay coverage/completion hay continuation
quyền retest. Workflow: chỉ thêm trường hiển thị từ state đã có trong context;
không thay schema/persistence/ownership/evidence integrity hay finding eligibility.

Đánh giá: **READY WITH KNOWN LIMITATIONS cho lan-23 trong authorized lab**,
với functional regressions đã GREEN và failure timing/harness được công bố ở trên.
Đây là readiness của patch guidance/context, không phải xác nhận model đã có năng
lực tốt hơn hoặc raw-body policy phù hợp cho môi trường ngoài lab. Không dùng
Continue path chưa chốt làm thước đo riêng năng lực LLM.

Sau nghiệm thu, đề xuất đóng baseline theo HEAD + exact diff/Skill hashes đã kiểm
tra và chuyển sang ba kịch bản: 3.3.1 Burp Suite integration; 3.3.2 validation trên
bộ dữ liệu chuẩn; 3.3.3 Whole-target. Ghi rõ build/model/config/target state và các
biến thay đổi; không quy kết hiệu quả guidance chỉ từ trial đổi đồng thời budget.
