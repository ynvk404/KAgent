# Audit chiến lược SQLi sau Official 05

## Phạm vi và nguồn đối chiếu

Audit chỉ đọc lịch sử; không gửi probe tới Benchmark hay mục tiêu khác.
Không sửa Evaluator v2, ground truth, runtime, Planner, WorkflowState hoặc
artifact Official 05. Không tăng `max_steps` hay resource limits.

Nguồn public:
`artifacts/benchmarks/scenario1-official-20261027T065536Z-b812e8c65698/`.
`report/report.json` xác nhận SQLi: 20 ca, 8 assessment accepted (5 TP, 1 FP,
2 TN, 0 FN), 12 unresolved; 5 ca có execution `budget-exhausted`.
Không diễn giải 0 FN trên 8 assessment thành recall đầy đủ cho 20 ca.

Nguồn canonical và history cục bộ:
`.kagent/benchmarks/scenario1/runs/ce0cff2bc4444589968d44767f710938/`.
Đã đối chiếu SHA-256 của cả 20 canonical SQLi result với
`canonical.result_sha256` trong public projection để chọn đúng run, thay vì
suy từ tên thư mục. Mỗi `results/<case>.json` cung cấp
`result.session_id`; session tương ứng nằm ở
`workspaces/*/.kagent/sessions/<session_id>.json`, chứa request tool arguments,
responses, playbook đã tải và workflow calls. Public projection không chứa
toàn bộ transcript và không được dùng thay history.

Trước khi chỉnh sửa, output `load_skill` trong cả 12 session unresolved đều
kết thúc bằng đúng body SQLi hiện tại được materialize bởi production loader.
Vì vậy nhiều quy tắc dưới đây **đã được cung cấp nhưng Agent không áp dụng**;
không thể kết luận chỉ thiếu hướng dẫn. Không có compaction trong metrics của
các session này. Không có trace suy luận nội bộ để chứng minh vì sao LLM bỏ qua
một quy tắc hay ưu tiên một giả thuyết.

## Cơ chế hiện tại từ source

- `src/skills/registry.py` đọc metadata (`stage`, `candidate-classes`,
  `requires`, triggers, allowed-tools); `validators_for_class` và
  `src/workflow/validation/route.py` chọn expert validator SQLi.
- `src/agent/decision_planner.py` dùng phase readiness, canonical inputs,
  candidate/result/coverage/finding state và prerequisite để đề xuất Skill.
  `src/agent/validation_guidance.py` đã nhắc chọn theo context/oracle và tránh
  probe tương đương; không có runtime engine tự suy luận SELECT/INSERT/CALL.
- `src/skills/load_skill.py` cung cấp toàn bộ playbook, với preface quyền runtime
  ưu tiên, nguồn owned và immutable proof. Đây là hướng dẫn cho LLM, không phải
  bộ thực thi chiến lược SQL hay semantic SQL oracle.
- `src/tools/http/http_tool.py` hỗ trợ Direct hoặc Captured Replay và trả
  effective request preview, timing, completeness, hash, observation ID.
  `src/tools/http/request_builder.py` thay **giá trị** query/form/JSON và các
  vị trí được hỗ trợ; replay không đổi tên key hay header/cookie.
- `src/tools/common/registry.py` giữ permission/admission gate;
  `workflow.start_validation` tạo ownership và validation context từ canonical
  handoff (`src/workflow/validation/context.py`). Analysis observations vẫn là
  planning context, không tự trở thành owned proof của validation.
- `record_evidence` đăng ký snapshot redacted với parent observations;
  `record_result` lưu assessment; confirmed mới đủ điều kiện gọi
  `confirm_finding`. Runtime kiểm tra provenance/integrity/scope và hợp đồng,
  còn ý nghĩa SQLi thuộc Agent. Không thay thiết kế này để sửa một FP.

## Kết luận audit: điều đã chứng minh và giới hạn suy luận

1. **Context và vị trí input:** Skill cũ đã yêu cầu statement shape, SQL
   expression, prefix/suffix và oracle; nhưng thiếu CALL trong danh sách chọn
   statement và thiếu checkpoint riêng cho HTTP parameter name/value. Hai lớp
   định danh HTTP input và vị trí trong SQL dễ bị gộp chung.
   Trong `01302`, diagnostic thực sự có CALL hoàn chỉnh và lỗi `unexpected
   token: AND/OR` sau call; Agent vẫn thử predicate/call suffix nhiều lần.
   Trong `00441`, `01221`, `01394`, baseline báo INSERT và write acknowledgement,
   sau đó xuất hiện type/syntax/count errors; vẫn tiếp tục các AND/OR variants.
   Đây là bằng chứng chọn phép thử không tạo oracle tương thích, không chứng
   minh toàn bộ câu SQL hay mọi kỹ thuật khác đều thất bại.

2. **Boolean/error áp dụng máy móc:** Có trace lặp AND/OR khi statement/position
   không hỗ trợ giả thuyết, hoặc khi TRUE chưa có marker hợp lệ. Ví dụ `00441`
   tiếp tục thay số phần tử dù `row column count mismatch` lặp lại; `01302`
   lặp `CALL 1=1/1=0` bị từ chối. Không gọi những lỗi này là controlled
   error-based evaluation. Chưa chứng minh tồn tại một phép thử khác sẽ thành
   công trong giới hạn và quyền hiện có.

3. **Phản hồi không thêm thông tin:** `00338`, `01215`, `01389`, `01729`,
   `01811`, `02282`, `02546` giữ nội dung phản hồi ổn định qua các phép thử đã
   gửi. Nội dung query in trên trang có thể cố định; không dùng nó để khẳng
   định đường đi dữ liệu hay executed query. `01811` có 20 dispatch nhưng không
   có content differential. Điều này bác bỏ **oracle nội dung đã dùng**, không
   chứng minh input bị bỏ qua, có cache, được sanitize, hay không có SQLi.

4. **Đổi giả thuyết/kỹ thuật:** Skill và transient guidance đã cho phép đổi
   technique có cơ sở, không ép thứ tự hay corpus exhaustion. History vẫn có
   các đổi syntax/encoding và thử engine/technique khi oracle chưa rõ; `02546`
   gửi một SLEEP không có matched zero-delay control. Có thể việc hướng dẫn
   dài, lặp và corpus nổi bật góp phần gây chọn theo payload, nhưng đây chỉ là
   giả thuyết về nguyên nhân nhận thức; không có ablation/model run để kết luận.

5. **Parameter name/value:** `02357` nhận prompt chỉ rõ component `name`,
   baseline `answer=&bar=<baseline-value>`. Tám request tiếp theo vẫn đổi giá
   trị `bar`, giữ tên key, và bị harness từ chối trước dispatch. Chỉ một baseline
   đến target. Các lần đổi encoding không sửa sai thành phần. Đây là lỗi sử
   dụng request contract của Agent, không phải bằng chứng HTTP adapter không
   thể gửi một Direct form key mutation. Không sửa hoặc nới harness gate.

6. **Proof/result muộn:** Vòng probe, đọc lại diagnostics và sửa JSON/effect
   bookkeeping chiếm các lượt trước finalization. `00441` ghi proof ở lượt 29,
   register ở 30; `01221` và `01302` ghi file ở 29/30 nhưng không register;
   `01811` không ghi proof hay register. `01394` gặp cleanup contradiction rồi
   parent mismatch khi đã gần hết budget. `00338` mất bốn lần submit negative
   không hợp lệ trước khi ghi unresolved, gồm lỗi thiếu nguồn/proof và oracle.
   Runtime đã giữ gate; thiếu accepted terminal result không nên được chữa bằng
   cách hạ gate hoặc đổi unresolved thành negative.

7. **FP cũng có bằng chứng độc lập:** `00200` được Evaluator phân loại FP.
   Trong canonical `confirmation`, FALSE được gắn marker
   `WARNING: Accepting ...`, nhưng captured responses không chứa marker đó;
   cả 14 nguồn trong manifest có cùng response hash
   `fa0ae5a537afc69bb59a4eb203e34009254c2861be82c1385c082c5302c84926`.
   Vì vậy claim content differential không khớp nguồn. Có thể chứng minh lỗi
   gán marker này mà không cần xem target implementation hay thay ground truth.
   Chưa xác định nguồn phát sinh marker tưởng tượng từ history; không coi
   admission thành bằng chứng Runtime đã xác minh SQL semantics.

Baseline write acknowledgements trong nhóm INSERT còn cho thấy cần nhắc lại
guard stateful đã có: reported write không phải verified persistence hay quyền
cleanup. History không đủ để xác minh isolation/cleanup thực tế; audit không
giả định reset bên ngoài tạo isolation cho mọi probe.

## Toàn bộ 12 ca unresolved

Tên ca dưới đây chỉ dùng để tra history trong báo cáo, không đi vào Skill,
payload hay nhánh runtime/test phụ thuộc ID. Cột lượt là số thứ tự assistant
message trong session; nhiều tool có thể cùng lượt. `llm_calls=31` của năm ca
budget-exhausted gồm 30 agent-loop calls và một final synthesis, không phải tăng
agent budget. `record_result` cuối có thể thuộc final synthesis. Outcome và
execution status là hai trục khác nhau.

| Case | LLM calls / HTTP dispatch | Quan sát chính | Lượt file / register / result |
|---|---:|---|---|
| 00338 | 25 / 9 | Trang SELECT cố định; 4 negative submissions bị từ chối rồi unresolved | 17 / 18 / 19–23 |
| 00441 | 31 / 17 | INSERT acknowledgement; type/count/syntax errors lặp; hết budget | 29 / 30 / 31 |
| 01215 | 26 / 9 | Trang SELECT cố định; không có oracle nội dung | 22 / 23 / 24 |
| 01221 | 31 / 11 | INSERT; nhiều lỗi expression-not-boolean; hết budget | 29 / không / 31 |
| 01302 | 31 / 22 | CALL; predicate/suffix rejected, lặp CALL expressions; hết budget | 30 / không / 31 |
| 01389 | 27 / 9 | Cùng empty results; nhiều lượt readback | 23 / 24 / 25 |
| 01394 | 31 / 11 | INSERT; syntax/type/count errors; cleanup/parent repairs; hết budget | 26 / 27 / 28–30 |
| 01729 | 14 / 5 | Trang báo processed, affected rows unknown; không có discriminator | 10 / 11 / 12 |
| 01811 | 31 / 20 | Cùng SELECT/no-results page; đổi nhiều payload; hết budget | không / không / 31 |
| 02282 | 23 / 6 | Static batchUpdate page; hai cặp không tạo oracle | 18 / 20 / 21 |
| 02357 | 20 / 1 | 8 value mutations trái yêu cầu name; bị chặn trước dispatch | 16 / 17 / 18 |
| 02546 | 17 / 5 | Cùng INSERT acknowledgement; một SLEEP không đủ control | 13 / 14 / 15 |

Không đề xuất đổi assessment lịch sử của 12 ca này. Không đủ dữ kiện để kết
luận ca nào chắc chắn sẽ có accepted assessment nếu áp dụng hướng dẫn mới.

Các điểm tra trực tiếp (index `messages` dưới đây bắt đầu từ 0):

- [Session name/value](../.kagent/benchmarks/scenario1/runs/ce0cff2bc4444589968d44767f710938/workspaces/bcdbd5a4c18c4aaa936bc4d8166077c4/.kagent/sessions/2fa68367-d328-45f7-b5af-77e1fbb71828.json): prompt operator và tám HTTP tool calls đổi value; result tại `messages[36]`.
- [Session CALL](../.kagent/benchmarks/scenario1/runs/ce0cff2bc4444589968d44767f710938/workspaces/5a445925b8fc4552bb955141701f60a3/.kagent/sessions/cc3f4e4d-aa52-4864-b30a-7bc5bf545eea.json): xem SQL diagnostics của HTTP calls; unresolved result tại `messages[62]`.
- [Session cleanup/proof repairs](../.kagent/benchmarks/scenario1/runs/ce0cff2bc4444589968d44767f710938/workspaces/58a3327392bc46e5851f78accfa0a8a0/.kagent/sessions/6739828f-c000-4ee5-8992-47c9a044f184.json): registration `messages[54]`, result submissions `[56]`, `[58]`, `[60]` và tool responses ngay sau chúng.
- [Canonical FP result](../.kagent/benchmarks/scenario1/runs/ce0cff2bc4444589968d44767f710938/results/BenchmarkTest00200.json): đối chiếu `result.workflow.validation_results[-1].confirmation` với `evidence_manifest[*].source.response_hash` và các captured responses của session được liên kết bằng `result.session_id`.

## Thay đổi tối thiểu

| File | Mục đích |
|---|---|
| `skills/sql-injection/SKILL.md` | Checkpoint HTTP component; bảng SELECT/INSERT/UPDATE/CALL/identifier theo position/type/oracle; semantic diagnostic comparison và marker phải có trong nguồn; hoàn tất local evidence/result ngay khi đủ cơ sở. |
| `skills/sql-injection/payloads.txt` | Chỉ thêm hướng dẫn liên kết component/context với corpus; không thêm payload hoặc kỹ thuật mới. |
| `tests/skills/test_sqli_context_strategy.py` | Kiểm tra guidance thực sự được loader cung cấp; SQLite minh họa khác biệt SET/WHERE và literal echo/evaluation. Không mô phỏng trí tuệ LLM. |
| `tests/security/test_sqli_whole_target_handoff.py` | Production registry/HTTP/workflow với MockTransport và SQLite: analysis input → Candidate → owned validation → immutable evidence → accepted result → coverage → Finding; Direct name/value và Replay value. |
| `docs/official05-sqli-strategy-audit.md` | Root cause, giới hạn bằng chứng, tác động, kiểm thử và rủi ro. |

Không tạo trường `input_component` mới trong Candidate/Workflow schema. Nếu
operator/context có nhãn thì dùng nó, còn Whole-target Candidate thông thường
vẫn dùng canonical input, template, source và signals hiện có. Replay chỉ thay
supported values; unsupported bound mutation vẫn giữ blocker. Không có Direct
fallback để né capture binding.

Mỗi probe tiếp tục cần hypothesis, observable prediction và falsifier. Thay
technique chỉ khi có cơ sở riêng và đủ quyền/capability. Không có hard syntax cap,
minimum payload count, bắt buộc chạy mọi technique hay tăng quota. Giữ nguyên
SQLI-2, hai Boolean repetitions, time controls, impact/OOB/write gates và honest
`insufficient-evidence` khi oracle chưa established.

## Tương thích Scenario 3 và giới hạn thực nghiệm

Metadata selection, triggers, allowed-tools và `requires` không đổi, nên không
đổi Planner skill/phase selection. Các file runtime, prompt builder, WorkflowState,
persistence, compaction, session recovery, scope/permission/YOLO/admission,
request/resource limits, evidence gates, XSS và UI không sửa.

Fixture mới kiểm tra giữ endpoint, method, parameter, location, content type,
sample, explicit template, source reference, baseline reference/availability và
analysis observation. Các quan sát trước attempt vẫn unowned; chỉ control và
hai probes trong attempt được đưa vào immutable proof. Canonical input không
đổi, Candidate chỉ đổi status khi result được nhận; Finding dùng result/evidence
đã lưu. Không thêm HTTP sau khi đủ repeated controlled constant proof.

Discovery trong fixture mới được đánh dấu skipped/not-applicable một cách tường
minh qua helper hiện có; fixture không giả vờ đã thực hiện Recon/Enumeration.
Pipeline/Planner tests hiện có bao phủ chuyển phase. Kiểm thử local không chứng
minh LLM sẽ chọn đúng technique, không phải một lần chạy Scenario 3 thật, và
không chứng minh TP/Assessment Coverage sẽ tăng trong Scenario 1.

## Xác minh

- Nhóm tập trung SQLi (ba module Skill, ba module security): **148 PASS**.
- Toàn bộ `tests/skills`: **482 PASS** sau điều chỉnh cuối, gồm XSS,
  metadata/conformance và giới hạn độ dài decision checkpoint. Không nới test
  giới hạn độ dài: phần giải thích bổ sung nằm sau checkpoint ngắn hiện có.
- `tests/skills/test_validation_grounding_contract.py`,
  `tests/skills/test_sqli_context_strategy.py`,
  `tests/security/test_sqli_whole_target_handoff.py`: **40 PASS**.
- `tests/benchmarks/test_scenario1_closure.py`,
  `tests/benchmarks/test_scenario1_request_body.py`,
  `tests/benchmarks/test_scenario1_assessment.py`: **86 PASS** (unit/fixture,
  không phải chạy lại Official Benchmark).
- `venv-linux/bin/pyright` cho hai test module mới: **0 errors/warnings**;
  `venv-linux/bin/ruff check` hai module: **PASS**.
- Hash check bundle canonical + public Official 05: **564/564 không đổi**.
- Kiểm tra metadata SQLi/allowed-tools với HEAD: **không đổi**. So sánh các
  dòng payload không phải comment: **không đổi**. Body các Skill khác: **không đổi**.

Lệnh hồi quy rộng:

```bash
venv-linux/bin/python -m pytest -q \
  tests/skills tests/security tests/integration tests/agent \
  tests/tools/test_skill.py tests/tools/test_http_replay.py \
  tests/tools/test_request_builder.py tests/tools/test_workflow.py \
  tests/tools/test_finding.py \
  tests/runtime/test_headless_yolo_characterization.py \
  tests/runtime/test_prompt_file_headless.py tests/system/test_ui_lifecycle.py
```

Kết quả lần chạy rộng: **4561 PASS, 11 FAIL, 1 SKIP**. Run này bắt đầu trước
điều chỉnh vị trí giải thích bổ sung. Một failure là length guard của decision
checkpoint; đã sửa hướng dẫn và kiểm tra lại thành **482/482 Skill PASS**, không
đổi assertion. Mười failures còn lại được tái hiện trên checkout tạm từ
`git archive HEAD` tại commit `daeb30f438af3d4375add38d48fe30468479ccfa`, dùng
cùng `venv-linux`, để xác nhận tồn tại trước bản sửa:

| Module / test | Số FAIL hiện tại và trên HEAD | Hiện tượng |
|---|---:|---|
| `tests/integration/test_burp_offline_audit.py::test_burp_evidence_and_finding_ledger_with_native_replay` | 2 | Nhánh False đếm 1 request nhưng fixture gửi 2; nhánh True thiếu accepted result. |
| Cùng module, `test_burp_committed_result_checkpoint_survives_cancel_before_receipt` | 1 | Một result, hai HTTP requests; assertion buộc bằng 1. |
| `tests/integration/test_discovery_service_policy.py::test_burp_selected_request_keeps_replay_without_service_discovery` | 1 | Assertion đếm 1 HTTP request, thực tế fixture có 2. |
| `tests/integration/test_workflow_checkpoint_artifacts.py::test_discovery_artifact_loss_and_authorized_repair` | 6 | Các nhánh not-confirmed (missing/empty × ba phase) đếm 1 request nhưng negative fixture có control + comparison. |

Baseline chạy ba module terminal-goal/discovery-service/workflow-checkpoint:
**131 PASS, 7 FAIL**; module Burp offline: **22 PASS, 3 FAIL**. Không sửa test
hoặc runtime để che các failure sẵn có này. Tất cả security tests trong đợt rộng
đều PASS trừ opt-in live characterization được SKIP; không bật live harness.
Kiểm tra lại trên bản sửa cuối các ca Burp/discovery/artifact nêu trên, hai module
Whole-target và fixture handoff mới: **81 PASS, đúng 10 FAIL như HEAD**, không có
failure mới trong nhóm này.
Không chạy toàn bộ suite `tests/`, external-model evaluation, Official Benchmark
hoặc một phiên Scenario 3 thực tế. Các số PASS ở các nhóm trên có overlap,
không cộng dồn thành tổng số test độc lập.

Lần đầu fixture name-template bắt đầu trực tiếp bằng `{INJECTION_POINT}`;
redactor hiện tại nhận chuỗi bắt đầu bằng `{` như JSON và redact toàn bộ khi
không parse được. Fixture cuối dùng trường benign có sẵn trước key marker,
giữ request/template cùng thứ tự và kiểm tra đầy đủ key/value. Không sửa hoặc
giảm assertion bảo vệ redaction; không mở Direct fallback cho captured traffic.
Template form bắt đầu bằng marker này vẫn là một giới hạn hiện có, chưa sửa.

## Rủi ro còn lại

- Hướng dẫn vẫn do LLM áp dụng; no-signal loops, bỏ qua stateful guard hoặc gán
  sai marker vẫn có thể tái diễn. Không thêm runtime SQL semantic verifier.
- Skill vốn dài; phần thêm ngắn và đặt điểm quyết định sớm nhưng chưa có
  ablation để đo hiệu quả hoặc chi phí token. Các snapshot skill trong profile
  thí nghiệm cũ vẫn giữ nguyên; run mới phải dùng snapshot mới qua launcher.
- CALL/typed DBMS behavior thực tế chưa được replay qua target hoặc external
  model. SQLite minh họa và scripted HTTP chỉ kiểm chứng SQL local/hợp đồng.
- Static/empty responses, thiếu baseline/auth, write-only context, thiếu isolation
  hay capability vẫn có thể kết thúc unresolved. Đây là giới hạn cần giữ trung
  thực, không phải lý do ép negative/confirmed hoặc tự thêm readback.
