# KAgent — Tool Contract & Recovery: final implementation acceptance

Ngày nghiệm thu offline: **24/10/2026 (Asia/Saigon)**. Đây là báo cáo triển khai, không phải một RCA mới. Kết luận bên dưới chỉ nói về readiness offline; không xác nhận kịch bản 1 hoặc Whole-target lan-09 đã chạy thành công.

## 1. Baseline và tài liệu thiết kế

Chỉ dùng [KAgent — Tool Contract & Operation Recovery RCA](kagent-tool-recovery-rca.md), đủ 11 mục. SHA-256 của RCA trước/sau: `b7344632e3c79659e88b6cd4be70cbecffebd137c1c1481d2631f86bc2b69594`. Đối chiếu thêm nghiệm thu kịch bản 1 khi cần xác định A/B; không tìm, hợp nhất hay tái tạo RCA cũ.

HEAD baseline: `a8b673414e161bd38694d304434de665b74f8441`. Worktree đầu lượt có **13 tracked files đã sửa và 17 untracked files**. Các thay đổi lan-06/07/08, skills, prompt, workflow state và các báo cáo có sẵn được giữ nguyên. Snapshot byte/hash, status và diff nằm tại `/tmp/kagent-recovery-baseline-jfaqkegb`; diff nghiệm thu được tính so với snapshot này, không coi toàn bộ `git diff HEAD` là công việc của lượt này.

Có các tiến trình editor/app-server khác. Không có bằng chứng xác nhận độc quyền sửa repository; kiểm tra hash trước từng lần ghi và kiểm tra drift cuối lượt không phát hiện thay đổi đồng thời trong tập baseline. Không reset, checkout, clean, stash, stage, commit hay push.

## 2. Root-cause / decision matrix

| Nhóm | Phân loại / ưu tiên | Quyết định thực hiện | Bất biến và regression |
|---|---|---|---|
| RC-R2: HTTP chỉ cùng endpoint; proof chỉ cùng Candidate owner | CONFIRMED DEFECT / P0 | Tách owner khỏi resource/intent. HTTP hash toàn requested arguments và đối chiếu receipt của effective request; evidence gắn source path + parent set + registered snapshot | Đổi query/body/auth/proof/parents không clear failure. Không sửa request hay ownership để khớp |
| RC-R2: sibling dispatch trước failure | CONFIRMED DEFECT / P0 | Tạo retry edge nội bộ tại dispatch, chỉ tới đúng một failure đã ghi nhận; lưu dispatch/failure order và failed invocation | Pre-dispatched/live siblings, nhiều failures, late/duplicate/fake results fail closed |
| RC-R3: denial/persistence/timeout/unknown bị generic success clear | CONFIRMED DEFECT / P0 | Allowlist loại lỗi có thể sửa; authority, persistence, export, cancellation, timeout và unknown effects giữ unmatched | Không suy success thành fresh approval hoặc reconciliation |
| Receipt accepted của submission khác cùng Candidate/Attempt | CONFIRMED DEFECT / P0, biến thể phát hiện khi triển khai | Kiểm tra receipt bằng accepted state và constraints của chính submission: candidate, attempt, skill, outcome, evidence và source IDs được cung cấp | Ba negative regressions về outcome/evidence/source tái hiện trước phần sửa này và pass sau sửa |
| RC-R1: selected obs reference không tạo canonical proposal | CONFIRMED DEFECT / P1 | Chỉ tạo presentation intent nếu imported observation có trusted capture association, đúng current analysis session/epoch, không historical và selection còn hợp lệ | Runtime vẫn reject `obs_...`. Missing/wrong capture, wrong baseline/hypothesis không ghép |
| B: unsupported fields trên record_result | EXPECTED REJECTION; positive recovery phải giữ | Giữ action allowlists; accepted result cùng submission có thể recover sau corrected dispatch | Unsupported fields reject trước mutation; correction với receipt/state đúng accepted |
| RC-C1/C3: flat superset, attempt_id wording, bounds | CONTRACT GAP / P1 | Renderer chung từ ACTION_INPUTS/ACTION_REQUIRED; field-local membership/required guidance; bounds và obs reader pattern | Không viết lại action validation; giữ flat provider schema |
| RC-C2: selected retrieval / baseline / observation namespace | CONTRACT GAP + EXPECTED REJECTION / P1 | Additive selection source_ref metadata, hướng dẫn namespace và targeted typed argument errors | Không có obs→burp conversion cho execution; origin/method/path/baseline/signature/permission guards giữ nguyên |
| RC-R4: Direct final_response suy work remains từ history | CONFIRMED DEFECT / P1 | Workflow residual lấy từ facts; unmatched history/permission/export vẫn được hiển thị riêng | Direct/Whole-target complete + historical issue không tạo việc mới; incomplete không bị ẩn |
| Ownership/admission/prerequisite/budget/scope rejection | EXPECTED REJECTION | Giữ behavior fail-closed | Không nới permission, evidence, cleanup, attempt hoặc Finding gates |
| Schema khác trong matrix RCA, split/strict/universal validator | DEFER | Không có bằng chứng cần thiết cho correctness gate này hoặc cần thay đổi lớn | Không sửa hàng loạt HTTP/coverage/files/discovery/reader/adapter contracts |

## 3. Source files/functions thực sự sửa

- [agent.py](../src/agent/agent.py): `_selected_capture_workflow_args`, UI-only `_selected_capture_presentation_args`, `ToolCallResult`, result event receipt forwarding. Không thay planner/phase orchestration.
- [events.py](../src/agent/events.py), [outcome.py](../src/tools/common/outcome.py): optional transient native `RecoveryReceipt`; không thêm tool arguments hoặc session fields.
- [selection.py](../src/browser/selection.py): `SelectedCaptureArgumentError`, `CAPTURE_GUIDANCE`, additive `metadata.source_ref` giữ nguyên retrieval `id`.
- [http_tool.py](../src/tools/http/http_tool.py): presentation receipt tại native send/completion. Chỉ single-hop native ConnectError có no-send receipt đủ điều kiện; request admission, dispatch accounting, permission checks, limits và exceptions vẫn đi qua luồng cũ.
- [workflow_tool.py](../src/tools/workflow/workflow_tool.py), [action_view.py](../src/tools/workflow/action_view.py): `describe_action_contract`, schema field descriptions/bounds và dùng lại constants cùng giá trị hiện hữu. ACTION_INPUTS/ACTION_REQUIRED và accepted runtime set không đổi.
- [tool_result.py](../src/tools/common/tool_result.py): `ReadHTTPObservation.schema` công bố obs ID pattern/namespace đã được runtime kiểm tra.
- [admission.py](../src/ui/core/admission.py): complete HTTP argument digest, dispatch/resource/receipt constraints, giữ typed error kind/cancellation semantics.
- [outcomes.py](../src/ui/core/outcomes.py): owner/intent riêng, accepted assessment/evidence receipt đối chiếu authoritative state và submission.
- [state.py](../src/ui/core/state.py): dispatch-bound retry edge; issue category/resource/chronology gates; original sanitized diagnostic và recovered_by; fail closed khi local ledger mất history; banner tách workflow và history.

Không sửa skills/playbooks, source ownership validators, Workflow state machine, permission registry, provider/config, session stores, evidence/result/Finding admission hoặc artifact paths trong lượt này. Những diff có sẵn ở các nhóm đó vẫn thuộc baseline.

## 4. Phương án không chọn

Không triển khai oneOf/strict, 18 action tools, universal registry validator, provider adapter changes hay durable retry ledger. Flat schema vẫn có thể cho LLM gửi tổ hợp fields sai; runtime action-specific validation tiếp tục là nơi từ chối. Field guidance giảm ambiguity, không phải structural enforcement hay bảo đảm model tuân thủ.

Không dùng endpoint/action/Candidate owner đơn lẻ làm retry authority. Không chuyển obs IDs sang retrieval IDs để chấp nhận execution. Không ghép permission/persistence/export failures từ generic success. Không thay SQLi oracle, XSS execution/readback contract hoặc kết quả nghiệm thu cũ.

## 5. Regression mới và pre/post behavior

Thêm **53 test cases**: 30 UI recovery cases, 12 native controller/Burp/HTTP cases và 11 contract cases. Các tests có sẵn được cập nhật khi chúng kỳ vọng đúng hành vi false recovery cũ, hoặc giả định JSON example phải kết thúc toàn bộ description; không giảm live skip hay thay evidence/safety assertions.

- [test_tool_recovery_acceptance.py](../tests/ui/test_tool_recovery_acceptance.py): changed request/resources, categories, chronology, ambiguity/eviction, compaction/new turn, evidence registration, B correction, Finding/export, stale accepted submission và original diagnostics.
- [test_native_recovery_receipts.py](../tests/agent/test_native_recovery_receipts.py): trusted selected A association và negative controls; real native HTTP tool qua MockTransport cho exact retry/query/body/auth/timeout/read-error/redirect.
- [test_workflow_argument_contract.py](../tests/tools/test_workflow_argument_contract.py): generated action membership/projection, bounds và record_result unsupported-state-fields-before-mutation.

Có **14 negative failures được tái hiện trước patch đầu**, từ reducer/runtime presentation; cancellation/unknown-kind cases là robustness fixtures, không tuyên bố runtime cancellation cũ tự recovered trong thực nghiệm. Rà soát tiếp tái hiện **3 stale submission receipt failures** trước khi thêm đối chiếu submission. Sau sửa, các trường hợp tương ứng giữ unmatched; các positive retries A/B, same-resource evidence và exact native no-send HTTP retry recover với receipt đúng.

| Yêu cầu regression | Fixture/nhóm kiểm chứng |
|---|---|
| 1–3: unsupported fields, accepted args, action contract | Contract tests mới + existing Workflow argument/action view tests |
| 4–7: obs mismatch, unique/ambiguous selection, typed provenance | Native selected cases + capture selection, Burp selection, captured replay security tests |
| 8–10: A/B correction, sibling Candidate isolation | Native selected A, UI result B, candidate recovery contract và sibling matrix có sẵn |
| 11–12: changed/exact HTTP | Native requested/effective request matching; only attested no-send ConnectError eligible; generic network stays unmatched |
| 13–14: proof A/B, same resource/parents | Actual missing-proof repair → immutable registration; another path never clears A; receipt/parent/state checks |
| 15–16: authority/effects/persistence/export/cancellation | Parameterized typed errors + Finding/export separation + existing persistence/cancellation responsibility groups |
| 17: dispatch-before-failure | Pure reducer contract cases với eligible invalid_args, ngoài network sibling repro |
| 18–19: target/Candidate/Attempt/auth/objective/epoch; fake/stale/duplicate | Existing scope/candidate/progress matrices + hidden auth native case + new stale submission constraints |
| 20–21: ambiguity/256 cap/compaction/resume | New bounded ledger/compaction/new-turn cases + existing scope/session lifecycle fixtures; không suy retry qua resume |
| 22–23: Finding/export obligations; original history | Failures remain unmatched; persisted finding progress riêng; original sanitized issue trong recovered details và recovered_by |
| 24–26: completion/Direct/Whole-target | Direct new regression, lan-08/progress/outcomes fixtures; facts pending vẫn chặn completion |
| 27–28: offline Scenario 1 flow, SQLi/XSS gates | Burp selection/candidate validation recovery/whole-target/runtime completion/XSS/cleanup security và skill contract fixtures trong full collection |

## 6. Kết quả kiểm chứng

| Kiểm tra | Kết quả thực tế | Giới hạn |
|---|---|---|
| Targeted integration/compatibility checkpoint | **330 passed**, 113,38s | Có overlap với các nhóm dưới; không cộng thành unique total |
| Final regressions + contract/provider checks trên worktree bàn giao | **124 passed**, 11,01s | Bao gồm toàn bộ 53 cases mới; không provider/network thật |
| Full pytest trong disposable worktree | **8.864 passed, 12 skipped, 5 failed, 2 warnings**, 1.518,19s | Collection đủ **8.881 tests**; không gọi lần chạy này là full-green |
| Re-test sau sửa fixture/harness | **12 passed**, 8,64s | Toàn bộ 5 failed nodes đã pass, cộng 7 tests còn lại của related-request contract |
| Full Pyright với venv-linux | **0 errors, 0 warnings, 0 informations** | Thông báo có phiên bản Pyright mới không phải type-check warning; không cài/cập nhật package |
| Pyright cho test related-request vừa cập nhật | **0 errors, 0 warnings, 0 informations** | Production source không đổi sau full Pyright |
| Provider encoding | Core **32** mode/provider/stream combinations pass; thêm **7** mocked transport/retry cases và **4** related-request encoder cases pass | Nằm trong final 124/re-test 12; chỉ kiểm chứng local encoding/mock transport, không live API enforcement |

Bốn failed nodes của full run là `test_schema_examples_and_error_text_survive_supported_provider_encoding` cho OpenAI-compatible, DeepSeek, Anthropic và Gemini. Test cũ dùng json.loads trên toàn phần cuối description, vốn nay có action guidance; đổi sang đọc JSON example độc lập, vẫn assert chính xác example và toàn description sau objective projection. Không sửa provider encoders hoặc bỏ assertions về error/schema.

Failed node thứ năm là `test_overlapping_process_writers_serialize_read_dedupe_commit`: harness ban đầu thiếu `if __name__ == '__main__'`, khiến multiprocessing spawn chạy lại pytest. Sửa main guard của harness tạm; không sửa IntelligenceStore hay test giao dịch đó. Re-test trong cùng bản sao, sau đồng bộ test fixture đã sửa, pass cả 12 cases.

**Chưa chạy lại toàn bộ 8.881 tests trong một invocation sau các sửa fixture/harness.** Full collection và failed-node re-tests là hai bằng chứng riêng; không tuyên bố có một lượt full-suite sạch duy nhất. Không còn failed node chưa xử lý trong tập full run này.

Các lệnh chính (không bật live flags):

```text
venv-linux/bin/python -B /tmp/kagent-offline-pytest.py -q tests/ui/test_tool_recovery_acceptance.py tests/agent/test_native_recovery_receipts.py tests/tools/test_workflow_argument_contract.py tests/agent/test_related_request_contract.py tests/llm/test_workflow_action_projection.py
KAGENT_TEST_CHECKOUT=/tmp/kagent-offline-checkout-54sxsneg venv-linux/bin/python -B /tmp/kagent-offline-pytest.py -q
KAGENT_TEST_CHECKOUT=/tmp/kagent-offline-checkout-54sxsneg venv-linux/bin/python -B /tmp/kagent-offline-pytest.py -q tests/agent/test_related_request_contract.py tests/data/test_intelligence_reliability.py::test_overlapping_process_writers_serialize_read_dedupe_commit
venv-linux/bin/pyright
venv-linux/bin/pyright tests/agent/test_related_request_contract.py
```

Logs chi tiết: `/tmp/kagent-recovery-final-regressions.txt`, `/tmp/kagent-recovery-full-isolated.txt`, `/tmp/kagent-recovery-full-failures-retest.txt`, `/tmp/kagent-recovery-pyright-verified.txt` và `/tmp/kagent-recovery-pyright-test-update.txt`.

Các lệnh verification dùng `venv-linux`. Harness `/tmp/kagent-offline-pytest.py` bảo vệ dữ liệu gốc và chỉ cho socket connections tới cổng loopback do test process tự bind. MockTransport không mở socket. Các live opt-ins không được bật; không cài package hoặc gọi provider/target thực nghiệm.

Lượt full đầu trong repository gốc bị dừng vì guard chặn retained artifacts mặc định; **111 failed / 1.136 passed** trước interruption không được tính là verdict sản phẩm. 15 cases trách nhiệm đó pass trong disposable copy. Full run dùng `/tmp/kagent-offline-checkout-54sxsneg`, chứa source/tests/skills/config đang được review, không copy historical runtime data; hash source được đối chiếu với worktree.

## 7. Direct, Whole-target và Scenario 1 offline

Direct final_response với workflow facts không còn việc vẫn có thể báo operation error without a matched retry. Whole-target workflow_completed vẫn đòi completion_supported và không có pending workflow obligations. Finding chưa persist, thiếu proof, cleanup/coverage pending hoặc requested goals chưa xong vẫn là việc thật. Historical issues không tạo hoặc xóa các obligations này.

Scenario 1 được kiểm chứng bằng fixtures tổng hợp/offline: selected Burp → canonical Candidate → owned Attempt → native mocked HTTP → immutable Evidence → accepted Result → Finding, cùng các negative scope/source/prerequisite/cleanup cases. Không replay session lịch sử, không chạy lại kịch bản 1 và không chạy lan-09. Một finding/probe của fixture không phải bằng chứng target thực tế.

Schema freeze SHA-256, JSON canonical compact/sorted:

| Mode | Workflow schema SHA-256 | Bytes |
|---|---|---:|
| Direct | `e68e095f0568b23e7a0381a65bc955684365d5a1217aa18427c2f27568e7763d` | 15.148 |
| Whole-target | `9686410c013b0e9dc7826df1033378ab7167a94f37b707d16339140b78344836` | 16.848 |

Đây là schema baseline mới; thay descriptions có thể thay model tool/argument selection và token cost. Offline encoding không xác nhận live server API/model behavior.

## 8. Runtime safety invariants

Giữ Registry action-aware permission gate, exact active-origin/effective-port policy, private-host approval/cache rules, target/scope/permission epoch, selected request geometry/signature/revision/baseline/unique match, input/Candidate/Attempt ownership và budgets.

Giữ redaction, minimal persisted evidence, immutable proof hashes/parent sets, accepted result/confirmation/cleanup prerequisites, Finding eligibility/persistence và collision-safe artifact paths. HTTP receipts chỉ phục vụ presentation: không retry HTTP tự động, không đổi args, không cấp quyền, không đổi effects journal hoặc severity/impact.

Operation issues vẫn bounded 256; overflow làm correlation fail closed và có thông báo limitation. Invocation/retry metadata không trở thành model-supplied authority, session schema hoặc durable authorization. Compaction cùng turn giữ ledger; new turn/resume không phục dựng trusted edge từ historical text.

## 9. Historical integrity và phạm vi diff

Kiểm tra cuối: **3.107/3.107 files khớp byte hash**, không mất/thêm file trong tập historical đã inventory. Aggregate trước/sau giống nhau. Không có baseline file ngoài patch thay đổi; không phát hiện concurrent drift ở các file sửa. Production source và toàn bộ 20 source/test files cuối cùng khớp bản sao verification sau đồng bộ fixture.

Phạm vi lượt này: **11 source files + 9 test files + báo cáo này**. Đã inspect diff so với snapshot, git diff và git status; git diff --check sạch. RCA và mọi báo cáo nghiệm thu có sẵn giữ nguyên hash. Evidence/state do tests tạo nằm trong pytest tmp/disposable checkout, không trong historical stores gốc.

Tập bảo toàn gồm project `.kagent/`, `artifacts/`, `experiments/` và personal saved sessions; aggregate SHA-256 của manifest path/hash: `9a5319e29ce0c864dbb4db846efaa8e8fee9ab47ce27499891feff51d4d8b6c5`. Đây là fingerprint tập đã inventory, không tuyên bố mọi file trên máy bất biến.

Không sửa RCA, nghiệm thu kịch bản 1, lan-06/07/08, session, observations, evidence, Finding, coverage, Intelligence hoặc dữ liệu thực nghiệm. Không sửa unrelated baseline files. Chỉ tạo báo cáo triển khai này trong docs; không có RCA mới hoặc commit.

## 10. Residual limitations / BLOCKER / DEFER

**BLOCKER đã tái hiện: không còn trong phạm vi kiểm chứng offline.** Các false recovery chính và stale-submission variant có negative regressions; A/B và same-resource/native no-send positives pass.

Giới hạn verification: full run không single-green; 5 failed nodes được sửa ở test fixture/harness và re-test pass, như mục 6. 12 skips giữ nguyên semantics: 9 Java-gate cases thiếu cached WAR/Tomcat, 1 existing-container case cần operator opt-in, và 2 live model/provider opt-ins không bật. Hai pytest warnings thuộc malformed-config fixtures. Không gọi đây là một lượt full validation sạch hoặc live validation.

Ở một lượt UI hỗn hợp trước đó đã thấy failure timing của responsiveness (heartbeat 125,36 ms, io_on_ui_thread=false); một lượt control asyncio-wait riêng cũng thiếu recovery tick. Giữ nguyên tests/thresholds, không sửa responsiveness runtime. Trong full isolated run cuối, toàn bộ nhóm responsiveness pass. Đây không phải bằng chứng benchmark ổn định trên mọi tải máy.

- **DEFER:** Automatic reconciliation của permission denial/pending, policy/scope, persistence/publication, export, timeout/cancellation/unknown effects. Chưa có trusted reconciliation receipt phù hợp thì giữ unmatched, kể cả operation mới thành công. Finding saved và export success là hai obligations khác nhau.
- **DEFER:** Recovery cho arbitrary tools/action repairs ngoài các acceptance predicates đã chứng minh. Missing metadata, changed resources, multi-hop HTTP, read/write failures và ambiguous failures giữ warning; không đoán từ endpoint/tool name.
- UI ledger là local bounded history, không phải durable audit tổng số lỗi qua resume hoặc mọi turn. Overflow không được dùng làm bằng chứng không còn vấn đề.
- Live provider enforcement, xác suất model gửi đúng args, hiệu quả SQLi/XSS và kết quả whole-target chưa được đo bởi bản vá offline. Không oneOf/strict hoặc adapter rollout dựa trên encoder mock.
- XSS wording rộng về mutation/cleanup và các schema mismatches nhỏ khác trong RCA không được mở thành playbook/schema refactor trước lan-09.

## 11. Kết luận nghiệm thu

**READY FOR SCENARIO 1 RE-TEST — offline, với giới hạn verification ở mục 6/10.**

Bản vá đã loại các false recovery blocker tái hiện được; corrected retries chỉ được ghép khi đủ trusted association/receipt, thiếu bằng chứng thì vẫn unmatched. Action validation và safety guards giữ nguyên. Direct/Whole-target facts và historical issues được trình bày độc lập. Final regressions, failed-node re-tests và Pyright pass; không có dữ liệu lịch sử bị sửa.

Không đồng nhất readiness này với thành công thực nghiệm live hoặc một lượt full-suite sạch duy nhất. Không chạy kịch bản 1, lan-09, target thật hoặc provider thật trong lượt triển khai này.

Dừng sau implementation và offline verification. Người vận hành quyết định chạy kịch bản 1 trong session mới, đối chiếu nghiệm thu cũ, rồi mới cân nhắc Whole-target lan-09. Báo cáo này không cấp quyền hoặc tự khởi chạy các bước đó.
