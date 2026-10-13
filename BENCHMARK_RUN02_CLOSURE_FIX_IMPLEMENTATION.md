# Official Run 02 — Headless readback và workflow closure implementation

Ngày bàn giao: 2026-10-14. Phạm vi: offline implementation theo
`BENCHMARK_RUN02_CLOSURE_ROOT_CAUSE.md`; không chạy lại Official benchmark,
provider/model thật, HTTP target hoặc Docker reset.

## 1. Root causes đã xử lý

- **Fix A / RC-P1:** Headless adapter có capability đọc lại bounded range của
  observation native HTTP thuộc đúng case/controller/session hiện tại.
- **Fix B / RC-C1:** Terminal refusal và các nhánh synthesis vì bounded stall
  kiểm tra active attempt và thực hiện unresolved disposition khi metadata đủ
  an toàn. Khi không đủ, phát error và lưu diagnostic rõ ràng, giữ stop reason.
- **RC-P2:** `ask_user` headless phân loại input unavailable bằng
  `PermissionPolicyBlocked`, không ghi nhận operator explicitly denied. Agent
  dừng ngay sau unavailable; không chọn option hoặc lặp hỏi.
- **Fix C / RC-H1:** Worker kiểm tra lifecycle sau background drain, trước
  freeze/export. Active orphan không còn được xuất với status `completed`.

Fix B là implementation bảo thủ có explicit failure, không bảo đảm tự động ghi
result cho mọi attempt từng gửi HTTP. Không có mục tiêu chuyển 18 cases thành
TP/TN hoặc thay đổi điểm benchmark.

## 2. Files/functions thay đổi

| File | Functions / thay đổi | Lý do |
|---|---|---|
| `benchmarks/scenario1/core/runtime.py` | `HeadlessPermissions.bind_case`, `_owned_readback`, `ask`; wiring trong `execute_case` | Bind case identity và trả approval một lần cho exact owned range |
| `benchmarks/scenario1/core/runtime.py` | `MissingInput.ask` | Phân biệt thiếu input với explicit refusal |
| `benchmarks/scenario1/core/runtime.py` | `case_closure_diagnostic`, `execute_case` | Bảo vệ export completion invariant |
| `src/agent/agent.py` | Refusal branch; `_whole_target_synthesis`; `_close_terminal_attempt`, `_submit_unresolved_closure` | Dừng probing, disposition đúng owner hoặc explicit failure |
| `tests/benchmarks/test_scenario1_closure.py` | Offline regressions mới | Real Agent/Registry/WorkflowState, scripted client và mocked HTTP |
| `tests/security/test_http_readback_lifecycle.py` | Một assertion về error khi stall | Fixture thiếu current owner/declaration phải có explicit closure failure; giữ assertion attempt/evidence không đổi và không negative |

`_stop_evidence_recovery()` giữ nguyên implementation hiện có. Việc trích helper
chung ban đầu làm hỏng exhausted-budget recovery của state đã hydrate thành
`interrupted`; thay đổi đó đã được bỏ và tests resume gốc được giữ nguyên.
Submission mới dùng cùng cơ chế assistant tool call → `execute_tool_calls` →
Registry → WorkflowTool, với kiểm tra commit/persistence riêng cho active owner.

## 3. Permission behavior sau Fix A

Adapter reconstruct exact `observation:<obs_id>:<start>:<maximum>` và đối chiếu
key do Reader tạo; reviewed prose không được dùng làm authority. Trước approval
phải có current review, `high-impact`, `no-session-cache`, đúng Reader của
controller; gọi lại `ReadHTTPObservation.validate_rights(receipt=False)`.

Ngoài production checks, harness kiểm tra case binding đã seal trong observation,
session, candidate fingerprint, current objective/candidate, selected attempt,
epoch/revision và exact declared origin. Nguồn phải là `native-http`.
Approval chỉ là `ALLOW_ONCE`; Reader/Registry vẫn kiểm tra receipt, freshness,
revocation, integrity và managed secrets trước/sau permission suspension.

Reader không gửi HTTP. Tests đối chiếu số sent requests, dispatch attempts và
HTTP admissions trước/sau range reads. `yolo=false`; grant/quota/private-host/
origin controls giữ nguyên. Generic `read_tool_result` không nhận thêm quyền;
`obs_`, `sf_`, `tr_` không được alias hoặc chuyển reference family.

## 4. Terminal closure lifecycle sau Fix B

1. Refusal batch hoặc headless input unavailable dừng probing. Direct và
   Whole-target stall gọi closure trước tool-free synthesis.
2. Chỉ xem active attempt thuộc current objective. Kiểm tra controller binding,
   session, candidate binding, current selector, epoch, target revision,
   result position, exact origin và workflow state. WorkflowTool phải gắn đúng
   live state/target/session trước submission. Không repair ownership.
3. Không disposition pause/interruption, cancelled goals hoặc pending/stale/
   cancelled permission state. Không tạo attempt khi chưa có attempt.
4. Actual permission/scope/policy/input blocker chọn `blocked`. Khi required
   conclusion/proof chưa được commit trong bounded validation và không có
   blocker đó, chọn `insufficient-evidence`. Stop label không tự chọn outcome.
5. Runtime submission chỉ có `workflow.record_result`, đúng candidate/attempt,
   unresolved outcome, reason và mutation/cleanup metadata đủ an toàn. Không
   salvage rejected observation/evidence IDs hoặc proof parents.
6. Kiểm tra `ok=true`, matching result ID/attempt/outcome, source seal,
   attempt `unresolved`, candidate `deferred`; await `save()` và kiểm tra saved
   workflow revision trước khi coi closure thành công.

Failure phát fixed/sanitized diagnostic `Workflow closure failed (...)` và error
event. Original `all_tools_refused`/`workflow_stalled` được giữ; worker dùng
execution failure nếu còn orphan. Không có direct state flip hoặc fake result.
Cancellation được propagate; nếu WorkflowTool đã commit trước save failure/
cancellation thì giữ actual in-memory commit, không báo persistence thành công.

Repeated/concurrent closure không tạo result thứ hai. Existing accepted terminal
result và source seals được giữ nguyên. Whole-target không đóng candidates khác,
không tiếp tục probing sau explicit denial, không tạo findings hoặc passed
coverage từ unresolved.

## 5. Mutation/cleanup safety

`mutation_performed=false` chỉ được runtime tự điền khi có bằng chứng bảo thủ:
native HTTP dispatch/admission đều bằng 0, không có retained/selected source và
history chỉ có bookkeeping/readers thuộc tập giới hạn. Điều này bao phủ fixture
name-tainted sai component bị reject trước admission.

Sau HTTP dispatch, absence of a declaration không chứng minh read-only: HTTP
method hoặc response giống nhau không được dùng để suy mutation. Closure mới
chỉ carry declaration `mutation_performed=true` của **đúng attempt** trong repair
ledger, với cleanup `pending`, `failed` hoặc `requires-user-action` và explanation;
WorkflowTool vẫn validate declaration. Fixture có write acknowledgement kiểm tra
giữ `true` và unresolved cleanup đúng như đã khai.

Không suy cleanup `succeeded`/`not-required`, không dùng benchmark reset làm Agent
cleanup. Unknown, contradictory hoặc chưa đủ xác minh metadata dẫn tới explicit
failure; không fabricate canonical result để giải phóng ownership.

## 6. Worker/export/evaluator semantics sau Fix C

`case_closure_diagnostic()` là read-only. Active attempt của case tạo diagnostic
`active-case-attempt-without-closure`; completed/unresolved attempt không có
matching result tạo `closed-case-attempt-without-result`.

Chỉ status vốn là `completed` bị đổi sang `runtime-error` khi invariant thất bại.
Timeout/provider/budget errors vẫn giữ execution status của chúng. Export giữ
actual stop reason, workflow snapshot và additive `closure_diagnostic` trong
runtime metadata. Không có attempt thì không tạo attempt/result.

`canonical.freeze()` và evaluator không sửa. Valid blocked/insufficient-evidence
vẫn thuộc unresolved partition; closure failure thuộc execution-failed theo
contract. Missing/blocked không trở thành TN. Tests kiểm tra TP/TN đều không được
tạo từ những fixtures unresolved/failure này.

## 7. Verification thực tế

| Kiểm tra | Kết quả thực tế |
|---|---|
| Fix A focused: new harness tests + `test_http_observation_reader.py` | **39 PASS**, 0 FAIL, 0 SKIP |
| Final targeted: closure, request-body, reliability, HTTP reader/readback, bounded-validation | **157 PASS**, 0 FAIL, 0 SKIP |
| Final security: correctness/blockers, observation grounding, recovery contract, execution policy, private host | **138 PASS**, 0 FAIL, 0 SKIP |
| Lifecycle checkpoint: full recovery contract + new closure fixtures | **85 PASS**, 0 FAIL, 0 SKIP |
| Additional terminal-seal + save-cancellation regressions | **2 PASS**, 0 FAIL, 0 SKIP; included subsequently in final targeted run |
| Final exact-attempt declaration lookup recheck: stop paths, failure cases, concurrent duplicate | **17 PASS**, 0 FAIL, 0 SKIP |
| Broader Agent/tools/state/benchmark/integration responsibility groups | **2559 PASS**, 0 FAIL, 0 SKIP (784.39 s) |
| Final entire new regression file, gồm WorkflowTool foreign-state guard | **55 PASS**, 0 FAIL, 0 SKIP (36.88 s) |
| Repository-wide `venv-linux/bin/pyright` | **0 errors, 0 warnings** |
| Final Pyright on all four changed Python files | **0 errors, 0 warnings** |
| `git diff --check` và whitespace check trên hai files mới | Không có whitespace errors |

Các con số ở các rows có overlap, không cộng thành số lượng tests độc lập.
File regression mới có **55 test cases**. Final owner recheck chạy sau khi
lookup declaration được giới hạn trực tiếp bằng active `attempt_id`.
Broader run bắt đầu ở integration checkpoint. Sau checkpoint, restored
evidence-recovery behavior được retest trong final security group; final native
WorkflowTool ownership guard và các paths của nó được retest qua toàn bộ 55 cases
mới và final changed-file Pyright. Không lặp full broader run cho guard này.

Commands:

```bash
venv-linux/bin/python -m pytest -q \
  tests/benchmarks/test_scenario1_closure.py \
  tests/benchmarks/test_scenario1_request_body.py \
  tests/benchmarks/test_scenario1_reliability.py \
  tests/security/test_http_observation_reader.py \
  tests/security/test_http_readback_lifecycle.py \
  tests/agent/test_bounded_validation_regressions.py --tb=short

venv-linux/bin/python -m pytest -q \
  tests/security/test_evidence_correctness_blockers.py \
  tests/security/test_evidence_correctness.py \
  tests/security/test_observation_grounding.py \
  tests/security/test_evidence_recovery_contract.py \
  tests/security/test_execution_policy.py \
  tests/security/test_private_host.py --tb=short

venv-linux/bin/python -m pytest -q tests/agent tests/tools tests/state tests/benchmarks \
  tests/integration/test_whole_target_workflow.py \
  tests/integration/test_requested_goal_lifecycle.py \
  tests/integration/test_phase4_workflow_e2e.py \
  tests/integration/test_skill_workflow.py \
  tests/integration/test_workflow_checkpoint_artifacts.py \
  --ignore=tests/benchmarks/test_scenario1_operator_target.py \
  --ignore=tests/benchmarks/test_scenario1_idle_gate.py --tb=short

venv-linux/bin/python -m pytest -q tests/benchmarks/test_scenario1_closure.py --tb=short

venv-linux/bin/pyright
venv-linux/bin/pyright benchmarks/scenario1/core/runtime.py src/agent/agent.py \
  tests/benchmarks/test_scenario1_closure.py tests/security/test_http_readback_lifecycle.py
git diff --check
```

Các runs trung gian đã phát hiện và sửa: lỗi fixture CWE của manifest SQLi, một
metric key trong test mới, assertion về silent stall, và regression khi dùng
active-owner helper cho exhausted restored recovery. Không làm yếu evidence,
permission, scope hoặc resume assertions để đạt PASS.

Failures trung gian đáng chú ý: responsibility subset **80 PASS / 1 FAIL** do
assertion silent stall; security **136 PASS / 2 FAIL** do shared-helper resume
regression; targeted **152 PASS / 1 FAIL** do metric key đã load trước khi sửa.
Các failures đó đã được retest PASS trên final responsibility subsets ở trên.
Pyright lần đầu báo 29 errors về optional/asserted types; sau bổ sung narrowing
và corrected API field names, cả repository-wide và final changed-file check
đều không có errors. Không cài hoặc đổi version Pyright.

## 8. Những kiểm tra không chạy

- Official Run 01/02 hoặc targeted live benchmark: bị loại khỏi session theo
  yêu cầu. Historical manifests/results/metrics không được rewrite.
- Live provider/model, target requests và Docker reset: không chạy.
- `tests/benchmarks/test_scenario1_operator_target.py` và
  `test_scenario1_idle_gate.py` không nằm trong broader run: nhóm này bao gồm
  container/live-target hoặc prepared Java deployment checks; không cần cho
  offline runtime closure verification.
- Full repository pytest suite chưa chạy: dùng responsibility groups cho Agent,
  tools, state, benchmark và các integration/security workflow liên quan; không
  mở rộng sang provider/UI và integrations ngoài phạm vi.

## 9. Remaining limitations và regression risks

- Không có closure-only LLM stage. Main Agent chưa khai mutation/cleanup sau HTTP
  có thể vẫn để attempt active, nhưng sẽ có explicit error và failure export.
  Đây là blocker cụ thể cho deterministic canonical closure của các attempts đó.
- Closure mới giới hạn expert route và current session/controller. Generic route,
  unknown/foreign metadata hoặc ambiguous active ownership fail closed.
- Zero-action test và permission-history check có chủ ý bảo thủ trên session
  history; earlier dispatch hoặc pending/stale review có thể khiến một attempt
  mới không đủ điều kiện tự disposition. Resume/recovery thông thường giữ nguyên.
- Cleanup declarations `succeeded` hoặc `false` sau admitted traffic không được
  runtime tự xác minh; giữ explicit failure nếu chưa có terminal result.
- Existing evidence-recovery mechanism và interpretation của model declarations
  giữ nguyên; patch này không thiết kế lại mutation bookkeeping trong playbooks.
- Offline fixtures xác minh lifecycle/permission, không chứng minh stochastic
  model sẽ submit proof đúng sau readback hoặc mọi historical case sẽ đóng được.
- Không sửa payloads, SQLi/XSS semantic thresholds, timing novelty, reference
  retention, compaction, taxonomy, ground truth hoặc confusion-matrix logic.

## 10. Mức sẵn sàng cho targeted benchmark recheck

Sẵn sàng kiểm tra có mục tiêu sau offline verification: owned readback,
refusal/stall disposition khi metadata đủ, và failure export khi metadata thiếu.
Giữ anti-stall threshold **4**, exploration allowance **8** và `max_steps`/budgets
hiện hành. Recheck cần phân biệt valid unresolved với execution failure và theo
dõi mutation/cleanup declarations; không đặt kỳ vọng tăng TP/TN hoặc score.

Không install packages, stage, commit hoặc push. Hai tài liệu audit/root-cause
untracked có trước task được giữ nguyên.
