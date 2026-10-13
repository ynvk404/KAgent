# Phase 2 — Whole-target Workflow Reliability

Ngày: 2026-10-13. Repository: `D:/DOANTOTNGHIEP/kagent` (WSL:
`/mnt/d/DOANTOTNGHIEP/kagent`). HEAD lúc bắt đầu: `7aab25e`.

## Baseline đã kiểm tra trước implementation

Đã đọc `AGENTS.md`, handoff Phase 1, production Agent/Planner/Workflow,
permission/validation context và các playbooks recon, enumeration, input analysis,
SQLi, XSS. `git status --short` và `git diff --stat` đều rỗng khi bắt đầu.
Không có thay đổi từ session khác cần ghi đè hoặc đảo ngược.

Source thực tế đã có:

- Evidence Recovery: submission ban đầu + tối đa hai repair submissions;
  rejection limit 3, terminal repair iteration limit 6.
- Accounting sau successful commit tính vòng repair cuối trước khi đóng budget;
  continuation/restore không hoàn lại consumed budget.
- Default Agent steps: Direct 30 / Whole-target 60; explicit overrides được giữ.
- Các sửa baseline tests sau Phase 1 đã nằm trong HEAD hiện tại.

Audit đúng các nhóm từng có tám failing cases trong handoff Phase 1:
**62 passed, 4 failed** trước sửa Phase 2, 36.41s.

| Baseline group | Trạng thái trên worktree ban đầu |
|---|---|
| `test_isolation_and_permission_boundaries` | PASS; HTTP phase fixture đã được sửa |
| `test_evidence_receipt_uses_existing_readonly_workflow_action` | PASS |
| Candidate recovery transcript, Direct và Whole-target | PASS |
| Default/hybrid schema budget 28.000 | FAIL, có trước Phase 2; ngoài phạm vi |
| Retry projection, Anthropic và Gemini | FAIL, có trước Phase 2; ngoài phạm vi |

Không sửa bốn lỗi baseline còn lại. Không đổi pytest collection config.
Dùng `--import-mode=importlib` trong các lệnh để tránh collision đã ghi trong
handoff. Không dùng kết quả này để tuyên bố toàn repository xanh.

Checkpoint rộng còn phát hiện một baseline failure chưa có trong danh sách
handoff: `tests/scenarios/test_recovery.py::test_s04_s16_native_truncation_immutable_repair_or_bounded_closure[budget-closure]`
vẫn đòi dừng sau hai submissions. Đã extract tracked HEAD bằng `git archive`
vào `/tmp/kagent-phase2-head-baseline-cdark8hr` và chạy lại đúng bảy failing
cases của checkpoint đầu: **6 passed, 1 failed**, 86.81s. Cùng budget-closure
failure tái hiện trên HEAD, không do Phase 2. Không sửa test này hoặc recovery
accounting trong nhiệm vụ này.

Sáu safety cases còn lại thất bại ở expectation cũ `workflow_state` cho unknown
candidate khi start. Đây là thay đổi classification có chủ đích của B:
`invalid_args` + `UNKNOWN_CANDIDATE` + `argument_error`, không phải thay đổi
admission/ledger. Cập nhật đúng một expectation trong shared scenario script,
thêm assertions về diagnostic; giữ mọi oracle kiểm tra evidence, ownership,
permission, immutable state, HTTP count và kết quả cuối.

## A. Orchestration và discovery prerequisites

**VERIFIED — NO CHANGE** đối với orchestration/admission/completion contracts.

Planner ưu tiên discovery phase còn mở; đây là guidance, không phải permission
gate. `phase_completion_readiness` giữ prerequisite recon → enumeration →
input_analysis, canonical artifact, coverage dimensions, failed/cancelled work
và input disposition checks. Expert `start_validation` sử dụng current
objective/target, unique validator, Candidate và validation context; không thêm
discovery prerequisite chung. Generic route vẫn giữ prerequisite riêng hiện có.

Regression gọi production `start_validation` và terminal assessment khi chưa có
phase completion, cho SQLi ở cả Whole-target, Direct, candidate-validation.
Whole-target vẫn trả `phase:recon`; hai chế độ còn lại không bị ép discovery.
Phase completion/coverage correction dùng artifact và records, không phát sinh
HTTP để đánh dấu tiến độ. Các integration tests hiện có kiểm tra Planner không
đề nghị lặp lại phase còn hợp lệ và artifact/readiness invalidation.

| Requirement | Status | Bằng chứng / quyết định |
|---|---|---|
| A1, ba required phases | VERIFIED — NO CHANGE | `REQUIRED_WHOLE_TARGET_PHASES` không đổi |
| A2, giữ discovery prerequisites | VERIFIED — NO CHANGE | Out-of-order completion bị chặn; readiness gate không nới |
| A3, Validation sớm khi hợp lệ | VERIFIED — NO CHANGE | Production expert admission trước discovery |
| A4, Validation sớm không tự complete discovery | VERIFIED — NO CHANGE | Terminal result vẫn để `completed_phases` rỗng |
| A5, không thêm prerequisite chung cho start | VERIFIED — NO CHANGE | Không thêm discovery gate vào expert start |
| A6, Direct/candidate-validation không chạy discovery | VERIFIED — NO CHANGE | Ba-mode regression và existing Direct paths |
| A7, reuse observations/records | VERIFIED — NO CHANGE | Repair fixtures không recapture; correction không HTTP |
| A8, không lặp phase hợp lệ | VERIFIED — NO CHANGE | Existing Whole-target Planner/phase integration |

## B. Workflow errors và self-correction

**IMPLEMENTED** diagnostics/schema cục bộ; không tạo recovery controller mới.

Root causes:

1. `dns_resolution` không thuộc coverage vocabulary: contract dùng
   `target_resolution`. Schema trước đây để `coverage_dimension` là string mà
   không quảng bá mapping theo phase. Không thêm alias `dns_resolution`.
2. `record_phase_coverage` chỉ nhận recon/enumeration. Input analysis hoàn tất qua
   canonical inputs/dispositions + artifact + `complete_skill`, không qua một
   coverage phase mới. Schema nay giải thích rõ điều này.
3. `active attempt declaration changed` là immutable-state conflict hợp lệ:
   normalized related requests/criteria đã được đóng vào attempt. Không thay
   primary sink hoặc thêm required readback vào attempt đang chạy. Diagnostic
   trả attempt ID và hướng dẫn resume cùng declaration hoặc honest closure và
   explicit retest.
4. Sai action/unsupported args/missing required args đã được kiểm tra trước
   mutation bằng `invalid_args`; wrong attempt/source references có stable
   Phase 1 evidence codes. Unknown candidate khi start nay có next action lấy
   ID thật từ list. Active-attempt collision giữ honest closure guidance, thêm
   category/code có cấu trúc.
5. LLM cố kết thúc khi còn công việc đã được Agent xử lý bằng actual WorkflowState
   completion gate, continuation/stall/max_steps/synthesis. Không cần thêm retry
   budget hoặc terminal state giả.

`_typed_result` bảo toàn `ToolOutput` đã typed, thay vì ghi đè mọi error thành
`workflow_state`. Error text prefix vẫn tương thích; các targeted errors bổ sung
JSON `code/category/next_action`, allowed dimensions hoặc readiness snapshot.
Policy denial vẫn đi qua existing Registry/permission `policy_block`,
`permission_denied`, `scope_denied`, cancellation và pending metadata.

| Requirement | Status | Bằng chứng / quyết định |
|---|---|---|
| B1, root cause từng nhóm | IMPLEMENTED | Phân tích trên; source contract đối chiếu với regression |
| B2, schema/diagnostic/guidance đúng tầng | IMPLEMENTED | Workflow schema/error envelope; không sửa provider |
| B3, thao tác hợp lệ tiếp theo | IMPLEMENTED | Allowed vocabulary, phase readiness, list/attempt guidance |
| B4, phân biệt bốn nhóm lỗi | IMPLEMENTED | Argument category, missing prerequisite, immutable conflict; policy metadata giữ nguyên |
| B5, blocked hợp lệ không nới contract | IMPLEMENTED | Các lỗi vẫn reject trước commit |
| B6, không mở API để hợp thức hóa call sai | VERIFIED — NO CHANGE | ACTIONS/ACTION_INPUTS/coverage vocabulary không đổi |
| B7, không global retry/recovery budget | VERIFIED — NO CHANGE | Chỉ diagnostic và existing outer loop |
| B8, không đổi Phase 1 Evidence Recovery | VERIFIED — NO CHANGE | Constants, accounting, manifests và recovery codes không sửa |

Scripted offline Agent kiểm tra correction hai coverage errors qua production
dispatch. Điều này không chứng minh mọi lỗi Workflow, hoặc mọi external LLM,
đều tự sửa thành công. Các legacy errors ngoài nhóm được sửa vẫn có existing
typed classification; không tuyên bố đã normalize toàn bộ Workflow error API.

## C. Completion consistency

**VERIFIED — NO CHANGE** đối với production completion gates; bổ sung regression.

`validation_completion_error` tách accepted assessment, immutable proof,
coverage synchronization, cleanup và finding persistence. `whole_target_status`
giữ mọi input/candidate/discovery obligation; Agent bổ sung requested-goal
reconciliation và no-candidate review binding. Không thêm completion marker.

| Requirement | Status | Bằng chứng / quyết định |
|---|---|---|
| C1, nghĩa vụ bắt buộc chưa xử lý | VERIFIED — NO CHANGE | Pending inputs/phases/sibling candidates ngăn completed |
| C2, confirmed có evidence/result hợp lệ | VERIFIED — NO CHANGE | Production assessment/evidence ownership + finding persistence |
| C3, not-confirmed terminal có giới hạn | VERIFIED — NO CHANGE | Accepted negative complete assigned work, không target-safe claim |
| C4, không ép insufficient thành terminal | VERIFIED — NO CHANGE | Outcome vẫn insufficient; candidate deferred và completion blocked |
| C5, no_candidate khác negative | VERIFIED — NO CHANGE | Goal-review tạo no_candidate, không thêm ValidationResult âm tính |
| C6, recorded scope khác exhaustive coverage | VERIFIED — NO CHANGE | Existing synthesis limits; XSS guidance thêm distinction cụ thể |
| C7, pending state/next action thực | VERIFIED — NO CHANGE | Structured finding/coverage/revalidate/input/phase/goal-review actions |
| C8, không bỏ obligations/tạo terminal giả | VERIFIED — NO CHANGE | Mixed terminal + unresolved, proof tampering, closure rejection |

New matrix kiểm tra actual `_whole_target_state()` và canonical records:
SQLi confirmed thiếu persisted finding; coverage pending; immutable snapshot
bị thay bytes; pending/blocked input sau candidate terminal; terminal sibling với
browser-required/insufficient-evidence; valid not-confirmed; requested class chưa
có candidate; early Validation thiếu discovery; Direct admission không discovery.
Đây không chỉ là assertions về wording của final response.

## D. XSS coverage và unresolved surfaces

**IMPLEMENTED** guidance/identity advertisement; **VERIFIED — NO CHANGE** đối
với data model, dedup, outcome/ownership/finding/completion enforcement.

Root cause guidance: XSS playbook đã phân biệt API, DOM và stored, nhưng chưa
chỉ rõ cách giữ riêng hai hypotheses có cùng endpoint/method/input. Candidate
đã có `test_case` trong fingerprint, binding, serialization và coverage subcase.
Không cần schema version mới hoặc hệ thống trạng thái song song.

Schema và input-analysis/XSS playbooks nay hướng dẫn stable `test_case` dựa trên
source/sink path có evidence, trước khi start attempt. Cùng hypothesis reuse
identity; payload variants không tạo sibling mới. DOM cần observed source-to-sink;
stored cần persistence và rendering/readback context. Không suy ra hypothesis
từ parameter name, SPA route name, application type, raw JSON hoặc markup.
Browser-dependent proof giữ `browser-required`; không tự nâng thành terminal.

| Requirement | Status | Bằng chứng / quyết định |
|---|---|---|
| D1, track DOM/stored hypothesis riêng | IMPLEMENTED | Existing Candidate/test_case/signals/source_ref + unresolved outcomes |
| D2, HTTP/API không complete XSS toàn bộ | IMPLEMENTED | Bounded API-only guidance và terminal/unresolved sibling regression |
| D3, không tạo từ tên/raw markup | VERIFIED — NO CHANGE | Existing input-analysis bar; guidance nêu rõ không suy diễn |
| D4, API/DOM/stored identity và dedup | IMPLEMENTED | Advertise existing test_case; cùng geometry ba IDs, duplicate reuse |
| D5, không browser cho mọi XSS | VERIFIED — NO CHANGE | Production JSON API negative terminal; deterministic HTTP contract giữ |
| D6, browser-required không đổi thành terminal | VERIFIED — NO CHANGE | Persist/restore + completion blockers |
| D7, Finding chỉ đủ evidence | VERIFIED — NO CHANGE | Unresolved candidates không finding-eligible |
| D8, không browser automation/MCP changes | NOT APPLICABLE | Không triển khai hoặc sửa Browser MCP |

Tracking không bị deferred do data model đã đủ. Semantic source/sink discovery
vẫn thuộc skill/assessment reasoning; tests không chứng minh LLM luôn nhận diện
hết DOM/stored surfaces hoặc mọi XSS judgement đều đúng.

## E. Attempt failure và independent continuation

**IMPLEMENTED** conservative continuation chỉ cho Whole-target.

Root cause: hai exhaustion entrypoints (budget đã cạn đầu turn và rejection/clock
cạn sau batch) đều return `_stop_evidence_recovery` vô điều kiện.
Một unresolved attempt bị đồng nhất với dừng toàn Agent turn dù state có
candidate độc lập. Ngoài ra expert start có thể reopen unresolved exhausted
candidate trong cùng Whole-target objective.

Giữ controller closure qua production Registry → Workflow `record_result` với
`insufficient-evidence`. Chỉ sau receipt hợp lệ mới xét lại actual WorkflowState.
Nếu có fresh expert candidate độc lập, current context/scope hợp lệ, không còn
active attempt, execution quota còn, autonomous target HTTP grant còn hiệu lực
và request quota còn, tiếp tục trong outer-loop budget hiện tại. Mỗi call vẫn
đi qua permission, policy, evidence và ownership gates; preflight không grant
quyền hoặc dispatch HTTP. Không reset loop, budget, counters hoặc đổi old result.

Không tiếp tục khi batch có policy/permission/scope failure; quyền bị revoke,
grant expired/exhausted, stale explicit auth/baseline, scope mismatch, cancellation
hoặc closure failure. Explicit operator stop trong Whole-target không có goals
nay cũng dừng trước recovery dispatch và giữ unresolved state. Existing goal
cancellation path và Direct/candidate-validation stop behavior giữ nguyên.

Whole-target `start_validation` từ chối reopen closed exhausted insufficient
candidate trong cùng objective. Explicit operator-selected retest dùng objective
identity khác như contract hiện có; không cấp retest qua một flag LLM mới.

| Requirement | Status | Bằng chứng / quyết định |
|---|---|---|
| E1, không auto retry exhausted | IMPLEMENTED | Same-objective start rejection; old candidate không được chọn continuation |
| E2, Continue/Resume không reset recovery | VERIFIED — NO CHANGE | Existing accounting source không sửa; restore/retest/mode regressions |
| E3, giữ old unresolved obligations | VERIFIED — NO CHANGE | Old outcome vẫn insufficient; completion vẫn blocked sau sibling terminal |
| E4, attempt failure không assessment completion | IMPLEMENTED | Continuation không trả completed; final state kiểm tra toàn objective |
| E5, operator stop/cancel ưu tiên | IMPLEMENTED | Stop không-goal + existing goal cancellation; aborted signal không continuation |
| E6, policy/permission/closure không bỏ qua | IMPLEMENTED | Real policy/permission denial batch; closure failure fail-closed |
| E7, không tiếp tục chỉ né workflow_blocked | IMPLEMENTED | Eligible independent work là điều kiện; hết actionable vẫn blocked |
| E8, Direct/candidate-validation giữ hành vi | VERIFIED — NO CHANGE | Start/batch exhaustion matrix và mode-specific restart regression |
| E9, không mở rộng Direct request/candidate | VERIFIED — NO CHANGE | Continuation flag và helper chỉ Whole-target; không tự start sibling Direct |

**DEFERRED — broader independent work:** chưa auto-continue nếu chỉ còn discovery,
finding persistence, cleanup, evidence revalidation, Generic proposals hoặc work
cần fresh/confirm-each authorization. Các action này cần action-specific context,
dependency và admission facts khác; candidate preflight hiện tại không chứng
minh chúng an toàn. Giữ fail-closed. Hướng tối thiểu về sau là reuse read-only
admission facts cho từng existing action và kiểm chứng denial/cleanup/ownership
trước khi mở rộng selector; không thêm parallel state hoặc global retry budget.

**DEFERRED — preexisting scenario expectation:** budget-closure scenario vẫn
kiểm tra mức hai submissions có trước điều chỉnh recovery. Đối chiếu HEAD xác
nhận không phải runtime regression Phase 2; để nguyên và báo riêng. Sửa fixture
này cần một nhiệm vụ bảo trì acceptance của Phase 1, không thay recovery limits.

## Files sửa và invariants

| File | Lý do |
|---|---|
| `src/tools/workflow/workflow_tool.py` | Coverage/hypothesis schema guidance; targeted diagnostic envelopes; exhausted Whole-target reopen guard |
| `src/agent/agent.py` | Hai exhaustion boundaries; safe candidate continuation; stop không-goal; policy/permission priority |
| `skills/cross-site-scripting/SKILL.md` | Evidenced separate API/DOM/stored hypothesis và existing identity guidance |
| `skills/web-input-analysis/SKILL.md` | Triage/dedup guidance cho sibling source/sink hypotheses |
| `tests/integration/test_phase2_whole_target_reliability.py` | New production-based structured state/Agent regressions |
| `tests/security/test_evidence_recovery_contract.py` | Existing restart regression chia Whole-target rejection và unchanged Direct/candidate-validation carry behavior |
| `tests/scenarios/test_safety.py` | Unknown candidate expectation và diagnostic assertions theo category mới, không nới outcome/ledger oracle |
| `components/phase2_whole_target/implementation-verification.md` | Handoff này |

Không sửa Evidence Recovery constants/accounting, default max_steps/overrides,
ordinary validation budgets, required discovery contracts, state version,
source ownership/immutable manifests, findings/redaction, permission/registry
gates, provider retries, Browser MCP/Burp bridge, BenchmarkJava, context transport,
compaction hoặc TUI. Không thêm parallel execution. Không commit/push/reset/clean,
install package hoặc xóa artifacts.

Trong lúc verification xuất hiện untracked `components/discovery_quality_review/`
từ công việc khác. Không đọc, sửa, xóa hoặc đưa thư mục đó vào Phase 2 scope.

## Verification

Offline HTTPX fixtures và scripted/fake LLM; không external LLM, live target,
Docker benchmark hoặc exploit thực tế. Live container opt-in được unset trong
process verification. Python/Pyright dùng `venv-linux` qua WSL.

| Checkpoint | Kết quả |
|---|---|
| Baseline groups trước sửa | 62 passed, 4 preexisting failures |
| Regression đầu tiên trước sửa | 16 passed, 6 failed; một failure là fixture thử ghi snapshot read-only, đã sửa fixture bằng chmod trong tmp_path; năm failures còn lại tái hiện diagnostic/continuation/reopen gaps |
| Focused sau implementation | 87 passed (trước bổ sung scripted coverage correction cuối) |
| Focused với scripted correction cuối | 88 passed, 48.59s |
| Final focused + safety/recovery scenarios | 111 passed, 1 preexisting failure, 415.43s; lỗi duy nhất là budget-closure đã tái hiện trên HEAD |
| Broader integration/scenario checkpoint đầu | 866 passed, 7 failed, 519.84s; sáu expectation đổi classification đã sửa, một recovery scenario baseline đối chiếu HEAD như trên |
| Final integration checkpoint | 465 passed, 2 failed trong lúc chạy đồng thời nhóm scenarios; cả hai failing cases đã chạy riêng và PASS, 2 passed / 12.11s, không sửa source/budget |
| Final diagnostic assertions trong sáu safety cases | 6 passed, 103.85s; current script kiểm tra code/category/next_action cùng protected ledger oracle |
| Pyright, hai production và ba test files sửa | 0 errors, 0 warnings |
| `git diff --check` và scope inspection | Sạch; không có thay đổi ngoài danh sách Phase 2 từ session này |
| Full repository suite | Không chạy; không tuyên bố toàn repo xanh |

Logs/JUnit nằm trong WSL `/tmp/kagent-phase2-*`, không xóa. Các nhóm focused và
broader có overlap; không cộng thành tổng test độc lập.

Hai cases ở final integration là
`tests/benchmarks/test_scenario1_reliability.py::test_missing_step_then_schema_error_has_deterministic_closure[False/True]`.
Trong run có cạnh tranh tài nguyên, client dừng ở step 12/10 thay vì 13. Cả hai
đã PASS ở checkpoint rộng đầu và ở isolated recheck cuối, gồm toàn bộ assertions
về controller closure, fail-closed rejection, persisted session và counters.
Fixture có timeout 10 giây; wall-clock pressure là suy luận phù hợp với sự khác
biệt giữa concurrent run và isolated run, chưa có trace xác định nguyên nhân
duy nhất. Không tăng timeout hoặc thay production budgets để làm test qua.

Final integration selection: Whole-target, runtime validation completion,
requested-goal lifecycle/review, candidate-validation recovery, Burp offline
audit/selection, workflow checkpoint artifacts, phase coverage attestation,
WorkflowState/requested goals, benchmark-facing reliability, Workflow actions,
XSS canonical outcomes, Phase 1 loaded skill contracts và workflow request
preparation. Checkpoint rộng đầu còn bao gồm native assessment/permission,
Agent loop/defaults, argument/completion outcomes, safety và recovery scenarios.

Artifacts chính:

- `/tmp/kagent-phase2-baseline.xml` và `.txt`: audit danh sách Phase 1 trước sửa.
- `/tmp/kagent-phase2-reproduce.xml` và `.txt`: regression đầu trước production.
- `/tmp/kagent-phase2-focused-v5.xml` và `.txt`: 88 focused cases.
- `/tmp/kagent-phase2-integration.xml` và `.txt`: checkpoint rộng 873 cases.
- `/tmp/kagent-phase2-new-failure-baseline.xml` và `.txt`: bảy cases trên HEAD độc lập.
- `/tmp/kagent-phase2-final-scenarios.xml` và `.txt`: final focused/scenarios.
- `/tmp/kagent-phase2-final-integration.xml` và `.txt`: final integration selection.
- `/tmp/kagent-phase2-benchmark-recheck.xml` và `.txt`: hai timing-sensitive cases chạy riêng.
- `/tmp/kagent-phase2-diagnostic-scenarios.xml` và `.txt`: sáu cases với diagnostic assertions cuối.
- `/tmp/kagent-phase2-pyright-final-verified.txt`: type check source/tests cuối.

Lệnh chính (chạy ở repository root qua WSL):

```sh
env -u KAGENT_S1_EXISTING_CONTAINER venv-linux/bin/python -m pytest --import-mode=importlib -q \
  tests/integration/test_phase2_whole_target_reliability.py \
  tests/security/test_evidence_recovery_contract.py \
  tests/tools/test_workflow_argument_contract.py \
  tests/scenarios/test_safety.py tests/scenarios/test_recovery.py
venv-linux/bin/pyright src/agent/agent.py src/tools/workflow/workflow_tool.py \
  tests/integration/test_phase2_whole_target_reliability.py \
  tests/security/test_evidence_recovery_contract.py tests/scenarios/test_safety.py
git diff --check
```

Pyright dùng bản có sẵn 1.1.411; không install/update. State/evidence recovery,
assessment, permission/runtime HTTP grants, existing redaction và pytest config
đã đối chiếu không đổi với HEAD (normalize CRLF/LF khi so sánh).

## Tác động, giới hạn và live verification còn lại

Direct và candidate-validation dùng cùng evidence/assessment contracts, không
nhận independent continuation mới và không bị ép discovery. Burp capture/MCP
ownership paths được kiểm tra offline; không sửa bridge hoặc adapter. Benchmark-
facing runtime kiểm tra bằng existing offline reliability fixtures; không chạy
BenchmarkJava, không sửa dataset/selection/ground truth/scorer.

Live Whole-target về sau cần kiểm chứng: LLM chọn đúng dimension/phase/ID sau
diagnostic; xen kẽ early Validation vẫn complete đủ discovery; source-to-sink
inference và stable identity cho API/DOM/stored; exhausted candidate không được
probe lại; independent candidate còn scope/quota được xử lý; operator stop,
permission denial và stale resume không bị bỏ qua; final assessment reconcile
mọi unresolved surface, coverage, proof và persisted finding.

Không dùng offline success để khẳng định exhaustive target coverage, target an
toàn, browser execution đã xảy ra hoặc mọi Workflow errors đều self-correct.
Kết thúc ở Phase 2 implementation/verification; không Independent Review,
benchmark, Phase 3 hoặc sửa ngoài phạm vi.
