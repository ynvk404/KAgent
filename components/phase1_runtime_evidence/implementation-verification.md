# Phase 1 — Runtime correctness và evidence quality

Phạm vi cuối theo điều chỉnh của người dùng: A (governed HTTP streaming), B
(bounded evidence recovery), C (XSS contract), D (SQLi proof provenance).
Credential Minimization đã được loại bỏ khỏi implementation và acceptance của
Phase 1. Không chạy external LLM, live assessment hoặc Phase 2.

## Checkpoint 1A

### A. HTTP observation completeness

Root cause được tái hiện bằng production Registry → ContentDiscoveryTool →
governed transport với HTTPX AsyncByteStream. HTTPX tự gọi `aclose()` trong
`aiter_raw()` trước khi decoded iterator báo EOF và flush decoder/chunker.
Wrapper cũ snapshot ngay trong `aclose()`, khi `complete` vẫn là `False`;
buffered decoder còn có thể chưa yield những bytes cuối. Trước sửa: 7 ca thất
bại, 13 ca qua trong regression tái hiện đầu tiên.

Sửa cục bộ `src/permission/network/transport.py`: phân biệt close nội bộ trong
lúc advance iterator với close từ consumer; snapshot sau decoded EOF đối với
normal exhaustion. Early termination, exception và cancellation vẫn incomplete;
cap truncation được phân biệt với interruption. Snapshot và reservation release
chạy một lần; reservation vẫn được release nếu capture/persistence phát sinh lỗi.

Không tái hiện lỗi này trong native `HTTPTool` ở các ca under-cap/exact-cap và
gzip tương ứng; không sửa native HTTP dispatch. Regression còn dùng server
loopback ephemeral với chunked framing và gzip thực, không chỉ response đã
buffer sẵn. Permission, scope, DNS pinning, quota và response cap không đổi.

### B. Bounded evidence recovery

Root cause: Agent chỉ nhận diện một prefix `evidence-admissibility` và khởi tạo
lại accounting mỗi `run_inner`. Missing primary IDs, wrong references,
ownership mismatch và immutable parent conflict có thể đi ngoài recovery.

Submission nay trả stable code và `repair_kind` trong envelope có cấu trúc,
giữ string compatibility. Hướng dẫn sửa dùng reference thực của current
candidate/attempt; sửa proof/parents cần snapshot mới, không reparent snapshot
cũ. Missing validation start/request được phân biệt với manifest repair.

Accounting nằm trong session WorkflowState, keyed theo attempt, tách khỏi
immutable attempt declaration và result seal. Continuation/resume giữ số lượt
đã dùng; khi resume cần fresh execution rights/observations, accounting vẫn được
mang sang continuation identity phù hợp. Explicit retest với objective/binding
mới có budget độc lập. Không sao chép authorization hoặc evidence ownership.

Sau điều chỉnh bounded recovery, giới hạn là ba rejection: submission ban đầu
và tối đa hai repair submissions. Terminal repair có tối đa sáu iterations,
đủ cho hai chu kỳ write proof → register evidence → submit result nếu mỗi
bước ở một vòng Agent. Hai ngưỡng được dùng thống nhất khi dispatch trong batch,
kiểm tra cuối iteration và khôi phục session; failed schema retry cũng tiêu thụ
một lượt. Budget validation và Evidence/Ownership/Permission Gates giữ nguyên.
Mặc định `max_steps` được nâng riêng lên 30 direct / 60 whole-target theo yêu cầu
sau Phase 1; chi tiết và verification nằm ở cuối tài liệu.
Lỗi registration trước terminal assessment tiêu thụ rejection
budget, nhưng chưa kích hoạt terminal repair clock. Validation step thật sự còn
thiếu có thể tiếp tục qua gates hiện có mà không reset consumed budget.

Hết budget dừng qua workflow contract với `insufficient-evidence`, không
`confirmed`/`not-confirmed`; closure bị gate từ chối thì dừng với lỗi rõ ràng,
không giả vờ commit. Budget đã cạn khi continuation bắt đầu được xử lý trước
model/HTTP dispatch. Không fabricated IDs, salvage invalid parents hoặc recapture
HTTP để sửa manifest khi capture hiện có đủ dùng.

Rà cuối còn tái hiện hai lỗi trong accounting mới và sửa cục bộ: recovery đầu
lượt phải nhường nhánh operator stop hiện có; metadata closure bị hỏng/quá
kích thước không được làm mất consumed budget khi restore. Giữ nguyên goal
cancellation logic; metadata không dùng được bị bỏ, accounting vẫn được giữ.

## Checkpoint 1B

### C. XSS skill contract

`skills/cross-site-scripting/SKILL.md` trước đây chỉ hướng dẫn rõ proof registration
cho `confirmed`. Contract và examples nay dùng candidate → attempt → observation
→ evidence → result; cả hai terminal outcomes cần usable primary và registered
proof. `insufficient-evidence` có thể bỏ unavailable references; mọi reference
đã cung cấp vẫn phải qua ownership checks. Examples được thực thi qua production
workflow với IDs thật từ fixture, thay vì fabricated handles.

Giữ riêng API reflection, DOM sink và stored write/readback; không triển khai
browser, sửa DOM tracking hoặc completion logic. Allowed-tools không đổi.

### D. SQLi proof grounding

Read-only đối chiếu ledger phiên cũ xác nhận proof đã gọi một benign control là
exploit repeat. Các captures tương ứng gồm một complete UNION positive, hai
complete controls và một truncated UNION positive. Do đó không hỗ trợ lời mô
tả “two successful complete exploit repetitions”. Không sửa historical proof,
Finding hoặc observations của phiên đó.

`skills/sql-injection/SKILL.md` bổ sung checkpoint reconcile countable claims với
effective requests/observations: control, positive, error, incomplete; truncated
positive không được tính là complete successful repetition. Giữ technique-specific
validation semantics; không thêm fixed observation count cho mọi SQLi, payload
classifier hoặc SQLi semantic verifier.

### Phần Credential Minimization đã gỡ

Gỡ contextual alias redactor, hook cho Markdown write/edit, Finding excerpt
credential context, đoạn SQLi hướng dẫn mới và tests yêu cầu minimization mới.
`src/redaction/redact.py`, `src/tools/execution/file.py`,
`src/tools/workflow/finding.py` khớp byte-for-byte với source trước Phase 1.
Existing redaction bảo mật giữ nguyên. Regression scope kiểm tra alias display
vẫn theo policy cũ, đồng thời labelled credential guards vốn có vẫn hoạt động.

## Files và regression coverage

| Files | Lý do |
|---|---|
| `src/permission/network/transport.py` | EOF, deferred snapshot và release lifecycle |
| `src/workflow/evidence_errors.py` | Stable evidence error envelope và repair guidance |
| `src/workflow/evidence_recovery.py` | Attempt-scoped accounting và bounded handoff metadata |
| `src/workflow/assessment.py`, `src/workflow/evidence.py` | Classify existing rejection paths; carry continuation budget |
| `src/tools/workflow/workflow_tool.py` | Structured submission errors, không nới gates |
| `src/workflow/state.py` | Serialize/restore/replace/clear session accounting |
| `src/agent/agent.py` | Bounded recovery đọc codes, continuation và controlled stop |
| Hai SQLi/XSS `SKILL.md` | Contract/examples và proof ledger guidance |
| `tests/security/test_streaming_observation_completeness.py` | Real async stream/wire EOF, caps, gzip, interruption, release và persistence |
| `tests/security/test_evidence_recovery_contract.py` | Missing/wrong references, ownership, parent conflict, continuation/resume, retest, recovery clock và exhaustion |
| `tests/skills/test_phase1_evidence_contracts.py` | Loaded skill/schema examples và effective request provenance |
| `tests/scenarios/test_safety.py` | Mỗi evidence fault có independent attempt và một corrected submission; vẫn kiểm tra mọi ledger/gate |
| `tests/integration/test_candidate_validation_recovery.py` | Assert rejection chỉ thay đổi recovery accounting; evidence/ownership/traffic không đổi |
| `tests/security/test_redact.py` | Bảo vệ phạm vi rollback minimization và preexisting redaction |

## Verification cuối

Các kết quả trong bảng này thuộc verification Phase 1 trước khi nâng recovery
budget. Verification cho mức hai lần recovery được ghi riêng ở cuối tài liệu.

| Nhóm | Kết quả |
|---|---|
| Focused sau gỡ Credential Minimization: streaming, recovery, XSS/SQLi contracts, observations, findings, existing redaction và reliability | 481 passed |
| Scope regression + corrected production Burp/native ownership integration | 52 passed |
| Kiểm tra cuối sau hai sửa accounting: recovery, explicit stop, requested goals, reliability, production Burp integration và WorkflowState persistence | 149 passed |
| Pyright dùng `venv-linux`, các production/test files liên quan | 0 errors, 0 warnings |
| Full suite, `--import-mode=importlib` | 7038 passed, 8 failed, 18 skipped, 3 xfailed; 23m33s |
| Đối chiếu 8 failing cases trên HEAD tách riêng trong `/tmp` | Cả 8 cùng thất bại trên HEAD |
| Historical files fingerprinted trước/sau verification | 10 files: SHA-256, size và mode không đổi |
| Final diff whitespace/scope | `git diff --check` sạch; không có rollback ngoài phạm vi |

Các nhóm có overlap; không cộng thành một tổng test riêng. Full suite chạy
trước hai sửa accounting cuối; sau đó chạy lại nhóm 149 cases và Pyright cho
source cuối, không lặp full suite.

Lệnh `pytest -q` mặc định bị chặn ngay ở collection do hai file đã có trên HEAD
cùng tên `test_related_requests_independent.py` dưới `tests/scenarios` và
`tests/tools`. Dùng `--import-mode=importlib` chỉ trong lệnh verification;
không sửa `pytest.ini`, đổi tên tests hoặc xóa cache để né lỗi.

Full suite còn 8 failures có trước Phase 1, đã tái hiện đủ cả 8 trên HEAD trong
thư mục nguồn tạm độc lập, dùng cùng venv:

| Cases | Nguyên nhân quan sát |
|---|---|
| `test_isolation_and_permission_boundaries` | Test thiếu HTTP `phase`; nhận phase validation error thay vì text `outside` |
| `test_evidence_receipt_uses_existing_readonly_workflow_action` | CWE enrichment kết thúc với UI error entry thay vì system entry |
| Hai default/hybrid schema budget tests | Inventory 29,590 characters vượt cap 28,000 |
| Transport retry projection: Anthropic và Gemini | Hai retry request bodies có tool schema khác nhau |
| Candidate recovery transcript: direct và whole-target | Test đòi old error text ở entry đã được UI thay bằng recovered summary |

Không sửa các vấn đề benchmark/CWE/schema/provider/TUI ngoài phạm vi này. Live
operator-target test được giữ skip bằng cách bỏ `KAGENT_S1_EXISTING_CONTAINER`
trong process verification; không chạy external LLM hoặc live assessment.
Legacy Burp integration bị `pytest.ini` ignore vẫn giữ nguyên skip/collection
policy đó; production Burp selection/MCP-related offline paths đã được kiểm tra.

Artifacts verification tạm:

- [Focused JUnit](/tmp/kagent-phase1-focused.xml)
- [Final scope/integration JUnit](/tmp/kagent-phase1-final-fixes.xml)
- [Final recovery/cancellation/persistence JUnit](/tmp/kagent-phase1-recovery-final.xml)
- [Full suite JUnit](/tmp/kagent-phase1-full-importlib.xml)
- [Full suite output](/tmp/kagent-phase1-full-importlib.txt)
- [HEAD baseline comparison JUnit](/tmp/kagent-phase1-baseline-failures.xml)

Final diff review gồm tracked changes và các helper/tests/report mới. Ba files
redaction/file I/O/Finding đã xác minh lại byte-identical với HEAD. Các thay đổi
còn lại chỉ thuộc A–D và regression/handoff; worktree có trước được giữ nguyên.

## Giới hạn và tác động

Direct/Burp dùng cùng evidence submission contract; Burp-selected evidence vẫn
phải thuộc đúng candidate/attempt. Whole-target giữ discovery/completion gates;
unresolved recovery không trở thành completed validation. Native HTTP không đổi;
governed discovery transport được sửa lifecycle snapshot.

Tests dùng scripted/fake LLM và production components. Chúng kiểm tra contracts,
provenance, persistence và runtime gates, không chứng minh một external LLM luôn
tuân thủ prose/counting guidance. Semantic SQLi/XSS judgement vẫn ở skill/assessment
contract hiện tại. Credential Minimization không thuộc acceptance theo yêu cầu mới.

Không đổi TUI, LLM client, context compaction, expert prerequisite,
Input Analysis/requested-goal completion, artifact locations hoặc network gates.
Thư mục untracked `components/scenario2_benchmark_review/` là worktree có trước;
được giữ nguyên. Không commit, push, install packages hoặc xóa runtime/artifacts.

## Acceptance

Phase 1 đạt acceptance A–D theo phạm vi đã điều chỉnh. Credential Minimization
không được triển khai. Repository full suite chưa xanh do 8 failures tái hiện
được trên HEAD và default collection collision nói trên; các responsibility
groups liên quan tới thay đổi Phase 1 đều qua. Dừng ở implementation/verification,
không chuyển Phase 2.

## Điều chỉnh sau Phase 1 — hai lần recovery

Nâng riêng bounded evidence recovery từ một lên hai lần sửa sau submission ban
đầu. Một chuỗi terminal repair có tối đa ba submissions; submission thứ tư bị
chặn trước workflow dispatch, kể cả khi cùng một batch. Rejection limit là 3,
terminal repair iteration limit là 6: hai chu kỳ write proof → register evidence
→ submit result có thể chạy ở các vòng Agent riêng biệt. Giới hạn vẫn chịu
`max_steps` hiện có, không tăng budget validation hoặc quyền thực thi.

Các ngưỡng dùng chung constants trong `src/workflow/evidence_recovery.py`.
Restore chấp nhận bộ đếm vòng mới để các giá trị 5/6 không bị bỏ và reset budget.
Failed schema submissions trong chuỗi recovery tiêu thụ từng lượt; thiếu bước
validation riêng vẫn tạm dừng clock mà không hoàn lại lượt đã dùng. Cập nhật
repair hints và đúng câu giới hạn trong SQLi/XSS, giữ nguyên playbook/gates khác.

Regression kiểm tra cả `confirmed` và `not-confirmed`, với lỗi manifest hoặc
schema ở lần sửa thứ nhất: lần sửa thứ hai ghi/register proof mới và commit
submission thứ ba bằng capture hiện có. Kiểm tra riêng submission thứ tư có
payload hợp lệ nhưng vẫn bị chặn sau ba lần từ chối; controller ghi
`insufficient-evidence`. Continue/Resume giữ hai lượt đã dùng và clock qua các
vòng đơn; explicit retest, operator stop, unavailable/foreign sources và closure
bị từ chối vẫn có coverage. Không sửa các failure baseline ngoài phạm vi.

| Kiểm tra bổ sung | Kết quả |
|---|---|
| Tái hiện regression mới trên mức một recovery trước sửa | 4 failed như dự kiến |
| Focused: recovery, agent assessment, execution policy, benchmark reliability, requested goals, WorkflowState, production candidate integration, safety scenarios và skill contracts | 275 passed, 2m50s |
| Pyright với `venv-linux`, production/tests thay đổi | 0 errors, 0 warnings |
| Diff whitespace và scope review | `git diff --check` sạch |
| Full suite | Không chạy lại theo yêu cầu |

Artifacts: [regression trước sửa](/tmp/kagent-recovery-two-reproduce.xml),
[focused verification](/tmp/kagent-recovery-two-focused.xml).

## Counter sau thành công và mặc định max_steps 30/60

Root cause: successful `record_result` xóa transient recovery clock và đóng
budget trong dispatch, trước bước cập nhật `repair_turns` ở cuối iteration.
Vì vậy counter sau thành công thiếu vòng cuối: Continue repair lưu 0 thay vì 1,
chuỗi ba submissions ở ba vòng lưu 1 thay vì 2, và commit ở repair boundary
thứ 6 lưu 5 thay vì 6.

`run_inner` truyền step hiện tại vào `execute_tool_calls` bằng metadata nội bộ
`repair_step`. Khi result đã commit thành công, dispatch cập nhật `repair_turns`
trước khi đóng budget và xóa transient clock. Clock đang paused và controller
closure không được cộng thêm vòng; duplicate success trong cùng batch không
đếm lại. Tool schema, admission gates và điều kiện commit giữ nguyên.

Ví dụ vòng 15 bị từ chối, vòng 16 sửa nhưng bị từ chối, vòng 17 thành công nay
lưu đúng `rejections=2`, `repair_turns=2`, `closed=true`. Ba submissions trong
cùng một batch vẫn có `repair_turns=0`, vì không có vòng Agent tiếp theo sau
initial rejection. Regression kiểm tra cả confirmed/not-confirmed, persistence
qua serialize/restore và success tại boundary thứ 6.

Theo yêu cầu tiếp theo của người dùng, nâng riêng default Agent steps từ
20 → 30 ở direct và 40 → 60 ở whole-target. Explicit constructor/config/CLI
override và per-run override giữ precedence hiện có; `/maxsteps default` xóa
override và khôi phục hai defaults mới. Không đổi rejection limit 3, repair
iteration limit 6, Continue/Resume accounting, explicit retest, operator stop,
validation/permission/scope gates hoặc stall thresholds. Không mở rộng Phase 2.

| Verification cho thay đổi này | Kết quả |
|---|---|
| Recovery regressions, gồm counter sau commit | 31 passed |
| Default limits, override, reset và defensive zero-iteration cases | 17 passed |
| Focused Agent/context/UI, recovery, assessment, execution policy, benchmark reliability, requested goals, WorkflowState, candidate integration, safety và skill contracts | 584 passed, 3m19s |
| Pyright với venv-linux: agent và ba test files thay đổi | 0 errors, 0 warnings |
| Final diff whitespace/scope review | `git diff --check` sạch |
| Full suite | Không chạy lại |

Các nhóm targeted có overlap với focused; không cộng thành tổng riêng.
Artifacts: [trước sửa](/tmp/kagent-counter-defaults-reproduce.xml),
[counter targeted](/tmp/kagent-final-counter-targeted.xml),
[step limits targeted](/tmp/kagent-step-defaults-targeted.xml),
[focused verification](/tmp/kagent-counter-defaults-focused.xml).
