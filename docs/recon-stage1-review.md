# Báo cáo Stage 1 — recon/enumeration

> Bản được chuẩn bị để commit: đường dẫn máy cá nhân đã chuẩn hóa. Raw logs,
> snapshots và evidence trung gian được giữ local, không xóa; xem
> [bộ evidence portable](verification-milestone-c/README.md) và inventory/hash của archive.

Phạm vi được phép: Batch 1, 2, 3 và Milestone A. **Không có thay đổi thuộc
Stage 2/3**, không chuẩn bị trước schema/state endpoint/source/frontier, không
mở rộng capability Nmap/ffuf. Chưa chốt Milestone A trước khi có kết quả cuối.

## Audit và reproducer trước sửa

- Worktree ban đầu sạch; đã đọc AGENTS.md root, không có AGENTS.md lồng trong
  src/tests/skills. Đã đọc implementation, test và allowed-tools contract của
  recon, web-enumeration, web-input-analysis. Không sửa các skill này.
- Có sẵn venv-linux/bin/python, pytest, pyright. Không cài package, không
  reset/restore/clean, không stage/commit/push.
- Producer input mới trong src là WorkflowTool; restore hydrate trực tiếp
  historical records. Đã trace state/list/get, serialization/linkage/coverage,
  HTTP resolution, native loop, ToolOutput, Agent retention, reader và restore.

| Reproducer offline trước sửa | Kết quả cũ |
| --- | --- |
| /login và http://TARGET.test:80/login | Hai input ID |
| record_input endpoint http://other.test/login | Ghi thành công, get_input từ chối |
| Thiếu method/parameter/location | Vẫn nhận |
| Hai endpoint khác nhau sau ký tự 500 | Cùng ID sau truncate |
| 300/1.000 inputs, list limit=1 | Trả 300/1.000 inputs |
| _result với 120 hits và 130 rejects | Chỉ còn 100/100 trước retention |

`_text` redact, gộp whitespace và truncate trước fingerprint. Admission mới
phải từ chối identity bị mất dữ liệu trước các bước đó; sample vẫn qua redactor.
Không tìm thấy contract whole-request input riêng. Không suy ra input từ trường
thiếu, không tạo parameter/location giả; request-level Candidate trực tiếp vẫn
có contract optional geometry hiện có.

HTTP hiện append relative path vào target base, còn validation resolve theo
origin root. Ví dụ target http://target.test/app + /login: HTTP đi /app/login.
WorkflowTool nay chuyển thành absolute effective URL /app/login ngay tại
admission theo contract append hiện có; state-only relative path hiểu theo
origin root. URL absolute đã quan sát được ưu tiên. Không đổi HTTP dispatch.

## Đã triển khai

### Batch 1 — canonical input admission/identity

- Helper nhỏ `src/target/input_admission.py`, dùng HTTPOrigin. WorkflowTool
  validate trước constructor/hash; AttackSurfaceInput và state insertion cũng
  chặn internal producer bỏ qua admission.
- Ordinary input cần method, endpoint, parameter, location hợp lệ. Các location
  được giữ theo runtime hiện có: query/path/body/form/json/header/cookie/raw.
- Kiểm raw identity trước cả parser shorthand GET /path, để newline không bị
  strip mất trước admission. Giữ positive coverage cho shorthand hợp lệ.
- Chuẩn hóa scheme/hostname/default port; giữ path case, trailing slash, query
  order, duplicate keys, percent-encoding spelling và empty query marker.
- Từ chối foreign origin, credentials, controls/encoded controls, percent encoding
  sai, network-path/dot-segment/fragment mơ hồ, identity quá dài hoặc bị redaction
  làm đổi. Fragment được báo là client-route clue cần giữ trong source artifact,
  không bị âm thầm xóa rồi biến thành HTTP input.
- Không hash trên identity đã truncate. Giữ giới hạn storage cũ (endpoint/parameter
  500 ký tự); vượt giới hạn trả lỗi rõ. Cho phép outer spaces vô hại ở method,
  location/type/media; vẫn giữ normalized media semantics hiện có.
- Không đổi fingerprint algorithms. Không rekey Candidate/Input/attempt đang
  tồn tại. Hydration giữ historical representation/ID/linkage.
- Canonical match chỉ reuse khi duy nhất và compatible; ambiguous thì reject.
  Giữ context merge/source_ref conflict guard; không overwrite auth/baseline/source.
- Linkage kiểm semantic compatibility trước fingerprint integrity để giữ lỗi
  context mismatch/recovery hiện có. Historical malformed/off-origin input không
  thành valid execution context, nhưng vẫn giữ được để chẩn đoán/drop qua
  disposition path hiện có.
- Bỏ qua sớm các absolute URL đã có canonical origin nhưng khác path/query,
  tránh chạy lại admission/redaction cho mọi row không thể match. Không thêm index.

### Batch 2 — bounded workflow listing

- Pure projection helper `src/workflow/input_view.py`, không thêm store.
- API list thêm `view="inputs"`, `input_limit` (default 20, range 1–25),
  `input_cursor`, `input_disposition`. Candidate limit và paging của
  observation/scanner giữ nguyên nghĩa.
- Output thêm `input_counts` (total và mọi disposition), `inputs_filtered_total`,
  `inputs_returned`, `inputs_complete`, `next_input_cursor`; giữ array
  `attack_surface_inputs` nhưng chỉ chứa compact summaries.
- JSON của explicit input-only view tối đa 16 KiB sau escaping, tự giảm số row;
  không cắt JSON hoặc ID. Không nhúng sample/template/link array trong summary.
  `get_input` vẫn lấy full canonical sanitized detail theo exact ID.
- Cursor bind objective/generation/filter và ordered membership/disposition
  digest. Inventory/disposition/objective/reset/restore/filter đổi thì reject
  kèm hướng dẫn restart. Commit không liên quan không làm cursor stale.
- Prompt đưa counts và pending/blocked input lên trước completed rows và các
  projection dài của goals/candidates. Không sửa context_reduction_policy.
- List không mutate state và cursor không cấp quyền.

### Batch 3 — native discovery retention

- _result giữ đầy đủ sanitized discovered/rejected/baseline. Thêm
  `discovered_total`, `rejected_total`, `complete`; `scanned_paths` đếm path probe
  đã hoàn tất thay vì toàn bộ path dự kiến trên run bị ngắt.
- Typed runtime-only `NativeDiscoveryResult` và per-invocation producer hook;
  không deserialize authority từ JSON/model/plugin. Metadata được gắn sau wrapper
  phase_coverage để không bị mất khi tạo ToolOutput mới.
- Agent dùng ToolResultStore hiện có, quota không đổi, synchronous transaction
  dưới WorkflowOwner/turn/retention guards. Không có offloaded writer bỏ chạy.
- Chỉ preview sau publication thành công: tối đa 20 row/array, budget 16 KiB,
  có `retention` metadata (result_ref/hash/char_length). Toàn bộ JSON lấy lại bằng
  read_tool_result và character-range pagination hiện có.
- No-store/quota/write failure (kể cả exception store ngoài dự kiến): giữ full bounded sanitized JSON inline và báo
  explicit limitation. Stale owner ở cả publication lẫn fallback đều withheld.
- Additive `ResultReference.source_kind="native-discovery"`; không đổi cấu trúc
  session/ref khác, không tạo ScannerJob/native dataset store riêng.
- Reader adapter kiểm concrete tool, current capability/receipt/revocation,
  project/session/generation, objective/origin/scope và stored integrity.
- Dataset partial có observation status để đọc lịch sử; JSON và tool receipt
  vẫn giữ error/cancelled status, completed/requested counts và stop reason thật.
- Task.cancel finalize các row đã hoàn tất, join probe khi bị cancel lặp lại,
  giữ paired cancelled receipt khi tool call còn pending, rồi propagate cancel.
- Restore giữ reference để đọc dữ liệu; không restore grants/authorization,
  không biến historical observation thành current validation evidence.

## Binding matrix và regression

| Reference / owner | Producer → consumer | Boundary/guard được giữ hoặc bổ sung | Regression |
| --- | --- | --- | --- |
| objective_id / target_origin | record/restore → insertion/link/get/list | active whole-target/objective và exact-origin; endpoint admission | positive đúng owner; foreign origin/objective; stale cursor |
| input_id | fingerprint/hydrate → candidate/get/disposition | exact lookup, fingerprint integrity, unique compatible canonical match | invalid supplied ID không đoán lại; legacy roundtrip; ambiguity; atomic reject/retire |
| candidate_id | candidate → input linkage/validation | validate_input_candidate và semantic geometry/context | wrong candidate/context; preserved active linkage; no mutation/publication khi reject |
| baseline_request_ref / auth_context_ref | input/capture → context/execution | existing merge, capture/auth ownership và validation context guards | identity separation, mismatch rejection; handoff/contextual coverage groups |
| source_ref | caller → input merge/runtime provenance | source anchor/conflict guard cũ | khác source vẫn conflict; không ép merge hoặc borrow context |
| validation attempt / observation_id | existing execution → assessment | ownership/generation/attempt guard hiện có; admission/list không tạo attempt | turn/parallel cancellation, contextual validation và native callback groups |
| request/capture/baseline/auth execution refs | HTTP/capture → validation | execution identity độc lập input identity; không tự replay/recapture | HTTP pipeline, persistence handoff, phase2a security |
| evidence_ref / finding/result binding | evidence/assessment → report | eligibility/attempt/candidate proof guards hiện có | contextual coverage, security/persistence/handoff và full suite; native không tạo evidence/finding |
| scanner_job_id / scanner_record_id | scanner → triage/handoff | existing scanner admission/recovery/dedup | scanner handoff/recovery groups; native không tạo ScannerJob |
| input cursor | list → next page | objective/generation/filter/membership-order digest; read-only | 300/1.000 inputs, traversal, Unicode bytes, stable/stale/filter/disposition/restore |
| WorkflowOwner / turn owner | native invocation → publication | state object/generation, objective identity, target revision, engagement/policy/session, current turn | đổi target/objective/session/scope/reset/replace/retention/retired turn; stale fallback |
| result_ref / retention provenance | private store → reader/restore | private filesystem/hash/integrity, session/project/generation, concrete adapter, current rights | full reader pagination, tamper, denied/revoked/no receipt/no policy/foreign project/session, plugin giả |
| source_ref/provenance inventory mới | — | Không applicable: thuộc Stage 2, không thêm field/state này | deferred |

Historical availability không đồng nghĩa current execution authority. Không
borrow auth/baseline/request/evidence/provenance từ context khác; không dùng
source/result ref như authorization hay evidence; không tự fetch/crawl/rerun.

Regression mới tập trung ở:

- tests/state/test_input_admission.py
- tests/tools/test_workflow_input_paging.py
- tests/agent/test_native_discovery_retention.py

Các test cũ được cập nhật fixture geometry và assertion cho endpoint absolute/
summary không sample. Historical malformed fixtures dùng helper test-only
`historical_input` để pin old fingerprint; không nới production admission,
không bỏ negative assertions hay đổi skip semantics.

## Files thay đổi

Runtime:

- src/target/input_admission.py (mới)
- src/workflow/input_view.py (mới)
- src/workflow/state.py
- src/tools/workflow/workflow_tool.py
- src/agent/system_prompt.py
- src/tools/discovery/content.py
- src/tools/common/outcome.py
- src/agent/tool_results.py
- src/agent/agent.py
- src/session/tool_results.py

Tests: ba file regression mới nêu trên và các fixture/assertion trong
state/test_workflow_state, tools/test_workflow, tools/test_workflow_action_view,
tools/test_workflow_argument_contract, agent/test_agent, agent/test_systemprompt,
helpers/workflow, integration/test_phase1_review_regressions,
integration/test_phase2a_handoff, integration/test_phase2a_security,
integration/test_requested_goal_lifecycle, integration/test_structured_handoff_hardening,
integration/test_whole_target_workflow, security/test_generic_validation,
report/test_builder, ui/test_outcomes. Báo cáo này là file tài liệu mới.

## Verification

Các kết quả trong quá trình triển khai, không dùng thay final-source verification:

- Batch 1 focused group: 321 passed.
- Batch 2 focused group: 240 passed; pyright mục tiêu 0 errors/warnings.
- Discovery/retention group: 305 passed; workflow/handoff group: 662 passed.
- Preflight trên intermediate source: 4427 passed, 13 failed, 1 skipped,
  549.87 giây. Đã xử lý nguyên nhân: fixture thiếu geometry, assertion URL cũ,
  tương thích outer whitespace của media; không nới các rejection test.
- Integration lần đầu: 709 passed, 1 failed do thứ tự diagnostic Content-Type/
  fingerprint. Sửa production guard order; focused rerun 141 passed.
- Integration tiếp theo trước tối ưu performance: 827 passed, 127.02 giây.
- Sau fast skip cho distinct canonical URLs: focused group 252 passed, 11.69 giây.
- Benchmark 1.000 insertion thật: trước fast skip 138.286 giây, sau 19.707 giây
  trên cùng máy khi có các verification process chạy đồng thời. Đây là phép đo
  quan sát, không phải performance guarantee hoặc benchmark độc lập hệ thống.
- Các full-suite attempt trên intermediate source bị chủ động ngắt khi có
  production correction; không được tính là final full-suite verification.

Reproducer bổ sung: RuntimeError từ store trước sửa làm mất JSON đầy đủ và trả
lỗi tool chung. Regression mới yêu cầu fallback đủ dữ liệu, không để exception
retention đổi execution outcome. Đã sửa catch tại storage boundary, tách
ExecutionBlocked và recheck owner trước fallback; responsibility group sau sửa
144 passed. Final-source verification được chạy lại với regression này.

Kiểm tra cuối phát hiện và reproduce thêm hai trường hợp parser shorthand
strip newline khỏi endpoint/method trước admission. Đã chuyển raw identity
validation lên trước parser trong record_input; Candidate builder giữ nguyên
contract optional geometry. Responsibility group sau sửa: 195 passed (4.29 giây).
Thêm positive shorthand regression và chạy lại final verification.

Kết quả trên source trước correction này (không thay final verification):

- Targeted admission/listing/retention/schema/prompt: **195 passed**, 33.75 giây.
- `venv-linux/bin/pyright`: **0 errors, 0 warnings, 0 informations**.
  Tool in thông báo có phiên bản pyright mới; không cài hoặc đổi phiên bản.
- Final integration: **828 passed**, 92.00 giây.
- Full-suite attempt bị ngắt khi correction trên được xác nhận.

Targeted command:

```text
venv-linux/bin/pytest -q tests/state/test_input_admission.py \
  tests/tools/test_workflow_input_paging.py tests/agent/test_native_discovery_retention.py \
  tests/tools/test_workflow_argument_contract.py tests/tools/test_workflow_action_view.py \
  tests/agent/test_systemprompt.py --tb=short
```

Kết quả đã có trên source cuối (sau shorthand correction):

- Targeted: **198 passed**, 48.67 giây.
- Integration: **828 passed**, 110.28 giây.
- Pyright: **0 errors, 0 warnings, 0 informations**.
- Full suite đang chạy; chưa chốt milestone.

Log cuối: $LOCAL_TMP/kagent-stage1-targeted-verified.log,
$LOCAL_TMP/kagent-stage1-integration-verified.log,
$LOCAL_TMP/kagent-stage1-pyright-verified.log,
$LOCAL_TMP/kagent-stage1-full-verified.log.

Final integration command (các path dưới đây đều có prefix tests/):

```text
venv-linux/bin/pytest -q \
  tests/state/test_workflow_state.py tests/state/test_session_store.py \
  tests/state/test_tool_result_store.py tests/state/test_workflow_progress_ownership.py \
  tests/tools/test_discovery_tools.py tests/agent/test_native_discovery_retention.py \
  tests/agent/test_tool_result_offloading.py tests/integration/test_phase2a_handoff.py \
  tests/integration/test_phase2a_security.py tests/integration/test_structured_handoff_hardening.py \
  tests/integration/test_contextual_coverage.py tests/integration/test_discovery_service_policy.py \
  tests/integration/test_workflow_checkpoint_artifacts.py tests/integration/test_http_pipeline_regressions.py \
  tests/security/test_scanner_workflow_recovery.py tests/security/test_native_callback_ownership.py \
  tests/security/test_persistence_handoff_audit.py tests/integration/test_scanner_agent_handoff.py \
  tests/agent/test_turn_ownership.py tests/agent/test_parallel_cancellation.py --tb=short
```

Full-suite command: `venv-linux/bin/pytest -q --tb=short -ra`.
Pyright: `venv-linux/bin/pyright` (dùng pyrightconfig.json/venv-linux hiện có).
Trước bàn giao: git diff --check, inspect git diff, git status --short và kiểm
source digest so với snapshot lúc bắt đầu các verification process cuối.

## Giới hạn và deferred

- Identity dài/redacted/mơ hồ bị từ chối có hướng dẫn; không có secret identity
  scheme mới, không lưu secret để giữ ID.
- Whole-request/endpoint-only input không được tổng hợp giả; HTML/document-base
  extraction, endpoint/source/provenance/frontier và OpenAPI thuộc Stage 2.
- Canonical duplicates hợp lệ trong lịch sử cần inspect/reuse exact existing IDs;
  không có auto migration/rekey/arbitrary-first merge.
- Full inline fallback có thể tăng dung lượng session/context; quota và context
  guard không đổi. Không rerun vì reference không có hoặc không đọc được.
- Mọi skill lifecycle/phase guidance/tooling_profile work thuộc Stage 3 được giữ
  deferred. prompt_profile full|compact không đổi; Nmap/ffuf không feature-expand.
- Registry, exact-origin/private-host checks, permission/grant/revocation,
  scanner admission, request/observation/attempt identity, recovery/dedup và
  evidence/finding eligibility không bị bỏ qua hoặc thay bằng subsystem khác.
- Không có unrelated worktree changes lúc bắt đầu; không xóa/ghi đè work ngoài
  phạm vi, không cài package, không stage/commit/push.

**DỪNG IMPLEMENTATION tại Milestone A. Không bắt đầu Batch 4 trước review và
một yêu cầu tiếp tục rõ ràng của người dùng.**


## 11. Final verification addendum — 2026-10-18 (Asia/Saigon)

**Verdict mới nhất cho Stage 1: PASS WITH LIMITATIONS. Full configured suite KHÔNG green.**

Lượt này chỉ tiếp tục verification trên worktree đã fix F1–F5. Không audit lại từ đầu, không sửa source/test/config, không triển khai Stage 2/3, không cài package, stage, commit hoặc push. Các phần review trước fix và addendum fix được giữ để phân biệt evidence lịch sử với kết quả mới nhất.

### Source freeze và preservation

- Đã đọc hai bản independent review (trước khi append, nội dung giống hệt nhau), original reproducer, before-fix log, full-final log, incremental patch, checksum/source snapshots cũ. Inventory có SHA-256 của 14 artifact snapshot/checksum được lưu trong `prior-snapshot-inventory.json`.
- Snapshot trước fix `$LOCAL_TMP/kagent-stage1-source-digest.txt`: 593 file; hiện tại chỉ đúng 9 file trong `$LOCAL_TMP/kagent-fix-changed-files.json` khác snapshot đó. **0 file thay đổi ngoài F1–F5** trong manifest này.
- Snapshot final-source cũ `$LOCAL_TMP/kagent-fix-final-source-digest.json`: **657/657 khớp** trước và sau verification.
- Snapshot mở rộng của lượt này: **690 file**, bao gồm src/tests/benchmarks/skills và root config. `entry-source.json`, `before-full-source.json`, `after-full-source.json`: cùng nội dung; **0 changed/missing/added files**. Kiểm tra lại sau focused diagnostics vẫn khớp.
- Original reproducer SHA-256 vẫn là `7c03902c70c1aef16b7fc0a3afe914285be8d3cc6707b281b1366e5d519dc1d7`. Bản review trước fix tại `$LOCAL_TMP/kagent-stage1-independent-review-before-fixes.md` được giữ nguyên. Chỉ append báo cáo; source/test/config không bị sửa.
- `git status --short`, `git diff --check`, `git diff` đã được đọc trước run và kiểm tra lại khi bàn giao. Tracked diff và status không đổi so với lúc bắt đầu lượt verification; thay đổi nội dung tài liệu untracked là addendum báo cáo có chủ đích.

### Exact final counts

Các nhóm overlap; không cộng counts để diễn giải thành một suite lớn hơn. Duration dưới đây lấy từ summary pytest, không phải thời gian wrapper.

| Verification | Kết quả | Log |
| --- | --- | --- |
| Independent original reproducer | **13 passed**, 0 failed/skipped/xfail; 1,48s | independent.log |
| Targeted Stage 1 | **240 passed**, 0 failed/skipped/xfail; 19,31s | targeted.log |
| Integration responsibility groups, cùng command trong phần 10 | **1185 passed**, 0 failed/skipped/xfail; 77,52s | integration.log |
| Pyright, venv-linux và config hiện có | **0 errors, 0 warnings, 0 informations** | pyright.log |
| Final-source full configured suite | **8212 passed, 2 failed, 12 skipped, 0 errors, 0 xfailed, 79 warnings; 1196,38s** | full.log / full.xml |
| session_save trước full suite, chạy riêng 3 process | **1 passed mỗi lượt**; 1,20s / 1,40s / 1,35s | prior-timing-focused-1/2/3.log |
| Hai full-suite failures rerun trong môi trường gốc, 3 process | **1 failed, 1 passed mỗi lượt**; 2,12s / 1,44s / 1,42s; chỉ light-theme fail | full-failures-focused-1/2/3.log |
| Cả hai module UI trong môi trường gốc | **25 passed, 1 failed**; 10,49s; chỉ light-theme fail | full-failures-modules.log |
| Hai original failure cases với COLORTERM=truecolor, 3 process | **2 passed mỗi lượt**; 1,33s / 1,52s / 1,36s | truecolor-focused-1/2/3.log |
| Cả hai module UI với COLORTERM=truecolor | **26 passed**, 0 failed/skipped/xfail; 10,93s | truecolor-modules.log |

Full suite thực thi collection **8226 tests** đến 100%, không bị dừng. 12 skips giữ nguyên: 9 Java gate cần cached WAR/Tomcat, 1 prepared operator lab, 1 live-system opt-in, 1 live-model characterization opt-in. File Burp integration vẫn bị ignore theo pytest.ini, không được tính là đã chạy.

**79 warnings** gồm 2 RuntimeWarning từ fixture malformed provider config và **77 PytestWarning do xuất JUnit xunit2 với record_property**. Tham số `--junitxml` chỉ được thêm để lưu evidence; không suppress warning, đổi timeout, bỏ assertion hay thay skip/xfail. Mọi exact command được lưu trong `results.json`, `failure-reruns.json`, `truecolor-reruns.json`; counts và node IDs nằm trong `counts.json`.

### Phân loại hai failures

1. **Fixture / terminal environment — reproducible root cause đã xác nhận.**
   `tests/ui/test_light_theme_app.py::test_light_first_terminal_frame_uses_selected_theme` tìm RGB escape `48;2;250;248;242`, nhưng môi trường full run có `TERM=xterm-256color`, không có `COLORTERM`. Diagnostic gọi nguyên test và ghi lại driver output cho thấy Rich dùng `color_system=256`, có frame màu `48;5;`, không có RGB `48;2;`; vì vậy `paints=[]` không phải bằng chứng thiếu paint hoặc dark flash. Cùng diagnostic với `COLORTERM=truecolor` dùng đúng RGB light palette và original assertion pass. Original test pass cả 3 focused lượt và trong full module với truecolor; không sửa fixture hoặc renderer. Failure y hệt đã có trong full-suite trước F1–F5. Evidence: `color_diagnostic.py`, `color-default.log`, `color-truecolor.log`. Diagnostic là file ngoài repo; 1 failed / 1 passed tương ứng hai môi trường, không tính vào suite chính.

2. **Flaky timing / suite-context harness — root cause cụ thể chưa chứng minh.**
   `tests/ui/test_persistence_responsiveness.py::test_async_wait_control_keeps_textual_responsive[session_save]` fail ở `recovery_ticks=1 < 2`, heartbeat gap 270,15ms. Log final-source cũ cũng có cùng recovery_ticks failure. Case này pass cả 3 process trước full, 3 process focused sau full, 3 process focused truecolor và hai lần chạy module. Điều này chứng minh failure phụ thuộc ngữ cảnh/timing và chưa tái hiện khi chạy focused; không chứng minh chính xác GC, scheduler, tải máy hay một runtime root cause nào. Không sửa source, không tăng khoảng chờ hoặc threshold. Phân loại timing là kết luận có giới hạn từ evidence; không khẳng định mọi runtime interleaving an toàn.

Không có reproducer mới chứng minh regression runtime của F1–F5. Không có fixture thiếu location còn fail trong targeted/full. Source giữ nguyên vì không có reproducible production root cause mới để sửa.

### Hiệu chỉnh context và giới hạn verdict

Full-final run cũ thực tế đã kết thúc trong background: `$LOCAL_TMP/kagent-fix-full-final.log` ghi **8213 passed, 1 failed, 12 skipped, 2 warnings; 1275,42s**, exit code 1, checksum 657 file không đổi theo `$LOCAL_TMP/kagent-fix-full-source-check.json`. Không gọi run đó là green hoặc còn dang dở. Failure là session_save timing nêu trên.

Run full mới vẫn có **2 failures**, và không có full-suite rerun với truecolor. Focused/module passes chỉ dùng để phân loại, không thay thế kết quả full suite. Vì vậy verdict là **PASS WITH LIMITATIONS cho verification Stage 1/F1–F5**, không phải PASS toàn bộ repository. Những giới hạn còn lại: fixture first-frame phụ thuộc capability màu terminal; timing full-suite chưa được giải thích tận gốc; các live/lab cases bị skip và Burp exclusion chưa được kiểm tra ở lượt này.

**DỪNG tại Stage 1. Không bắt đầu Stage 2. Không commit/push.**

Evidence directory (UTC timestamp in path): $LOCAL_TMP/kagent-stage1-verification-20261017-174756
