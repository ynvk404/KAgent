# Stage 2 — audit và verification

> Bản được chuẩn bị để commit: đường dẫn máy cá nhân đã chuẩn hóa. Raw logs,
> snapshots và evidence trung gian được giữ local, không xóa; xem
> [bộ evidence portable](verification-milestone-c/README.md) và inventory/hash của archive.

Phạm vi: Batch 4, 5, 6a, 6b và Milestone B. Không Stage 3, không cài
package, không stage/commit/push. Worktree đầu vào chứa Stage 1 chưa commit;
snapshot diff/status đầu vào ở `$LOCAL_TMP/kagent-stage2-entry.diff` và
`$LOCAL_TMP/kagent-stage2-entry.status`. Không có AGENTS.md lồng trong src/tests/skills.
Python/pytest/pyright dùng `venv-linux`; cấu hình pyright hiện chọn Python 3.14.
WSL không có rg, dùng grep/find sau khi thử rg. Git chạy trong WSL để tránh
thay cấu hình safe.directory của Windows.

## Batch 4: boundary và binding audit

Đã trace state serialization/clear/replace, mutation_lock/committed_revision,
inventory review binding, native producer/retention/reader, scanner finished
callback/dataset integrity/triage, scoped browser reader/import và controller
HTTP output admission. Đã đọc contract recon/web-enumeration/web-input-analysis
và regression Stage 1. Không sửa playbook, registry hoặc transport.

| Reference | Producer → consumer | Guard | Regression dương / âm |
| --- | --- | --- | --- |
| objective/origin | WorkflowObjective → admission | active whole_target + exact origin | canonical origin / foreign objective, scheme, port |
| generation/session/target | WorkflowOwner/native callback; runtime_scope/controller HTTP | existing owner.current(), stamp, invocation scope | native retention / stale callbacks, restore/revoke |
| endpoint_id | EndpointRecord → provenance | full canonical URL + known/unknown method fingerprint | cross-source aggregation / wrong endpoint ID |
| discovery source_id | SourceRecord → ProvenanceRecord | deterministic immutable retained identity, exact reference | multiple provenances / foreign/missing source |
| retained_ref/hash | existing result/observation store → source metadata | producer publication guard; immutable hash | native ref / corrupt retained source, no replacement guessing |
| scanner_job_id/record_id | finalized ScannerJob/dataset → endpoint provenance | exact current stored job, objective/origin, dataset SHA, row membership + operation | ffuf handoff / foreign job, row, corrupt bytes |
| capture/observation ref | scoped admitted capture/HTTP output → source | existing typed output, policy stamp/session/epoch, body integrity, current invocation scope | capture locator / wrong scope |
| input_id | existing AttackSurfaceInput → provenance | exact existing ID + objective/origin/method/canonical URL | independent input IDs / missing or wrong operation |
| source_ref/auth/baseline/request | existing request context → existing validation | unchanged; discovery fields cannot populate these | Stage 1 context separation / conflict regression |
| candidate/attempt/evidence/result/finding | existing stores → validators/recovery | unchanged existing owner/context/eligibility gates | responsibility groups; discovery produces none |

Các regression cụ thể để đối chiếu matrix:

| Binding | Positive regression | Negative regression / no-publication assertion |
| --- | --- | --- |
| endpoint/source aggregation | test_cross_source_aggregation_separates_operations_and_execution | test_invalid_source_rejection_is_atomic; test_provenance_binding_atomic |
| exact input/media linkage | test_transaction_input_dedup_provenance_occurrences_zero_input_and_repeated_read | test_provenance_cannot_mislabel_existing_input_media; test_invalid_item_is_excluded_without_orphan_input_or_processed_claim |
| native retained source/owner | test_native_source_ref_and_baseline_rejection | test_native_old_owner_cannot_publish_to_replacement_state; existing native callback ownership group |
| scanner job/record/dataset | test_finalized_scanner_inventory_preserves_exact_job_rows_and_no_auto_inputs | test_scanner_provenance_rejects_cross_record_binding; foreign-objective exact-job guard |
| capture/observation/source bytes | test_capture_source_extraction_handoff_repeated_processing_and_session; test_native_http_source_bytes_use_actual_document_url_without_another_request | test_source_read_failure_is_atomic_without_replacement_or_authority (wrong source/ref/revoke/replacement/eviction/scope/secret) |
| generation/review/cancellation | ordinary process_source + persisted metadata roundtrip | test_restore_during_source_review_cannot_reuse_old_generation_approval; test_source_update_queued_across_reset_never_guesses_replacement; test_cancel_queued_source_update_does_not_publish |
| historical completion/readiness | test_late_source_blocks_current_readiness_without_rewriting_history | test_corrupt_selected_source_never_restores_as_completed_empty_inventory; test_budget_stop_requires_explicit_ack_bounds_and_reason |
| auth/baseline/request context | Stage 1 canonical legacy reuse/context tests; captured replay responsibility group | Stage 1 test_source_conflict_is_not_provenance_merge_and_does_not_mutate; provenance/source actions không nhận execution context |
| candidate/attempt/evidence/finding | existing test_terminal_agent_assessment_without_verifier and finding persistence tests | existing test_invalid_source_never_publishes, model-only proof/context borrowing regressions; mọi new discovery pipeline assert candidate/evidence/attempt/result stores không được tự tạo |

Additive schema: `endpoints`, `discovery_sources`, `discovery_provenance` in
WorkflowState. Legacy absent fields default empty. New graph hydration requires
original IDs and valid cross-links; corrupt graph is discarded atomically and
no-candidate reviews invalidated. Historical input/candidate/attempt/result IDs
and representations stay unchanged. Sources are observations, never authority.

Reproducer on the initial Batch 4 adapter: foreign-objective copy of a scanner
job with the same job ID was accepted (`batch4-first.log`: 1 failed, 128 passed).
Minimal fix requires the exact stored job and verifies provenance row membership
and operation against the hash-bound dataset. Targeted rerun: 129 passed.

New metadata bounds: 4,096 endpoints; 128 sources; 8,192 provenance rows;
256 provenance rows/source; 16 limitations of at most 240 characters. Raw native
results, datasets and capture bodies remain in their original stores. Native
baseline/rejected rows are not endpoints; their full metadata remains retained.
Nmap service clues remain scanner rows; no inferred HTTP origin.

Batch 4: implementation hoàn tất, không còn blocker đã xác nhận. Nhóm mục tiêu
136 passed; integration 333 passed; pyright 0 errors/0 warnings. Các nhóm overlap,
không cộng thành một suite. Chi phí insert 100 sources ban đầu 10,738s do
serialize toàn inventory hai lần/mutation; sau patch nhỏ 0,057s. Không thêm index.

## Batch 5: binding audit before frontier implementation

Reuse Batch 4 ownership matrix. New selection/disposition updates must address
an exact source ID in the current objective/origin. A supplied retained reference
must equal that record's retained reference; no fallback lookup or replacement.
Selection does not read bytes or grant execution rights. Content identity and
meaningful disposition facts feed existing progress_facts/stall tracker; reasons,
timestamps, locator IDs and repeated reads do not establish progress. Relevant
source/inventory updates invalidate existing no-candidate bindings. Historical
phase markers remain readable while unresolved selected sources block readiness.

Required positive/negative tests: exact current source and retained ref / foreign,
missing, stale generation, wrong ref; processed zero-input / limited-as-processed;
explicit partial bounded-stop / acknowledgement without bounds; late selection /
unchanged reread and rewording; selected scanner work remains independent.

Batch 5: implementation hoàn tất. Mục tiêu 138 passed; integration 124 passed;
pyright theo pyrightconfig/venv-linux trên responsibility files: 0 errors/0 warnings.
`select_source`, `get_source`, `get_endpoint`, `set_source_disposition` là metadata
actions. `list(view=sources|endpoints|provenance)` có cursor bind generation,
objective, view/filter và membership, tối đa 25 rows/16 KiB. `get_source` không đọc
raw body. Unselected sources không tự vào frontier. Pending/blocked và partial
chưa acknowledgement còn unresolved; processed zero-input và not_applicable khác
pending. Partial có acknowledgement vẫn là partial, cần reason + limitations +
typed processing bounds. Không xóa producer limitations để tự nhận processed.

Late inventory/source thay đổi làm goal no_candidate về pending, xóa binding cũ.
Review binding bao gồm discovery graph. Historical phase markers không bị rewrite;
current readiness và whole-target completion vẫn xét selected sources chưa giải
quyết, input dispositions, scanner obligations và artifact gates hiện có.
Progress dùng operation/content syntax và disposition/selection facts qua stall
tracker hiện có. Fresh locator/hash, timestamp, prose, đọc lại, cursor không đổi
không được credit. Không có recovery/frontier manager mới.

Content identity dùng multiset fact đã sort, không locator/node position/member
order. Occurrences vẫn được giữ nguyên ở provenance; raw query order vẫn nằm
trong URL identity. Reproducer đổi riêng thứ tự OpenAPI paths: 1 failed trước
fix; nhóm parser/frontier/runtime/progress sau fix 87 passed. Lượt full thứ hai
dừng có chủ đích ở 926 passed, exit 2/interrupted, 89,55s wrapper; không dùng làm
full-suite verdict. Log/manifest được giữ trong intermediate/attempt-2.

## Batch 6a: binding audit before HTML extraction

Source bytes must be resolved through the original admitted store and current
source rights. Source URL comes from the admitted record, never target-root
guessing. Extraction stages all endpoint/input/provenance/disposition changes
before publication. Existing source_ref, baseline/auth and evidence remain
untouched. Positive tests cover document-relative geometry and repeated controls;
negative tests cover wrong source/hash/origin/generation, external URLs, secrets,
invalid extracted items and rollback without partial linkage or processed claim.

Batch 6a: implementation hoàn tất. Nhóm mục tiêu 163 passed; integration 368
passed; pyright responsibility files 0 errors/0 warnings. Benchmark tái hiện
admission bounded HTML trên inventory 1.000 endpoints mất 15,397s vì so inventory
cho từng input. Patch chỉ bỏ serialization khi không có no_candidate review cần
bảo vệ; sau sửa 1,056s. Responsibility regression sau patch: 156 passed.

Reproducer trước fix: 2 failed/21 passed bắt tag chưa hoàn chỉnh và input mồ côi
khi provenance invalid. Fix kiểm dangling syntax trước HTMLParser.close() và
validate provenance trước input admission. Runtime fixtures ban đầu dùng sai key
responseBody/reset_session; sửa fixture theo CaptureStore respBody và reset hiện
có, không thay production contract để hợp thức hóa fixture.

`process_source(discovery_source_id, retained_ref, extractor)` là action đọc bytes
cục bộ có Registry permission riêng, noSessionCache, không HTTP/crawl. Controller
context RAM-only bind `runtime_scope` hiện có trước review; sau review phải còn
đúng generation/objective/target/session. Reader reuse policy receipt, capability,
revocation, exact scoped capture reader, ObservationStore integrity/epoch/session;
candidate-owned observations còn qua ReadHTTPObservation ownership/attempt guards.
Không restore quyền từ SourceRecord. Known non-HTML media không được parse thành
form sống; unknown media chỉ xử lý theo extractor được chọn rõ ràng.

HTML giữ document-relative URLs, first-base semantics, form actions/method/enctype,
named controls, query names và occurrences. Không giữ value/default/text, password,
hidden/token/cookie values. GET form enctype ở provenance, không giả request-body
media cho query input. Unsupported method giữ uncertainty; explicit form owner,
submit override, nested forms, malformed/truncated/encoding/bounds đều có limitation
thích hợp. External/fragment references chỉ để lại bounded excluded-category clue;
không URL ngoài scope thành endpoint, không fetch. Parser này không phải validator
HTML đầy đủ hoặc browser DOM implementation.

## Batch 6b: binding audit before OpenAPI extraction

Reuse 6a byte/source transaction. Operations bind paths/methods, parameters and
request-body schema/media to their own operation. Local refs stay in-document,
bounded and cycle checked. Servers never change origin. Response properties
never become request inputs. Negative tests include external refs/servers,
cycles, malformed/oversized docs, wrong source/ref, unsupported geometry and
bounded-stop semantics. No JSON/YAML/JS/network capability expansion.

Batch 6b: implementation hoàn tất. Preliminary group gồm API/schema budgets:
199 passed; scanner production pipeline mới 2 passed. Malformed `in`/schema type
là list tái hiện TypeError: 2 failed/22 passed trước fix; type guards nhỏ sau sửa
cho 24 parser tests pass. Sai provenance media type của existing input: 1 failed
trước fix, admission/restore cùng dùng media compatibility guard; nhóm sau fix
99 passed. Các con số này là batch checks trung gian; Milestone B bên dưới là
verification trên manifest cuối.

JSON OpenAPI 3.0/3.1 minimum hỗ trợ paths/methods, operation/path parameters (query,
path, header, cookie), requestBody media, request properties, local refs, nested
request fields dưới JSON Pointer, required declarations trong provenance. Path
parameters phải hiện diện trong operation template. Operation parameters override
path declarations theo name/location. JSON duplicate members bị reject; không
silently overwrite operation. Required là declaration tại schema chứa field,
không chứng minh field luôn bắt buộc trong mọi conditional request.

Servers cùng origin được resolve theo actual specification URL; operation/path
overrides được giữ. External servers không được thay bằng origin hiện tại để
invent operation. Server variables/query, external/missing/cyclic refs, reference
siblings, schema composition/dynamic properties, array selectors và media serialization
chưa hỗ trợ đều có limitation. Swagger 2/YAML/JS không hỗ trợ. Responses và arbitrary
response JSON không thành request schemas. Không download external refs.

## Schema/API và persistence cuối

| Object | Trường/identity chính | Vai trò |
| --- | --- | --- |
| EndpointRecord | ep_ + SHA-256(objective, canonical origin, raw-query-preserving URL, known/unknown method) | conservative operation, không request/candidate |
| SourceRecord | ds_ + retained provenance identity; objective, origin, kind, locator, retained_hash/ref, document_url, scanner_job_id | bounded source metadata, không body/quyền |
| Source processing | selected, disposition, limitations, stop_reason, bounded_stop, processing_bounds, syntax-only content_identity | frontier/completion/progress |
| ProvenanceRecord | pv_ + source/endpoint/input/locator/occurrence/required/media linkage | aggregation riêng với source_ref |
| AttackSurfaceInput | schema/ID Stage 1 giữ nguyên | độc lập với endpoint inventory và request execution |

State persistence thêm ba arrays; không migration/rekey hoặc tạo historical
processing cho legacy sessions. `clear`/`replace_from` giữ lifecycle generation
hiện có và clear/copy graph. Restore không tạo permissions/receipts/active attempt.
Corrupt new graph không để linkage một phần; legacy stores còn nguyên và review
không được âm thầm bỏ qua source đã discard. Restore graph chỉ là đọc lịch sử,
không thay việc kiểm raw source/job/capture tại current runtime boundary.

Thêm boolean bounded `discovery_restore_invalid` (legacy default false). Khi
graph mới bị hỏng, graph bị discard atomic và flag true chặn completion/readiness
kể cả objective không có requested goals. Flag persist qua save/restore/replace,
hiện trong prompt/list, không biến thành fake source hay quyền. Thêm source mới
không âm thầm xóa lỗi; phục hồi snapshot hợp lệ hoặc operator reset dùng lifecycle
hiện có. `clear` xóa flag theo cùng state reset.

Shared extraction transaction stage trên detached WorkflowState bằng admission
Stage 1 hiện có. Item invalid bị loại với limitation; graph/owner/global-bound
failure reject toàn proposal. Chỉ publish input/endpoint/source/provenance stores
trong một bước synchronous dưới workflow mutation boundary; không copy candidates,
attempts, evidence, coverage hoặc execution context từ snapshot. Historical input
match duy nhất có thể reuse exact ID theo Stage 1; ambiguous/conflicting IDs không
được đoán hoặc thay thế. Occurrences nằm ở provenance, không re-key inputs cũ.
Occurrence là ordinal của syntax/query/control/schema trong nguồn; nó không
được truyền tự động thành selector hoặc occurrence của HTTP replay/validation.

| Processing bound | Giá trị |
| --- | --- |
| Document bytes | 65.536 bytes, UTF-8; invalid encoding có limitation |
| HTML tag events | 4.096 |
| Extracted rows/source | 255; chừa chỗ cho admitted source operation, tổng provenance/source ≤256 |
| OpenAPI paths / operations | 64 / 128 |
| Parameter declarations | 256 |
| Schema/ref nodes / ref depth | 1.024 / 8 |
| Inline schema nesting | 16 |
| Server/media alternatives | 8 mỗi loại |

Vượt bound/truncation/malformed không được silently mark processed. Raw bytes
vẫn ở stores gốc. No-store native fallback chỉ có metadata partial + inline raw
sanitized result; không tạo reader/ref giả hoặc tự rerun để bù.

## Audit bổ sung trước verification cuối

- Known JSON response chứa chuỗi ví dụ `<form>`: reproducer 1 failed trước fix;
  runtime kiểm observed Content-Type trước HTML extraction. Nhóm sau fix 65 passed.
- Restore trong lúc chờ Registry review `process_source`: reproducer 1 failed
  trước fix; controller context giờ bind existing runtime_scope trước await và
  kiểm lại sau review. Nhóm source/ownership/cancellation sau fix 61 passed.
- Encoded sensitive query keys/refresh tokens có regressions; existing shared
  redactor đã chặn đúng, không thay Stage 1 admission hoặc thêm redactor thứ hai.
- Registry/private-host/exact-origin/scanner admission/grant/receipt/revocation
  không bị sửa. Endpoint inventory không dedup HTTP hay validation execution.
  Input/candidate IDs, scanner job/row/observation IDs và historical attempt/result
  linkage giữ nguyên. Source/provenance không đi vào auth/baseline/evidence binding.
  Discovery không tự tạo candidate/finding hoặc tested/performed coverage.
- Corrupt selected source trên historical completed phases, không requested
  goals: reproducer ngoài repo xác nhận 1 failed (sai completion=completed).
  Sau thêm persisted restore-invalid flag, responsibility regression 154 passed.
  Lượt full đầu được dừng có chủ đích ở 919 passed, exit 2/interrupted, 78,98s
  wrapper; source lúc đó không đổi. Đây là lượt incomplete, không phải full green.

Freeze đầu đã bị thay đổi bởi hai audit fixes cuối; các lượt đó chỉ là intermediate,
đã giữ đầy đủ log/manifest trong `intermediate/`. Không dùng chúng làm final green.

## Milestone B verification

**Verdict: PASS WITH LIMITATIONS cho Stage 2 / Milestone B. Full configured suite
KHÔNG green.** Batch 4/5/6a/6b đã hoàn tất, không còn correctness blocker Stage 2
đã xác nhận. Full suite hoàn tất 100%, checksum khớp trước/sau. Dừng implementation
tại Milestone B; không bắt đầu Stage 3.

Final source freeze hiện tại: **713 files**, bao gồm src/tests/benchmarks/skills/
scripts và AGENTS.md, pyproject.toml, pytest.ini, pyrightconfig.json,
requirements.txt. Báo cáo/docs và runtime caches không nằm trong source manifest.
SHA-256 aggregate:
`7d28f94a35f3c7ced2dd813b5d0b91df9c66e3c04bbf21671346d06cb69bd79b`.

| Final-source responsibility group | passed | failed | skipped | xfailed | Thời gian pytest |
| --- | ---: | ---: | ---: | ---: | ---: |
| Stage 2 + Stage 1 admission/listing/native retention | 249 | 0 | 0 | 0 | 63,34s |
| Integration/whole-target/session/ownership/cancellation/scanner/recovery/evidence/finding/schema budgets | 1.418 | 0 | 0 | 0 | 167,04s |
| Full configured suite trên final source | 8.355 | 1 | 12 | 0 | 1.342,20s (22:22) |

Hai nhóm overlap, không cộng counts. Cả hai before/after manifests khớp freeze.
Full collection **8.368 tests**, hoàn tất, **0 errors**, exit code 1. Không có
selected/collected test bị bỏ dở trong final run. Hai lượt full dừng sớm trước đó
chỉ là intermediate/incomplete và không thay thế kết quả final này.
Integration có 27 PytestWarning từ JUnit xunit2 + record_property hiện có;
không suppress warning hay thay skip/xfail. Pyright đầy đủ theo pyrightconfig.json:
**0 errors, 0 warnings, 0 informations**. Banner báo phiên bản pyright mới không
được dùng để cài/cập nhật dependency.

Evidence directory: `$LOCAL_TMP/kagent-stage2-verification-20261018/`. `freeze.json`,
`targeted-{before,after,result}.json`, `integration-{before,after,result}.json`,
`targeted.log/xml`, `integration.log/xml`, `pyright.log`, `performance.json`,
`preservation.json` giữ exact commands, counts và hashes. Runner bên ngoài repo:
`$LOCAL_TMP/kagent-stage2-verify.py`; targeted gồm 11 modules được liệt kê đầy đủ trong
targeted-result.json, integration gồm 42 modules trong integration-result.json.
Full command là `venv-linux/bin/pytest -q --tb=short -ra --junitxml=.../full.xml`,
dùng pytest.ini hiện có. TERM=xterm-256color, COLORTERM unset; không force truecolor.

Lưu ý khi tiếp tục bàn giao: runner và thư mục evidence `/tmp` nêu trên không
còn tồn tại trong môi trường hiện tại. Các counts/checksum ở đây là kết quả
đã ghi nhận từ lượt verification hoàn tất, không phải một lượt chạy lại khi
resume; không thể đối chiếu lại log/manifest gốc lúc bàn giao. Kiểm tra
`git diff --check` khi resume vẫn sạch. Chỉ bổ sung ghi chú báo cáo này,
không thay đổi source/test/config sau verification.

| Performance trên source cuối | Observed seconds |
| --- | ---: |
| Insert 1.000 endpoints (4 batches ×250) | 0,304 |
| Dedup 1.000 endpoints (cùng batches) | 0,334 |
| Insert 100 sources | 0,044 |
| Update 104 sources | 0,012 |
| 100 frontier listings | 0,193 |
| Large bounded HTML parse / admission | 0,013 / 1,060 |
| Large bounded OpenAPI parse / admission | 0,023 / 1,035 |

Đo bằng `venv-linux/bin/python -m benchmarks.recon_stage2` trước full run, khi
responsibility groups/pyright đã kết thúc. Không gọi các số này là SLA. Lượt
benchmark dưới tải verification đồng thời chậm hơn và không được dùng để suy
ra regression hoặc bỏ test threshold.

### Failure classification và skipped/not-run

Failure duy nhất:
`tests/ui/test_light_theme_app.py::test_light_first_terminal_frame_uses_selected_theme`.
Assertion tìm RGB escape `48;2;250;248;242` nhưng `paints=[]`. Đây là cùng case,
assertion và terminal environment đã được phân loại ở Stage 1: TERM=xterm-256color,
COLORTERM unset. Source UI test và renderer không bị đổi ở Stage 2.

| Focused diagnostics sau full | passed | failed | skipped / xfailed | pytest time |
| --- | ---: | ---: | ---: | ---: |
| Light first-frame + session_save, môi trường gốc | 1 | 1 | 0 / 0 | 1,90s |
| Cùng hai cases, chỉ COLORTERM=truecolor cho focused process | 2 | 0 | 0 / 0 | 1,89s |

Differential này khớp evidence terminal-capability của Stage 1. Không có
reproducer mới chứng minh Stage 2 gây runtime regression; không sửa production,
fixture, timeout hay threshold. Không chạy lại full với truecolor để thay kết quả.
Focused pass chỉ phân loại failure, không biến full suite thành green.

`test_async_wait_control_keeps_textual_responsive[session_save]` **pass trong
final full run và cả hai focused runs**. Timing limitation Stage 1 không tái hiện
ở lượt này; chưa có root cause/patch, không được gọi là đã fix.

Full run có **79 warnings**: 2 RuntimeWarning từ fixture malformed provider config
và 77 PytestWarning từ JUnit xunit2/record_property hiện có. Không suppress warnings.

12 skips giữ nguyên semantics:

- 9 Java gate cases cần cached offline WAR/Tomcat (idle, transition, session,
  reset-failure, drain-timeout, idle-failure, premature, crash và TUI HTTP adapter).
- 1 prepared-existing-lab operator case.
- 1 live system opt-in cần KAGENT_SYSTEM_LIVE=1.
- 1 live model characterization opt-in cần KAGENT_RUN_LIVE_TOOL_CHARACTERIZATION=1.

`tests/integration/test_kagent_burp.py` vẫn bị ignore theo pytest.ini: **not run**,
không được tính là passed/collected. Không bật live/external-model cases, không
thay skip/xfail. Exact skipped node IDs ở full-result.json và full.xml.

### Freeze/preservation và kết thúc

- `full-before.json`, `full-after.json`, `freeze.json`: **713/713 files khớp**,
  SHA-256 aggregate `7d28f94a35f3c7ced2dd813b5d0b91df9c66e3c04bbf21671346d06cb69bd79b`.
  Kiểm lại sau focused diagnostics vẫn 0 changed/missing/added files.
- Manifest Stage 1 690 files: chỉ đúng 7 existing files thuộc Stage 2 thay đổi;
  **0 unrelated changes, 0 missing**. Các Stage 1 changes chưa commit được giữ.
- Đã chạy git diff --check, đọc git diff/status; final.diff/final.status giữ evidence.
  Docs/report được hoàn thiện sau source freeze, nằm ngoài manifest code/test/config.
- Không cài packages, không reset/restore/clean worktree, không stage/commit/push.
- **Đã dừng tại Milestone B. Stage 3 cần explicit authorization mới.**

## Files thuộc thay đổi Stage 2

Các file cũ được sửa, đã đối chiếu manifest Stage 1 (690 files):

- `src/agent/agent.py`: controller source publication và invocation context.
- `src/agent/tool_results.py`: native retained/inline result → metadata handoff.
- `src/agent/system_prompt.py`: bounded discovery counts/restore limitation.
- `src/tools/workflow/workflow_tool.py`: source actions/listing/readiness gate.
- `src/tools/workflow/action_view.py`: whole-target projection của source actions.
- `src/workflow/state.py`: graph/state/transaction/frontier/completion/persistence.
- `tests/tools/test_workflow_action_view.py`: bỏ hard-coded 15-actions assertion
  để kiểm additive actions; giữ toàn bộ action/field/objective projection checks.

File mới:

- `src/workflow/discovery.py`
- `src/workflow/extraction.py`
- `src/workflow/openapi.py`
- `src/tools/workflow/source_processing.py`
- `benchmarks/recon_stage2.py`
- `tests/state/test_discovery_inventory.py`
- `tests/state/test_source_frontier.py`
- `tests/state/test_html_extraction.py`
- `tests/state/test_openapi_extraction.py`
- `tests/tools/test_workflow_sources.py`
- `tests/agent/test_discovery_handoff.py`
- `tests/integration/test_discovery_extraction.py`
- `tests/integration/test_discovery_scanner_handoff.py`
- `docs/recon-stage2-review.md`

Tổng: 21 files thuộc Stage 2. Git status còn chứa các thay đổi Stage 1 đã có
sẵn; chúng không được tính thành work mới của Stage 2. Không có unrelated
changed/missing files trong manifest Stage 1 đã đối chiếu. Không stage/commit/push.

## Giới hạn và stop gate

- Bounded syntax metadata không chứng minh endpoint reachable, input controllable,
  authentication context, performed testing, severity hay vulnerability.
- Chỉ HTTP/capture bytes đã admitted có local HTML/OpenAPI processing. Native và
  scanner giữ handoff riêng; thiếu retained ref không được tự rerun/fetch. Source
  cần quyền/capability hiện tại; historical readability không cấp execution authority.
- Các bounds, unsupported syntax và raw-source availability có thể giữ partial/
  blocked work; cần bounded-stop acknowledgement rõ ràng hoặc phục hồi source.
- Admission transaction lớn vẫn synchronous/bounded; performance observations là
  số đo trên máy hiện tại, không phải SLA hay chứng minh mọi interleaving an toàn.
- Hai limitation Stage 1 về first-frame truecolor và session-save suite timing
  không được sửa/tăng timeout/threshold/skip. Failure nào tái hiện trong full sẽ
  được phân loại riêng; focused pass không thay kết quả full.
- Deferred toàn bộ Stage 3: Batch 7 phase-aware guidance, Batch 8 skill lifecycle,
  Batch 9 tooling_profile removal; ffuf auth, Nmap -sV, scanner capability expansion,
  JS extraction, crawler và external-ref fetch. Không được bắt đầu nếu chưa có
  explicit authorization mới.
