# Stage 3 / Milestone C — phase guidance, skill lifecycle và tooling policy

> Bản được chuẩn bị để commit: đường dẫn máy cá nhân đã chuẩn hóa. Raw logs,
> snapshots và evidence trung gian được giữ local, không xóa; xem
> [bộ evidence portable](verification-milestone-c/README.md) và inventory/hash của archive.

Phạm vi: Batch 7 → Batch 8 → Batch 9 → Milestone C. Không triển khai Stage 4,
scanner mới, Scenario 3, sửa luận văn, cài package hoặc commit/push.

**Cập nhật Final Corrections ngày 18/10/2026: full-suite gate PASS —
8.490 passed, 12 skipped, 79 warnings, exit 0 trên freeze mới 715 files.**
Xem [báo cáo Final Corrections](recon-milestone-c-final-corrections.md) và
[artifacts hiện hành](verification-milestone-c/README.md#local-archive).
B/C đã sửa có regression; A chưa xác định root cause, M2 không sửa khi chưa chứng
minh contract violation. Không chạy Scenario 3 hoặc Stage 4.

Các kết quả dưới đây thuộc verification trước Final Corrections và được giữ
như lịch sử của các freeze tương ứng; không dùng làm verdict source hiện tại.

**Trạng thái trước Final Corrections: full-suite gate CHƯA ĐẠT.**

Targeted và integration đạt trên freeze cuối; full configured suite hoàn tất với
2 failures. Một failure là giới hạn terminal truecolor tái hiện; một timeout
validation-finalization chưa tái hiện focused và chưa xác định root cause.
Không sửa source khi tiếp quản; dừng tại Milestone C, không chạy Scenario 3.

## Baseline và bảo toàn worktree

Đã đọc AGENTS.md root (không tìm thấy nested AGENTS.md), báo cáo Stage 1/2,
code/runtime/tests hiện tại và contracts/allowed-tools của recon,
web-enumeration, web-input-analysis. Dùng venv-linux có sẵn, pytest.ini và
pyrightconfig.json hiện hành. Full suite ignore Burp theo pytest.ini.

Baseline đầu Stage 3 được chụp tại `$LOCAL_TMP/kagent-stage3-verification/`:
`baseline.status`, `baseline.diff`, `baseline.json`, và bản sao từng source file
trong `baseline-source/`. Có 713 files, aggregate SHA-256 (dòng `hash  path\n`
theo thứ tự path):
`3cecf2dd365b045ed02aa950eecafc2aeef4b87b2b3e5fc8b3ab19ca54ddac6c`.
Worktree chứa 27 tracked files đã sửa cùng các untracked files Stage 1/2 và docs.
Đây là baseline bảo toàn hiện tại, không phải một checkout sạch.

Stage 2 báo cáo 713 files và aggregate
`7d28f94a35f3c7ced2dd813b5d0b91df9c66e3c04bbf21671346d06cb69bd79b`.
Manifest/log gốc Stage 2 không có trong môi trường bàn giao; không thể đối chiếu
hash từng file với freeze lịch sử hay khẳng định hai cách tính aggregate giống
nhau. Các counts 249/1.418/8.355 passed trong báo cáo cũ là lịch sử, không phải
verification mới. So sánh/bảo toàn bên dưới dùng baseline thực tế đầu Stage 3.

## Batch 7

Root cause tái hiện: action guidance chọn nhánh theo có/không Candidate, không
theo phase; cả Recon và Enumeration đều nhận `Recommended: record_candidate`.
Planner bỏ qua completed phase ngay cả khi readiness đang yêu cầu sửa canonical
artifact của phase đó. Reproducer `tests/agent/test_phase_guidance.py`: 4 failed,
1 passed trước sửa; log `b7-before.log`.

Thay đổi: PlannerContext suy ra structured phase từ runtime readiness, completed
markers và late pending/blocked inputs. Action hints ưu tiên inventory trong
Recon/Enumeration, cho phép Candidate có điều kiện ở input analysis, và giữ
runtime gates cho validation/finding. Terminal workflow hướng dẫn status/repair.
Source counts theo pending/partial/blocked được render gọn cùng paging/cursors;
không copy inventory/body. Không thay workflow state hoặc performed coverage.
Sửa media identity trong enumeration playbook; bỏ wording legacy tooling profile.

Binding: phase/readiness thuộc objective hiện tại do Agent/WorkflowTool cung cấp;
không dùng display current_phase. Hints chỉ đọc snapshot. Candidate/input/source,
scanner/evidence/auth/baseline IDs giữ nguyên; không tạo hoặc thay ID, quyền,
attempt, result hoặc finding. Artifact repair vẫn qua canonical readiness gate.

Regression bổ sung: Recon/Enumeration có và không có early Candidate, input
analysis conditional path, artifact repair, terminal status, bounded source
counts/cursors và không mutation. Existing request preparation tests giữ nguyên
budget 1.000 ký tự/300 tokens; không tăng threshold. Tests wording cũ được cập
nhật để kiểm native transport/typed scanner boundary, không giữ hai tooling modes.

Checkpoint được ghi bên dưới; kết quả final-source nằm ở phần Milestone C.

Batch 7 checkpoint cuối: targeted 170 passed (6,05s), integration 125 passed
(13,62s), pyright 0 errors/0 warnings/0 informations, diff --check sạch.

## Batch 8

Ba reproducer offline trên state có structured Recon completion đều trả True
trước sửa: recon còn cho phép service_discovery trong Enumeration; body disabled
vẫn được projected; deleted active skill qua reload mở lại unrestricted access.
Sau sửa cả ba trả False (`b8-before.log`, `b8-after.log`).

Agent lưu activation nhỏ, có source manual/model/legacy, UUID, fingerprint toàn
Skill definition, và owner transient (state/generation/store/session/target
revision/URL/objective). Không đoán manual/model cho API active-name cũ. Model
phase contracts retire khi model load contract thay thế phù hợp với structured phase
(hoặc artifact-repair readiness); manual selection hợp lệ được giữ;
manual và model load cùng tên không làm mất manual provenance. Không eager load.
Disabled/deleted/changed definitions retire deterministic; identical reload giữ
contract, re-add không resurrect contract. Unknown names và tập active rỗng do
retirement chặn permission-requiring tools, vẫn giữ bootstrap tools hiện có.
Natural per-turn expiry vẫn giữ semantics cũ; explicit `allowed-tools: []` của
một definition hợp lệ giữ wildcard semantics hiện có, độc lập với quyền Registry.

Message thêm archival skill_activation (id/name/fingerprint/source) và cờ
skill_admission_required chỉ có khả năng hạn chế. Session decoder validate shape;
resume không hydrate live activations. Cờ restriction giữ qua compact/save/resume
để mất body không trở thành allow-all. Không lưu owner/callback/permission mới.
Raw transcript body không đổi do disable/delete/reload; projection elide body có
provenance stale, giữ tool call/result pairing. Legacy thiếu provenance được giữ
làm historical data, demote known manual system wording; không suy ra authority.
Không thể chứng minh/lọc mọi bản sao prose của skill cũ khi thiếu provenance.

Recheck dùng controller_admission trong existing ReviewGuard. Không đổi
Registry.execute, execution receipts, grant/revocation/scope/private-host/YOLO
semantics. Callback chỉ hạn chế, bind original owner/TurnOwner và recheck current contracts và đi
qua các review/dispatch guards có sẵn, kể cả native HTTP inner permission wait
với/không bound ExecutionPolicy. Không tạo permission system mới. Request
readmission elide body sau await; compaction discard summary khi skill stamp đổi
trong admission/model wait. Reload/transaction rollback restore contract metadata
chỉ trong generation hợp lệ; reset/resume retire owners qua lifecycle hiện có.

Checkpoint cuối: 285 targeted passed (41,58s); responsibility integration 554
passed, 24 JUnit record_property warnings (61,39s, exit 0, source unchanged);
pyright 0 errors/0 warnings/0 informations. diff --check sạch. Các lượt debug
intermediate có failure do fixture giả loader, metadata UUID equality và protocol
signature test mới; fixture nay dùng LoadSkillTool thật, so sánh content và
provenance thay vì UUID giữa hai Agents. Không tăng timeout/threshold/skip.
Một lệnh intermediate chỉ định nhầm tests/session (không tồn tại) không collect
case nào; đã thay bằng tests/state/test_session_store.py và persistence_async.

## Batch 9

Trước sửa: serializer persist tooling_profile cho minimal/full/null, CLI còn
run_first_run_picker, và hai prompt tooling branches khác nhau (`b9-before.log`).
Đã gỡ ToolingProfile enum/Config field/parser/serializer branch,
AgentOptions/Agent/BuildOptions propagation, CLI first-run setup/save branch và
picker function. Xóa src/ui/core/first_run_picker.py và tests/ui/test_first_run_picker.py
sau audit imports/callers; xóa unused UI import. Native discovery bỏ các argument
capabilities/tooling_profile không dùng; workflow nay là keyword-only để tránh
silently bind một inventory object cũ thành WorkflowState.

Legacy minimal/full/null/missing đều được xử lý như unknown config key và load
an toàn về cùng Config/runtime; config load không rewrite file. Chỉ explicit
save bỏ key cũ. Không sửa physical writer/provider transaction hoặc provider
identity/secrets domains. PromptProfile, BuildOptions.prompt_profile,
AgentOptions.prompt_profile và full/compact behavior vẫn giữ.

353 targeted passed (33,86s, 2 existing malformed-provider RuntimeWarnings),
315 integration passed (69,25s, 24 existing JUnit record_property warnings),
pyright 0 errors/0 warnings/0 informations, diff --check sạch. New tests chạy
startup/resume thật qua offline CLI cho cả bốn config forms, assert không picker,
không config save, registry có native/scoped tools, và không gọi LLM. Service
policy regressions giữ nguyên scopes, budgets, review và coverage assertions cho
cả bốn forms. Tests explicit old constructor API/picker đã được thay bằng
current native-policy/no-write tests; không đổi live skips hay runtime thresholds.
Lệnh integration intermediate chỉ định hai test paths không tồn tại đã collect
0 tests; đã chạy lại với tests/ui/test_app.py và tests/runtime/test_cli_main.py.

## Public API/schema/compatibility

- Additive private session Message metadata: skill_activation và restriction-only
  skill_admission_required. Provider serializers vẫn chỉ encode established
  provider fields, không đưa owner/activation metadata vào API requests.
- Live _SkillActivation và ReviewGuard callback không serialize/restore.
  New sessions không skill vẫn có admission semantics cũ; known retired contracts
  cần load/select explicit để có contract mới. Registry permissions vẫn bắt buộc.
- Missing legacy metadata không được đoán fingerprint/source/current ownership.
  Retained historical text là dữ liệu, không phải live activation.
- Removed internal APIs: ToolingProfile, PromptToolingProfile,
  tooling_profile constructor fields, first-run tooling picker, unused discovery
  constructor arguments. Repo callers đã được audit/update. External Python
  callers dùng constructor cũ cần cập nhật; disk configs vẫn load tương thích.
- Input/candidate/attempt/evidence/finding/discovery/scanner schemas, IDs,
  canonical artifacts và source_ref/auth/baseline semantics không đổi.

## Cross-object binding matrix

| Reference | Producer → consumer và boundary | Negative/stale handling |
| --- | --- | --- |
| objective_id | WorkflowState → planner phase/readiness và activation owner | Chỉ objective hiện tại; đổi objective retire owner, không substitute ID |
| session/generation/target/owner | Existing state/store/Target/TurnOwner → activation và ReviewGuard callback | Pending manual bind state/generation/store trước next request; active bind target revision/URL/objective; reset/resume không restore authority |
| activation id/fingerprint/source | inject_skill/current LoadSkillTool → live contract + archival Message → projection/admission | Definition change/disable/delete retire; identical reload giữ; re-add cần load mới; legacy source không đoán manual/model |
| input_id/counts/cursors | objective_inputs/source frontier → structured phase và bounded prompt | Chỉ đọc counts; không tạo/link/dispose input do hints; late input/no-candidate contract giữ qua regression |
| candidate_id/validation_attempt_id/result | Existing WorkflowTool + validation gates → Agent tools | Không thêm candidate/attempt/result; generic admission vẫn chạy trước skill gate; stale dispatch bị chặn |
| request/capture refs, baseline_request_ref, auth_context_ref | Existing capture/source resolvers → HTTP/validator | Không copy/rebuild credentials hoặc borrow context; existing exact capture/owner checks giữ; callback chỉ restrict |
| observation_id/evidence_ref/finding binding | HTTP/scanner observations + evidence/result/finding stores | Không sửa producer/evidence eligibility; negative lifecycle cases assert không new artifacts |
| scanner_job_id/record_id/dataset | Typed scanner pipeline → bounded retained readers/triage | Constructor cleanup không chọn backend; job integrity, partial coverage và scanner permission tests giữ |
| discovery source/provenance/endpoint/source_ref | Stage 2 stores/extraction → bounded prompt/source pages | Không rekey/fetch/upgrade observation thành input/candidate/finding; Stage 1/2 regression kiểm handoff/extraction/readiness |
| provider profile/model/secret IDs | Không applicable cho lifecycle/guidance; Batch 9 chỉ gỡ dead config key | Không thay provider transactions, backend identity, secrets hoặc network probing |

Đã audit positive và negative paths; guidance/provenance không thể cấp runtime
rights. Các binding stores không được sửa bằng Stage 3; không thêm test hình thức
cho mỗi ID khi producer/consumer không đổi. Regression groups cũ kiểm các stores
thật thay vì giả lập eligibility từ prompt text.

## Regression mapping

| Contract | Tests chính |
| --- | --- |
| Recon → Enumeration → Input analysis; no premature Candidate; budget/source counts; artifact readiness | tests/agent/test_phase_guidance.py, test_workflow_request_preparation.py, test_planner_emission.py, tests/integration/test_whole_target_workflow.py |
| Phase retirement, manual/model, unknown/empty, disable/delete/body/reload, pairing/raw transcript | tests/agent/test_skill_lifecycle.py, test_agent.py, tests/runtime/test_skill_reload_responsiveness.py, tests/ui/test_skill_entrypoint.py |
| Review races có/không ExecutionPolicy, original owner/contracts; no adapter execution/artifacts | test_skill_lifecycle.py, tests/security/test_http_invocation_lifecycle.py, test_scanner_lifecycle.py, tests/agent/test_turn_ownership.py |
| Reset/cancellation, compact/save/resume restriction, stale compaction publication | test_skill_lifecycle.py, test_parallel_cancellation.py, test_skill_context_policy.py, tests/state/test_session_store.py, test_session_persistence_async.py |
| Legacy configs/native backend/no startup write/prompt profiles | tests/runtime/test_tooling_policy.py, test_config.py, test_cli_main.py, test_cli_exit_diagnostics.py, tests/tools/test_discovery_tools.py, tests/integration/test_discovery_service_policy.py |
| Stage 1/2 admission, native retention, paging, extraction, source frontier, no-candidate late source, evidence/finding/recovery | Final targeted/integration commands và full configured suite bên dưới |

## Milestone C source freeze

Freeze đầu Milestone C: 714 files, aggregate SHA-256
`41a06639be89913c23da1e0212c2ccfe9049982e4f9df125ca82c45c50551deb`.
Bao gồm src/tests/benchmarks/skills/scripts và root AGENTS.md, pyproject.toml,
pytest.ini, pyrightconfig.json, requirements.txt; exclude caches/docs/runtime
artifacts. Docs/report hoàn thiện sau freeze không thay code manifest.
Manifest từng file và exact commands/results được lưu riêng để đối chiếu sau
mỗi verification group. Chưa dùng checkpoint batch làm final-source full result.

## Files thay đổi trong Stage 3

Danh sách so với baseline đầu Stage 3 (không gộp work Stage 1/2):

| Thay đổi | File |
| --- | --- |
| modified | `skills/recon/SKILL.md` |
| modified | `skills/web-enumeration/SKILL.md` |
| modified | `src/agent/action_guidance.py` |
| modified | `src/agent/agent.py` |
| modified | `src/agent/decision_planner.py` |
| modified | `src/agent/system_prompt.py` |
| modified | `src/cli/runtime.py` |
| modified | `src/config/config.py` |
| modified | `src/llm/core/types.py` |
| modified | `src/permission/runtime/invocations.py` |
| modified | `src/session/store.py` |
| modified | `src/skills/reload.py` |
| modified | `src/skills/transactions.py` |
| modified | `src/tools/discovery/content.py` |
| modified | `src/tools/discovery/service.py` |
| modified | `src/ui/core/app.py` |
| deleted | `src/ui/core/first_run_picker.py` |
| modified | `tests/agent/test_agent.py` |
| added | `tests/agent/test_phase_guidance.py` |
| added | `tests/agent/test_skill_lifecycle.py` |
| modified | `tests/agent/test_systemprompt.py` |
| modified | `tests/integration/test_discovery_service_policy.py` |
| modified | `tests/runtime/test_cli_exit_diagnostics.py` |
| modified | `tests/runtime/test_config.py` |
| added | `tests/runtime/test_tooling_policy.py` |
| modified | `tests/security/test_browser_deployment.py` |
| modified | `tests/security/test_cli_repair_entrypoint.py` |
| modified | `tests/skills/test_recon.py` |
| modified | `tests/skills/test_web_enumeration.py` |
| modified | `tests/tools/test_discovery_tools.py` |
| deleted | `tests/ui/test_first_run_picker.py` |
| modified | `tests/ui/test_skill_entrypoint.py` |

Ancillary docs mới: báo cáo này và docs/verification-stage3/ chứa manifest, commands/results và logs verification; chúng nằm ngoài code freeze. Các báo cáo Stage 1/2 không được sửa.

## Audit correction sau integration rộng (trước full suite)

Freeze đầu Milestone C có 4 failures / 1.574 passed / 26 warnings trong
integration 1.578 tests (285,21s, exit 1), checksum không đổi. Chưa chạy full suite
trên freeze đó. Focused reproducer: 4 failed / 7 passed. Không sửa bốn tests cũ.

Root cause production Stage 3: retirement tự động theo artifact-repair readiness
đã vô tình trở thành extra scanner-admission gate, trong khi existing scanner
phase prerequisites vẫn cho phép job. Brief yêu cầu retire khi contract model
được thay bằng contract phù hợp, không yêu cầu scheduler tự retire mọi playbook
khi readiness thay đổi. Đã chuyển retirement về explicit model-loaded handoff,
derive phase từ structured completed/input state, cho phép readiness chỉ định
repair contract; old model phase contracts không union sau handoff, manual còn
hợp lệ không bị mất. Validation → late input-analysis replacement cũng có test.
Completion/readiness và Registry/scanner execution gates giữ nguyên.

Failure scope-event: trusted controller API có thể ghi nhận load result trực
tiếp sau khi issue tool-call event; chỉ snapshot definition ở run_parsed đã bỏ
sót đường này. Snapshot nay freeze tại controller event (và fallback cho API
standalone chưa có event), không recapture khi execution bắt đầu. Body/reload
thay giữa event và result không được activate. Historical events/session restore
vẫn không hydrate authority. Không suy ra activation từ display/history text.

Bổ sung tests cho artifact-repair hint/scanner admission, late-analysis
replacement, manual replacement có cùng tên, và dispatch-event fingerprint race.
Các artifacts freeze đầu được giữ trong intermediate-freeze1/; counts/checksum
đó chỉ là intermediate, không thay kết quả final frozen source.

Freeze 2 sau correction đầu: **714 files**, aggregate SHA-256
`d91b69be343207a48205f9339930a796ef7df232f29297c12060e6d16f7ab49d`.
Final targeted/integration/pyright/full sẽ chạy lại trên freeze này.

## Phạm vi chứng minh và giới hạn

Observed: các regression dùng Agent/Registry/WorkflowTool thật cùng fake model,
mock transport/process boundaries và bounded local test fixtures. Provider
serializers OpenAI/Anthropic/Gemini encode explicit established fields; metadata
skill nội bộ không được wire-encode. Không claim đã kiểm live model decision
quality hay chạy Whole-target Scenario 3. Benchmark Stage 2 không được chạy lại.

Historical: Stage 1/2 test counts/checksum chỉ từ báo cáo cũ; không có log/manifest
gốc để xác minh lại từng file. Preservation chỉ chứng minh đối với baseline đầu
Stage 3 hiện tại, cộng với regression trên source cuối.

Conservative compatibility: legacy body chưa xác định provenance/version vẫn
được giữ làm historical data, không xóa mù hay tự activate. Không thể chứng minh
mọi bản sao playbook trong prose/summary cũ đã được loại khỏi context. Known
injections có metadata được elide, compaction mới không publish stale skill
summary. Raw skill messages được giữ; current system-prompt sentinel vẫn refresh
theo contract hiện có.

Retirement diễn ra khi explicit model-loaded phase replacement phù hợp được
adopt; readiness hint một mình không retire/schedule skill và không đổi scanner
admission. Manual selections và provenance legacy không bị đoán thành model
activation. Hợp lệ `allowed-tools: []` vẫn mang wildcard semantics cũ, nhưng
không bypass actual Registry/network/worker permissions. Empty retired active
set và unavailable names không mang wildcard semantics đó.

Deferred: Stage 4, scanner/authenticated ffuf/Nmap flags/capability expansion,
JS/dynamic extraction/crawler/external refs/OSINT/providers/vulnerability classes,
new permission/recovery/identity systems và luận văn. Không install packages,
stage, commit hoặc push. Pyright update banner không được thực thi.

## Milestone C verification — source cuối

| Nhóm | Passed | Failed / errors | Skipped / xfailed | Warnings | Exit | Pytest time |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Stage 3 + Stage 1/2 + toàn tests/agent targeted | 1.245 | 0 / 0 | 0 / 0 | 0 | 0 | 94,96s |
| Responsibility integration mở rộng | 5.746 | 0 / 0 | 1 / 0 | 34 | 0 | 428,46s |
| Full configured suite | 8.436 | 2 / 0 | 12 / 0 | 79 | 1 | 1.269,56s |

Các nhóm overlap, không cộng passed counts. Pyright toàn repo theo cấu hình:
**0 errors, 0 warnings, 0 informations**, exit 0. Targeted/integration/pyright
before/after manifests đều khớp final freeze 714 files; không sửa source giữa các
lượt. Targeted/integration/pyright chạy với TERM=xterm-256color,
COLORTERM=truecolor. Khi session mới tiếp quản, TERM vẫn xterm-256color nhưng
COLORTERM unset; full acceptance giữ nguyên môi trường inherited này. Không
set/unset chúng để thay kết quả full. Không suy ra UI limitation cũ đã được sửa
chỉ từ integration pass với truecolor.

Exact argv, exit codes, elapsed wall times và source-unchanged checks:
[targeted](verification-milestone-c/README.md#local-archive),
[integration](verification-milestone-c/README.md#local-archive),
[pyright](verification-milestone-c/README.md#local-archive),
[full configured suite](verification-milestone-c/README.md#local-archive).
[Acceptance audit](verification-milestone-c/README.md#local-archive) đối chiếu cả bốn
verification groups và ba diagnostics với freeze cuối, JUnit, timestamps,
artifact SHA-256 và git status. Full wall time 1.273,467s (21 phút 13 giây);
pytest time 1.269,56s. Collection 8.450 cases; toàn bộ đã có outcome cuối,
không có case bị bỏ dở và không có error. Full exit 1 được giữ nguyên.
[Runner](verification-milestone-c/README.md#local-archive) mô tả source selection/hash algorithm;
[baseline](verification-milestone-c/README.md#local-archive),
[final freeze](verification-milestone-c/README.md#local-archive),
[preservation audit](verification-milestone-c/README.md#local-archive) và
[Stage 3-only diff](verification-milestone-c/README.md#local-archive) cho phép review độc lập.
Thư mục logs gốc là $LOCAL_TMP/kagent-stage3-verification/; bản sao quan trọng được giữ
trong docs/verification-stage3 để tránh phụ thuộc vào /tmp khi bàn giao.

Full acceptance được chạy từ đầu sau khi xác minh integration cuối đã hoàn tất
và không còn pytest/pyright đang chạy (pytest.ini giữ nguyên):

```sh
venv-linux/bin/pytest -q --tb=short -ra --junitxml=$LOCAL_TMP/kagent-stage3-verification/full-acceptance.xml
```

Warnings integration mở rộng: 32 PytestWarning từ record_property/JUnit xunit2
trong scanner tests, 2 RuntimeWarning từ malformed-provider config fixture.
Không suppress warnings. Không sửa timeout, threshold, skip/xfail hoặc test
environment. Full configured suite tiếp tục ignore
`tests/integration/test_kagent_burp.py` theo pytest.ini (not run).

## Audit correction từ full run intermediate

Full run trên freeze 2 được dừng có chủ đích sau reproducer xác nhận 4 Stage 3
regressions: **2.348 passed, 4 failed, 10 skipped**, exit 2/KeyboardInterrupt,
344,57s pytest. Đây là **incomplete/intermediate**, không phải full-suite verdict.
Manifest trước/sau vẫn khớp freeze 2. Artifacts trong intermediate-freeze2/.

Bốn cases là test_live_file_skill_capability_after_each_review với range/sensitive
reviews và bound=True/False. Focused reproducer 4 failed / 2 passed. Root cause:
callback Stage 3 đã yêu cầu toàn bộ active-contract map giữ nguyên qua review,
trong khi FileReadTool là non-permissioned capability được dùng bởi mọi skill.
Đây là extra restriction sai semantics, không phải baseline/environment failure.

Fix production tối thiểu: bỏ exact contract-map equality. Existing ReviewGuard
vẫn recheck is_tool_allowed hiện tại, original owner và TurnOwner. Permissioned
tool từ retired contract vẫn bị chặn khi replacement không cho phép; nguồn file
non-permissioned giữ runtime semantics độc lập. Không sửa sáu tests cũ. Thêm
regression phase replacement trong lúc service permission review để chứng minh
current tool capability vẫn được recheck, không chỉ nhìn initial list.

Freeze 3: **714 files**, aggregate SHA-256
`e7b3ee86e1e8df20ced8dec9db3c873c7fa8222e0b631ad4955971e7cc6dd7a4`.
Targeted được mở rộng sang toàn tests/agent trước khi chạy lại integration và
full từ đầu. Không dùng bất kỳ kết quả source cũ nào làm final evidence.

## Correction planner recovery và browser version binding

Full intermediate trên freeze 3 dừng tại **6.064 passed, 2 failed, 12 skipped**,
34 warnings, exit 2/KeyboardInterrupt, 796,12s pytest; source unchanged. Không dùng
làm full result. Focused reproducer: 2 failed / 1 passed. Artifacts được giữ trong
intermediate-freeze3/.

Planner regression: khi canonical artifact của completed phase cần repair nhưng
playbook đó unavailable, phase guidance đã return None trước khi đến generic
validation/recovery còn hợp lệ. Fix chỉ cho phép đi tiếp existing owned work khi
phase đã có completion marker; phase chưa complete không bị bỏ qua. Generic
admission/probe/readiness và workflow completion gates giữ nguyên. Tests mới có
positive/negative completed markers và generic_startable flags; test bounded
probe cũ không đổi, không auto requeue hay tự chọn probe.

Browser test cũ mong mutation trực tiếp skill.tools tự mở capability. Semantics
đó được Stage 3 chủ đích thay bằng fingerprint binding. Test nay assert deny sau
edit, explicit manual reselect ở next request rồi allow; browser adapter vẫn
không dispatch và actual permission vẫn bắt buộc. Đây là cập nhật contract test,
không bỏ check browser/tool permissions hoặc chấp nhận stale capability.
Focused subsystem sau sửa: **119 passed**.

Freeze 4: **714 files**,
`6e31584a647dedca5e24181b9acbce32eed811147504c17b33ad98dd73341c2d`.
So baseline đầu Stage 3: **27 modified, 3 added, 2 deleted**, 684 files giữ nguyên
byte; expected-scope audit không có unrelated changes. Exact changed-file list và
Stage 3-only diff được cập nhật theo manifest này. Targeted toàn Agent và
responsibility integration mở rộng sẽ được chạy trước full mới.

## Binding audit — action-aware recheck snapshot

Reproducer ngoài repo trên freeze 4 dùng CoverageTool/CoverageStore thật:
permission review sửa parsed.args.action thành summary, đồng thời explicit load
Enumeration thay Recon. Registry vẫn dispatch immutable action=clear; callback
Agent đã đọc mutable args mới và nhầm xem action là permissionless summary.
Kết quả trước sửa: error rỗng, coverage_retained=0, trong khi current clear
capability=False. Đây là Stage 3 correctness bug, không phải baseline failure.

Fix tối thiểu: snapshot tool name và deepcopy args đồng bộ trước await; callback
is_tool_allowed và Registry dispatch cùng original tool identity/action. Không
đổi Registry gate, receipt, grant, digest hoặc actual review decision. Regression
bound/unbound, mutable args/tool-name đều assert không clear coverage, không
thay workflow/evidence/finding eligibility ngoài phase marker fixture rõ ràng.
Sau sửa: stale permission review bị chặn, coverage_retained=1; nhóm focused
admission/lifecycle/old security regressions **188 passed**.

Full trên freeze 4 bị dừng có chủ đích trước khi sửa. Không có final pytest
summary/JUnit mới: interruption gặp offline-boundary fixture teardown và XML
trong đường dẫn cũ vẫn byte-identical XML của freeze 3. Runner metadata lấy
counts cũ ở lượt đó là **invalid**, không dùng hoặc báo là counts của freeze 4.
Giữ raw log/invalid metadata cùng correction trong intermediate-freeze4/.
Runner nay xóa XML artifact cũ trước mỗi lượt, ghi junit_valid và không parse
stale counts. Không sửa offline fixture hay nới environment boundaries.

Freeze cuối sau binding fix: **714 files**,
`1013d5c2366faad3f3b49353f951f8e823772502251f9136c67049a88ca65b07`.
Targeted, integration mở rộng, pyright và full được chạy lại trên đúng source này.


## Tiếp quản verification ngày 18/10/2026

Session mới xác minh lúc 13:47 giờ Việt Nam: không còn tiến trình verification
đang chạy. Source thực tế khớp freeze cuối **714 files**,
`1013d5c2366faad3f3b49353f951f8e823772502251f9136c67049a88ca65b07`.
Integration thật trong /tmp kết thúc exit 0; JUnit mới có timestamp bắt đầu
06:32:49 UTC, được tạo sau integration-before.json và trước
integration-after/result.json. Counts JUnit khớp log: **5.746 passed, 1 skipped,
34 warnings**, 428,46s pytest, 432,177s wall. Cả before/after manifests khớp
freeze cuối. Đây là kết quả mới đã kiểm, không lấy từ bản docs cũ.

Bản integration/checks cũ trong docs được giữ tại
[superseded-pre-handover](verification-milestone-c/README.md#local-archive); chúng
không còn là evidence final. [Handover audit](verification-milestone-c/README.md#local-archive)
ghi hashes, timestamps và đối chiếu manifests cho targeted/integration/pyright.
[Full launch receipt](verification-milestone-c/README.md#local-archive) ghi exact
process/argv/cwd/environment, dùng artifact prefix mới full-acceptance để không
đọc nhầm full.xml của freeze cũ. Chỉ một full suite được khởi chạy; không dừng
hay chạy trùng lượt verification có sẵn.

Không sửa source/test/config khi tiếp quản. So baseline đầu Stage 3 vẫn là
27 modified, 3 added, 2 deleted; 684 files giữ nguyên byte, không có thay đổi
ngoài expected scope. Các intermediate freeze/corrections bên trên là lịch sử;
bảng verification hiện tại chỉ dùng source freeze cuối.


## Nghiệm thu Milestone C — kết quả cuối và phân loại failures

**Verdict: hoàn tất công việc verification/báo cáo, nhưng chưa đạt full-suite
gate. Không công bố toàn suite green hoặc hai failures đã được sửa.** Targeted
1.245 passed, responsibility integration 5.746 passed/1 skipped, Pyright
0 errors/0 warnings/0 informations; full 8.436 passed/2 failed/12 skipped,
79 warnings, exit 1. Các nhóm overlap, không cộng counts.

Full acceptance là một lượt chạy hoàn chỉnh trên đúng freeze cuối, không bị
interrupt, không chạy trùng verification cũ. Source trước/sau full và mọi focused
diagnostics đều khớp 714 files, SHA-256
`1013d5c2366faad3f3b49353f951f8e823772502251f9136c67049a88ca65b07`.
Python 3.14.4, pytest 9.1.1 từ venv-linux có sẵn. Tất cả log/JUnit/results và
manifests quan trọng đã được lưu trong docs/verification-stage3; không phụ thuộc
chỉ vào /tmp khi bàn giao.

| Failure trong full | Observed evidence | Phân loại / giới hạn kết luận |
| --- | --- | --- |
| `tests/security/test_validation_finalization.py::test_owned_stop_without_declaration_records_unknown_not_false[stall]` | `ex.status=timeout`, expected completed; fixture có timeout 10s không đổi; JUnit ghi 10,151s | Timeout trong full run, chưa tái hiện focused; root cause chưa xác định. Không đủ evidence quy cho Stage 3 hoặc khẳng định đây là baseline/environment-only. Vẫn là giới hạn nghiệm thu chưa giải quyết. |
| `tests/ui/test_light_theme_app.py::test_light_first_terminal_frame_uses_selected_theme` | RGB assertion có `paints=[]` khi COLORTERM unset; tái hiện focused; pass khi child diagnostic process có COLORTERM=truecolor | Giới hạn terminal-capability phù hợp Stage 1/2, không phải patch đã fix. Test/recording driver/palette/render helpers giữ nguyên so baseline đầu Stage 3; app Stage 3 chỉ bỏ unused ToolingProfile import. |

Diagnostics sau khi full đã kết thúc:

| Nhóm | Passed | Failed / errors | Skipped / xfailed | Exit | Pytest time |
| --- | ---: | ---: | ---: | ---: | ---: |
| Hai cases fail + session_save, môi trường gốc | 2 | 1 / 0 | 0 / 0 | 1 | 6,01s |
| Cùng ba cases, chỉ child process COLORTERM=truecolor | 3 | 0 / 0 | 0 / 0 | 0 | 7,14s |
| Toàn validation_finalization + trusted_scanner_admission đứng ngay trước trong full, môi trường gốc | 214 | 0 / 0 | 0 / 0 | 0 | 23,17s |

Stall case pass trong integration (3,325s), focused gốc (4,129s), focused
truecolor (5,084s), và predecessor/module context (3,756s). Những pass này chỉ
giới hạn phạm vi tái hiện, không thay thế timeout của full run hoặc chứng minh
nguyên nhân do tải/GC/terminal/permission. Archival session của full timeout còn
attempt active, chưa có validation result; không coi đó là closure thành công.
Chỉ lưu metadata tối thiểu không có traffic/credentials trong
[stall-full-context.json](verification-milestone-c/README.md#local-archive).
`session_save` pass trong full và cả hai diagnostics; không claim đã fix
historical timing limitation.

Evidence và exact commands:
[failure classification](verification-milestone-c/README.md#local-archive),
[focused gốc](verification-milestone-c/README.md#local-archive),
[focused truecolor](verification-milestone-c/README.md#local-archive),
[predecessor/module context](verification-milestone-c/README.md#local-archive).
Không tăng timeout/threshold, không sửa test/skip/xfail hoặc suppress warning;
không chạy lại full với truecolor để thay verdict. Không có reproducer focused
chứng minh lỗi production Stage 3 cần patch trong session tiếp quản.

Full warnings: **77 PytestWarning** từ record_property/JUnit xunit2 và
**2 RuntimeWarning** từ malformed-provider fixture. 12 skips giữ điều kiện repo:
9 Java gate cases cần cached offline WAR/Tomcat; 1 prepared-existing-lab operator
case; 1 live system opt-in; 1 live mutating-tool characterization opt-in.
Full tiếp tục ignore `tests/integration/test_kagent_burp.py` theo pytest.ini.
Exact skip IDs/reasons nằm trong full-acceptance-result.json. Không chạy live
model/target hoặc lấy skips làm evidence pass cho các đường đó.

Kiểm tra bàn giao cuối: git diff --check sạch; git status khớp snapshot khi
tiếp quản; stage3.diff khớp diff tái tạo từ baseline-source từng byte; preservation
vẫn 27 modified/3 added/2 deleted và 684 files giữ nguyên. Không đổi source,
tests, config, permissions hoặc durable stores. Chỉ cập nhật report/evidence
trong docs; không reset/clean/restore, install package, stage, commit hoặc push.
Không chạy Scenario 3 Whole-target, benchmark Stage 2 độc lập hay Stage 4.

Milestone C dừng tại verdict này. Nếu cần full green, timeout validation
finalization cần reproducer xác định nguyên nhân trước khi sửa source; UI
truecolor vẫn là giới hạn terminal đã phân loại.


## Final Corrections — kết quả mới nhất

Source freeze mới: 715 files, SHA-256
`76168e98a362ef43f4636dc745fc356cfa57a425e59f89ec842b5b174bce653c`.
Focused 118 passed; targeted Stage 1/2/3 1.296 passed; responsibility integration
(có Agent) 6.729 passed/1 skipped/34 warnings; pyright 0 errors/0 warnings.
Full configured suite hoàn tất 8.490 passed/12 skipped/79 warnings, 0 errors,
exit 0, 1.146,89s pytest; checksums trước/sau/current khớp. Đây là evidence mới,
không tái sử dụng kết quả trên freeze 1013d5c… hoặc freeze correction trung gian.

A/stall pass trong full mới (3,597s) nhưng root cause timeout lịch sử vẫn unknown;
không có patch finalization. B sửa harness theo terminal capability, giữ RGB
assertion. C/S1 sửa auto-target inference với 51 regressions. M2 tái hiện sync
goal/dirty revision nhưng chưa chứng minh vi phạm contract; không refactor.
Chi tiết exact commands, JUnit, skips và preservation ở
[báo cáo mới](recon-milestone-c-final-corrections.md).
Dừng sau verification, không chạy Scenario 3, không commit/push.
