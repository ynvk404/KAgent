# Đồng bộ tests/fixtures theo contract — 21/10/2026

Phạm vi là tests, fixtures và tài liệu. Đã đọc `AGENTS.md`, audit tại
`/tmp/kagent-full-audit-20261021-01lo4mwp/AUDIT.md`, source và tests liên quan.
Không thay đổi production logic, refactor workflow, Planner fix hoặc cancellation
fix có sẵn. Không thêm skip/xfail hoặc thay đổi giới hạn bảo mật.

Trạng thái hiện hành: theo quyết định của operator, đã xóa đúng năm tests chỉ
dành cho `setup.sh`/`doctor.sh` bị loại bỏ có chủ đích trong commit `ce05271`.
Chúng không còn thuộc collection và không được tính là PASS, FAIL hoặc SKIP.
Kết quả trước khi xóa chỉ được giữ ở phần lịch sử, không phải kết quả hiện tại.

## Từng test được cập nhật ở lượt đồng bộ trước

Tên trong bảng là tên sau cập nhật; số case bao gồm parametrization.

| File / test | Lý do và contract được kiểm tra | Kết quả focused |
|---|---|---|
| `agent/test_decision.py::test_terminal_whole_target_planner_does_not_recommend_extra_work` | Dùng `completed`/`not_applicable` với phases hoàn tất. `blocked` không phải terminal toàn cục. | PASS, 2 case |
| `agent/test_decision.py::test_blocked_whole_target_preserves_results_but_allows_independent_recovery` (mới) | Goal `in_progress`/`blocked`/`deferred`: không validate lại Candidate có `preserve_result`; vẫn chọn đúng Candidate độc lập có `start_validation`. Context không bị mutate. | PASS, 6 case |
| `agent/test_decision.py::test_blocked_whole_target_can_repair_an_incomplete_discovery_phase` (mới) | Artifact recon bị thiếu vẫn cần recovery dù phases đã từng hoàn tất và workflow đang blocked. | PASS, 1 case |
| `ui/test_app.py::test_main_shell_regions_have_distinct_native_panels` | Overview nằm trong `overview_scroll`, wrapper nằm trong Transcript panel. Giữ kiểm tra border/panel và thêm kiểm tra transcript/input còn chỗ ở terminal thấp. | PASS |
| `ui/test_minimal_presentation.py::test_workflow_overview_stays_separate_from_inventory_and_blocked_outcome` | Thay tên cũ `test_workflow_overview_and_inventory_use_authoritative_milestone_style`. Chọn dòng theo nội dung, yêu cầu inventory thật và đủ counts/endpoint; inventory là info/accent, blocked là warning. Overview giữ trong facts, không lặp trong transcript. | PASS |
| `ui/test_http_permissions.py::test_slash_yolo_activates_http_without_manual_grant_and_honors_revoke` | Fixture Agent và HTTPTool dùng chung Target thật. Warning hiện hành phải nêu scope, change/delete và deny/revoke/limits. Giữ nguyên assertions revoke chặn gửi, retry, số request, không hỏi quyền lại và xóa grant YOLO khi off. | PASS |
| `ui/test_presentation_layout_audit.py::test_status_badge_stays_visible_with_long_runtime_metadata` | Cấp busy/YOLO/model từ app state và token estimates từ fake Agent, qua `apply_yolo`; tránh recompute ghi đè widget fixture. Giữ kiểm tra AutoApprove trên compositor, cell width và viewport. | PASS, 6 case: 160×40 / 100×30 / 48×20, idle/busy |
| `runtime/test_paths.py::test_project_paths_are_stable_from_nested_working_directories` | `marked_project` xóa riêng override môi trường để kiểm tra marker discovery. Giữ assertions canonical root/artifact/coverage. | PASS |
| `runtime/test_paths.py::test_stores_write_to_project_root_not_nested_cwd` | Cùng fixture trên; vẫn yêu cầu stores ghi ở project root và không tạo `.kagent` dưới nested cwd. | PASS |
| `runtime/test_paths.py::test_legacy_nested_project_data_remains_readable` | Cùng fixture trên; vẫn yêu cầu legacy read fallback và canonical write path. | PASS |
| `runtime/test_paths.py::test_user_data_root_is_independent_of_cwd` | Dùng fixture đã cô lập override; vẫn kiểm tra user root độc lập với cwd. | PASS |
| `runtime/test_paths.py::test_project_root_environment_override` | Giữ kiểm tra override có hiệu lực; thêm kiểm tra explicit `start` ưu tiên hơn override. Không vô hiệu override trong runtime. | PASS |
| `security/test_browser_local_protocol.py::test_real_persistent_owner_permission_and_cleanup_in_private_namespace` | Sau `--tmpfs /tmp`, bind lại đúng source root read-only để helper vẫn đọc được khi checkout nằm trong `/tmp`. Giữ `--unshare-net`, tmpfs, kiểm tra deployment và toàn bộ permission/revocation/cleanup assertions. | PASS cả ngoài và trong `/tmp` |
| `benchmarks/test_scenario1_closure.py::test_cancellation_during_closure_save_joins_without_claiming_persistence` | Controller release writer trước khi chờ task kết thúc, xác nhận cancellation vẫn đợi writer. Writer thất bại có kiểm soát; phải nhận `CancelledError` với cause chính xác, không claim persistence, không task rơi rớt hay HTTP/assistant output mới. Giữ production cancellation fix. | PASS |

`ui/test_overview.py` và các regression Planner/cleanup/cancellation có sẵn được
chạy lại trong responsibility group, không sửa để thay đổi contract.

## Năm tests setup/doctor đã loại bỏ có chủ đích

`git show ce05271 -- scripts` xác nhận scripts được xóa trước baseline audit.
Đã kiểm tra `pyproject.toml`, `requirements.txt`, CLI/help và scripts hiện có.
Package metadata/pip cung cấp đường cài đặt; CLI startup kiểm tra readiness của
invocation. Hai scripts không còn thuộc supported contract; theo yêu cầu hiện
tại của operator, không cần tạo chức năng thay thế cho các tests chỉ dành cho
chúng. Không khôi phục scripts hoặc đổi production code.

Đã xóa toàn bộ `tests/runtime/test_toolkit_scripts.py`: file chỉ chứa năm tests
dưới đây, không có test runtime còn dùng hoặc fixture/helper dùng chung.
`REPO_ROOT`, `SCRIPTS_DIR`, `ALL_SCRIPTS`, imports và fake setup/venv nội bộ chỉ
phục vụ năm tests này nên được xóa cùng file. Đối chiếu AST với JUnit của lượt
trước xác nhận đây chính xác là năm cases từng FAIL do missing scripts.

| Node ID đã xóa dưới `tests/runtime/test_toolkit_scripts.py::` | Phạm vi đã nghỉ dùng |
|---|---|
| `test_all_scripts_syntax` | Existence/syntax chỉ của hai scripts |
| `test_doctor_read_only_and_pass` | Health output và secret-output assertion chỉ cho doctor đã xóa |
| `test_setup_check_only` | Chế độ check-only của setup đã xóa |
| `test_doctor_reuses_setup_validation_and_propagates_failure` | Delegation doctor→setup và fake venv riêng |
| `test_setup_check_only_rejects_missing_venv_without_creating_it` | Missing-venv behavior chỉ của setup đã xóa |

Các tests bảo mật/permission/secret protection cho runtime đang dùng được giữ
nguyên, gồm redactor, sensitive paths, execution policy, private-host gate và TUI
credential safeguards. Không di chuyển hoặc bỏ assertions trong các tests đó.
README không còn hướng dẫn/chờ replacement cho hai scripts; references còn lại
trong tài liệu chỉ ghi lịch sử loại bỏ. Không chỉnh `.kagent/`, sessions,
artifacts hoặc caches cũ để xóa lịch sử.

## Kiểm tra sau khi loại bỏ tests

Logs/JUnit mới ở
`/home/khainguyen/.cache/kagent-script-tests-retirement-pgnb4gjk/logs/`.
Lượt này dùng snapshot mới nên file đã xóa không còn sót trong source snapshot.

| Lượt thực tế sau khi xóa | PASS | FAIL | SKIP | Ghi chú |
|---|---:|---:|---:|---|
| Focused offline | 230 | 0 | 0 | Runtime và security/secret/permission controls; 9,83 s pytest |
| Broader regression | 3.530 | 1 | 0 | 3.531 cases; giảm đúng 5 cases; 417,94 s pytest |
| UI responsiveness recheck | 11 | 0 | 0 | Toàn file, giữ nguyên ngưỡng timing/assertions; 8,30 s pytest |
| Default suite collection | — | — | — | 9.042 cases, 0 collection errors; không phải test execution |
| Pyright bundled 1.1.411 | PASS | 0 errors | 0 warnings | 680 files, chặn mạng, dùng bản có sẵn trong venv-linux |
| `git diff --check` | PASS | | | Bao gồm báo cáo untracked |

Các lượt focused/broader/recheck có overlap, không cộng chúng thành số cases
duy nhất. Default collection không phải một lượt execution của full suite.

Chỉ thay đổi ba files trong follow-up này: xóa test file trên, cập nhật
`readme.md` và báo cáo này. Không thêm ignore/deselection/skip/xfail để loại tests.
Production, refactor workflow, Planner cleanup fix, cancellation fix và các
tests/dirty/untracked khác được giữ nguyên.

Manifest trước follow-up có 4.753 files; sau xóa còn 4.752. Chỉ ba files nêu
trên thay đổi, 4.750 files còn lại giữ nguyên hash/mode. Cả 2.664 files runtime
dưới `.kagent/`, `artifacts/`, `sessions/` và Git index không đổi; production
không có thay đổi mới. Đối chiếu được lưu ở `preservation-final.json` cạnh logs.
Không cài package trong follow-up này; pyright chạy đúng bản bundled 1.1.411
trong network namespace không có kết nối ra ngoài.

So sánh từng node ID của JUnit broader cũ/mới xác nhận chỉ thiếu đúng năm tests
đã liệt kê, không thêm/mất case nào khác (`broader-comparison.json`). Toàn nhóm
runtime hiện có **363 PASS, 0 FAIL, 0 SKIP**, so với 368 cases trước khi xóa.
Hai warnings của test malformed custom-provider config vẫn là controls có chủ đích.

Broader có một failure riêng ở
`tests/ui/test_persistence_responsiveness.py::test_async_wait_control_keeps_textual_responsive[finding_post_read]`:
heartbeat gap 127,37 ms vượt ngưỡng 120 ms. Timeline cho thấy gap lớn nhất nằm
trước khi operation bắt đầu; Esc delivery 0,70 ms, 20 ticks trong operation và
4 recovery ticks. Đây là async-wait control; source test và production không
đổi trong follow-up. Chưa có bằng chứng quy failure này cho thay đổi production
hay việc xóa setup/doctor tests. Giữ nguyên failure và đo lại toàn file để kiểm
tra khả năng tái hiện, không tăng threshold, skip/xfail hoặc sửa runtime.
Recheck toàn file đạt **11 PASS, 0 FAIL, 0 SKIP**. Case nêu trên có heartbeat gap
21,11 ms, Esc delivery 2,98 ms, 21 operation ticks và 5 recovery ticks. Failure
broader không tái hiện trong recheck; nguyên nhân gián đoạn timing vẫn chưa được
xác định. Kết quả recheck không thay thế hoặc xóa một FAIL đã ghi ở broader.

## Lịch sử kiểm tra trước khi loại bỏ tests

Các bảng dưới đây ghi đúng kết quả đã chạy ở lượt đồng bộ trước. Năm FAIL cũ là
lịch sử của tests nay đã bị xóa; không cộng chúng vào PASS/FAIL/SKIP hiện hành.

Logs, commands đầy đủ và JUnit được giữ tại
`/home/khainguyen/.cache/kagent-test-contract-85q7_ie4/logs/`.
Các lượt dưới đây là selections có chủ đích, không phải full-suite mới và không
cộng các recheck vào một con số test duy nhất.

| Lượt | PASS | FAIL | SKIP | Ghi chú |
|---|---:|---:|---:|---|
| Baseline focused trước sửa | 1 | 10 | 0 | Tái hiện Planner/TUI/badge failures trong audit |
| Focused đầu | 171 | 3 | 0 | Warning `/yolo` cũ; hai Browser deployment checks gặp UID mapping của harness |
| Focused cuối | 172 | 0 | 0 | `focused-final.xml`; bao gồm 12 regression checkpoint writer và 12 Planner cleanup có sẵn |
| Browser bằng UID gốc, snapshot ngoài `/tmp` | 2 | 0 | 0 | `native-browser.xml`; mock extension, child network namespace |
| Browser bằng UID gốc, snapshot trong `/tmp` | 2 | 0 | 0 | `native-tmp-browser.xml`; exercise đúng điều kiện lỗi của audit |
| Paths với `KAGENT_PROJECT_ROOT` từ harness | 6 | 0 | 0 | `override-paths.xml`; cả override và marker discovery vẫn hoạt động |
| Broader offline | 3.531 | 5 | 0 | `broader.xml`; 3.536 cases, không ERROR/deselection; 474,80 s pytest |
| Pyright bundled 1.1.411, config `venv-linux` | PASS | 0 errors | 0 warnings | 681 files; `pyright-bundled.json` |
| `git diff --check` | PASS | | | Bao gồm kiểm tra riêng báo cáo mới bằng no-index |

Broader của lượt trước có năm FAIL ở chính các tests nay đã bị xóa, không phát
hiện production bug mới trong selection đó. Hai RuntimeWarning đến từ test malformed
custom-provider config có chủ đích; không phải pyright diagnostics. Các controls
whole-target cleanup/Planner và checkpoint cancellation có sẵn đều PASS.

| Nhóm trong broader selection | PASS | FAIL | SKIP |
|---|---:|---:|---:|
| agent (toàn nhóm) | 1.099 | 0 | 0 |
| ui (toàn nhóm) | 1.277 | 0 | 0 |
| runtime (toàn nhóm) | 363 | 5 | 0 |
| state (toàn nhóm) | 494 | 0 | 0 |
| benchmarks (file được chọn) | 55 | 0 | 0 |
| security (files được chọn) | 173 | 0 | 0 |
| integration (files được chọn) | 70 | 0 | 0 |

Broader selection:

```text
tests/agent
tests/ui
tests/runtime
tests/state
tests/benchmarks/test_scenario1_closure.py
tests/security/test_direct_mode_completion_regressions.py
tests/security/test_checkpoint_cancellation.py
tests/security/test_http_grants.py
tests/security/test_http_yolo_session.py
tests/security/test_private_host.py
tests/security/test_yolo_memory_transport.py
tests/security/test_yolo_results_resume.py
tests/integration/test_whole_target_workflow.py
tests/integration/test_candidate_validation_recovery.py
tests/integration/test_workflow_checkpoint_artifacts.py
tests/integration/test_scope_event_lifecycle.py
```

Dùng interpreter hiện có `venv-linux/bin/python`, `pytest -p
tests.system.offline_suite -q -ra --tb=short`, JUnit và cache/basetemp riêng.
`pytest.ini` giữ nguyên; không tăng ignore hay nới production sandbox.
README cũng ghi đúng default exclusion của file Burp và live opt-ins, không còn
gọi default collection là toàn bộ suite không có ngoại lệ.
Focused/broader chạy trên snapshot riêng trong mount/network namespace, chỉ có
loopback, UID 1000 và bỏ capabilities sau mount. Repo gốc read-only, `~/.kagent`
được che bằng scratch, live opt-ins/credentials được gỡ khỏi test environment.
`PYTHONDONTWRITEBYTECODE=1` ngăn viết cache vào repo/venv gốc.

Browser chạy bằng UID gốc để xác minh root-owned deployment trước khi vào
sandbox riêng của từng test. Không patch ownership/deployment checks để vượt
user-namespace mapping. Dùng mock extension, không Chrome/tab/live target.
TUI/Agent chỉ được exercise bằng headless fixtures và offline model/transport
doubles của tests; không khởi động CLI/Agent/TUI tương tác. Không gọi provider API.

Pyright chạy bundled version và chặn network bằng namespace:

```sh
unshare --user --map-current-user --keep-caps --net -- \
  setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
  env PYTHONDONTWRITEBYTECODE=1 PYRIGHT_PYTHON_FORCE_VERSION=1.1.411 \
  PYRIGHT_PYTHON_USE_BUNDLED_PYRIGHT=1 PYRIGHT_PYTHON_IGNORE_WARNINGS=1 \
  venv-linux/bin/pyright --outputjson
git diff --check
git status --short
```

Lỗi thao tác ở lượt pyright đầu: cờ `PYRIGHT_PYTHON_FORCE_VERSION=latest` đã khiến
wrapper tải npm pyright 1.1.414 vào `~/.cache/pyright-python/1.1.414`, trái yêu cầu
không cài package. Đã dừng lượt đó và chạy lại bằng bản bundled 1.1.411 đã có,
chặn mạng; không dùng lượt 1.1.414 làm kết quả validation. Không đổi dependencies
hoặc venv của repo; cache mới được giữ nguyên, không tự xóa/hoàn nguyên dữ liệu.

## Preservation của lượt đồng bộ trước và giới hạn

Ở lượt đồng bộ trước: 4.752 files ban đầu, chỉ 9 tests/docs có sẵn thay
đổi và thêm báo cáo này; 4.743 files còn lại giữ nguyên hash/mode, gồm production,
dirty/untracked khác và sessions/artifacts. Index giữ nguyên hash. Kết quả đối
chiếu cuối lưu ở `preservation-final.json` cạnh thư mục logs bên trên.
Toàn bộ 2.664 files dưới `.kagent/`, `artifacts/` hoặc `sessions/` được kiểm tra
không đổi. Diff check của file mới dùng no-index trả 1 vì có file mới, không có
whitespace diagnostics; tracked `git diff --check` trả 0.
Không commit/push, reset, stage, restore scripts hay chạy cleanup.

Không chạy lại toàn bộ repository suite, live-provider tests, live target,
Docker/lab reset hoặc interactive TUI. Kết quả full audit cũ không được đổi tên
thành kết quả của lần đồng bộ này. Phần setup/doctor đã được giải quyết bằng
retirement theo yêu cầu hiện tại; legacy workflow import compatibility được
audit nêu trước đó không được thay đổi trong phạm vi tests/docs này.
