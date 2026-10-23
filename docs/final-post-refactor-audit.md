# FINAL POST-REFACTOR AUDIT & LEGACY CLEANUP

Ngày kiểm tra: 2026-10-23. Phạm vi: runtime hiện tại sau Runtime Simplification
và CWE Local Catalog; không thiết kế lại kiến trúc.

**READY — Không còn blocker đã biết đối với việc chạy Whole-target lan-05
qua runtime hiện tại và profile v4.**

## 1. Trạng thái tiếp nhận và bảo toàn dữ liệu

HEAD tiếp nhận: `49ee3b3`. Worktree ban đầu có hai tệp modified:
`scripts/experiment_profile.py` và `tests/runtime/test_experiment_profile.py`.
Sửa lỗi import adapter CWE đã retire và các kiểm tra exact legacy allowlist
trong hai tệp này được giữ; audit bổ sung thay đổi trên cùng tệp.

Đã đọc AGENTS.md, thiết kế/triển khai runtime simplification, tài liệu CWE,
contract skill và implementation/tests liên quan. Không reset, restore, stage,
commit, push, cài package, chạy cleanup dữ liệu hoặc tạo profile thực nghiệm thật.
Đã fingerprint 2.794 tệp lịch sử dưới `experiments/scenario3`, `.kagent` và
`artifacts` để đối chiếu trước/sau; không đưa nội dung traffic/secrets vào báo cáo.
Đối chiếu cuối: **0 changed, 0 deleted, 0 new files** trong các roots dữ liệu này.
Config SHA-256 và hai nguồn intelligence backup của plan ban đầu/cuối cũng
không đổi. Thư mục run/profile lan-05 vẫn chưa được tạo.

Runtime hỗ trợ năm playbook tích hợp: Recon, Enumeration, Input Analysis,
SQL Injection và XSS. Các lớp khác giữ shared workflow/generic route và khả năng
cài custom validator. Native HTTP/TCP/Content Discovery, Shell trực tiếp, Burp,
Finding, Session/Continue, compaction và Local CWE còn hoạt động. Worker/broker,
typed Nmap/ffuf, integrated Browser MCP và CWE MCP execution đã bị retire.

## 2. Lỗi thực sự và nguyên nhân

| Vấn đề | Nguyên nhân / xử lý |
| --- | --- |
| Shell có thể treo quá timeout sau khi process leader thoát | Child giữ pipe mở và bỏ qua TERM; code chỉ chờ `proc.wait()` trong deadline. Deadline nay bao gồm process và hai pipe readers; TERM/KILL vẫn áp dụng cho process group đã tạo. |
| Hủy Shell lần thứ hai có thể cắt ngắn cleanup | Cancellation ngắt phần thu hồi trước khi pipes/process group được drain. Cleanup có task sở hữu riêng, shield/join trước khi trả cancellation và giải phóng receipt. |
| Exact-ID search của Local CWE bị từ chối | Parser hỗ trợ `CWE-N` nhưng validator enrichment cũ cấm mọi `exact_id_match`. Nay chỉ chấp nhận cờ khi ID khớp chính query đã chuẩn hóa; query khác/thiếu vẫn bị từ chối. Không thay lựa chọn automatic/manual CWE. |
| Legacy headless shell preset tham chiếu `policy.worker` không còn tồn tại | Nhánh cũ dựa trên isolated executor và có thể consume run marker trước khi crash. Đã bỏ adapter khôi phục quyền; preset được từ chối rõ ràng trước prepare/launch, giữ policy Headless hiện tại. |
| Experiment plan không pin mã Local Catalog | `runtime_files` chỉ bao phủ `src/`; parser/contract trong `components/` nằm ngoài kiểm tra. Thêm `component_files`, kiểm tra trước/sau snapshot và verify; cấm run-dir chồng lên `components`. |
| System prompt vẫn quảng bá Worker/broker/isolated MCP | Đoạn controller policy được append cho cả Full và Compact còn mô tả executor cũ, trái với capability hiện tại. Đã sửa thành direct subprocess/account rights, cwd không phải OS sandbox, không có native HTTP attestation và không host fallback cho MCP/plugins. |
| Hướng dẫn Input Analysis còn yêu cầu scanner job summaries/readers/triage | Producers và actions này đã xóa. Đã thay bằng hướng dẫn native observations và opaque historical metadata, giữ bounds và chuẩn evidence. |
| Standalone capture help trỏ tới module không tồn tại | Sửa module invocation cũ thành `src.browser.mcp_server`; nói rõ server phục vụ external MCP client, không quảng bá process MCP execution trong KAgent. |

Hai lỗi Shell, lỗi exact-ID CWE và system prompt có regression tái hiện thất bại trước sửa.
Các lỗi fixture được tách khỏi lỗi production; không thay runtime để nhận HTTP
context sai path, baseline giả hoặc validator tích hợp đã xóa.

## 3. Production files sửa/xóa

| Tệp | Thay đổi |
| --- | --- |
| `src/tools/execution/shell.py` | Sửa timeout/cancellation/descendant cleanup; bỏ identity rewrite shim không có runtime caller. |
| `src/findings/cwe_enrichment.py` | Bind exact-ID flag với query; bỏ MCP text-envelope parser không còn caller production. |
| `scripts/experiment_profile.py` | Giữ incoming fix; pin component sources và retire isolated headless preset. |
| `scripts/run_experiment.sh` | Help phản ánh preset đã retire. |
| `components/cwe_mcp/{launch,pack_runtime,server,setup}.py` | Xóa launcher, packaging, stdio server và installer dependency cũ; Local Catalog không gọi chúng. |
| `components/cwe_mcp/{contract,__init__}.py` | Giữ corpus identity/model/parser contracts; bỏ MCP tool schemas, ZIP acquisition hash và serializer không còn dùng. |
| `src/cli/runtime.py` | Bỏ danh sách MCP sessions luôn rỗng và teardown không có producer; giữ watchers/reloader/Burp cleanup. |
| `src/tools/mcp/integration.py` | Bỏ dead name-generation, timeout/size constants và result-formatting helpers; giữ fail-closed APIs và text reader còn dùng bởi UI. |
| `src/tools/execution/plugin.py` | Bỏ process imports/resource constants không còn dùng; giữ từ chối host fallback. |
| `src/permission/permission.py`, `src/tools/common/{types,registry}.py` | Bỏ Browser grant interface/callbacks không còn producer. Giữ permission gate, HTTP grants, cache hints, deny/revoke, lifecycle và invocation receipts. |
| `src/ui/bridges/perm_bridge.py`, `src/ui/widgets/permission_modal.py` | Bỏ grant presentation của integrated Browser đã xóa; giữ HTTP/capture/file/sensitive-path approvals. |
| `src/permission/runtime/execution.py` | Sửa comment worker validation thành local catalog validation. |
| `src/agent/system_prompt.py` | Sửa controller policy của cả hai prompt profiles, giữ scope/deny/revoke/budget/prerequisite rules. |
| `src/permission/network/transport.py` | Bỏ mô tả ResponseDiagnostics như dữ liệu do broker cũ cung cấp. |
| `src/browser/{mcp_server,capture_mcp}.py` | Sửa help của standalone capture servers; không thêm browser execution. |
| `skills/web-input-analysis/SKILL.md` | Bỏ workflow scanner đã retire, giữ scope/evidence/stop rules. |

## 4. Tests, fixtures và cấu hình kiểm thử

| Tệp / nhóm tệp | Lý do sửa/xóa |
| --- | --- |
| `tests/security/test_shell_descendant_cleanup.py` | Thêm bốn cases: timeout, cancellation, repeated cancellation và abort sau leader exit; kiểm tra child dừng, pipe EOF và task settle. |
| `tests/agent/test_systemprompt.py` | Hai regression kiểm tra capability/isolation/attestation và permission invariants trong controller policy Full/Compact. |
| `tests/cwe/test_server.py` → `tests/cwe/test_catalog.py` | Chuyển các invariants parser, pin, XML/DTD, bounds, lexical ranking, metadata sang local calls. Xóa launcher/server-only error/envelope cases; giữ direct query deadline và duplicate-manifest rejection. |
| `tests/cwe/test_enrichment.py`, `test_finding_review.py` | Thay transport wrapper tests bằng payload checks; thêm exact-ID query/binding và manual review với evidence. Bỏ wrapper/duplicate-envelope tests chỉ phục vụ MCP đã retire. |
| `tests/runtime/test_experiment_profile.py`, `test_experiment_reviewed_request.py` | Giữ incoming allowlist tests; thêm stale component checks ở prepare/verify/during-copy và refusal của retired preset trước run marker. |
| `tests/tools/test_related_request_associations.py` | Cài explicit custom test validators cho lớp không còn shipped expert. Giữ toàn bộ duplicate/atomicity/redaction/ownership assertions. |
| `tests/state/test_manual_metadata_compatibility.py` | Custom access-control validator cho fixture; historical operator reports không chứa automatic annotation của phiên hiện tại. Giữ accepted-result, session/PDF round-trip và không rewrite lịch sử. |
| `tests/helpers/scenarios.py` | Thay observation của document làm endpoint request context bằng exact document attribution; không bỏ provenance hoặc mở rộng scope. |
| `tests/helpers/system_runtime.py` | Bỏ teardown gọi `scanner_runtime` đã xóa, giữ drain Agent/background tasks và receipt/idle assertions. |
| `tests/benchmarks/test_scenario1_closure.py` | Fixture Whole-target phải cài đủ ba discovery/analysis skills trước completion gates. |
| `tests/ui/test_candidate_recovery_contract.py` | Dùng capture baseline thật, cùng workflow/target/engagement, thay invented baseline; giữ sibling không recover original issue. |
| `tests/ui/test_c6_permission_transcript.py` | Kiểm tra diagnostic Shell theo metadata contract; raw legacy error text không thành process facts, unresolved issue vẫn giữ. Bỏ Browser grant-only parameter. |
| `tests/ui/{test_minimal_presentation,test_permission_review,test_theme,test_non_native_permission_presentation}.py` | Xóa Browser grant-only cases; chuyển các checks generic preview/theme còn có giá trị sang current requests. Giữ scroll, secret redaction và approval callback assertions. |
| `tests/tools/test_tools_registry.py` | Plugin unavailable bị chặn trước review/spawn; giữ approval assertions cho Shell/file/HTTP còn được hỗ trợ. |
| `tests/tools/test_shell.py` | Xóa tests chỉ kiểm tra identity rewrite shim, giữ exact native command/subprocess, timeout, output và platform dispatch tests. |
| `tests/integration/test_discovery_service_policy.py` | Bỏ tham số Nmap không còn tác dụng và các bản lặp tương ứng; giữ scope, private-host, native budget và denied/revoked assertions. |
| `tests/integration/test_mcp_integration.py`, `tests/tools/test_plugin.py` | Bỏ dead FakeSession/name-collision/process helpers; giữ permission metadata và fail-closed responsibility tests ở các suite liên quan. |
| `tests/runtime/test_cli_main.py`, `test_cleanup_script.py` | Bỏ mock MCP teardown không có producer; fixture protected source dùng catalog thay server đã retire. |
| `tests/agent/{test_parallel_cancellation,test_tool_result_offloading}.py`, `tests/security/{test_observation_publication,test_repair_runtime,test_cli_repair_entrypoint}.py` | Bỏ imports, fake MCP server program và fake worker attribute không còn caller; không bỏ security tests đang dùng. |
| `tests/security/test_action_approval.py`, `tests/system/test_happy_variants.py`, `tests/ui/test_presentation_layout_audit.py` | Sửa mô tả subprocess boundary; bỏ PID loop luôn rỗng của scanner variant và thay obsolete display sample. |
| `tests/skills/test_web_input_analysis.py` | Contract native discovery / historical metadata thay scanner workflow đã retire. |
| `tests/system/offline_matrix.txt`, `tests/system/README.md` | Thay sáu đường dẫn test không tồn tại bằng trách nhiệm native/direct/CWE hiện tại. |
| `pytest.ini` | Bỏ ignore vô điều kiện của Burp extension tests. Cả 31 cases chạy offline với Java/Swing stand-ins/loopback; full suite nay thu thập chúng. |
| `AGENTS.md`, `readme.md` | Sửa source map, danh sách supported playbooks và mô tả historical worker outputs. |

Không thêm skip/xfail để che failure, không nới security assertions và không
khôi phục expert playbook/scanner/Worker/browser executors đã bị loại bỏ. Các
regression process-group có POSIX platform guard; chúng không skip trên Linux.

## 5. Dependencies và compatibility được giữ

- `mcp`: standalone capture stdio servers còn được hỗ trợ và có tests; không
  đồng nghĩa KAgent mở process MCP sessions hoặc browser automation.
- `components.cwe_mcp.catalog`, `contract`, `manifest.json` và package name:
  parser/identity hiện tại của Local Catalog; provenance/schema pin được giữ.
- `cwe_mcp_deployment_path`: compatibility config key chọn data manifest/XML,
  không import/launch code từ deployment.
- MCP/plugin configuration và fail-closed direct-call surfaces: không xóa cấu
  hình đã lưu, không tự fallback host execution. `extract_mcp_text` còn caller UI.
- Scanner/source/provenance metadata readers và hai collection lịch sử bounded:
  round-trip Session/Continue; không tạo progress, coverage, capabilities hay findings.
- `BrokerHTTPMetadata`/archival presentation readers: đọc runtime history,
  không khởi tạo HTTP broker hay cấp attestation mới.
- `benchmarks/scenario1/core/worker.py`: worker process của benchmark runner
  hiện hành, không phải Worker/Bubblewrap executor đã retire. Giữ metric/export
  readers và tests của benchmark này.
- `requests`/`httpx`, YAML, Rich/Textual, watchdog và ReportLab còn caller runtime;
  filelock/Pygments là enhanced dependencies còn dùng. Không cài/gỡ dependency.
- Historical cleanup paths và các báo cáo audit cũ được giữ; tên có `worker`,
  `browser` hoặc `scanner` không phải bằng chứng code vô dụng.

## 6. Truy vết production và security/evidence

| Đường chạy | Đối chiếu |
| --- | --- |
| CLI/TUI | `cli.main` → parse/startup/runtime → registry/Agent/UI; flags đã retire bị từ chối; provider/config transactions giữ nguyên. |
| Permissions | Freeze/deepcopy arguments → validate → review/dispatch receipt → pre-launch guard → settle; không biến một approval/YOLO thành durable policy. |
| Native HTTP | Request builder/capture binding → exact-origin/private-host/credential gates → quotas/pinned transport → bounded observations. |
| Native TCP/Content | Active host/effective target port, vetted addresses, same-origin GET/no redirect, request/rate/timeout/output bounds và cancellation. |
| Shell | Registry receipt → direct subprocess/project cwd → bounded streams/timeout/process-group cleanup; stdout vẫn là tool output, không phải native HTTP evidence. |
| Workflow/Finding | Objective/phase/input/candidate → owned attempt → immutable artifact/primary source → accepted validation/coverage/cleanup → canonical Finding. |
| Burp | Authenticated bounded ingest → CaptureStore/scoped selection → replay gate/evidence; HTTP traffic/reflection không chứng minh JavaScript execution. |
| CWE | Pinned local retrieval sau confirmed Finding persist; annotation/promotion CAS và context/evidence guards; không đổi eligibility, severity/impact hay confirmation. |
| Session/Continue/compaction | Atomic private persistence, interrupted active attempts, retained historical references; không tạo observation/receipt/coverage/Finding mới khi restore. |
| Experiment | Read-only plan → exclusive preparation → pinned verify → isolated store wiring → official CLI; không ghi đè run/profile hoặc inject quyền mới. |

Shell có filesystem/network rights của account. Project cwd và file-tool guards
không phải OS sandbox; native HTTP scope gate không kiểm soát socket do Shell tự
mở. Process-group cleanup không bảo đảm containment cho process chủ động tách
session/group; containment thuộc VM/container do operator cấu hình.

## 7. Kết quả kiểm thử

Lượt chẩn đoán rộng đầu: **8.566 passed, 101 failed, 12 skipped**. Lượt này chạy
trong quá trình chỉnh sửa, không phải acceptance snapshot. Hai failures launcher
CWE đến từ việc executable đã được retire trước khi lượt đó tới test; các failure
còn lại thuộc fixtures/contracts cũ đã nêu trên. Không dùng lượt này để kết luận
regression mới hoặc cộng vào số tests độc lập cuối.

Các nhóm focused đã xác nhận, có overlap nên không cộng tổng:

| Nhóm | Kết quả |
| --- | --- |
| Shell + CWE sau bug fixes | 388 passed |
| CLI/Direct/Whole-target/CWE/descendant smoke với loopback guard | 254 passed |
| Registry/permission/bridge/modal/redaction | 208 passed, 1 existing live opt-in skipped |
| CLI cleanup/direct/process lifecycle | 234 passed |
| Capture servers/native evidence repair | 123 passed |
| Benchmark closure/manual source/evidence/conformance | 96 passed |
| Burp extension trước khi bỏ default ignore | 31 passed |
| Ba real loopback Whole-target regressions sau sửa attribution | 3 passed |
| Experiment profiles / skill contracts / offline scenarios sau sửa attribution | 209 passed |
| Prompt capabilities / phase guidance / tooling policy / Direct / Input Analysis | 127 passed |
| Regression group sau lần cleanup cuối | 294 passed |

Một lượt full trung gian đã dừng chủ động sau 2.082 passed, 10 skipped để sửa
controller prompt còn mô tả executor cũ; đây không phải kết quả full acceptance.

Full pytest cuối: **8.670 passed, 0 failed, 0 errors, 12 skipped, 0 xfailed,
0 xpassed**, 19 phút 30 giây. JUnit ghi nhận **8.682 tests**; exit code **0**.

Lệnh nghiệm thu, với các live opt-ins bị unset và guard chặn real DNS/socket
connections ngoài loopback:

```bash
env -u KAGENT_SYSTEM_LIVE -u KAGENT_RUN_LIVE_TOOL_CHARACTERIZATION \
  -u KAGENT_S1_EXISTING_CONTAINER venv-linux/bin/python -m pytest -q \
  -p tests.system.offline_suite --tb=short --durations=20 \
  --junitxml=/tmp/kagent-audit-final.xml
```

Toàn bộ skips giữ nguyên điều kiện môi trường/opt-in, không có skip mới để che lỗi:

| Số cases | Điều kiện chưa chạy |
| --- | --- |
| 9 | Thiếu cached offline WAR/Tomcat archives cho production Java reset-gate tests của benchmark Scenario 1. |
| 1 | Không opt-in một existing prepared lab/container. |
| 1 | Không bật `KAGENT_SYSTEM_LIVE=1` để gọi saved provider. |
| 1 | Không bật `KAGENT_RUN_LIVE_TOOL_CHARACTERIZATION=1` để gọi model thật. |

Không còn failure cần phân loại ở snapshot cuối. Các tests chưa chạy nêu trên
là giới hạn môi trường/live acceptance, không được tính là passed. Có 44 warnings
trong log: cảnh báo của malformed-config fixtures và pytest `record_property`
với JUnit xunit2; không phải lỗi runtime hay diagnostic Pyright.

Pyright toàn repository qua `venv-linux/bin/pyright`: **0 errors, 0 warnings,
0 informations**. Thông báo có version Pyright mới là thông báo tool, không phải
diagnostic; không cài/update package.

Đã kiểm tra cả các roots nằm ngoài `include` mặc định bằng
`venv-linux/bin/pyright src tests benchmarks components scripts`:
**0 errors, 0 warnings, 0 informations**.

`git diff --check`: **PASS**. Đã review diff/status toàn worktree và kiểm tra
whitespace cho các tệp mới; không stage/commit/push.

## 8. Runtime smoke và lan-05 dry-run

- Import trực tiếp **230 production modules** không gọi network/process launch;
  CLI help/version pass. AST/import-path audit không tìm module nội bộ bị thiếu.
- Kiểm tra AST **661 Python files**, gồm imports relative và literal dynamic
  imports: không thiếu module nội bộ; các đường dẫn test manifest đều tồn tại.
- Bảy invocations help/version của console `kagent`, benchmark CLI, hai
  standalone capture modules và experiment scripts đều exit 0. `pip check`:
  không có broken requirements; không cài/update package.
- Cấu hình CWE production hiện tại có data; Local Catalog xác minh pin **4.20**,
  search `sql injection` và get CWE-89 thành công, không network/subprocess.
- `bash -n` trên các shell entry scripts pass. Manifest offline hiện tại collect được.
- Đã chạy đúng lệnh thực tế:

  ```bash
  bash scripts/run_experiment.sh --dry-run \
    --run-dir "$PWD/experiments/scenario3/runs/lan-05" \
    --origin http://127.0.0.1:8081
  ```

  Exit **0**; plan v4 hợp lệ, 226 runtime files, 5 component files và 9 skill
  files được pin. `existing_files_to_modify=[]`, `deletions=[]`; không tạo
  `runs/lan-05` hoặc `profiles/lan-05`, không gọi LLM/provider/target.
  Normal v4 giữ defaults/config hiện hành; không tự thêm prompt, max steps,
  HTTP grants, token/cost cap hoặc Shell rights.

Logs/JUnit/plan kiểm chứng ở `/tmp/kagent-audit-*`, gồm
`kagent-audit-full-final.log`, `kagent-audit-final.xml`,
`kagent-audit-pyright-final.log` và `kagent-audit-lan05-plan.json`.
Chúng là artifact audit, không phải dữ liệu thực nghiệm lan-05.

## 9. Giới hạn chưa thể kiểm chứng offline

Không gọi LLM/API, không chạy live pentest hoặc liên hệ origin `127.0.0.1:8081`.
Loopback sockets trong tests thuộc fixtures disposable và có exact-address
guards; không phải target thật. Model doubles chứng minh orchestration/runtime
contracts, không chứng minh model thật luôn tuân thủ playbook hoặc phát hiện đủ
lỗ hổng. Chưa xác nhận credentials, provider availability/rate limits, lab state,
chất lượng thực nghiệm, live Burp UI/Jython, browser execution hoặc Windows
process-tree behavior. Không tuyên bố code hoàn toàn không còn lỗi.

## 10. Nghiệm thu

**READY — Không còn blocker đã biết đối với việc chạy lan-05.**

Cơ sở: full suite hợp lệ xanh, Pyright cả configured/expanded roots xanh,
imports/entrypoints và offline Direct/Whole-target/TUI/Continue smoke xanh,
Local Catalog production xác minh được, lan-05 dry-run hợp lệ và dữ liệu lịch sử
giữ nguyên. Không suy từ các kết quả này rằng code hoàn toàn không còn lỗi hoặc
model thật sẽ hoàn thành đúng thực nghiệm. Legacy isolated headless Shell preset
vẫn unavailable; kết luận áp dụng cho supported runtime/profile hiện tại.
