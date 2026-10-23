# Triển khai runtime tối giản

Đây là báo cáo của đợt triển khai. Kết quả audit/cleanup tiếp nối được ghi tại
[FINAL POST-REFACTOR AUDIT](final-post-refactor-audit.md); các số test và failure
dưới đây mô tả thời điểm triển khai, không phải trạng thái nghiệm thu mới nhất.

## Phạm vi

Thực hiện theo `docs/design-runtime-simplification.md`, trên HEAD `5b1554d`.
Đầu task chỉ có thiết kế untracked; không reset/restore/stage/commit/push.
Không cài hoặc uninstall dependencies. Không sửa dữ liệu experiments, captures,
sessions, findings hoặc durable user/project stores.

## Thành phần đã loại bỏ

- `src/permission/worker/`: worker launcher, Bubblewrap wrapping, HTTP broker
  và relay dành cho worker. CLI không còn probe hoặc khởi tạo worker.
- Nmap/ffuf typed Shell jobs: runner, resource profiles, argument/binary
  readiness, external wordlist catalog và bundled external wordlist.
- Browser MCP tích hợp: deployment/launch/grant binding, component preparation
  package, CLI flag `--browser`, UI grant commands và startup wiring.
- Agent scanner execution hooks, job publication và runtime drain lifecycle.
  Shell schema không còn scanner form. Các flags đã bỏ bị reject rõ ràng.
- Package-data declaration dành cho external wordlist đã bỏ.

Các test chỉ dành cho triển khai đã gỡ được retire; các suite mixed được sửa
để giữ assertions về receipt, arguments, redaction, native discovery và Burp.
Không skip các chức năng đang được giữ để tránh failure.

## Shell trực tiếp và unavailable adapters

Shell/Bash chạy bằng `asyncio.create_subprocess_exec` qua capture runner sẵn có,
cwd là execution-policy root, hoặc project root cho library caller không bound.
Không thêm execution engine hoặc chế độ worker fallback. Giữ per-command
approval, exact invocation receipts, revoke/stale checks trước launch, denylist,
timeout, process-group cancellation, stdout/stderr caps và runtime diagnostics.

Không còn RLIMIT_AS 512 MiB của worker. Regression offline khởi động Node thật
nếu binary đã có sẵn; không cài Node hoặc gọi network để chạy test.

CLI giữ nguyên configured plugins/MCP trong Config nhưng không đăng ký tools
hoặc mở sessions của chúng; báo unavailable, không in command/secret. Legacy
`CommandPluginTool`, `run_plugin`, MCP discovery/open/run cũng fail closed khi
được gọi trực tiếp. Không có local/remote host fallback qua những API này.
MCP text-formatting helpers được giữ cho UI/lịch sử, không còn client executor.

## Chức năng giữ lại

- Burp bridge start/stop/status, token bảo vệ ingest, CaptureStore, bounded
  retention, capture selection và baseline replay gates. Giữ native capture
  tools dù tên chúng còn có `browser_capture_*`.
- Standalone capture-server handlers phục vụ dữ liệu capture vẫn được giữ;
  chúng khác Browser MCP điều khiển trình duyệt. KAgent không tự launch chúng
  qua MCP client đã unavailable.
- Native Service Discovery giữ native TCP, active host/effective target port,
  private-host permission, DNS vetting và giới hạn/cancellation hiện có.
- Native Content Discovery giữ native HTTP, paths/extensions, wildcard
  baselines, same-origin/GET-only/no redirects, request/rate/timeout limits và
  native-result publication/retention/provenance.
- Native HTTP/file guards, workflow phases, coverage, observations, evidence,
  redaction, findings, session/Continue và provider/config transactions.
  Không thay SQLi/XSS validation algorithms hoặc finding eligibility.

Bổ sung theo yêu cầu operator: đã gỡ cả ScannerJob, normalized dataset
readers/writers, workflow triage/handoff và scanner UI events/rendering. Chỉ
hai trường metadata bounded `scanner_jobs`/`scanner_observations` được hydrate
như dữ liệu lịch sử opaque, round-trip mà không mở artifact, không đưa vào
prompt và không tạo progress/coverage/capability. Historical source/provenance
vẫn hydrate với kiểm tra liên kết; admission scanner source mới là unavailable.
Source limitation đã lưu không tự chuyển thành completed. Dữ liệu trên đĩa
không bị xóa. Native Discovery giữ nguyên backend/bounds/provenance.

## Evidence và giới hạn bảo mật

Shell có filesystem/network rights của tài khoản KAgent. Project cwd không
phải sandbox; file-tool root checks không hạn chế được shell truy cập ngoài
project. HTTP exact-origin gate không kiểm soát được socket/curl do shell tạo.
Triển khai trong VM/container lab riêng nếu cần containment ở cấp hệ điều hành.
Permissions vẫn duyệt hành động qua registry; không mô tả denylist là isolation.

Shell output vẫn được sanitize và lưu như shell output; không còn brokered
HTTP attestation. HTTP text hoặc `obs_` giả trong stdout không tạo native HTTP
evidence. Native HTTP/Burp dùng provenance/ownership gates hiện có; finding
vẫn cần reproducible admitted evidence. Giữ phân biệt `tr_`/`obs_`.

Không còn browser execution tự động. HTTP reflection/Burp traffic không tự
chứng minh DOM/JavaScript execution; các trường hợp cần browser giữ outcome
chưa đủ capability/evidence theo contract, không hạ chuẩn xác nhận.

## Kiểm chứng offline

- Targeted vòng đầu sau migration: **340 passed** trên shell, execution policy,
  tool-result offloading, native discovery, whole-target workflow, Burp captures
  và regression lan-04. Các vòng sau mở rộng thêm trách nhiệm liên quan.
- Nhóm contract/skills/CLI/package imports/permissions UI sau cập nhật:
  **516 passed**. Không nới schema budgets để vượt test; action guidance được
  giữ ngắn trong giới hạn hiện có.
- Nhóm direct/native discovery/callback ownership: **118 passed** trước vòng
  xác nhận tổng hợp cuối, gồm các cases mới và native safety/provenance tests.
- Suite rộng offline đầu tiên: **6.800 passed, 236 failed, 1 skipped**, 645 giây.
  Chạy trong quá trình migration; nhiều failure do test còn tham chiếu worker,
  scanner readiness hoặc MCP execution đã gỡ. Không coi đây là lượt xanh.
- Snapshot HEAD read-only được dựng tại `/tmp`, không reset worktree. Chạy các
  tệp baseline liên quan: **113 passed, 49 failed, 4 deselected**. Bốn cases
  deselected là worker/reader cases không thuộc so sánh baseline này.
- Xác nhận cuối trên toàn bộ tệp từng fail cùng direct-runtime/Burp/native
  retention/whole-target/lan-04/historical-scanner responsibility tests:
  **899 passed, 49 failed**, 127 giây. So sánh exact node IDs: tập 49 failure
  bằng baseline HEAD, **không có failure mới**. Không cộng các lượt có overlap
  thành một số tests riêng biệt và không tuyên bố full suite xanh.
- Pyright toàn repository theo cấu hình `venv-linux`: **0 errors, 0 warnings**.
- `git diff --check`, whitespace checks cho tệp mới và review diff/status: pass.
  Giữ line endings của các phần source/tests hiện có khi chỉnh sửa.

Chín cases direct-runtime mới kiểm tra cwd/observations và save/resume cho
Direct/Whole-target; Node khởi động không có worker AS cap; file-tool guard
so với quyền thực tế của shell; stdout giả HTTP không tạo HTTP evidence;
deny/revoke/stale review không launch; plugins/MCP/scanner form không fallback;
flags đã bỏ bị reject; CLI giữ native/Burp tools và không sửa configured profiles.

## Các vấn đề chưa xử lý ngoài phạm vi

49 failures đã tái hiện trên HEAD gồm:

- 44 cases `tests/tools/test_related_request_associations.py` kỳ vọng expert
  validators cho IDOR/CSRF/SSRF/SSTI, trong khi catalog HEAD không còn các skill đó.
- 3 cases access-control trong `tests/state/test_manual_metadata_compatibility.py`
  phụ thuộc expert validator tương tự.
- 1 case `tests/ui/test_candidate_recovery_contract.py` về sibling Candidate.
- 1 case `tests/ui/test_c6_permission_transcript.py` về legacy shell error text.

Không sửa routing/catalog hoặc UI semantics ngoài scope để làm xanh các cases
này. Lượt rộng toàn nhóm không được chạy lại nguyên khối sau cùng; tất cả tệp
từng fail đã được chạy lại, cộng responsibility tests cần thiết. Không chạy
live/external-model acceptance. Tests chứng minh contract/offline behavior,
không bảo đảm model thật sẽ tuân thủ playbook trong mọi lần chạy.

Không gọi LLM/API hoặc live target. Tests dùng FakeClient/MockTransport, temporary
projects/stores và synthetic fixtures; subprocess thật chỉ chạy lệnh local.
Không tuyên bố đã thực hiện acceptance qua model thật hoặc lab target.


## Bổ sung: CWE enrichment không phụ thuộc Worker/MCP

`TrustedSource(policy)` dùng `components.cwe_mcp.catalog.Catalog` đã có sẵn
trong repository. Constructor và mỗi lần retrieve xác minh config path canonical,
manifest pin, XML SHA-256 và giới hạn bytes. Parser vẫn từ chối DTD/entity,
sai identity/schema và vượt cấu trúc; query/response giữ nguyên bounds. Tra cứu
chỉ đọc dữ liệu, không import code/dependency/archive từ deployment, không
subprocess, không network và không nâng MCP/plugin thành host execution.

Giữ tên config `cwe_mcp_deployment_path` để tương thích dữ liệu đã chuẩn bị.
Chỉ cần `manifest.json` + `corpus/cwec_v4.20.xml`; launcher/runtime.zip/server
không được dùng. Dữ liệu thiếu/sai bị từ chối, không tự tải hoặc tự dựng catalog.
Configured file-tool protection và finding/evidence contract giữ nguyên.
Sau khi bỏ Worker, shell/account vẫn có quyền sửa control-plane files trên host;
không mô tả pinned validation là OS sandbox.

Ở HEAD trước đợt bổ sung, helper chưa có caller CLI/TUI/agent. Theo yêu cầu mới,
đã nối /cwe để review thủ công và enrichment tự động sau persist khi
confirm_finding thiếu mapping. Không thêm model tool hoặc LLM call. Xem
`docs/cwe-enrichment.md` để đối chiếu luồng, provenance và các giới hạn lựa chọn.

Bổ sung scanner cleanup đã được xác nhận bằng **1.523 tests passed**: toàn nhóm
integration offline cùng CWE local, workflow/session/source/frontier, native
retention, Burp, Direct/Whole-target/Continue, lan-04 và UI có liên quan.
Pyright: **0 errors, 0 warnings**; diff whitespace check sạch. Đây là kiểm chứng
trước phần mở rộng Finding enrichment sau đó, không cộng với các lượt overlap.
