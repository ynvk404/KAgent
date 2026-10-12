# Final TUI Minimal Presentation Cleanup — offline handoff

## Follow-up: permission modal không có Details

Theo yêu cầu chốt tiếp theo của operator, bỏ `v Details` và local toggle state. Native HTTP preview hiển thị action, exact URL, scope và sanitized headers/body; không in response cap, timeout, ordinary socket metadata, execution envelope hoặc cảnh báo HTTP chung. Giữ cảnh báo ngắn `TLS verification: off` khi native execution metadata cho biết HTTPS không verify TLS; giữ thông tin redirect khi producer nêu explicit follow-up, không suy diễn rằng scope đã bị vượt. Grant review giữ exact origin, phạm vi all endpoints/methods/payloads và lifetime/quota ngắn; không in issuer/session metadata, detailed resource limits hoặc cảnh báo chung. Không đổi nguồn request, permission decisions, grants hay transport settings. Unknown producer formats và text giống metadata nằm trong payload vẫn được giữ nguyên, tránh xóa nội dung hành động hoặc cảnh báo đặc biệt không phân loại được an toàn.

Các phần bên dưới ghi lại lần triển khai ban đầu; mô tả Details và ảnh trước follow-up không còn phản ánh permission modal hiện tại. Turn Details (`/turn-details`) không bị ảnh hưởng.

```text
HTTP request
POST https://fixture.test:8443/action
Session trust: HTTP https://fixture.test:8443; all endpoints,
methods and payloads; active session; no request quota or fixed grant TTL
TLS verification: off
<full sanitized headers/body>
y allow once · a trust origin · n deny · Esc cancel
```

Follow-up verification: **318 passed** với nhóm `test_minimal_presentation`, permission modal/review/bridge/HTTP/C6, remaining UI defects, review lifecycle, HTTP FIFO, action approval, HTTP grants và Browser YOLO. Mounted tests có `100×40` và `40×18`, scroll/copy/keyboard, phím `v` không có tác dụng, payload tail và source request không đổi. Pyright cho `src/ui/widgets/permission_modal.py` và `tests/ui/test_minimal_presentation.py`: **0 errors, 0 warnings** qua `venv-linux`; `git diff --check`: PASS. Không chạy lại full repository suite hoặc live test. Các thay đổi UI của Task A/C giữ nguyên.

## Verdict

Task A: PASS. Task B: PASS với fallback bảo toàn full preview khi không có format metadata đáng tin cậy. Task C: PASS. Overall: PASS trong phạm vi presentation và offline verification.

Baseline: HEAD `75a1008` (`Implement persistence checkpoint report and controlled responsiveness tests`). Trước khi sửa, tracked diff và untracked list đều rỗng. Không sửa Agent, Planner, WorkflowState, permission producers/policy, runtime guards, tools, Evidence, findings hoặc persistence. Planner emission fix và Session Persistence C1 ở HEAD được giữ nguyên.

## Changed files

| File | Lý do |
| --- | --- |
| `src/ui/widgets/transcript.py` | Giữ role color cho mọi dòng assistant/user, kể cả dòng thụt lề; dùng dấu ◆/bold cho milestones và ! cho warnings/errors. |
| `src/ui/core/state.py` | Đổi presentation kind của workflow/coverage/inventory sang info; rút summary; chụp immutable local TurnDetails từ counters/facts hiện có. |
| `src/ui/widgets/permission_modal.py` | Wording theo loại quyền; Details đóng mặc định cho native HTTP limits; bớt scope Browser lặp lại; giữ full action preview và warnings. |
| `src/ui/widgets/turn_details_modal.py` | Local view chỉ đọc của latest completed turn, dùng overlay và cơ chế scroll/selection có sẵn. |
| `src/ui/core/app.py` | Nối Turn Details vào local overlay; scroll, fixed footer và Esc close độc lập với cancellation của turn đang chạy. |
| `src/ui/commands/slash_items.py`, `slash_handler.py` | Thêm một command `/turn-details` và mục help tương ứng. |
| `tests/ui/test_minimal_presentation.py`, `test_turn_details.py` | Focused regression mới cho style/content, Details, authority, counters, turn ownership và runtime modes. |
| `tests/ui/test_transcript_view.py`, `test_progress_milestones.py` | Cập nhật prefix/style/summary wording được chủ động thay đổi; giữ các behavior assertions. |
| `tests/ui/test_permission_modal.py`, `test_permission_review.py`, `test_c6_permission_transcript.py` | Cập nhật wording; vẫn kiểm tra đủ preview, controls và không có reusable quyền khi không hỗ trợ. C6 kiểm tra đủ 30 operations trong snapshot và local view. |
| `tests/ui/test_outcomes.py`, `test_c5_rendering_progress.py`, `test_candidate_recovery_contract.py`, `test_slash_items.py` | Cập nhật labels/catalog; không đổi cách đếm, recovery hoặc stop semantics. |
| `tests/ui/MINIMAL_PRESENTATION_IMPLEMENTATION.md` | Báo cáo bàn giao. |

## Before / after mockups

Các mockup sau minh họa presentation, không phải kết quả kiểm thử một target thật.

```text
BEFORE transcript                    AFTER transcript
  Assistant explanation               Assistant explanation
    Indented explanation [muted]        Indented explanation [neutral]
  Candidate recorded                  ◆ Candidate recorded [bold cyan]
  Validation confirmed                ◆ Validation confirmed [bold green]
  Finding saved                       ◆ Finding saved [bold green]
  Permission denied                   ! Permission denied [amber]
```

```text
BEFORE permission
HTTP request
POST https://fixture.test:8443/action
Session authority: HTTP ...; all endpoints, methods and payloads; ...
<full sanitized request>
Once-only execution envelope: expires in ...; requests <= ...;
token bucket ...; burst ...; concurrency ...; byte limits ...
<full security warning>
y allow once · a trust for session · n deny · Esc cancel

AFTER permission (Details closed)
HTTP request
POST https://fixture.test:8443/action
Effective port: 8443
Session trust: HTTP https://fixture.test:8443; all endpoints,
methods and payloads; active session; no request quota or fixed grant TTL
<full sanitized request, TLS/redirect/socket metadata>
<full security warning>
y allow once · a trust origin · n deny · Esc cancel · v Details

AFTER pressing v
<same action preview and warning>
Technical details
Once-only execution envelope: <complete original limits>
```

```text
BEFORE summary
Turn finished; 1 saved finding; Operations completed:
browser_capture_get (1); permissions_status (1); file_write (1).

AFTER summary
Turn completed; 1 finding saved.

AFTER /turn-details
Latest turn in this UI session
UI turn 1
Turn completed; 1 finding saved.
Completed operations (successful operation records):
  browser_capture_get (1)
  permissions_status (1)
  file_write (1)
↑↓ scroll · Home/End · Esc close
```

Khi còn việc chưa hoàn tất, summary ghi `Turn ended · work remains; ...`. Cancelled, Failed, max steps, blocked/stalled và unknown stop reasons không được đổi thành completed. Accepted-but-unsaved, incomplete validation/goals, pending permissions, deferred work, cleanup/coverage/export failures tiếp tục có mặt.

Dấu `;` giữa facts được giữ có chủ đích: redactor nhận đây là field boundary của form-like secrets. Thay toàn bộ bằng `·` có thể làm counters sau `password=...` trong blocker bị redaction nuốt mất. Regression cho blocker có secret vẫn giữ cả counters và redaction.

## Information hierarchy và quyền

- Assistant/user giữ toàn bộ nội dung vốn được renderer hiển thị sau sanitization. Không phân loại narration, không collapse entry, không có compact/full mode. Markdown renderer, streaming buffer và redaction không sửa.
- Milestones và workflow overview/inventory có dấu ◆ và bold; warnings/errors có dấu !. Detail phụ của finding/validation vẫn muted. Không suy diễn confirmation/finding từ assistant wording.
- Default permission giữ action, exact URL/path/resource, payload/diff/command/arguments, scope producer cung cấp, Browser interaction warning, TLS verification, redirects và socket. Không phân loại risk từ hostname, method hoặc text bất kỳ.
- Chỉ chuyển nguyên native HTTP limits block vào Details khi toàn bộ format khớp producer hiện có, bao gồm warning cố định. Grant review riêng giữ lifetime/quota trước approval và chuyển issuer/session ID cùng resource limits vào Details.
- Shell, File, generic MCP, Browser và HTTP format không nhận diện được giữ full sanitized detail mặc định. Không đoán phần nào của command/body là metadata. Shell timeout và ordinary HTTP socket/transport metadata vẫn có thể xuất hiện mặc định.
- Footer phân biệt `allow once`, `trust origin`, `trust artifact root`/`trust file scope`, `trust Browser <group>`, và `approve grant`. Exact file/artifact scope vẫn lấy từ `session_scope_display`. General MCP không tự có reusable quyền.
- `y/a/n/Esc` giữ decision mapping; `v` chỉ toggle local boolean. Không renew review, mint grant, resolve/reject request hoặc đổi receipt/FIFO/stale-callback logic khi toggle.

## Access và diagnostics ownership

Permission preview luôn ở scrollable default view. Dùng ↑↓, PageUp/PageDown, Home/End để xem đầy đủ; `v Details` chỉ xuất hiện khi có native metadata được tách an toàn. Controls nằm ngoài vùng cuộn. Selection/copy dùng widget hiện có.

`/turn-details` mở snapshot của turn vừa kết thúc; ↑↓, PageUp/PageDown, Home/End cuộn; Esc hoặc Enter đóng. Snapshot lấy trực tiếp từ `_new_records`, issue records và `OutcomeFacts` trong chính lần tạo summary. Không parse summary, không đếm transcript rows, không gọi completed operations là total tool calls. Outcome text được lưu để trình bày cùng typed counters; counters không được trích xuất từ text đó.

Snapshot bất biến và thuộc local UI turn ordinal, không phải runtime session/invocation ID. Mở view rồi bắt đầu turn mới vẫn giữ snapshot cũ trong view đó. Lần mở mới lấy latest finished snapshot. Chỉ một snapshot ở RAM; `/clear`/`/reset` xóa snapshot; resume không dựng lịch sử diagnostics và không thay session schema.

## Verification

Tất cả commands chạy qua WSL Ubuntu trong `D:/DOANTOTNGHIEP/kagent`, dùng `venv-linux`. Ví dụ prefix:

```powershell
wsl -d Ubuntu -- bash -lc 'cd /mnt/d/DOANTOTNGHIEP/kagent && venv-linux/bin/python -m pytest -q <groups>'
```

| Check | Kết quả |
| --- | --- |
| Test-first Task A | 4 regressions fail trước implementation, sau đó pass. |
| Task A transcript/progress/equivalence | 110 pass và 1 assertion prefix cũ; sau cập nhật prefix có chủ đích, subgroup 34 pass. Lượt cuối bao gồm toàn bộ nhóm này. |
| Test-first Task B | Các regression về hidden limits/Browser labels fail trước implementation; unknown-format assertion được sửa để kiểm tra từng dòng qua framing. |
| Task B modal/bridge/HTTP/lifecycle/FIFO/action approval | 181 passed, sau sửa setup repaint trong mounted fixtures. |
| Test-first Task C | 17 fail trước implementation; sau đó 17 passed. |
| Task C outcome/state/app/slash/equivalence | 282 passed. |
| Task C thêm plan-only/mounted snapshot | 21 passed. |
| Final focused presentation/outcome/equivalence | 130 passed. |
| Final UI + permission regression group | **1193 passed, 1 skipped, 4 xfailed**. |
| `venv-linux/bin/pyright` | **0 errors, 0 warnings, 0 informations**. Có notice phiên bản mới; không install/update. |
| `git diff --check` | PASS. Final diff/status đã kiểm tra, không commit/stage/push. |

Final regression command:

```sh
venv-linux/bin/python -m pytest -q tests/ui \
  tests/security/test_permission.py tests/security/test_action_approval.py \
  tests/security/test_http_grants.py tests/security/test_http_invocation_lifecycle.py \
  tests/security/test_c2_review_lifecycle.py tests/security/test_c2_internal_http_contract.py \
  tests/security/test_c3_http_fifo.py tests/security/test_browser_yolo.py \
  tests/security/test_ambiguous_mutating_tool_safety.py \
  tests/security/test_captured_http_replay.py tests/security/test_sensitive_paths.py
venv-linux/bin/pyright
git diff --check
```

Skip là opt-in live-model harness; không bật live testing. Bốn strict xfail là persistence responsiveness defects có sẵn ngoài Session Save C1; giữ nguyên markers/oracles. Không chạy full repository suite, live LLM, Burp hoặc external HTTP; không cài dependencies.

## Mounted visual verification và giới hạn

Đã dùng Textual `run_test` với `100×40` và `40×18`; mounted tests kiểm tra viewport bounds, không horizontal overflow, preview tail, scroll, selection/copy, toggle, Esc và immutable snapshot ownership. Transcript regression còn kiểm tra reading anchor, resize/reflow, split secrets và correlation/recovery indexes.

Đã export native Textual SVG và rasterize các compositor strips để xem PNG, không phải ảnh terminal OS. Đã inspect transcript, permission default/Details tail và Turn Details; fixtures chỉ minh họa styling, không đại diện evidence/finding từ một target thật. Artifacts nằm ngoài repo tại:

`C:/Users/ThinkPad T480s/.codex/visualizations/2026/10/12/01a12efa-4737-7cf2-bed2-05049811a6d1/`

Các ảnh chính: `transcript-100x40.png`, `transcript-40x18.png`, `permission-default-100x40.png`, `permission-default-40x18.png`, `permission-details-tail-40x18.png`, `turn-details-100x40.png`, `turn-details-40x18.png`; cùng tên có SVG và compositor text.

Ở `40×18`, viewport mặc định chỉ hiển thị vài dòng; operator phải cuộn để xem toàn bộ scope, warnings, preview và statistics. Không tuyên bố tất cả thông tin đồng thời nằm trong màn hình nhỏ. Không redesign modal subsystem hoặc thay giới hạn layout sẵn có.

Cross-mode tests dùng `WorkflowObjective` thật cho Direct, Whole-target, Candidate Validation và requested goals; no-objective fallback dùng state không có objective; plan-only chạy Agent với fake client và `AgentRunOptions(tools=False)`, cả response thường lẫn tool request bị chặn. Burp-assisted chỉ là capture/context fixture trong equivalence/progress tests, không tạo objective mode mới.

State/permission invariants giữ nguyên: Agent history và request projection, workflow snapshots, evidence/findings/capture/coverage artifacts, granted authority, invocation/correlation ledger, issue recovery và persistence không đổi do presentation. Runtime equivalence tests kiểm tra các dữ liệu này trực tiếp. Những giới hạn còn lại là local latest-only diagnostics, conservative metadata fallback, và việc cuộn trên terminal nhỏ.
