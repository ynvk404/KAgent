# Browser MCP trusted-local persistent — 09/10/2026

Trạng thái hiện hành: **PARTIAL về hiệu năng**; action WebSocket tới
Extension/Chrome vẫn có độ trễ và đã tái hiện timeout 30 giây. Không replay,
không tăng timeout, không sửa Extension. CLI dùng một flag `--browser` để
chọn verified trusted-local persistent backend. Xem [bằng chứng live v2](LIVE_TEST.md);
GO lịch sử không bảo đảm hiệu năng. Diagnostics v3 phân biệt lock, readiness,
MCP và từng WebSocket action/snapshot; không thay đổi deadline hoặc tự retry.
YOLO ON dùng [Browser grant hữu hạn do operator cấp](BOUNDED_YOLO.md), không tự cấp quyền Browser.
Skill XSS tiếp tục chặn Browser MCP cho tới khi latency được xử lý và verify;
Browser grant không vượt qua Skill gate.

## 1. Exact files changed trong đợt trusted-local

Đường dẫn tính từ `D:\DOANTOTNGHIEP\kagent`.

| Tệp | Lý do |
| --- | --- |
| `src/tools/mcp/browser_deployment.py` | Identity launch local, inventory patched, checksum Node/prlimit; giữ verifier upstream. |
| `src/tools/mcp/session_servers.py` | `--browser` chỉ chọn config local; không fallback vào worker. |
| `src/tools/mcp/integration.py` | Dispatch Browser local riêng, metadata controller qua stdio; giữ worker/lifecycle general/CWE. |
| `src/tools/mcp/browser_local.py` | Binding controller/engagement, neutral owner task, serialization, readiness, ownership, queue/revoke/teardown. |
| `src/cli/runtime.py` | Session-only flags, install binding, discovery local fail closed, cleanup. |
| `src/cli/help.py` | Help một flag Browser; Chrome/Extension do operator quản lý. |
| `src/permission/runtime/execution.py` | Check adapter/binding Browser chỉ định; receipt/policy chung và YOLO giữ nguyên. |
| `src/agent/agent.py` | Hook nhỏ `_clear_permission_cache` cho reset/resume/target/scope invalidation. |
| `components/browser_mcp/patch_local.py` | Patch deterministic trên đúng SHA-256 bundle upstream. |
| `components/browser_mcp/prepare_local.py` | Maintenance ngoài runtime: verify source, tạo tree mới, patch identity/inventory. |
| `components/browser_mcp/patch-local-v3.diff` | Unified diff reviewable, giống `patch.diff` trong deployment; thêm timing metadata. |
| `components/browser_mcp/README.md` | Báo cáo hiện hành và giới hạn lab mode. |
| `tests/security/test_browser_local.py` | Opt-in/config giả, receipts, queue, scope, readiness, reconnect/lifecycle, deployment failures. |
| `tests/security/test_browser_local_protocol.py` | Điều phối Node/Python thật trong namespace riêng. |
| `tests/security/browser_local_protocol.mjs` | Mock extension: loopback, replacement, refs, origin, disconnect, payload, port conflict. |
| `tests/security/browser_local_owner.py` | Owner thật: PID reuse, permission/revoke, env/limits, AnyIO teardown. |
| `scripts/check_browser_local_transport.py` | TCP/HTTP forwarding loopback và release cổng; không WebSocket/Chrome. |
| `scripts/check_browser_mcp.py` | Helper CLI discovery dùng một flag Browser; phép đo resource upstream giữ nguyên. |
| `scripts/browser_local_live.py` | Runner live có gates/receipts và evidence, DENY/revoke/reset/cleanup; không LLM. |
| `components/browser_mcp/LIVE_TEST.md` | Chrome live evidence, timeout incident và scope của kết luận GO. |

Giữ nguyên thay đổi có sẵn ở worker, UI permission, tests và deployment
upstream. Không sửa SQLi/XSS Skills, Shell, CWE/general MCP behavior, native
HTTP, Burp/capture, benchmark/canonical results. Không commit/push.

## 2. Opt-in và trust boundary

```bash
# Discovery; local discovery không mở listener host.
kagent --browser --list-tools

# Operator chuẩn bị Chrome lab và Extension, approve mỗi action.
kagent --browser --target http://juice.lab:8081
```

`--browser` không persist, không auto-approve. Action cần `--target` rõ ràng
và exact origin trong engagement scope; discovery không cần target/Extension.
Khuyến nghị profile Chrome riêng cho lab, không tài khoản/tab cá nhân và ngắt
Extension ở các profile khác. Operator tự mở Chrome, cài/bật/pair Extension.
KAgent không tạo/xóa profile, không cấu hình Chrome/Windows, không mở/đóng
Chrome, không xóa cookies/storage. Readiness chờ hữu hạn 15 giây rồi fail rõ
ràng trước dispatch nếu chưa kết nối. Đổi origin cần restart với target mới.

Chỉ controller cài `BrowserLocalBinding` mới chọn nhánh này. Check policy
object, binding/session object, frozen config, tên `browser`, command
`/usr/bin/node`, argv cố định và env config rỗng. Tên/config giả hoặc model
arguments/output không tạo quyền host. Local config tự nó không được
`MCPSession.open` launch. General/CWE vẫn cần worker và fresh process mỗi
dispatch như trước.

Đây là **trusted process trên Linux/WSL host**, không có filesystem/network
isolation như OfflineWorker. Child dùng env tối thiểu, override toàn bộ
default inherited variables của MCP SDK đã pin, không truyền provider/npm
tokens, proxy hoặc `NODE_OPTIONS`. Env tối thiểu không ngăn đọc filesystem host.

## 3. Upstream patch và deployment identity

Upstream `@browsermcp/mcp@0.1.3`; extension operator báo `1.3.4`. Giữ nguyên
dependency versions/package-lock. Runtime không npm/npx, install/download;
đợt này không tải gói mới.

Upstream giữ ở `/usr/local/lib/kagent-browser-mcp/0.1.3`.
Controller chọn `/usr/local/lib/kagent-browser-mcp/0.1.3-kagent-local-v3`.
`v1`/`v2` giữ nguyên, không được chọn; `v3` giữ guards/lifecycle của `v2` và
thêm monotonic timing metadata cho từng request, không đổi Extension protocol.
Identity được tạo
và review từ patch cụ thể; không đổi anchor để bỏ qua verification failure.

```text
Upstream inventory: 19bd4d4fa3b8454b54c4ebb8fa571f4ce23bdf31a94f8439ecb43f9916bb3a8b
Upstream bundle:    f391bfe0a8185e7551dfe70f129019b8eb786857fc1e8390edaa6ae3ad27ecfc
Patch:              kagent-local-v3
Patched inventory: 787b6f16b5b776f9f182df79041fee37cd0f0f351f0ef69a1ebd1d15ab4a2ae1
Node /usr/bin/node: d0efb6fcb9d023ba4e2b160ec2384dc28fe4f17732141ef47f676828fa960505
prlimit:            cb28811cb3902773c1a0f3ac0ea554c7a1e232724e9d4cae055ede54b65a7bc4
```

File upstream duy nhất đổi: `node_modules/@browsermcp/mcp/dist/index.js`.
Thêm `patch.json`, `patch.diff`, inventory schema 2. Source map upstream giữ
nguyên, không mô tả patch và không dùng làm bằng chứng source patched.

Patch bind **127.0.0.1:9009**, bỏ import/helper/call kill theo cổng và port-wait
vô hạn; EADDRINUSE fail rõ ràng. `maxPayload` **8 MiB**; snapshot/console/
screenshot lớn hơn sẽ fail. Socket mới bị từ chối thay vì thay connection.
Pending RPC reject khi close; JSON hỏng đóng socket. Fix recursive
`server.close`, terminate sockets, exit watchdog 1 giây. Giữ 12 tool names/
schema và extension messages.

Resource nội bộ `kagent://browser/status` và MCP stdio `_meta` mang
connection/snapshot generation + controller scope. `kagentBrowserTiming`
chỉ mang correlation/request IDs, tên message, thời gian, outcome; không
credentials/cookies/URLs/args/nội dung trang. Không expose thành model
tool hoặc đổi extension WebSocket protocol. Mỗi launch verify tree canonical,
root-owned, no group/world write, regular files/directories, no symlink/
hardlink/IPC, inventory đầy đủ và anchor cố định; hash/ownership Node/prlimit
cũng được verify. Missing/stale/modified block trước spawn.

Maintenance trên upstream đã chuẩn bị, destination phải mới:

```bash
sudo /usr/bin/python3 components/browser_mcp/prepare_local.py \
  /usr/local/lib/kagent-browser-mcp/0.1.3 \
  /usr/local/lib/kagent-browser-mcp/0.1.3-kagent-local-v3
# Trên máy này destination đã có: lệnh sẽ từ chối ghi đè.
venv-linux/bin/python -c 'from src.tools.mcp.browser_deployment import verify_browser_local_deployment; verify_browser_local_deployment()'
```

## 4. Persistent ownership, readiness, reconnect, cleanup

Discovery dùng patched Node `KAGENT_BROWSER_DISCOVERY=1`: initialize/list_tools,
không WebSocket listener, rồi đóng process. Host persistent process tạo lazily
ở invocation approved đầu tiên; initialize/list_tools lại, đối chiếu schema
với discovery.

Owner task được tạo bằng `contextvars.Context()` rỗng. MCP/AnyIO contexts
enter/exit trong cùng task. Lock/receipt ở invocation task; guard chạy snapshot
context ngay trước RPC rồi giải phóng, không giữ approval đầu trong owner
idle. Calls serialize. Queue recheck cancellation, binding epoch, current
policy revision, scope/receipt trước dispatch. Permission fresh high-impact/
noSessionCache mỗi invocation.

Trước listener: kiểm tra cổng Windows và WSL; occupied/inspection failure thì
dừng, không kill/adopt. Sau launch: PID báo bởi status phải có đúng Node exe;
inode listener loopback `/proc/net/tcp` phải thuộc fd PID đó. Không dùng
process/session CLI khác.

Status polling chỉ đọc server state, không WebSocket client probe hoặc tab
read. Deadline connection 15 giây, status RPC 3 giây; chưa có connection thì
không dispatch action. Connected/initialize/listener chỉ chứng minh transport.
**Response của operation đã được phép mới chứng minh tab Chrome trả lời**.
Offline tests dùng mock response; Chrome live evidence hiện có ở mục 8 và
`LIVE_TEST.md`, không dùng mock làm bằng chứng Chrome.

Reconnect đổi generation, mất refs. Ref tool cần generation snapshot hiện
hành và ref trong snapshot mới nhất ở server. Reset/resume/target/scope
invalidate epoch ngay, cancel owner, đóng process/channel; dispatch sau phải
chờ teardown. CLI cleanup đóng binding qua session cleanup hiện có. Không
chia sẻ binding giữa controller/engagement/CLI.

Giữ budget: RLIMIT_AS **1.5 GiB**, CPU **120 giây tích lũy**, FSIZE 16 MiB,
NOFILE 128, NPROC 1024, CORE 0; handshake 15 giây/tool 120 giây/close 3 giây.
Process death/budget exhaustion không auto-replay; RPC failure cần explicit
reset. Mutating response loss/cancel sau dispatch báo **outcome unknown**.
Đóng MCP không xóa cookies/storage hoặc bảo đảm rollback/hủy Chrome action.

## 5. Permission/scope thực sự được kiểm tra

Giữ Skill gates, generic validation, Registry approval, policy validation,
execution receipts, deny/revoke và policy YOLO chung. YOLO OFF hỏi từng call.
YOLO ON auto-approve khi có Browser grant còn hiệu lực, đủ quota và bao phủ
action; thiếu/uncovered/stale grant trở về operator dialog, hard blocks giữ nguyên.
`g` trong Browser dialog mở confirmation riêng (300 giây/20 dispatch): read,
navigate hoặc interaction. Interaction xác nhận khả năng submit/change state.
Grant không phải session trust; mỗi call vẫn có receipt riêng và recheck ngay
trước RPC. `/permissions browser` hiển thị origin/actions/time/quota;
`/permissions browser revoke` thu hồi. General/CWE/Shell/Native HTTP giữ policy cũ.
Không bypass worker gate
cho MCP khác. Stale receipts, queued cancellation/revoke và cross-controller
binding bị chặn; persistent/Connected không mang quyền approval.

Navigate validate absolute HTTP(S), loại credentials/backslash/control chars,
exact origin trong engagement và target binding. Server recheck origin từ
controller metadata. Approval không mở rộng scope.

Tool không URL đọc **getUrl hiện tại** qua socket pin cho call, đối chiếu
origin; không dùng last-known URL. Snapshot check URL lại trước đọc title/
ARIA. Origin/generation/ref không hợp lệ thì dừng. Đây là selected-tab metadata,
không có authenticated tab ID hoặc atomic browser navigation lock; không
bảo đảm context không đổi giữa check/action. Operator/profile lab discipline
vẫn bắt buộc.

## 6. Focused tests, Pyright, diff và CLI

Suite trước đợt live: **559 passed**, **0 skipped**, 67.67 giây. Bao gồm MCP/deployment,
worker, execution/approval, CWE, CLI, Shell/scanner, generic validation, Skill
workflow, cancellation, target/slash-target. Pyright **15 tệp Python đổi**:
0 errors/0 warnings. `git diff --check`/whitespace tệp mới đạt. Không chạy
benchmark/live pentest hoặc audit lại dependency/RAM.

Sau lỗi live đã sửa chẩn đoán outcome unknown giữ lỗi gốc redacted/bounded:
**53 passed** ở local/protocol/MCP integration; Pyright ba tệp Python đổi
0 errors/0 warnings. Không cộng số tests hoặc coi đây là full suite rerun.

Hai protocol tests có Node/Python thật nhưng **mock extension trong network
namespace riêng**: loopback/no-kill/port conflict, payload disconnect bounded,
current URL, latest refs, reject connection thứ hai, cùng PID/session,
DENY/revoke queued, unknown outcome và process/port cleanup. Owner test verify
Node environment/limits, không lỗi AnyIO. Fixture chỉ chuyển ownership root
sang UID overflow 65534 trong user namespace, sau parent verify root-owned
tree thật; hash/type/link/inventory và runtime verifier không bị nới lỏng.

```bash
venv-linux/bin/python -m pytest \
  tests/integration/test_mcp_integration.py \
  tests/security/test_browser_deployment.py tests/security/test_browser_mcp_resources.py \
  tests/security/test_browser_local.py tests/security/test_browser_local_protocol.py \
  tests/security/test_offline_worker.py tests/security/test_worker_startup.py \
  tests/security/test_worker_responsiveness.py tests/security/test_execution_policy.py \
  tests/security/test_action_approval.py tests/cwe/test_runtime_pack.py tests/cwe/test_server.py \
  tests/tools/test_tools_mcp_server.py tests/runtime/test_cli_main.py \
  tests/tools/test_shell.py tests/tools/test_discovery_tools.py tests/security/test_generic_validation.py \
  tests/integration/test_skill_workflow.py tests/agent/test_parallel_cancellation.py \
  tests/ui/test_slash_target.py tests/state/test_target.py -q
```

CLI thật, HOME tạm/provider placeholder, không LLM: cả
`--browser --list-tools` exit 0,
12 `mcp_browser_*`, mọi tool `[permission required]`. Không pairing/action.

## 7. Windows–WSL transport

`scripts/check_browser_local_transport.py` mở service **HTTP thuần** ở WSL
`127.0.0.1:9009`, sau verify/preflight. Windows Invoke-WebRequest nhận đúng
marker qua cả `http://localhost:9009` và `http://127.0.0.1:9009`; teardown
release cổng. Service không chấp nhận WebSocket Upgrade, không pair extension.
Không sửa WSL NAT, firewall, port forwarding hoặc Chrome profile. Bằng chứng
này là TCP forwarding hiện có, chưa phải extension pairing.

## 8. Chrome navigate/snapshot/click/type — đã có bằng chứng

Operator cho phép `http://juice.lab:8081` (OWASP Juice Shop), navigate,
snapshot, click/type search/biểu mẫu thử nghiệm; **không submit login, không
thao tác thay đổi dữ liệu**. Operator sau đó xác nhận profile lab sẵn sàng
và Browser MCP trong các profile khác đã ngắt.

Lượt xác minh `20261009T184036-ef684d85`, PID **72137**, owner task
**135836084043856**: navigate/snapshot/click/type liên tiếp, connection
generation 1 và binding epoch 0. Snapshot có OWASP Juice Shop, All Products,
Apple Juice và 46 sản phẩm; click Open search dùng `s2e30`, type dùng `s3e31`
với `submit=false`. Snapshot xác nhận `KAGENT-LIVE-20261009-VERIFY` trong
textbox. DENY không dispatch, queued/new revoke có 0 Browser RPC; reset/exit
đóng process và giải phóng cổng Windows/WSL.

Lượt đầu có click Close Welcome Banner timeout khoảng 30 giây dù operator
và snapshot sau reset xác nhận banner đã đóng; không retry click đó. Controller
đã sửa việc che lỗi gốc, không tăng timeout hay đổi extension/deployment.
Nguyên nhân nội bộ extension chưa được xác định; click/type ở lượt sạch
cũng chậm. [LIVE_TEST.md](LIVE_TEST.md) ghi timings, paths, checks và incident.

## 9. Giới hạn bảo mật còn lại

- Stock WebSocket không authentication riêng. Loopback/Origin filtering
  không tương đương authentication; không phải authenticated browser relay.
- URL checks không cưỡng chế toàn bộ redirect, form submissions, iframe hoặc
  background traffic. Origin guard chỉ dừng khi quan sát metadata đã đổi,
  không ngăn request ngoài scope đã xảy ra.
- Profile riêng giảm rủi ro dữ liệu, không tạo sandbox/bảo đảm scope. Tab/
  profile identity vẫn dựa vào operator, không có extension auth handshake.
- Trusted Node có filesystem/network rights của user host. Env tối thiểu/
  resource limits không cung cấp isolation như OfflineWorker.
- Cancel/close không bảo đảm hủy action đã gửi. Mutating response loss có
  outcome unknown; không rollback hoặc automatic retry.
- Payload >8 MiB disconnect, refs mất khi reconnect/reset. CPU budget tính
  tích lũy theo process; không tự tăng limits khi lỗi.

## 10. Phân loại kết thúc

Kết luận live v2 lịch sử: **GO — trusted-local lab mode** cho profile/target và bộ thao tác đã kiểm tra,
dựa trên Chrome thật, persistence, permission/revoke và cleanup. Không cần
relay, fork extension, listener ngoài loopback hoặc đổi mạng hệ thống. Giữ
timeout incident và các giới hạn nêu trên; không bảo đảm mọi operation luôn
thành công hoặc đạt contract authenticated browser relay.
