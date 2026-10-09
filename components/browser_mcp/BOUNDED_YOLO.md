# Browser MCP bounded YOLO — 09/10/2026

YOLO ON không vô hiệu hóa Browser và không tự tạo grant. Operator có thể
cấp một grant Browser hữu hạn qua Permission Modal hiện có; invocation thuộc
grant được auto-approve qua Registry và vẫn tạo execution receipt riêng.
YOLO OFF tiếp tục hỏi permission từng call.

## Nguyên nhân và phân biệt quyền

Generic Registry có shortcut ALLOW khi YOLO bật, trong khi `YoloPrompter`
thông thường chặn ask chưa có active receipt. Để Browser có review trước
`ExecutionPolicy.start`, adapter designated local chọn `forceOperator`;
Registry chỉ auto-approve nhánh này khi `yoloAutoApprove` được binding xác nhận
bằng grant hợp lệ. Khi không đủ điều kiện, YoloPrompter chuyển request tới
operator. Các request khác dùng defaults cũ.

`no_session_cache=True` chỉ ngăn session trust; không cấm auto-approval.
Risk tier vẫn high-impact. ALLOW_ONCE khác operator grant; grant không thay
execution receipt hoặc hard gates. Native HTTP grant ghi rõ không cấp quyền
MCP nên không được chuyển thành Browser authority.

## Grant và UX

Khởi chạy như trước:

```bash
kagent --browser --target http://juice.lab:8081
```

Bật YOLO qua cơ chế hiện có. Khi Browser cần permission, `y` chỉ approve
invocation đó; `g` mở một confirmation riêng. Confirmation hiển thị exact
origin, action names, **300 giây**, tối đa **20 dispatch** và cách revoke.
Chỉ `y`/ALLOW_ONCE tại confirmation mới cấp grant và approve invocation đang
đề xuất. DENY/ALLOW_SESSION không tạo grant.

| Nhóm đề xuất | Grant bao phủ | Ý nghĩa đã đối chiếu với handler 0.1.3 |
| --- | --- | --- |
| read | snapshot, screenshot, get_console_logs | Đọc ARIA, ảnh hoặc console từ tab đã kiểm tra scope. |
| navigate | read + navigate | Gửi browser_navigate, lấy snapshot; destination exact origin của grant. |
| interaction | read + navigate + click/type | Dispatch input rồi lấy ARIA; operator xác nhận có thể submit form, thay đổi trạng thái hoặc nhập dữ liệu nhạy cảm. |
| hover, select_option, press_key, go_back, go_forward, wait | Không auto-approve | Giữ manual review; không suy ra quyền interaction rộng hơn từ tên tool. |

```text
/permissions browser
/permissions browser revoke
```

Status và `permissions_status` hiển thị origin, action names, seconds/calls
còn lại, trạng thái và lệnh revoke. Grant chỉ nằm trong BrowserLocalBinding
của controller hiện tại; không serialize, không khôi phục từ session/memory,
không có model tool hoặc flag CLI cấp quyền mới.

## Binding và enforcement

Grant chứa origin, action set, session/controller lifecycle, binding epoch,
policy stamp/revision, grant revision, monotonic expiry và quota. Một active
grant; grant mới thay grant cũ chỉ sau confirmation operator. Không tự refill
khi bật YOLO, quota exhaustion, expiry hoặc khi model retry.

Registry freeze args/config và chuẩn bị receipt trước permission. Autoapproval
chỉ được adapter Browser local đã verify chọn. Binding kiểm tra grant trong
khi chờ lock/readiness và lần cuối trong owner guard, ngay trước tools/call.
Quota trừ đồng bộ ở lần dispatch đó, không trừ cho readiness/discovery.
RPC bị server scope/ref guard từ chối vẫn tính quota một cách bảo thủ.
Grant hết quota sau call cuối không làm mất quyền trả response của call đó.

Receipt, policy revision, deny/revoke, scope, owner/loopback verification,
resource limits, generation/ref guards và Skill gates giữ nguyên. Current URL
cho non-navigation action được patched server kiểm tra ngay trước handler;
navigate kiểm tra destination origin, snapshot kiểm tra origin lại. Grant
không bypass các guards này. Unknown/unverifiable current URL chặn action;
readiness deadline chặn khi Extension không kết nối.

Queued autoapproval mang grant ID/revision của chính invocation. Revoke,
expiry, quota loss, reset, scope/target/session/policy change hoặc YOLO OFF
đều ngăn RPC cũ dispatch. Reset/fault/close xóa grant. Thiếu hoặc không còn
grant hợp lệ ở invocation mới trở về review; không tự cấp grant thay thế.
Cancel/revoke sau dispatch không rollback Chrome action; giữ outcome unknown,
explicit reset và no-auto-replay.

## Tệp của phần bounded grant

| Tệp | Thay đổi |
| --- | --- |
| `src/tools/mcp/browser_local.py` | State grant hữu hạn, authorization/status/revoke, recheck và quota trước RPC. |
| `src/tools/mcp/integration.py` | Hints từ verified binding, frozen invocation token, confirmation grant riêng. |
| `src/permission/permission.py`, `src/tools/common/types.py`, `src/tools/common/registry.py` | Optional metadata cho Browser review; defaults và shortcut của tool khác giữ nguyên. |
| `src/ui/bridges/perm_bridge.py`, `src/ui/widgets/permission_modal.py` | Chuyển metadata Browser, nút g chỉ khi Browser offer có mặt. |
| `src/ui/commands/slash_handler.py`, `src/tools/common/permission_status.py` | Status/revoke do operator và status read-only. |
| `tests/security/test_browser_yolo.py`, `tests/security/test_permission.py` | Grant/YOLO/receipt/revoke/expiry/quota/UI và model-argument isolation. |
| `tests/security/browser_local_owner.py` | Node thật + mock private namespace: autoapproval giữ PID, foreign/invalid current URL không đọc snapshot. |

General MCP, CWE, Shell và Native HTTP không nhận Browser grant. Skill XSS
hiện chặn Browser MCP trong khi latency chưa được xử lý; grant không vượt
qua Skill gate. Runtime/Extension giữ giới hạn transport hiện có.

## Verification và giới hạn

Verification cuối: **520 focused tests passed** (132.64s), gồm Browser grant,
local/protocol, Registry, receipt/YOLO, Native HTTP grants/lifecycle, permission
bridge/modal, MCP integration, Shell, CWE và CLI. **44 slash-handler tests
passed** (22.72s). Scoped Pyright **21 tệp Python của các thay đổi tích lũy**:
0 errors/0 warnings. `git diff --check` đạt. Không cộng các checkpoint/test
rerun overlapping vào số này.

Không chạy full suite hoặc live Chrome cho phần grant; dùng production
Registry/receipts, real Permission Modal và pinned Node trong private network
namespace với mock Extension. Stock Extension không authentication WebSocket
riêng hoặc identity profile/tab đáng tin tuyệt đối; scope guards không cưỡng
chế mọi redirect/iframe/background Chrome traffic. Exact origin không làm
click/type an toàn. Grant interaction chỉ dành cho lab được operator xác nhận
có thể chấp nhận unknown application effects. Timeout/latency từ lượt trước
còn là PARTIAL và không được gọi là đã tối ưu.
