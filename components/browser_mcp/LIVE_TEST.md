# Browser MCP — bằng chứng Chrome live ngày 09/10/2026

**GO — trusted-local lab mode**, cho profile lab và exact origin
`http://juice.lab:8081` đã được operator xác nhận. Chuỗi navigate → snapshot
→ search click → type thành công với cùng process/session; DENY, queued/new
revocation, reset và cleanup đã được kiểm tra trên binding thật.

Có một click đóng welcome banner bị timeout/outcome unknown ở lượt đầu,
dù UI thực tế đã đóng banner. Không retry call đó. **Không khẳng định nguyên
nhân nội bộ extension của timeout này đã được giải quyết.** Lượt xác minh
đầy đủ sau đó không có lỗi; click/type vẫn có độ trễ đáng kể. GO ở đây không
là bảo đảm mọi operation luôn trả lời trước deadline hoặc authenticated relay.

## 1. Điều kiện và cách chạy

Operator xác nhận profile Chrome riêng không có tài khoản/dữ liệu cá nhân,
Browser MCP Extension bật tại profile lab và đã ngắt ở mọi profile khác.
Chỉ target Juice Shop nói trên và navigate/snapshot/click/type search được
phép; không submit login/form hoặc click chức năng đổi dữ liệu.

```bash
venv-linux/bin/python scripts/browser_local_live.py \
  --browser --browser-local --browser-lab-ready --target http://juice.lab:8081
```

Runner nhận flags qua parser KAgent, dùng production Agent Skill/generic gate,
Registry, YoloPrompter ở chế độ OFF, execution policy/receipts và Browser local
binding. Mỗi đề xuất chỉ nhận ALLOW_ONCE hoặc DENY của envelope test rõ ràng.
Không gọi LLM, không giả lập Browser/worker/extension; không kiểm thử TUI
permission dialog. Skill gate được gọi mỗi lần, không active pentest Skill.

Khởi động pairing chỉ initialize/list_tools/status với production owner;
không đọc tab trước operation được phép. Readiness/status không dùng client
WebSocket thứ hai. Không sửa networking/firewall/WSL/Chrome profile.

## 2. Identity, pairing và ownership

Deployment vẫn là `kagent-local-v2`; manifest:
`bc5fc7336fa72ca1d3e291e551516392def840fc7eee7f80d55d06335b9b3dab`.
Không đổi package, extension, patch hoặc trust anchor trong đợt live này.
Deployment, Node/prlimit và cổng Windows/WSL được verify trước launch.

Lượt xác minh đủ bốn tool có controller session ID:
`20261009T184036-ef684d85`.

| Bằng chứng | Giá trị |
| --- | --- |
| Node PID | `72137` |
| Owner task identity | `135836084043856` |
| Connection generation | `1` trong mọi call thành công |
| Binding epoch | `0` trong mọi call thành công |
| Listener | WSL `127.0.0.1:9009` |
| Extension connected | `18:40:44.499692 +07:00` |

Production `verify_listener_owner` đạt: PID có đúng Node executable và inode
listener loopback duy nhất thuộc fd của PID đó. Status từ same stdio owner;
không adopt process/listener CLI khác. Chrome trả URL/title/ARIA thật, thay vì
chỉ dựa vào Connected. Profile identity dựa vào xác nhận operator, không có
authentication handshake với extension.

## 3. Chuỗi Chrome thật cùng persistent session

Thời gian tính từ event proposed đến result, không phải phép đo riêng từng
WebSocket message. Mọi hàng có PID `72137`, cùng owner task ở trên.

| Thứ tự | Tool | Ref hoặc input | Snapshot generation sau call | Giây |
| --- | --- | --- | --- | --- |
| 1 | `browser_navigate` | `http://juice.lab:8081` | 1 | 6.048 |
| 2 | `browser_snapshot` | `{}` | 2 | 0.088 |
| 3 | `browser_click` | Open search, `s2e30` từ snapshot thứ 2 | 3 | 24.265 |
| 4 | `browser_type` | textbox `s3e31` từ kết quả click; `submit=false` | 4 | 26.702 |

Navigate/snapshot trả `http://juice.lab:8081/#/`, title **OWASP Juice Shop**,
**All Products**, **Apple Juice (1000ml)**, **Apple Pomace**, **Banana Juice
(1000ml)** và phân trang `1 – 15 of 46`.

Search click trả acknowledgment `Clicked ...`; ARIA sau click không còn
button Open search và có textbox `s3e31` cùng Close search. Type trả
acknowledgment và ARIA:

```text
- textbox [ref=s4e36]: KAGENT-LIVE-20261009-VERIFY
```

Refs lấy từ generation mới nhất trước mỗi action. Không dùng refs của process
trước reset. Các call liên tiếp vào same owner giữ một ClientSession/stdio
transport; không initialize server mới mỗi invocation. PID/task/generation
và binding epoch không đổi. Giỏ hàng trong snapshot vẫn **Your Basket 0**;
không submit login/form hoặc click Add to Basket/data mutation controls.

## 4. DENY và revoke

Đề xuất type `DENY-MUST-NOT-APPEAR`, ref `s4e36`, `submit=false`, nhận DENY
từ permission gate. Dispatch entry counter **4 → 4**, connection/snapshot
generation và owner state không đổi. Snapshot đọc sau DENY vẫn chứa
`KAGENT-LIVE-20261009-VERIFY`, không chứa giá trị bị từ chối.

Queued revoke test giữ serialization lock của controller, cho một snapshot
được ALLOW_ONCE đi qua receipt gate rồi chờ lock; revoke tool trước khi nhả.
Không làm một operation mutating để tạo hàng đợi. Kết quả:

```text
queued: blocked: Browser queued receipt revoked/stale or binding reset
new:    blocked: tool/session-revoked
owner call_tool RPC requests: 0
policy active: 0
```

Trước/sau revoke: PID/task/connection generation/snapshot generation giống
nhau. Invocation mới bị chặn trước dispatch. Counter `dispatches` trong
cleanup của runner đếm entry vào binding, gồm cả call queued bị chặn; nó
không phải số operation Chrome. Counter RPC riêng ở bài revoke chứng minh
không gửi tools/call tới Node cho hai operation bị revoke.

## 5. Reset, cleanup và cổng

`Agent.reset()` gọi hook production: binding epoch **0 → 1**, cancel owner,
teardown trong đúng owner task. Event reset lúc `18:44:57.929111 +07:00`:
`old_process_gone=true`, `port_free=true` cho PID `72137`.

Event cleanup lúc `18:46:32.718313 +07:00`: `all_processes_gone=true`,
`port_free=true`, `policy_active=0`. Kiểm tra độc lập sau exit thấy Windows và
WSL không có listener 9009; `/proc/70474`, `/proc/70911`, `/proc/72137` đều
không còn. Không kill process theo cổng, không xóa cookies/storage/profile.

## 6. Timeout ban đầu và sửa trực tiếp liên quan

Lượt đầu `20261009T182844-cbbd6ca8`:

- Pairing PID `70474`, navigate và snapshot thành công.
- Click Close Welcome Banner `s2e33` lúc `18:29:34.978883 +07:00`; lỗi
  outcome unknown lúc `18:30:05.043871 +07:00`, khoảng **30.065 giây**.
- Operator xác nhận banner đã đóng, sản phẩm hiển thị; cookie popup vẫn còn;
  Chrome hiện debugger notice bình thường, không báo lỗi quyền extension.
- Không replay click này. Reset/re-pair PID `70911`; snapshot mới chứng minh
  banner không còn. Search click/type, DENY và reset/cleanup ở PID này đạt.

Lỗi nằm ở response path sau một action đã có hiệu lực; khoảng thời gian phù
hợp với upstream WebSocket RPC deadline 30 giây. Tuy nhiên controller cũ
đã thay MCP error bằng thông báo unknown chung, nên không còn bản ghi lỗi
gốc để xác định message nào timeout hoặc nguyên nhân nội bộ extension.
Không suy ra lỗi firewall/namespace hoặc lỗi quyền từ trường hợp này.

Đã báo cho operator trước khi sửa. Sửa nhỏ tại `browser_local.py`: giữ MCP/
exception cause đã redacted, giới hạn 4096 ký tự, trong lỗi outcome unknown.
Runner lưu cause chain; không đổi deadline, policy, deployment hay retry.
Regression kiểm tra timeout diagnosis, redaction, length cap và no replay.

BrowserMCP có [báo cáo click timeout tương tự](https://github.com/BrowserMCP/mcp/issues/115),
nhưng báo cáo đó **không chứng minh nguyên nhân của lần lỗi trên máy này**.
Không tăng timeout hoặc fork extension để che triệu chứng.

## 7. Tệp đổi và verification của đợt live

| Tệp | Lý do |
| --- | --- |
| `scripts/browser_local_live.py` | Runner nhận flags thật; JSON commands, approval envelope, gates, evidence, DENY/queued revoke/reset/cleanup. |
| `src/tools/mcp/browser_local.py` | Giữ lỗi MCP gốc redacted/bounded trong outcome unknown. |
| `tests/security/test_browser_local.py` | Regression chẩn đoán lỗi, redaction/cap/no replay. |
| `components/browser_mcp/README.md` | Cập nhật trạng thái live và link bằng chứng. |
| `components/browser_mcp/LIVE_TEST.md` | Báo cáo thực tế này. |

Sau sửa: **53 passed** trong local/controller/protocol/MCP integration tests;
Pyright ba tệp Python đổi: **0 errors, 0 warnings**. Suite **559 passed**
trong README là checkpoint trước đợt live; không cộng hai số hoặc tuyên bố
đã chạy lại toàn bộ suite. `git diff --check` và whitespace tệp mới đạt.
Deployment được verify lại sau cleanup. Không benchmark/live pentest.

## 8. Evidence artifacts

Root Windows: `D:\DOANTOTNGHIEP\kagent\artifacts\browser_mcp_live`.
Logs đã qua evidence redactor; không đọc Chrome profile cá nhân/credentials.

| Lượt | Thư mục | Nội dung |
| --- | --- | --- |
| Đầu | `20261009T182844-cbbd6ca8` | Navigate/snapshot thật, timeout được giữ, recovery, search click/type, DENY/reset/cleanup. |
| Xác minh | `20261009T184036-ef684d85` | Chuỗi đủ bốn tool same session, DENY, queued/new revoke, reset/exit. |

Mỗi thư mục có `events.jsonl` với timestamps/state/decisions. Lượt xác minh
có `01-navigate.txt`, `02-snapshot.txt`, `03-click.txt`, `04-type.txt`,
`06-snapshot.txt` (sau DENY). Đối chiếu độc lập raw events/artifacts đạt cho
PID/task/generation, refs/marker, DENY/revoke, reset/cleanup và no error ở
lượt xác minh. Artifacts nằm trong vùng git-ignored, không canonical results.

## 9. Phạm vi GO và giới hạn

GO chỉ cho trusted-local lab mode với điều kiện operator và scope đã xác
nhận. Stock WebSocket chưa authentication; loopback không bảo đảm profile/
tab identity. Chrome redirects/form/iframe/background traffic không được
cưỡng chế hoàn toàn bởi URL guards. Env tối thiểu không sandbox filesystem/
network host. Cancel/close không rollback action đã gửi. Khi response loss,
phải coi outcome unknown và kiểm tra lab trước operation tiếp theo.

Timeout welcome-banner còn là incident chưa xác định đầy đủ trong extension;
click/type lần sạch cũng chậm (24.265/26.702 giây). Không tuyên bố độ ổn định
cho mọi UI hoặc bảo đảm không gặp timeout. Không đổi networking/firewall,
không mở rộng target, không commit/push, giữ nguyên unrelated worktree changes.
