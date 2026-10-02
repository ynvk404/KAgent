# Kết quả triển khai từng phần — 02/10/2026

> **Implementation cuối của lượt sửa bổ sung:** [REPAIR.md](REPAIR.md),
> [runtime guide](../../../docs/yolo-execution-policy.md). Phần chính dưới đây
> giữ kết quả triển khai ban đầu để đối chiếu: worker HTTP/local stdio MCP/ffuf và
> verifier SQL hẹp đã được bổ sung sau đó. Đây không phải mốc trước checkpoint.
> Full YOLO vẫn chưa đạt; không suy all-class acceptance từ regression test count.

**Chưa đạt release full YOLO.** Có code và kiểm chứng cho policy chung, native
network, worker Linux offline, kiểm soát kết quả chưa xác minh và memory. MCP,
worker có mạng, credential/data-domain adapters và verifier thực cho từng lớp
lỗ hổng chưa hoàn thành. Không dùng blocked hoặc skip để coi benign controls của
những nhóm đó đã đạt. Các khoảng trống được giữ chặn và công khai theo yêu cầu.

## Checkpoint và bảo toàn công việc trước

- Branch riêng: `work/yolo-all-tools-2026-10-02`.
- Checkpoint trước triển khai: `b1057dcf7de9478c1649a35612d3bebeb3824303`;
  parent `9406a4d92139b1ff98e9f5f1a743a84701be1505`.
- Trước checkpoint: đối chiếu 362 hash với baseline audit, git status/index và
  lịch sử; chưa có sửa code sản phẩm ở lượt bị dừng. Checkpoint giữ A/B/C, M1,
  native YOLO trước đó và sáu SVG không liên quan. Đây là mốc trước triển khai,
  không phải snapshot đang dở.
- Backup: `artifacts/checkpoints/yolo-all-tools-2026-10-02/pre-implementation.zip`,
  100 file; SHA-256 `73265b75d284e7b95c32832b4f98369299b0845372fb3138755d0a44ccec18ee`.
- Chỉ commit checkpoint do operator yêu cầu. Code triển khai sau đó vẫn chưa
  commit. Không reset/clean, cài dependency, gọi model API hoặc push.

## File và hành vi thay đổi

| Nhóm file | Nguyên nhân và hành vi cuối |
|---|---|
| `src/permission/execution.py`, `permission.py`, `src/tools/registry.py` | Controller giữ profile và explicit revoke; freeze args/config, receipt một lần có deadline/revision/digest, recheck + reserve đồng bộ trước dispatch, gộp pending review và suppression DENY/cancel. ON tự duyệt tool được profile/adapter bao phủ; không dựa risk/phase/model labels |
| `src/permission/http_grants.py`, `network.py`, `src/tools/http.py` | Giữ M1 exact request và limits; ON bỏ yêu cầu review confirm-each, OFF phục hồi mode. Native transport pin numeric IP, Host/SNI giữ origin; constraints/deny khác authorization và được lưu trong journal. OFF/ON/resume không tự refill constraints của bound profile |
| `src/tools/web.py`, `content_discovery.py`, `service_discovery.py` | Fetch/search/native discovery dùng shared authority, rate/quota/slots, scope/revoke/cache recheck và response close. Search có role DDG riêng, không mở target scope; env proxy và automatic redirects không được nhận quyền trong controlled runtime. External ffuf/nmap chưa có adapter, bị chặn |
| `src/tools/file.py`, `src/agent/mentions.py` | Đọc/ghi theo lab root, protected control-plane roots; chặn traversal/symlink escape, ambiguous hardlink, FIFO/socket/device. Giữ A evidence snapshot/re-read gates và source metadata. Sensitive lab input thuộc profile tự chạy ON; OFF giữ review. Preview file_write hiển thị full content sau redaction |
| `src/permission/worker.py`, `src/tools/shell.py`, `plugin.py` | Worker dùng bwrap/prlimit đã cài: network/PID/user/mount namespaces, môi trường sạch, lab read-only, chỉ artifacts/worker writable; protected roots che khuất. Không dùng command denylist làm boundary khi worker hoạt động. Plugin cfg đóng băng; stdout/stderr được giữ bounded trong lúc đọc, cancel/timeout dừng process group |
| `src/tools/mcp_integration.py`, `src/cli/main.py` | Không launch MCP server với ambient host rights. Chưa có adapter thực nên startup/dispatched MCP trong bound runtime trả enforcement-unavailable. Linux worker không khả dụng cũng không fallback host shell/plugin; Windows/macOS chưa có worker |
| `src/permission/observations.py`, `src/tools/workflow.py`, `finding.py`, `coverage.py` | Ledger runtime giữ ID/epoch/digest/actual destination/status/body hash/completeness. Confirmed/negative cần trusted class verifier và observation khớp candidate. Proof giả giữ insufficient-evidence; model mark/performed không thành tested. Finding lấy observed impact/severity/excerpt từ certificate. Không có production class verifier được đăng ký trong bản này |
| `src/agent/agent.py`, `system_prompt.py`, `src/intelligence/store.py`, `src/engagement/state.py` | Summary, memory catalog, recalled intelligence và workflow values vào turn dưới dạng untrusted data, không promote SYSTEM. Automatic learning chỉ project observed-summary với confidence giới hạn; không tự personal/user-preference. Resume không mint rights từ summary và giữ controller deny/constraints |
| `src/tools/permission_status.py`, `ask.py`, `src/skills/load_skill.py`, `src/ui/commands/slash_handler.py`, `slash_items.py`, CLI help | `/permissions` xem/điều chỉnh profile, revoke/restore/retry. permissions_status chỉ đọc; skill load kèm runtime authority guidance. Equivalent input question pending/cancelled trả pending; câu trả lời thật được reuse trong cùng profile, không bịa OTP/approval. Missing-input UI không phải permission grant |
| `tests/security/test_execution_policy.py`, `test_offline_worker.py`, `test_yolo_results_resume.py`, `test_yolo_memory_transport.py`; tests agent/data/UI/M1 liên quan | Desired assertions thay các kỳ vọng phase/confirm-each auto-review, model preference promotion và SYSTEM memory. Trước sửa được giữ trong checkpoint/audit. New tests gồm cả positive pentest và forbidden-action controls; fixture verifier không được tính là production vuln verifier |
| `docs/yolo-execution-policy.md` và báo cáo audit này | Cách sử dụng, thay đổi hành vi và release blockers theo code cuối; kết quả lịch sử được giữ riêng |

## Hành vi mode và quản lý quyền

| Tình huống | ON | OFF |
|---|---|---|
| Native HTTP, endpoint/params/payload/method mới trong declared scope | Tự chạy, không cần `/permissions grant` | Exact review/manual autonomous rights/confirm-each theo policy |
| Native discovery/fetch/search trong role được bao phủ | Không permission dialog | Ordinary gates/cache trước đây, independent policy vẫn kiểm |
| Lab source/wordlist/payload/evidence và artifact hợp lệ | Không permission dialog | Sensitive/write gates thông thường |
| Shell/plugin offline trong worker Linux thực | Không permission dialog | Exact effective action review |
| MCP, scanner process, generic host execution không có adapter | Blocked 0 dialog; **benign acceptance chưa đạt** | Cũng blocked, approval không tạo sandbox |
| Outside scope/root, deny/revoke, receipt/budget hết hiệu lực | Blocked trước dispatch, không mở dialog | Tương tự |
| Model claimed confirmed/negative, chưa trusted verifier | Giữ evidence/candidate insufficient-evidence | Tương tự; **luồng canonical finding chưa bảo toàn đầy đủ** |

Operator controls chi tiết: [docs/yolo-execution-policy.md](../../../docs/yolo-execution-policy.md).
`/permissions show`, `limits <calls> <concurrency>`, `revoke-tool <name>`,
`restore-tool <name>`, `deny`, `revoke <grant-id>`, `retry <origin>`, `retry-tools`,
`network-refresh`; manual `grant`/CLI lab grant chỉ là lựa chọn điều chỉnh.
Không suy bulk-delete-safe/test-object-safe từ broad grant hoặc từ method.
Native defaults giữ 500/20min/3s/burst3/concurrency2/request128KiB/response64KiB;
controller defaults 10.000 calls, concurrency16. Constraints khác receipts/rights.

## Ma trận acceptance: kết quả thật, không gộp partial thành pass

| ID | Trạng thái | Bằng chứng / phần thiếu |
|---|---|---|
| A01/A02/A04 | Đạt phần native | Method/phase/new endpoint/mutation/payload giữ bytes; ngoài exact origin không send; unknown effects được chấp nhận, không hứa an toàn app |
| A03 | Một phần | Arbitrary authorized auth/IDOR request vẫn gửi được; chưa có actor/credential handle adapter và ownership guarantee |
| A05 | Đạt native | Discovery shared deny/revoke/quota; native paths 0 dialog |
| A06 | Một phần | Native socket backend có shared authority; ffuf/nmap worker benign controls chưa chạy được |
| A07/A08 | Một phần | Fetch/search mock và fetch/native HTTP loopback thật; resource closure/pin/cache/revoke. Chưa approved redirect/proxy graph, source-domain export hoặc OAST |
| A09/A10/A11 | Một phần | Allowed input/evidence/artifact source paths giữ hoạt động; ngoài root/protected/symlink/hardlink/IPC bị chặn. Chưa import handles/root UI và OS-open race-proof broker |
| A12/A13 | Một phần | 6 test worker Linux thật: source/wordlist/payload/artifact/plugin tự chạy; host/protected reads, direct host socket, child persistence, hardlink/IPC bị chặn. Shell/plugin tới lab network chưa hoạt động |
| A14/A15 | Chưa đạt | MCP được chặn trước launch/dispatch; chưa positive real stdio/upstream adapter |
| A16/A17 | Một phần, release blocker | Forged proof của 15 class bị hạ insufficient-evidence, model coverage không counted tested; trusted fixture callback chứng minh contract positive. Không có SQLi/XSS/auth/IDOR/etc production verifier; canonical confirmed và negative/whole-target completion bị hạn chế |
| A18/A19 | Một phần | Memory/workflow dữ liệu không SYSTEM; project-only observed learning, journal revokes/quota không receipts, fake model client kiểm actual turn. Chưa typed observation/verifier fact persistence/retraction/personal promotion |
| A20 | Một phần | Skill gates giữ; runtime query/read-only guidance; OTP thật được coalesce. Không semantic-dedup mọi unstructured ask_user variant |
| L02–L08 | Đạt các đường đã kiểm | OFF review/DENY, ON confirm-each 0 dialog/OFF restore, args/plugin cfg freeze, scope change stale, revoke/deny journal, cancellation suppression, receipt forge/replay/expiry |
| L09–L12 | Một phần | HTTP concurrent quota, operation budget và bounded existing waits/cancel; legitimate repeated calls không dedup sau success. Chưa network/process-tree broker accounting toàn bộ generic tools |
| L13–L16 | Một phần | Numeric native transport/cache binding và no-env-proxy loopback; redirect outside không follow. First DNS binding, all integration routes/data-domain/aggregate quotas còn thiếu. Unsupported environment blocked không fallback |
| L01/P6 | **Chưa đạt** | Không có orchestration mọi nhóm tool tự pentest lab + confirmed findings 0 dialog; không công bố full release |

## Kiểm chứng

Runner offline: `venv-linux/bin/python artifacts/audits/yolo-all-tools-2026-10-02/run_implementation.py`.
Final output riêng `implementation-results.xml`; focused output riêng
`implementation-focused-results.xml`. Kết quả lịch sử `results.xml`,
`test_current_boundaries.py`, `baseline.json` không được ghi đè và không được
chạy như desired security acceptance sau sửa. Chi tiết con số/checks cuối được
lưu trong `implementation-verification.json` sau khi mọi lệnh hoàn tất.

Các group regression: security, tools, data, agent, UI, runtime, state, skills,
browser. Model integration/benchmark/live tests không được chạy; secret và
accounts đều fixture giả. Loopback HTTP và bwrap/process tests là thật, không
thay actual OS isolation bằng mock. `pyright` dùng venv-linux hiện có; không
update dependency. `git diff --check` chỉ so với checkpoint; sáu whitespace cũ
trong SVG đã ở checkpoint không bị sửa để làm đẹp kết quả.

## Việc tiếp theo cần thiết để hoàn thành thiết kế

1. Worker có network broker và resource mount/import contract; real Windows/
   WSL/VM lifecycle + executable/config generation pinning, aggregate quotas,
   scanner và stdio MCP startup isolation. Approved lab shell/curl/plugin/MCP
   benign controls phải chạy được trước P6; không bỏ blocked bằng ALLOW.
2. Actor/credential handles, trusted export/data-domain lanes và release
   procedure; configured research/OAST/proxy graph. Không kiểm keyword/encoded
   secret matching để tuyên bố full egress prevention.
3. Class-specific verifiers/capture/harness cho các lớp đã hỗ trợ; actual
   shell/MCP/browser proof import, negative/performed/cleanup observations,
   epoch-bound persistence và whole-target completion theo verified facts.
4. Typed memory/provenance, operator-only preference promotion/retraction,
   stable issue lineage/UI cho các input variants và release orchestration A/L
   đầy đủ. Existing coarse model maxsteps không chứng minh progress semantics.

Hiện chưa giải quyết toàn diện egress, finding semantics, compact/learning
poisoning, first DNS binding/rebinding ở mọi route, filesystem races hay sandbox
trên mọi nền tảng. Các API library không bind ExecutionPolicy giữ legacy gates
và không thuộc bảo đảm của CLI profile. Broad lab quyền vẫn có thể chứa hành
động do injection đề xuất nhưng nằm trong quyền; code không xác định mọi tác
động thật phía server. Test pass không chứng minh chống prompt injection toàn diện.


## Kết quả sau triển khai — 02/10/2026 (bổ sung, giữ lịch sử phía trên)

Đã triển khai và kiểm chứng **một phần** thiết kế. Không công bố full YOLO:
MCP, network worker/scanner, data-domain/credential adapters và production
class verifiers chưa hoàn thành; những đường thiếu enforcement được giữ chặn.
Các mục trước phần bổ sung này là kết quả **trước sửa**, không phải mô tả code cuối.

Chi tiết file, hành vi ON/OFF, operator controls, hạn chế chức năng và ma trận
acceptance: [IMPLEMENTATION.md](IMPLEMENTATION.md),
[hướng dẫn runtime](../../../docs/yolo-execution-policy.md).

Kiểm tra offline cuối: **2.429 passed, 1 skipped** trong regression security/
tools/data/agent/UI/runtime/state/skills/browser; **7 passed** bổ sung cho native
YOLO không manual grant, phase không tự mở quyền khi OFF và common receipt hết
hạn. 7 case này được thêm sau regression và có output focused riêng, không
cộng trùng các lần rerun. Pyright toàn src/tests: **0 errors, 0 warnings**;
`git diff --check`: đạt. XML/check metadata ở
[implementation-results.xml](implementation-results.xml),
[implementation-focused-results.xml](implementation-focused-results.xml),
[implementation-verification.json](implementation-verification.json).

Loopback HTTP và worker Linux offline được kiểm bằng thực thi thật; model client,
upstream web/search và secrets dùng fixture/mock. Fixture verifier chỉ kiểm
contract, không được gọi là verifier SQLi/XSS/auth/IDOR thực. Bằng chứng trước sửa
`results.xml`, `test_current_boundaries.py`, baseline và ZIP vẫn giữ nguyên.

Checkpoint trước triển khai: `b1057dcf7de9478c1649a35612d3bebeb3824303` trên branch
`work/yolo-all-tools-2026-10-02`. Các sửa đổi triển khai chưa commit; không push,
reset/clean, cài dependency hay gọi model API. Scope/deny/limits khác auto-review;
grant rộng không chứng minh tác động ứng dụng an toàn. Test pass không chứng minh
chống prompt injection toàn diện. **L01/P6 chưa đạt**, các A/L partial và release
blockers được liệt kê rõ trong IMPLEMENTATION.md.


## Sửa bổ sung và startup — 02/10/2026, giữ kết quả lịch sử

Implementation hiện tại và ma trận acceptance chi tiết: [REPAIR.md](REPAIR.md).
Đã sửa managed evidence re-read với protected CLI roots; scoped plaintext HTTP
broker cho Linux shell/plugin/compatible fresh stdio MCP và ffuf; exact DENY;
discovery response cap; browser scope views; narrow production SQL boolean/JSON
verifier; protected historical result persistence; operator proof review có nhãn.
Startup worker dùng scratch `/tmp`, không quét project để chạy `/bin/true`; real
dispatch vẫn inspection fail-closed. Bỏ splash dwell cố định 5 giây.

Regression cuối chạy tuần tự: **2.692 passed, 1 skipped**, 2 malformed-config
fixture warnings; focused startup/guidance **184 passed**. Pyright src/tests:
**0 errors, 0 warnings** (chỉ có thông báo phiên bản mới, không cài). Diff check đạt.
Artifacts: `repair-2026-10-02/regression-final-serial.xml`, `startup-and-guidance.xml`,
`startup-timing.json`, `pyright-final.txt`, `repair-final-verification.json`.

Live lịch sử trước chỉ dẫn dừng: 1 session/4 DeepSeek attempts, native HTTP và
shell HTTP control thành công, 0 permission dialogs/manual grants. Missing usage
ở một helper response đã dừng sớm; upper accounting $0.004865112 gồm reservation,
không phải actual invoice. **Không chạy thêm live pentest/API trong lượt cuối.**

Chưa full YOLO: nmap/raw/CONNECT/remote hoặc persistent/env MCP, actor/export,
autonomous all-class positive/negative/cleanup completion, complete egress,
typed memory/retraction, all-route DNS, filesystem races, aggregate cgroups và
non-Linux sandbox chưa đầy đủ. 15 lớp chỉ kiểm human-review workflow; không được
coi là 15 auto verifiers. L01/A03/A15 và full A16/A17 chưa đạt. Không dùng số test
pass hoặc tên worker để tuyên bố bảo toàn mọi luồng/chống prompt injection toàn diện.
Không commit/push/reset/clean/cài dependency. Checkpoint HEAD giữ nguyên.

## Bổ sung lỗi đứng giao diện sau checklist file/shell — 02/10/2026

Sau checkpoint `6100830915d5cf23ac7b9ebe55211e969bcbb48f`, probe offline phát
hiện actual dispatch vẫn gọi `OfflineWorker.wrap()` đồng bộ: quét cả project
trên event loop của Textual. Startup scratch probe không giải quyết đường này.
Metadata phiên người dùng cho thấy file_write/file_read đã xong, tiếp theo là
shell rồi file_read và câu trả lời hoàn tất; không đọc/in nội dung riêng của phiên
và không đóng tiến trình đang mở. Chưa có live stack để khẳng định mọi lần đứng
đều cùng nguyên nhân.

Đã thêm `OfflineWorker.prepare()` để kiểm tra filesystem bằng thread riêng,
ngân sách kiểm tra 120 giây, nhận cancellation và kiểm tra lại receipt/revision
trong lúc chờ và trước trả lệnh. Shell/plugin/MCP/ffuf đều dùng đường này. Root/
output được kiểm tra lại sau chuẩn bị; ffuf tính lại thời gian còn lại trước launch.
Không bỏ kiểm tra hardlink/FIFO/device, không cache kiểm tra, không nới quyền hoặc
thêm host fallback. Thread đang kẹt trong syscall có thể còn sống đến khi syscall
trả về; nó chỉ kiểm tra file và không khởi chạy tiến trình.

Chi tiết probe trước/sau và kiểm chứng cuối được ghi riêng tại
[worker-responsiveness-2026-10-02/RESULTS.md](worker-responsiveness-2026-10-02/RESULTS.md).
Phép đo read-only trên project thật `/mnt/d` mất 106,218 giây nhưng heartbeat chạy
2.109 lần, khoảng cách lớn nhất 0,073 giây. Đây là khắc phục khóa event loop,
không phải tăng tốc quét toàn bộ virtualenv. Phiên đang chạy phải được operator
khởi động lại để nạp code mới. Không gọi model API/live pentest, cài dependency,
commit hoặc push trong lượt sửa này; kết quả lịch sử phía trên được giữ nguyên.

### Prune dependency/cache và sửa cancellation HTTP — bổ sung cùng ngày

Theo yêu cầu bổ sung, `OfflineWorker.wrap()` prune trực tiếp `folders[:]` cho
10 tên thư mục dependency/cache tại mọi cấp. Các cây không được kiểm tra bị
mount thành thư mục rỗng read-only trong worker; không chỉ bỏ lstat mà vẫn cho
process đọc unchecked FIFO/socket/hardlink. Source/payload/wordlist ngoài các
cây này tiếp tục được kiểm tra và sử dụng; worker không sử dụng executable/file
trong excluded tree. Symlink tại excluded directory bị chặn rõ ràng. Native file
tools giữ policy cũ. Probe cùng project sau prune: **1,340 giây**, heartbeat gap
tối đa **0,051 giây**; kết quả 106,218 giây trước prune được giữ để đối chiếu.

Nguyên nhân HTTP được báo trước khi sửa: `authorize()` ghi cả cancellation/lỗi
vào `_declined_actions` theo request digest; Registry ghi cancelled/refused vào
`_denied` theo args digest. Cache sống quá invocation/turn và có thể chặn request
mới sau YOLO toggle. Private gate cũng pause origin khi cancelled. Không phải
grant/revoke bền vững do operator chủ động cấp, và các cache lỗi này không được
khôi phục từ journal; đây là state trong runtime đang mở.

Đã thêm review context do controller tạo ở `Agent.run()`; Registry và direct
HTTP ngoài Agent có scope riêng. Chỉ explicit exact DENY được chống hỏi lặp theo
turn; cleanup chỉ xóa các key thuộc turn vừa kết thúc. Cancellation/exception/
timeout không bị ghi thành DENY; cancel private gate không pause origin. HTTP
receipt còn ràng buộc invocation ID mới, bị retire riêng khi không dùng; HTTP
chờ/gửi/đọc nhận cancellation từ UI và đóng response/trả slot. Giữ private-host
DENY thật, broad-grant decisions, deny phiên, revoke, scope, giới hạn và accounting;
không clear mọi operator decision, không reset budget khi đổi turn/bật YOLO.

Test toàn chuỗi dùng whole-target Agent với model giả, registry/policy thật và
mock transport; không gọi API hoặc live target. Chi tiết kiểm chứng cuối và các
giới hạn nằm trong [RESULTS.md](worker-responsiveness-2026-10-02/RESULTS.md).

Regression mở rộng cuối: **2.756 passed, 1 skipped**, 2 warning fixture malformed
config; skip là live-model characterization chưa được bật. Sau chỉnh callback
cleanup chỉ về type return, HTTP/policy/resume focused cuối **162 passed**.
Không cộng số rerun vào tổng; XML trước lần sửa assertion cancellation cũ được
giữ riêng. Pyright/diff-check cuối và metadata: `worker-responsiveness-2026-10-02/`.
Pyright **0 errors, 0 warnings**; `git diff --check` đạt. Không cài bản pyright mới
theo version notice; không commit/push, HEAD checkpoint giữ nguyên.
