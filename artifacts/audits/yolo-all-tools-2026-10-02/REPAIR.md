# Sửa và kiểm chứng bổ sung — 02/10/2026

> Kiểm checklist 3–8 theo yêu cầu operator: **570 selected regression + 3 real
> OFF/ALLOW worker probes đạt**, không failure/skip; pyright và diff check đạt.
> [Checklist results](checklist-20261002-202635/CHECKLIST-RESULTS.md) nêu phạm vi và
> phần chưa kiểm chứng. Không sửa sản phẩm hoặc gọi thêm model/live target.

> UI bổ sung theo yêu cầu sau bàn giao: CLI đặt `show_splash=False`, mở thẳng
> giao diện nhập lệnh. Runtime/worker/provider/session initialization vẫn giữ.
> Test CLI thật có thêm assertion không mount splash và input/transcript hiển thị.
> Kết quả kiểm chứng riêng ở `repair-2026-10-02/no-splash-results.xml`.

Trạng thái cuối của lượt sửa bổ sung: **chưa đạt full YOLO**. Đã sửa lỗi evidence
với cấu hình CLI thật, thêm broker HTTP cho worker và MCP stdio tương thích,
khôi phục một hợp đồng xác minh SQLi cụ thể và đường duyệt kết luận bằng chứng
cho operator. Các lớp khác chưa được khôi phục xác minh tự động đầy đủ.
Startup worker không còn quét toàn dự án; splash không còn chờ cố định 5 giây.

## Mốc đối chiếu và phạm vi lượt này

- Branch: `work/yolo-all-tools-2026-10-02`.
- HEAD/checkpoint trước đợt triển khai lớn vẫn là
  `b1057dcf7de9478c1649a35612d3bebeb3824303`. Không tạo commit mới hoặc push.
- Trước lượt sửa bổ sung, worktree đã có implementation YOLO chưa hoàn chỉnh.
  `repair-2026-10-02/before-repair-manifest.json` ghi SHA-256 của trạng thái đó;
  `before-repair-redacted.diff` và ZIP giữ bản xem xét đã redact. ZIP **không phải
  bản backup byte-for-byte**; originals được giữ tại workspace, không reset/clean.
- Nội dung chính của IMPLEMENTATION.md mô tả đợt triển khai trước lượt sửa này,
  không phải toàn bộ trạng thái checkpoint. Kết quả 2.429 + 7 test là lịch sử.
- A/B/C và M1 được giữ: source permission trước đọc sensitive, Response lifecycle,
  preview shell/MCP đầy đủ có redact, quyền operator thay phase-based HTTP approval.
- Theo chỉ dẫn cuối: không chạy thêm live pentest hoặc DeepSeek. Kiểm chứng mới
  chỉ offline fixture/mock/loopback, từng tiến trình test/typecheck chạy tuần tự.

## Các thay đổi sản phẩm và cách phối hợp

| File / hàm chính | Nguyên nhân, hành vi sau sửa |
|---|---|
| `src/permission/execution.py`: `default_execution_policy`, `require_evidence` | Dùng chung protected roots với CLI. Managed snapshot trong `.kagent/evidence` được đọc qua đường nội bộ có receipt/source/hash binding; generic file read không được mở toàn `.kagent` |
| `src/cli/main.py` và runtime được tách ở `src/cli/runtime.py` | Giữ CLI wiring thật, factory policy chung; runtime khởi tạo worker qua capability probe nhỏ. Việc tách main/runtime đã tồn tại trước lượt sửa bổ sung |
| `src/workflow/evidence.py` | Capture/re-read giữ source path, kiểm sensitive và digest; snapshot/đổi đuôi không tự mất giới hạn |
| `src/permission/http_grants.py` | DENY/cancel request gắn exact action digest, không vô tình deny toàn origin; revoke/deny phiên vẫn riêng |
| `src/tools/content_discovery.py` | Reader tôn trọng response cap của policy, đóng response; ffuf chạy qua worker/proxy có accounting thật |
| `src/permission/worker.py`: `available`, `wrap` | Linux bwrap/prlimit giữ filesystem/network/process isolation. Startup probe chạy `/bin/true` trong tree nhỏ ở `/tmp`; real dispatch vẫn kiểm project hardlink/IPC/device, lỗi kiểm tra bị chặn |
| **Mới** `worker_broker.py`, `worker_relay.py` | Controller HTTP broker qua UDS và relay trong namespace. Direct network bị cấm; plaintext HTTP kiểm scope, pinned transport, shared budget/revoke trước send |
| `src/tools/shell.py`, `src/tools/plugin.py` | Worker offline hoặc HTTP broker có receipt; không fallback host. Shell description phản ánh worker/broker, không mô tả đã sandbox mọi giao thức |
| `src/tools/mcp_integration.py`: `MCPSession`, `OwnedMCPSession`, `MCPTool.freeze_for_execution` | Freeze server/args, stderr file đúng SDK, context mở/đóng trong cùng owner task. Mỗi invocation khởi động server stdio mới trong worker/broker; config env export chưa có adapter nên chặn |
| **Mới** `src/permission/verifiers.py`; sửa `observations.py` | Production SQL boolean-query/JSON-row contract; lưu bounded observations và chứng nhận kết luận trong protected sidecar. Hash/ID không bị redactor làm hỏng; narrative vẫn redact |
| `src/tools/workflow.py`, `src/agent/agent.py` | Terminal result/coverage/completion cần certificate khớp candidate/proof. Legacy model terminal claims không tự đủ để hoàn tất |
| `src/ui/commands/slash_handler.py`, `slash_items.py`, `src/cli/help.py` | `/review-result` cho operator kiểm bằng chứng/kết luận; help và `/yolo on` cập nhật adapter thật, không hứa mọi scanner/MCP đã chạy được |
| **Mới** `src/browser/scoped_store.py`; sửa `browser_capture.py` | Filter/get/clear theo origin/revoke; không biến imported capture thành browser-execution hoặc actor proof |
| `src/agent/system_prompt.py`, `src/skills/load_skill.py` | Guidance dùng runtime rights; ON không cần confirm-each execution dialog, OFF giữ review. Guidance không phải ranh giới enforce |
| **Mới** `src/llm/validation_budget.py`; sửa `transport.py` | Opt-in paid-validation ledger: reserve trước attempt, retry cũng tính, reconcile usage, missing usage giữ reservation và dừng. Không thay model/limits ở cấu hình thông thường |
| `src/ui/core/app.py`: `_run_startup_sequence` | Các readiness phases phản ánh khởi tạo đã xong; bỏ cosmetic sleeps 0,8 + 3,4 + 0,8 giây, mở input ngay |

Agent có active-skill tool gate trước khi gọi Registry. Trong `Registry.execute`,
thứ tự thực tế: resolve tool → freeze executor config/deepcopy args → bind browser
policy nếu cần → `prepare` (resource precheck/receipt) → `_execute` deepcopy và
argument validation. Tool thường đi qua ordinary approval hoặc ON auto-approval
rồi `start` (receipt/revision/revoke, reserve common budget) → executor/nested
network/file/evidence gates → result → `stop` trong finally. Nhánh native HTTP
`AuthorizedExecutionTool` gọi `start` rồi `run_authorized`, dùng exact request
authorization/accounting riêng tại executor, không generic Registry approval.
Common receipt không thay network grant. Schema/argument và skill checks nằm ở
các lớp tương ứng; không đổi thứ tự thực tế thành sơ đồ thiết kế lý tưởng.
Approval chỉ cho chạy hành động đã chốt; không mở scope, tài nguyên hay verifier.

Tests mới ở `tests/security/test_cli_evidence_repair.py`,
`test_cli_repair_entrypoint.py`, `test_repair_runtime.py`, `test_repair_controls.py`,
`test_worker_startup.py`; các test cũ được giữ/cập nhật behavioral expectations.
Scripts/XML/ZIP/JSON trong `artifacts/` chỉ hỗ trợ audit, không được import để cấp
quyền hoặc xác minh finding ở runtime. `docs/yolo-execution-policy.md` là hướng dẫn.

## YOLO và điều khiển operator hiện có

| Nhóm | ON | OFF | Giới hạn độc lập |
|---|---|---|---|
| Native HTTP, discovery, fetch, configured search | Trong profile tự chạy, không `/permissions grant` | Ordinary review/quyền thủ công còn hợp lệ; nhóm không yêu cầu permission giữ hành vi thông thường | Exact origin/role, deny/revoke, request/rate/concurrency/byte limits, transport checks |
| File/source/payload/wordlist và managed evidence | Approved lab input/artifact tự chạy | Sensitive/write reviews hiện có; quyền phù hợp vẫn cho dùng | Protected controller roots ưu tiên, source provenance/hash, receipt |
| Shell/Bash/plugin Linux | Offline và broker-compatible plaintext HTTP tự chạy | Review effective command/config/args | Namespaces/read-only mounts, direct sockets bị cấm; bounded output/process resources |
| Local stdio MCP tương thích | Auto chạy invocation trong worker/broker | Review server/tool/args thực | Server mới mỗi call; không ambient env, remote/persistent state chưa hỗ trợ |
| ffuf | Adapter HTTP chạy trong full tooling/runtime discovery-gap contract | Ordinary review | Proxy explicit, shared network budget, worker bounds |
| nmap/raw TCP, CONNECT, remote MCP hoặc thiếu worker | Chặn rõ lý do | Cũng chặn | Không có enforce adapter thì approval không tạo fallback |
| Finding/coverage | SQL contract đã có có thể tự chứng nhận; lớp khác cần verifier hoặc `/review-result` | Cùng yêu cầu proof | Human conclusion review vẫn có một lần, không được gọi là zero-dialog autonomous verification |
| Tool metadata/workflow/coverage/memory khác | Auto-approve khi profile cho phép; vẫn validate independent gates | Ordinary policy theo tool | Các thao tác trust/rights không mở cho model; unsupported terminal claims không promoted |

Profile mặc định: các origin operator đã xác lập, lab project read root, artifact
write roots, protected runtime/control-plane paths; configured public research
role riêng. Không tự mở home/provider keys/browser profile cá nhân. HTTP defaults
mỗi origin: 500 request/20 phút, 3/s burst 3, concurrency 2, request 128 KiB,
retained response 64 KiB. Common calls: 10.000, concurrency 16. Đây là hạn mức
thực thi, không suy luận request hay tác động ứng dụng an toàn.

- `/yolo on` / `off`: mode duyệt; đổi mode invalidate queued receipts, không gỡ revoke/refill.
- `/permissions show`: roots, adapter trạng thái, common limits và HTTP rights.
- `/permissions limits <calls> <concurrency>`: thay common limits.
- `/permissions grant <ORIGIN,MODE,SECONDS,REQUESTS,RATE,BURST,CONCURRENCY,REQUEST_BYTES,RESPONSE_BYTES>`:
  tùy chọn operator để thay HTTP limits/ordinary policy; ON không bắt buộc dùng.
- `/permissions revoke-tool <name|*>`, `restore-tool <name|*>`: revoke/restore tool hoặc phiên.
- `/permissions deny`, `revoke <id>`: deny network/revoke grant; `retry <origin>` mở lại vấn đề tương ứng.
- `/permissions retry-tools`: mở lại exact declined/cancelled review; không xóa durable revoke.
- `/permissions network-refresh`: re-vet DNS; không refill budget hoặc mở scope.
- `/review-result <candidate-id> <confirmed|not-confirmed> <severity> <observed impact>`:
  duyệt proof và conclusion, sau đó mới record result; luôn gắn nhãn operator-reviewed.

DENY một action không thành deny phiên. Repeated equivalent denied/cancelled issue
bị suppress; pending equivalent review được coalesce, không dùng chung one-use
receipt. Scope/target/mode thay đổi hoặc revoke khiến receipt cũ mất hiệu lực.
Resume giữ constraints/deny và chứng cứ lịch sử trong protected sidecars, không
khôi phục quyền/receipt từ summary, memory hay observation certificate. ON mới
được xác lập bằng invocation/UI tin cậy; gửi rồi thì revoke không rollback server.
Missing account/OTP là thông tin thật, không được tự bịa; hỏi thông tin không đồng
nghĩa với hỏi quyền. Arbitrary model questions vẫn chưa có lineage UI hoàn chỉnh.

## Các luồng pentest: đã kiểm và còn thiếu

Recon/enum/native HTTP/new endpoints, arbitrary authorized mutation/payload,
source/wordlists/artifact và snapshot/re-read có offline regression. Real Linux
shell/plugin/stdio MCP plaintext HTTP và ffuf chạy tới loopback lab; outside origin,
host key/protected paths/direct sockets và revoke có negative controls. Search và
fetch dùng library fixtures, không gọi upstream thật ở regression này.

SQL contract đã kiểm end-to-end: nhiều runtime request true/false → observations
→ managed evidence → verifier → verified result → coverage → canonical finding
→ protected certificate resume. Contract chỉ hỗ trợ lặp boolean predicate trong
query và JSON `data` rows/no-rows; không bao trùm time/error/union SQLi hoặc chứng
minh backend SQL causality trên target cố ý lừa. Không đủ proof trả insufficient,
không auto ghi negative hoặc confirmed từ lời model.

Inventory `skill-inventory.json` đối chiếu 19 SKILL bodies giữ nguyên so checkpoint;
một file là template, không được tính là lớp có runtime support. Giữ playbook
không chứng minh luồng end-to-end vẫn autonomous:

| Lớp | Auto verifier shipped | Đường bằng chứng/kết luận đã kiểm |
|---|---|---|
| SQL injection | Có, duy nhất boolean query/JSON rows nêu trên | Real fixture differential → canonical finding; các kỹ thuật khác cần adapter/review |
| XSS | Chưa | Human proof review → coverage/finding; chưa trusted browser execution/source-sink verifier |
| Access control, authentication | Chưa | Human review route; chưa actor/credential/IDOR boundary adapter |
| CSRF, SSRF, SSTI, XXE | Chưa | Human review route; chưa per-class execution/OAST verifier |
| Path traversal, command injection, file upload | Chưa | Human review route; chưa trusted filesystem/process/resource proof contract |
| NoSQL injection, JWT, CORS, open redirect | Chưa | Human review route; chưa per-class positive/negative runtime verifier |

15 lớp có test **workflow của operator review**, không phải 15 vulnerability
verifiers. Proof fixture ở các test review chỉ chứng minh mechanics/labeled human
decision, không chứng minh ứng dụng mắc lỗi. Imported evidence vẫn là unverified
trước review. Old finding files không xóa; old claims thiếu certificate không đủ
để newly sync terminal coverage/completion. Không có migration toàn bộ legacy rows.

Whole-target completion vẫn thiếu trusted phase-performed/negative/cleanup/actor
evidence. Ví dụ XSS có HTML/script echo không tự chứng minh JS đã chạy; IDOR thấy
JSON không tự chứng minh object thuộc actor khác. Human review khôi phục đường
lập report hợp lệ có người kết luận, nhưng không đạt yêu cầu tự hoàn tất mọi lớp
với zero dialogs. Không hạ chuẩn finding để làm coverage xanh.

## Startup: lỗi mới và phạm vi khắc phục

Before: `OfflineWorker.available()` gọi `wrap()` trên project, `os.walk(root)`
duyệt cả `venv-linux` trước UI. Timeout cũ chỉ bọc `proc.wait`. Người dùng báo đo
92,8 giây trên `/mnt/d`; không chạy lại quét cũ để tái tạo con số đó.

After: scratch tree cố định dưới Linux `/tmp`, dùng cùng bwrap/prlimit mounts và
`/bin/true`; timeout 5 giây bao gồm subprocess create/wait, cancellation/timeout
kill và reap. Không mở network/model. Khi chạy tool thật vẫn `wrap()` trên lab
root và fail closed khi inspection lỗi, hardlink/IPC/device bị phát hiện. Startup
availability chỉ chứng minh kernel/tool capability, không chứng minh mọi project
sẽ qua resource preflight. Không có host fallback nếu unavailable.

Ba lần đo mới: 0,01724 / 0,02068 / 0,01647 giây, available=true, project vẫn trên
`/mnt/d`; worker-module imports 0,302 giây trong lần chạy này. Đây là phép đo
capability check và cache trạng thái hiện tại, **không là cold full-CLI timing**.
`startup-timing.json` ghi phạm vi. Splash không thêm 5 giây; test coroutine chứng
minh không còn await cosmetic sleeps. Không tuyên bố toàn CLI mở trong 0,02 giây.

Virtualenv **chưa chuyển**, dependency không cài. Giữ `venv-linux` đang dùng để
không làm hỏng shebang/pyright/launcher giữa lượt sửa. Bước môi trường riêng nên
tạo/recreate environment ở `~/.venvs/kagent`, cập nhật launcher và pyright rồi
verify imports; không chỉ `mv` virtualenv vì absolute shebang có thể trỏ đường cũ.
Real dispatch vẫn quét toàn lab input tree nên có thể chậm với tree lớn; chưa
thêm cache dễ bỏ lọt file mới hoặc bỏ qua venv khỏi sandbox admission.
Timeout là async operation deadline; kernel/filesystem stalls và cleanup không
được hứa có hard wall-clock bound tuyệt đối.

## Kiểm chứng và lịch sử

- Evidence trước sửa: `evidence-before.xml` **2 failed, 2 passed** (ordinary
  CLI-managed snapshot lỗi khi ON/OFF); sau sửa `evidence-after.xml` **19 passed**.
- Regression lịch sử có lỗi thật của worker NPROC và SDK/fixtures; XML giữ nguyên.
  Real-UID NPROC 256 tính cả host IDE/WSL threads làm spawn thất bại ngay cả tuần tự.
  Default hiện 1024 vẫn hữu hạn; không gọi đó là per-worker/cgroup process quota.
  Shell AS 512 MiB, CPU 120 s, file 16 MiB/nofile128; ffuf trusted profile AS 4 GiB,
  GOMAXPROCS2/GOMEMLIMIT128 MiB soft. Không có aggregate memory/disk/cgroup bound.
- Lần broad trước sửa startup: **2.685 passed, 1 skipped**, giữ thông tin trong báo
  cáo này; XML broad cuối được runner cập nhật. Focused sau đó bắt được assertion
  shell-description cũ: **70 passed, 1 failed**; expectation đã sửa theo broker thật.
- Startup/guidance/security focused mới: **184 passed**, `startup-and-guidance.xml`.
- Regression rộng cuối: **2.692 passed, 1 skipped, 2 warnings** trong 87,54 giây.
  Skip là live opt-in cũ; warnings từ malformed-config fixtures. Pyright và diff
  check: xem `repair-final-verification.json` cùng
  `regression-final-serial.xml` / `pyright-final.txt` (chạy tuần tự). Không cộng
  số test rerun hoặc fixture review thành số luồng pentest tự động.

Đợt live **đã thực hiện trước chỉ dẫn dừng**, không chạy thêm lượt này:
configured model `deepseek-flash`, max_tokens=null không đổi, 1 session/4 API
attempts gồm startup/helper, chưa đủ 5 trial vì thiếu usage ở một helper response.
3 response có usage: prompt 21.406, completion313, total21.719; cache hit10.752,
miss10.654. Known peak-price upper estimate $0,003636312; giữ reservation $0,0012288
cho missing usage → ledger upper accounting **$0,004865112**, không phải invoice
thực. `unknown_usage=true` đã dừng; không mở phiên thứ hai/attempt thứ năm. Kết quả
CLI thật: native HTTP200 một model tool call và shell HTTP control thành công,
0 permission dialogs/0 manual grants. Không kiểm live 15 lớp/CRUD/full MCP/plugin;
cấu hình không có MCP/plugin. `live-cli-results.json` và `deepseek-budget.json`
giữ dữ liệu; bảng giá nguồn ở https://api-docs.deepseek.com/quick_start/pricing/.

## Acceptance thực tế

| Nhóm từ ACCEPTANCE.md | Trạng thái sau lượt sửa |
|---|---|
| A01/A02/A04/A05 | Paired core native controls chạy; không phải toàn orchestration disposable effects |
| A06 | ffuf plaintext HTTP đạt selected real adapter test; nmap/raw socket positive **chưa đạt** |
| A07/A08 | Response lifecycle/cap và native network gates kiểm fixture; complete redirect/cache/export graph **chưa đạt** |
| A09/A10/A11 | CLI roots/evidence regression và worker actual filesystem controls đạt selected paths; full races/import-export broker **chưa đạt** |
| A12/A13 | Real Linux offline/scoped HTTP positive + host/direct-network negative đạt; generic TLS/raw/aggregate bounds **chưa đạt** |
| A14 | Compatible fresh local stdio test đạt; persistent browser/auth/env/configured production MCP **chưa đạt** |
| A03/A15 | Actor/credential/upstream integration resource adapters **chưa đạt** |
| A16/A17 | Narrow SQL canonical chain đạt; human route15classes có nhãn; autonomous all-class/negative/cleanup completion **chưa đạt** |
| A18/A19 | Protected historical cert/revoke resume và untrusted prompt placement có tests; full typed memory/poison retraction **chưa đạt** |
| A20 | Existing skill guards/payloads/guidance regression; toàn playbook end-to-end **chưa chứng minh** |
| L02–L12/L16 | Receipt/replay/args freeze/mode/revoke/budgets/cancel/deny coalescing có selected controls; chưa lifecycle sweep mọi adapter/generation |
| L01 | Full all-tool, all-pentest-flow zero-dialog orchestration **chưa đạt** |
| L13/L14 | Native pinning có tests; complete DNS/proxy/browser graph và source-to-export isolation **chưa đạt** |
| L15 | Broad scope chấp nhận unknown effects được giữ; không có test-object ownership guarantee |

## Cách tái chạy offline và phần tiếp theo

Trong WSL Ubuntu, tại `/mnt/d/DOANTOTNGHIEP/kagent`, chạy **tuần tự**:

```sh
./venv-linux/bin/python -B artifacts/audits/yolo-all-tools-2026-10-02/startup_probe.py
./venv-linux/bin/python -B -m pytest -q -p no:cacheprovider tests/security/test_cli_repair_entrypoint.py tests/security/test_repair_runtime.py tests/security/test_repair_controls.py tests/security/test_worker_startup.py
./venv-linux/bin/python -B artifacts/audits/yolo-all-tools-2026-10-02/run_repair_checks.py
./venv-linux/bin/pyright
git diff --check
```

Focused commands trên dùng FakeLLM, loopback, secrets giả và installed Linux
binaries, không provider/model API. Không chạy `repair_live_cli.py --live`.

Bước nhỏ tiếp theo để khôi phục autonomy: chọn một lớp ngoài SQLi, xây trusted
actor/browser hoặc class adapter tương ứng và test real proof→verified negative/
positive→coverage→finding với đúng CLI profile. Sau đó làm native HTTPS-compatible
worker adapter/persistent MCP có resource ownership; raw scanner cần target/port
broker thực. Không bật host fallback, không ghi confirmed theo model để vượt blocker.

Khoảng trống còn lại: complete egress/source-domain isolation và secrets trong
allowed lab data; actor/credential handles; finding truth khi target cố ý giả;
typed compact/learning, preference promotion/retraction; first DNS binding/all
routes; filesystem/executable TOCTOU; Windows/macOS sandbox; cgroup/aggregate
limits; unsupported network/MCP protocols. Summary/memory không cấp quyền, nhưng
vẫn có thể ảnh hưởng ý tưởng phép thử. Broad allowed lab actions có unknown effects.
Test pass chứng minh các controls đã dựng, không chứng minh chống prompt injection
toàn diện hoặc bảo toàn mọi luồng pentest cũ.
