# Audit YOLO toàn bộ tool — 02/10/2026

> **Cập nhật mới nhất:** đã có lượt sửa bổ sung và sửa startup; xem
> [REPAIR.md](REPAIR.md). Nội dung audit và kết quả triển khai cũ phía dưới được
> giữ để đối chiếu, không phải mọi nhận định “chưa triển khai” còn đúng với code cuối.
> Network worker/local stdio MCP/ffuf hiện có adapter giới hạn; full YOLO vẫn chưa đạt.

## Kết luận khuyến nghị

Chọn **YOLO tự duyệt mọi permission trong một môi trường lab có policy thực thi độc lập**. Operator bật YOLO một lần; runtime tạo policy phiên từ target/scope, workspace, integrations và cấu hình operator hiện có. Không bắt nhập thêm `/permissions grant`. Tool hợp lệ trong policy chạy không có approval dialog. Vi phạm policy trả blocked với lý do và không mở hộp thoại để hợp thức hóa vi phạm.

Để đáp ứng đủ mục tiêu cần đồng thời: policy chung cho mọi executor; kiểm soát file/network của process và MCP server; provenance dữ liệu; xác minh finding/coverage. Việc đổi `YoloPrompter.ask()` thành luôn ALLOW chỉ hoàn thành phần tự duyệt, trong khi các đường đọc/gửi dữ liệu và tạo kết quả giả vẫn còn. **Code hiện tại chưa đáp ứng full YOLO có các bảo đảm này.**

Thiết kế cụ thể: [DESIGN.md](DESIGN.md). Test chứng minh yêu cầu sau triển khai: [ACCEPTANCE.md](ACCEPTANCE.md). Đây là audit và đề xuất; sản phẩm chưa được sửa trong lượt này.

## Phạm vi, trạng thái và bằng chứng

Đã đọc [AGENTS.md](D:/DOANTOTNGHIEP/kagent/AGENTS.md), các báo cáo REPORT/STEP1/M1/YOLO ngày 01/10 và audit bổ sung ngoài repo. Phân biệt các đoạn lịch sử với trạng thái native HTTP sau chỉnh YOLO. Đã rà code permission, Registry, executor, UI bridge, HTTP/discovery/web/file/evidence/shell/MCP/plugin, workflow/finding/coverage, Agent compact/resume và memory/intelligence. Rà thêm các checkpoint trong SQLi/XSS/auth/access-control skills; không áp dụng một contract chung cho mọi lớp lỗ hổng.

HEAD: `9406a4d92139b1ff98e9f5f1a743a84701be1505`. Worktree đã có A/B/C, M1, điều chỉnh YOLO và sáu SVG untracked; baseline hash lưu **362 tệp có sẵn** trong [baseline.json](baseline.json). Các file mới của audit chỉ nằm trong thư mục artifact này, vốn được git ignore.

Kiểm tra cuối: hash của cả 362 tệp, HEAD và git status đều không đổi so với baseline; [verification.json](verification.json). `git diff --check` đạt. Đã kiểm 35 liên kết file/line trong ba tài liệu bàn giao, không có đường dẫn thiếu hoặc dòng ngoài file. Không sửa các báo cáo cũ; giữ nguyên bằng chứng trước sửa để đối chiếu.

Chạy mới **334 pass, 1 live opt-in skip**, 24.34s; [results.xml](results.xml). Có **12 probe mới: 4 control cases và 8 case tái hiện khoảng trống** trong [test_current_boundaries.py](test_current_boundaries.py). Phần còn lại là current characterization và regression permission/discovery/Registry/plugin/evidence/memory/intelligence/compact/resume. Pass của case tái hiện khoảng trống không phải security acceptance. Những tests của thiết kế tương lai trong ACCEPTANCE.md chưa được triển khai hoặc chạy.

Các process/MCP/HTTP trong probe mới đều mock; secret/file là fixture giả. Regression dùng fixture/mock và loopback, không model API, không tải dependency, không chạy MCP/browser thật hoặc network pentest live. Kết quả 991 pass/1 skip và pyright 35 files của lần trước là bằng chứng lịch sử, không tính thành kết quả mới. Lượt này không chạy lại pyright sản phẩm vì không sửa sản phẩm.

## Các đường thực thi hiện tại

| Nhóm | Permission → executor hiện tại | Code cưỡng chế được | Khoảng trống |
|---|---|---|---|
| Native HTTP | Registry validate → `run_authorized` → HTTPPermissions → private-host gate → reserve → HTTPX send | Exact origin; immutable effective request; session/epoch/revisions; expiry/quota/rate/concurrency; one-shot receipt; response close; YOLO grant tự kích hoạt | Không egress/provenance toàn context; DNS check không pin HTTP socket; unknown server effects; chỉ native HTTP nhận revoke/session deny này |
| Content discovery | Registry permission/hints YOLO → resolve active scope → native HTTP hoặc ffuf argv runtime dựng | Active origin/base path, relative paths, request/rate/timeout caps theo operation, no redirects/raw scanner flags | Không dùng HTTPPermissions/session budget; native/ffuf không attest actual socket IP; process chưa có FS/network isolation |
| Service discovery | Registry permission/hints YOLO → resolve/vet IP → socket hoặc nmap | Chỉ active target và effective port; numeric IP pinned khi scan; all DNS answers vetted; operation timeout/concurrency; nmap argv cố định | Không dùng shared session deny/budget; process có ambient local privileges; scope change sau preparation chưa dùng receipt/revision chung |
| web_fetch | `requires_permission=False` → exact origin/private-host check → cache hoặc HTTPX | Scope trước cache/network; no redirects; body cap; response/client close | Không HTTP grant/revoke/budget; không source→sink control; cache không phải observation fresh có session provenance |
| web_search | `requires_permission=False` → query vào DuckDuckGo → HTTPX/cache | Query encoding, caps, timeout/lifecycle | Query là sink public ngoài target; không engagement/data-egress gate; redirects được follow |
| File/grep/glob/mentions | Reads thường không outer permission; known sensitive paths hỏi ở read gate; write/edit có Registry gate | Known sensitive path/canonical symlink checks; một số byte caps; artifact root eligibility; mention không inline known sensitive paths | Không comprehensive read roots/confidentiality grants; unlisted local file vẫn có thể đọc; metadata/inline text không có provenance đầy đủ; root checks chưa chống mọi TOCTOU |
| Evidence | Workflow gate source → immutable snapshot → source_path/sensitive branch → gated re-read | Project containment; nguồn sensitive known giữ restriction; checksum, size, read-only snapshot; A/B/C đã sửa | Arbitrary copies/legacy proof thiếu nguồn; checksum không attest thật sự xảy ra exploit; model-generated file vẫn là evidence bytes hợp lệ |
| Shell/Bash | Registry exact args/preview → always fresh approval → rewrite/denylist/portability → process | DENY trước dispatch; timeout/cancel/process group; bounded captured output | YOLO không auto; denylist không sandbox; không origin/file roots/egress; direct `run` không permission gate |
| MCP | Server từ config launch trước tool approval → metadata → Registry fresh approval → remote call | Args deepcopy/preview; DENY trước RPC; call timeout/cancel; result caps | Metadata không chứng thực behavior; không resource/data scope ở server; cancel không rollback; ambient privileges; direct run gọi RPC |
| Command plugin | Registry fresh approval → cfg.command/argv + stdin JSON → subprocess | DENY; timeout/abort; truncate kết quả | Cfg không frozen cùng args; stdout/stderr được collect trước truncate nên không bounded memory allocation; không process sandbox/egress; direct run không permission gate |
| Finding/coverage | Workflow refs/status/checksum → report; coverage mark/result sync | Candidate/ref/class/endpoint consistency và một số SQLi differential contracts; changed proof bị reject | Không runtime observation độc lập cho mọi nguồn/lớp; fabricated proof/confirmed/negative/coverage vẫn có đường được chấp nhận |
| Compact/resume/learning | Summary → SessionMemory → system prompt; intelligence learn summary → project + personal | Native grants/receipts không serialize; resume clear runtime rights; có regex loại một số authorization text và prompt warnings | Text nguồn target có thể thành objectives/todos/decisions; source_session_id không đủ trust provenance; memory label/regex không chứng minh nguồn; cross-project learning |

Nguồn: [Registry](D:/DOANTOTNGHIEP/kagent/src/tools/registry.py:137), [HTTP manager](D:/DOANTOTNGHIEP/kagent/src/permission/http_grants.py:204), [HTTP executor](D:/DOANTOTNGHIEP/kagent/src/tools/http.py:113), [content discovery](D:/DOANTOTNGHIEP/kagent/src/tools/content_discovery.py:186), [service discovery](D:/DOANTOTNGHIEP/kagent/src/tools/service_discovery.py:145), [fetch/search](D:/DOANTOTNGHIEP/kagent/src/tools/web.py:222), [file gate](D:/DOANTOTNGHIEP/kagent/src/tools/file.py:77), [evidence](D:/DOANTOTNGHIEP/kagent/src/workflow/evidence.py:30), [shell](D:/DOANTOTNGHIEP/kagent/src/tools/shell.py:197), [MCP](D:/DOANTOTNGHIEP/kagent/src/tools/mcp_integration.py:278), [plugin](D:/DOANTOTNGHIEP/kagent/src/tools/plugin.py:54).

## Findings audit hiện tại

| ID | Kết quả và mức độ | Bằng chứng / giới hạn |
|---|---|---|
| Y01 | **Cao cho mục tiêu full YOLO:** permission policy bị chia nhiều đường | 3 probe shell/MCP/plugin dùng YOLO nhưng hai calls bị deny tạo hai asks; sensitive read cũng hỏi hai lần. Bridge serialize hộp thoại, không gộp equivalent issue hoặc lưu generic deny suppression |
| Y02 | **Cao:** revoke/deny native HTTP không áp dụng mọi network tool | Native HTTP deny control chặn trước send, cùng state deny vẫn có fetch, public search và discovery transport. Đây là phạm vi control hiện tại, không tuyên bố bypass native receipt |
| Y03 | **Cao nếu blanket autoapprove:** arbitrary execution không enforce target/local rights | Existing approved shell/MCP probes truyền ngoài-scope args tới mock; source subprocess không hạn chế filesystem/network. Direct shell.run probe dispatch dù dùng Recorder DENY; direct call là trusted API gap, không phải model đã tìm được cách bỏ Registry |
| Y04 | **Cao:** local read và export là hai quyền chưa được tách đầy đủ | Existing probes đọc unlisted canary rồi POST same-origin/search query. Sensitive gate hiện không tìm mọi secret; origin hợp lệ không chứng minh dữ liệu được phép xuất |
| Y05 | **Cao cho integrity:** evidence hash có thể chứng thực bytes chứa khẳng định giả | Existing current probe ghi ordinary text → result confirmed XSS → confirm_finding tạo report với impact giả. Finding có nhiều consistency checks và SQLi differential validation; chưa phải semantic verifier đầy đủ |
| Y06 | **Trung bình–cao:** coverage/negative có thể làm assessment kết thúc sai | Current probe negative không observation thành terminal; direct coverage mark không cần observation. Legitimate skipped/unavailable cần giữ nhưng không được coi là tested/pass |
| Y07 | **Cao khi mở rộng autonomy:** compact/learning giữ chỉ dẫn nguồn target | Current probes scripted summary tồn tại sau resume và directive vào project/personal intelligence; code render memory và intelligence trong system context. Native permission không hồi sinh từ summary, nhưng model decisions/results có thể bị ảnh hưởng |
| Y08 | **Trung bình, phụ thuộc config mutation:** plugin preview/dispatch identity có thể lệch | Probe mutate cfg.command/args trong lúc review: preview fixture-before, dispatch fixture-after; args JSON vẫn nguyên. Không phải target tự sửa được cfg qua mạng; chứng minh cần freeze cả config/executor identity |
| Y09 | **Cao nếu quảng cáo strong scope:** generic process và MCP server chưa cô lập | Stdio server launch/env, plugin/shell subprocess; browser default `npx -y @browsermcp/mcp@latest` chưa pin executable/package identity. Không chạy/install package trong audit |
| Y10 | **Trung bình–cao:** policy/data gates không có một entrypoint chung cho mọi calls | Agent kiểm skill trước Registry, nhưng `is_tool_allowed` cho non-permission tools qua; direct executors khác HTTP dựa caller. Cần explicit capability map từ code, không trust permission flag/description của tool |
| Y11 | **Trải nghiệm/policy lệch:** skill text vẫn có approval checkpoints riêng | XSS nói `/yolo cannot bypass`; SQLi Phase3 yêu cầu ask_user riêng. Autoapprove Prompter một mình không tránh ask_user permission questions. Auth ask_user thiếu test accounts là yêu cầu thông tin thực, không thể tự bịa câu trả lời |

Nguồn kết quả: [current probes](test_current_boundaries.py), [characterization hiện tại](D:/DOANTOTNGHIEP/kagent/artifacts/audits/prompt-injection-2026-10-01/test_characterization.py:225), [finding](D:/DOANTOTNGHIEP/kagent/src/tools/finding.py:171), [record_result](D:/DOANTOTNGHIEP/kagent/src/tools/workflow.py:522), [coverage](D:/DOANTOTNGHIEP/kagent/src/tools/coverage.py:184), [compact](D:/DOANTOTNGHIEP/kagent/src/agent/agent.py:4452), [learning](D:/DOANTOTNGHIEP/kagent/src/intelligence/store.py:473), [memory](D:/DOANTOTNGHIEP/kagent/src/memory/store.py:91), [skill gate](D:/DOANTOTNGHIEP/kagent/src/agent/agent.py:1539), [XSS checkpoint](D:/DOANTOTNGHIEP/kagent/skills/cross-site-scripting/SKILL.md:98), [SQLi checkpoint](D:/DOANTOTNGHIEP/kagent/skills/sql-injection/SKILL.md:596), [browser bootstrap](D:/DOANTOTNGHIEP/kagent/src/tools/mcp_server.py:21).

## Điều code có thể và chưa thể bảo đảm

Một policy chung có thể cưỡng chế: operator-only mode/scope; exact resource identities; allowed source/read/write roots; actor/credential destination khi dùng broker; target socket destinations; protected control-plane files; immutable invocation; finite budget/timeout/concurrency; durable explicit revokes; no dialog under YOLO; provenance và eligibility theo verifier contract. Với process, các quyền này cần OS/network enforcement chứ không phải chỉ Registry metadata.

Không thể từ URL/method/payload hoặc `is_test=true` của model kết luận bao nhiêu rows sẽ bị xóa, việc gửi email/backend job hoặc object có phải test object. Broad disposable-lab quyền chấp nhận unknown effects; app-side containment cần lab/harness. Narrow test objects cần adapter biết canonical object/actor/operation và xác minh ownership bằng hệ thống đáng tin; không endpoint allowlist cố định hoặc model tự khai.

Không thể bảo vệ mọi local secret đồng thời cho arbitrary shell/MCP truy cập nguyên máy host và gửi dữ liệu tùy ý. Khuyến nghị tự chạy arbitrary commands trong worker hạn quyền, expose đúng dữ liệu lab; target scope và egress của worker là độc lập với permission autoapprove. Remote MCP cần enforcement phía server/credential resource hoặc adapter đáng tin; sandbox client không kiểm soát tác động server từ xa.

Policy có thể chặn **vi phạm quyền**, nhưng injection có thể đề xuất hành động nằm hoàn toàn trong broad lab quyền và làm sai mục tiêu phân tích. Cần result/provenance controls, progress tracking và lab isolation để giảm hậu quả. Không coi 334 test pass hoặc thiết kế này là chống tuyệt đối prompt injection.

## Tài liệu đối chiếu

[OWASP AI Agent Security](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) mô tả rủi ro tool abuse, data exfiltration và memory poisoning; [OWASP MCP Security](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) đề cập schema integrity, quyền tối thiểu và sandbox server. Báo cáo chỉ dùng các nguyên tắc này làm đối chiếu. Các ví dụ lọc keyword, hạn chế payload hoặc approval từng tác động trong tài liệu không được dùng làm cơ chế đề xuất cho yêu cầu full YOLO này. Thiết kế KAgent ở DESIGN.md là suy luận từ code, threat model và mục tiêu operator, không phải một giải pháp đã được OWASP chứng nhận.


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
