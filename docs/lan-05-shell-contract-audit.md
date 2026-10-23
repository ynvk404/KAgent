# Shell tool-selection & permission contract audit — chuẩn bị lan-05

Audit mã nguồn từ HEAD `a183d60`; worktree sạch trước khi thực hiện. Sửa hướng
dẫn có mâu thuẫn và một lỗi cancellation được tái hiện bằng test offline.
Không gọi provider/LLM/API, không chạy live target, không sửa dữ liệu thực
nghiệm, không commit/push.

## Kết luận

Sau các sửa tối thiểu bên dưới, Shell tool-selection contract nhất
quán cho lan-05 trên kiến trúc direct subprocess hiện hành. Không phát hiện
blocker trong phạm vi contract này. Đây không phải nghiệm thu một lần chạy
lan-05 thực tế hoặc bảo đảm LLM sẽ tuân thủ hướng dẫn.

Riêng native-only ở Input Analysis là quyết định siết policy của bản audit,
không phải yêu cầu kỹ thuật bắt buộc của runtime/evidence contract. Code cũ có
phần mở đầu cho fallback nhưng Tier 2/3 yêu cầu native; audit đã chọn thống nhất
theo hướng chặt hơn. Không nên phân loại lựa chọn này như một bản vá runtime.

Shell có Runtime Permission riêng; không có OS sandbox, không kế thừa Native
HTTP Permission và không tự tạo HTTP attestation. Nếu tiêu chí lan-05 đòi mọi
traffic từ Shell bị cưỡng chế theo HTTP scope/grant, hoặc revoke tự diệt process
đang chạy, kiến trúc hiện tại không đáp ứng tiêu chí đó. Audit không thêm các
khả năng này.

## Truy vết hướng dẫn đến request boundary

| Lớp | Mã/hành vi đã đối chiếu | Contract chọn công cụ |
| --- | --- | --- |
| System Prompt | `src/agent/system_prompt.py`: full, compact, Active engagement, Controller execution policy | Native HTTP cho target traffic; Shell chỉ khi cần OS/local processing hoặc chi tiết request native không biểu diễn được, còn chịu giới hạn skill. Viết curl tái hiện không đòi chạy lệnh. Chính sách chung được thêm vào cả hai profile. |
| Decision Planner | `src/agent/decision_planner.py`: phase/candidate/route plans, `build_checklist`, `render_guidance` | Chọn playbook/candidate và thứ tự công việc, không dispatch hay cấp quyền Shell. Từ khóa scanner tăng risk, không chọn executable. Generic route liệt kê native HTTP và tập công cụ hẹp, không Shell. |
| Action Guidance | `src/agent/action_guidance.py` | Available không phải permission. Native discovery chỉ cho gap thật; Enumeration ghi input trước fetch tiếp, hoàn tất inventory/coverage qua workflow. Không đề xuất chạy Shell để né readiness. |
| Validation Guidance | `src/agent/validation_guidance.py` | Start attempt trước probe, giữ request association/ownership và recovery budget; sau probing_stopped chỉ finalization được runtime cho phép. Không cấp quyền Shell hay giả lập browser/OOB. |
| Request boundary | `src/agent/agent.py`: `_workflow_request_view`, `is_tool_allowed`, `run_parsed_tool_call` | Reconcile state, project schema, thêm planner/action/validation guidance theo trạng thái hiện tại; kiểm lại skill admission khi review/dispatch. Guidance không tự ghi artifact hoặc thay runtime policy. |
| Load skill | `src/skills/registry.py`, `src/skills/load_skill.py` | Metadata/allowed-tools được nạp và kiểm tra; prefix khi có bound policy nói rõ runtime authority ưu tiên hơn wording review cũ trong playbook. |

## Năm skill hiện hành

| Skill | Khi dùng native | Shell và giới hạn |
| --- | --- | --- |
| Recon | `http`, phase recon, cho reachability/header/fingerprint; `service_discovery` khi thiếu thông tin service | Không shell scan loops/nmap tự động. CT lookup không là ngoại lệ scope: nguồn có sẵn hoặc origin được operator thêm rõ ràng và native gate cho phép. Không probe subdomain chỉ vì vừa tìm thấy. |
| Enumeration | `http` cho nguồn đã biết; `content_discovery` cho gap đường dẫn thật, sau prerequisite của whole-target | Curl chỉ cho request detail native không diễn đạt được. Nếu cần nguồn mới qua Shell: đúng active origin, một GET, không redirect, timeout ≤8s, download ≤64 KiB. Đây là giới hạn hướng dẫn, không phải parser/cưỡng chế của Shell runtime. Không dùng Shell để lấy lại content bị omit. |
| Input Analysis | Signal probes phải qua native HTTP, phase validation; ưu tiên phân tích nguồn hiện có | Shell chỉ cho local processing cần thiết trên artifact có sẵn. Native không biểu diễn được probe thì ghi limitation/handoff; không fallback shell HTTP. Không confirmation/impact trong phase này. |
| SQLi | Native HTTP và `elapsed_ms` của adapter cho timing | Không cần Shell chỉ để đo thời gian. Curl chỉ cho request detail thật sự thiếu; tách body/metadata, kiểm exit/stderr/parser. Không fake OOB; không tự chạy sqlmap/ghauri. Confirmation và optional bounded impact giữ contract/gates riêng. |
| XSS | Native HTTP cho marker/context và HTTP proof phù hợp | Ví dụ detection dùng marker thuần, không curl/quote-breaking. Không browser execution hiện hành: khi cần browser phải `browser-required`, không shell browser/scanner thay thế. |

Cả năm metadata vẫn cho phép capability `shell`. Điều đó không bảo Shell là
lựa chọn phù hợp cho mọi bước, không cấp runtime receipt và không tạo HTTP
rights. Agent có kiểm tra allowed-tools bằng code và chuẩn hóa alias; prose
trong prompt/skill không phải security boundary. GenericValidationBoundary
còn chặn Shell khi generic route bị giới hạn, dù skill khác có Shell.

Các câu review cũ trong skill, ví dụ ask_user cho impact, phải đọc cùng prefix
của `load_skill` và Controller policy: YOLO auto-approve công việc được runtime
bao phủ; OFF phục hồi review. Prerequisite, bằng chứng, stop condition và
unavailable capability vẫn áp dụng. Không diễn giải wording cũ thành một gate
bổ sung mà runtime hiện không có; cũng không dùng nó để tự cấp quyền.

## Phương án fallback cho Input Analysis

Không có lý do kỹ thuật tuyệt đối buộc Input Analysis cấm curl: tín hiệu ban
đầu có thể là observation bổ trợ để định hướng, trong giới hạn admission hiện
có. Nó không phải terminal validation evidence. Thiếu primary evidence phải
giữ kết luận chưa được xác minh, không xóa giá trị quan sát ban đầu và không
tự biến nó thành finding.

Fallback có điều kiện là một phương án policy hợp lệ: native thực sự không
biểu diễn được request; đúng phạm vi đã cấp; không né deny/revoke; có Shell
Permission riêng; chỉ signal probe an toàn theo giới hạn của phase; giữ rõ
provenance bổ trợ. Request bình thường vẫn ưu tiên native. Lỗi mạng, thiếu
approval hoặc content bị omit không tự tạo lý do fallback.

Những điều kiện này cần kiểm soát thực tế hoặc review thủ công đáng tin cậy.
Runtime hiện không kiểm HTTP scope/effects bên trong arbitrary Shell command,
và YOLO có thể auto-approve Shell: Shell Permission riêng chưa đồng nghĩa với
manual review. Nếu dùng manual review làm điều kiện của ngoại lệ, review đó
phải được runtime cưỡng chế cho chính hành động, gồm exact target/request và
bounds; không chỉ nhắc bằng prose rồi để YOLO bỏ qua. Prompt/skill không thay
thế gate này.

Phương án trên chưa được triển khai trong bản audit. Contract code hiện tại
vẫn là native-only cho signal probes ở Input Analysis; phần này phân biệt rõ
policy đang dùng với hướng fallback có kiểm soát, không tuyên bố chỉ xóa câu
cấm là đủ giải quyết quyền thực thi hoặc evidence.

## Điều kiện thực thi do runtime cưỡng chế

Đường CLI/TUI thật tại `src/cli/runtime.py` bind `default_execution_policy`
vào `YoloPrompter`, load permission journal rồi đăng ký `ShellTool` và
`BashTool`. `src/cli/main.py` là entrypoint; wiring hiện nằm trong runtime.py.

1. `Registry.execute` (`src/tools/common/registry.py`) freeze adapter, deepcopy
   arguments và validate trước review. Shell schema chỉ có `command` và
   `timeout_seconds`; scanner arguments/extra fields bị từ chối.
2. `ExecutionPolicy.prepare/validate` kiểm tool/session revoke, generic/probing
   restrictions, budget và review ownership. Review/receipt gắn digest lệnh,
   adapter, arguments, revision và lifecycle; approval không cho đổi lệnh.
3. Shell luôn yêu cầu permission ở registry. OFF cần ALLOW_ONCE từng command;
   không session-cache và ALLOW_SESSION bị từ chối. Bound YOLO auto-approve
   covered command, nhưng không vượt revoke, stale receipt hoặc các gate khác.
4. `dispatch_receipt/start` kiểm lại policy, digest, revision, thời hạn,
   cancellation và concurrency trước dispatch. `guard_process` trong
   `ShellTool.run` bắt buộc receipt hiện hành khi có bound policy, rồi kiểm lại
   action. Gọi thẳng `.run` với bound prompter không có receipt bị chặn.
5. Shell denylist vẫn áp dụng cả YOLO, trước spawn. Đây là bộ regex chặn một
   số lệnh, không phải phân tích đầy đủ shell semantics hay OS isolation.
6. `run_with_capture` chạy `/bin/sh -c` hoặc `/bin/bash -c` ở policy root bằng
   account rights. Windows có nhánh PowerShell. Không worker, `/work` mapping,
   filesystem jail, network broker hay HTTP policy tự động cho Shell.
7. Timeout mặc định 300s, tối đa 1800s; giá trị không dương/sai kiểu dùng mặc
   định. Timer bắt đầu sau khi spawn trả handle, tách với thời gian review;
   spawn acquisition không có deadline riêng. Timeout bao gồm chờ process và EOF của stdout/stderr, tránh leader đã
   exit nhưng child còn giữ pipe. Output giữ head/tail tối đa 64 KiB mỗi stream;
   observation còn có cap/redaction riêng.
8. Timeout, `signal.aborted` hoặc asyncio task cancellation gọi cleanup process
   group. POSIX dùng session/process group mới, TERM, grace 1s rồi KILL; chờ
   process/pipes, shield cleanup cả khi cancel lặp. Registry chỉ release active
   receipt sau khi adapter kết thúc. Windows dùng taskkill tree; audit chạy
   Linux, không nghiệm thu process-tree cleanup thực tế trên Windows.

Timeout/cancellation không rollback tác động đã xảy ra. Cleanup group không
phải supervisor cho daemon tự detach/setsid; lệnh thành công có thể để lại child
đã đóng pipe. Không có bảo đảm kill mọi descendant ngoài group hoặc mọi tiến
trình có cùng account.

Audit phát hiện và sửa một cửa sổ cancellation trước khi spawn trả handle:
process có thể đã chạy nhưng await `create_subprocess_exec` chưa trả về, nên
code cũ thoát trước đoạn cleanup group. Stdlib POSIX đóng transport bằng cách
kill leader, không thay thế cleanup cả group. Bản sửa shield tác vụ spawn, giữ
receipt cả khi cancel lặp, lấy handle rồi đi qua TERM/KILL/drain hiện có trước
khi trả cancellation. Không tạo executor, policy hay resource boundary mới.

Decline một invocation chặn dialog tương đương trong review turn; turn sau có
thể được hỏi lại. Prompt yêu cầu không né denial bằng đổi wording/tool. Revoke
tool/session tồn tại trong journal và được kiểm trước dispatch. Revoke không
là cơ chế kill một Shell đã spawn. Hai tên `shell` và `BashTool` bị revoke theo
tên đăng ký riêng; muốn vô hiệu cả hai phải revoke cả hai hoặc `*`.

Không khẳng định mọi hàm Python của Shell đều tự có approval: `.run` với
prompter không bind policy, hoặc `run_with_capture` dùng như library helper,
không cung cấp đầy đủ Runtime Permission contract. Chúng không là đường
dispatch LLM ở CLI/TUI đã audit.

## Đối chiếu Native HTTP/TCP/Content Discovery

Native HTTP đi qua AuthorizedExecutionTool và gate riêng
`HTTPTool.run_authorized`, không dựa vào approval Shell/generic registry.
`HTTPPermissions` kiểm exact origin, effective request/grant/receipt,
deny/revoke, epoch/revision, request/rate/concurrency/byte limits. Phase chỉ là
annotation, không phải authority hay bộ phân loại tác động server.

`private_host.py` phát hiện loopback/private/link-local/metadata và DNS private;
private gate chỉ session-cache cho exact declared origin. Native transport
pin numeric destination, giữ Host/SNI, dùng giới hạn hiện hành; redirect mặc
định 0, optional tối đa 5 qua per-hop checks, không tự theo cross-origin hoặc
captured redirects. Metadata-only cần `evidence_mode=metadata-only` khi cap 0.

Content Discovery dùng bounded native HTTP GET, không recursion/redirect/raw
scanner flags. Service Discovery dùng native TCP, resolve/vet địa chỉ rồi pin,
chỉ effective port của active URL; `socket_budget` giữ native policy/budget
trước connect. Không thay hai capability này bằng raw Shell scanner khi công
cụ semantic phù hợp. Process MCP/command plugins cần executor đã gỡ thì vẫn
unavailable; không host fallback.

HTTP deny/revoke, private-host checks, origin scope, rate/body/download cap và
file-tool protected roots không tự giới hạn một lệnh Shell đã được phép.
Regression chỉ in một URL giả khi HTTP denied để kiểm đường gate tách biệt;
không gửi request Shell tới bất kỳ target nào.

## Evidence và finding

`run_with_capture` gọi `ObservationStore.capture_output`: `source_kind` là
`tool-output`, producer shell, method OUTPUT, URL rỗng, status 0; HTTP-looking
stdout và observation marker do process in không đổi provenance. Runtime
metadata của Shell có `http=None`, không lấy attestation từ text.

`src/workflow/assessment.py` xếp nguồn đó vào supplementary `process-output`,
`required=false`. Có thể register immutable derived proof với nguồn này,
nhưng đăng ký không biến nó thành HTTP evidence. `WorkflowTool._record_result`
chặn cả confirmed và not-confirmed nếu thiếu complete, completed, non-truncated
native-http/imported-capture primary evidence đúng ownership. SQLi và XSS đều
chịu gate đó; required request associations còn phải có nguồn hợp lệ tương ứng.

`confirm_finding` kiểm Candidate/latest confirmed result và evidence hiện hành;
proof file hoặc shell stdout riêng lẻ không mở finding eligibility. Manual
document observations có thể giúp inventory với limitation trung thực, nhưng
không tự tạo admitted HTTP source, replay authority hay attested performed
coverage. Runtime không xác minh ý nghĩa lỗ hổng, severity/impact prose hoặc
mọi diễn giải của LLM.

Rủi ro hiểu nhầm ở phía model vẫn có, đặc biệt khi thấy status/body trong curl
stdout. Prompt chung nay nói rõ nguồn supplementary và yêu cầu primary. Đây
là hướng dẫn; code provenance/ownership/admissibility mới là gate. Shell cùng
UID có quyền account nên không có bảo đảm chống process độc hại sửa control
plane, thoát process group hoặc xuất dữ liệu. Không coi các gate theo tool là
sandbox cho arbitrary code.

## Sửa tối thiểu và file thay đổi

- `src/agent/system_prompt.py`: bỏ ngoại lệ chạy curl chỉ vì cần lệnh tái hiện;
  phân biệt render/execute, review OFF/YOLO; đưa native-first và supplementary
  evidence vào policy chung hai profile; bổ sung metadata-only khi cap 0.
- `skills/recon/SKILL.md`: thay CT shell retry loop bằng nguồn có sẵn hoặc native
  lookup qua scope/permission; không tự probe host mới; làm rõ redirect default.
- `skills/web-input-analysis/SKILL.md`: thống nhất intro và Tier 2/3 theo
  native-only; đây là siết policy, không phải yêu cầu kỹ thuật tất yếu. Phương
  án fallback có kiểm soát được phân tích riêng ở trên.
- `skills/cross-site-scripting/SKILL.md`: thay curl detection bằng native request
  marker inert, giữ baseline binding và không thêm syntax-breaking characters.
- `src/tools/execution/shell.py`: giữ ownership qua cancellation trong spawn;
  sau khi có handle dùng cleanup group hiện có rồi mới nhả receipt.
- `tests/agent/test_shell_tool_selection_contract.py`: thêm regression cho hai
  prompt profiles, CT boundary, Input Analysis và XSS example qua HTTP prepare.
- `tests/security/test_shell_permission_contract.py`: thêm kiểm chứng receipt,
  review không session-cache, revoke trong YOLO, HTTP/Shell gate tách biệt và
  từ chối terminal SQLi/XSS với Shell-only proof cho cả hai adapter.
- `tests/skills/test_recon.py`: cập nhật CT regression theo native lookup mới,
  giữ kiểm JSON hoàn chỉnh và xử lý unavailable/partial.
- `tests/security/test_shell_descendant_cleanup.py`: thêm bốn cases giữ spawn
  ở cửa sổ chưa trả handle, cancel/cancel lặp, kiểm receipt còn active đến sau
  cleanup và child kháng TERM không còn thực thi, cho cả shell và BashTool.
- `docs/lan-05-shell-contract-audit.md`: báo cáo này.

Không đổi planner/action/validation logic, kiến trúc/schema/quyền của Shell,
registry, HTTP/runtime gates, workflow/evidence semantics, allowed-tools hay data stores.
Enumeration và SQLi không cần sửa.

## Kiểm chứng

Baseline targeted suite: 363 passed. Năm guidance/example regression cases mới
fail trên bản trước sửa, pass sau sửa; kiểm chứng cục bộ sau đó: 36 passed.
Suite mở rộng lần đầu có 1509 passed và một cancellation test cũ fail tại spawn
window. Không sửa/skip test cũ: thêm bốn cases điều khiển cửa sổ spawn, cả bốn
fail trước sửa runtime. Sau sửa, targeted Shell/receipt/cleanup/integration:
174 passed. Pyright các Python files thay đổi: 0 errors, 0 warnings.

Kết quả cuối sau sửa runtime: **1514 passed** ở suite mở rộng; Pyright toàn
repository theo `pyrightconfig.json` qua **venv-linux**: **0 errors, 0 warnings**.
`git diff --check` và whitespace check các file mới: pass. Đã inspect diff và
status; chỉ có mười file liệt kê ở trên thay đổi/thêm, không dữ liệu thực nghiệm.

Lệnh suite mở rộng tương đương (Bash brace expansion):

```bash
venv-linux/bin/python -m pytest -q \
  tests/skills \
  tests/agent/test_{shell_tool_selection_contract,systemprompt,decision,phase_guidance,planner_emission,review_p2_guidance,trial1_phase_guidance,lan04_enumeration,workflow_request_preparation,skill_context_policy,skill_lifecycle,removed_manual_guidance}.py \
  tests/security/test_{shell_permission_contract,shell_capture_contract,shell_signal_contract,shell_descendant_cleanup,execution_policy,permission,action_approval,generic_validation,generic_fallback_audit,http_grants,http_invocation_lifecycle,http_yolo_session,agent_assessment}.py \
  tests/tools/test_{shell,tools_registry,http,discovery_tools,workflow_sources}.py \
  tests/integration/test_{direct_runtime,discovery_service_policy}.py
venv-linux/bin/pyright
git diff --check
```

Không chạy toàn bộ repository suite, live/external-model tests hoặc lan-05
thực tế. Test chứng minh guidance được tạo đúng, ví dụ native biểu diễn được
request, và runtime gate giữ contract; không chứng minh hành vi tuân thủ của
một LLM thật hoặc sửa hồi tố bất kỳ run nào.
