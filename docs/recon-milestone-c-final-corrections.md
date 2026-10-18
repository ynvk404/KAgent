# Milestone C — Final Corrections (18/10/2026)

> Bản được chuẩn bị để commit: đường dẫn máy cá nhân đã chuẩn hóa. Raw logs,
> snapshots và evidence trung gian được giữ local, không xóa; xem
> [bộ evidence portable](verification-milestone-c/README.md) và inventory/hash của archive.

**Full configured suite: PASS trên freeze cuối — 8.490 passed, 12 skipped,
79 warnings, 0 failures/errors, exit 0.** A chưa xác định root cause; không
tuyên bố timeout lịch sử đã được sửa. M2 giữ nguyên theo contract hiện có và
yêu cầu chỉ sửa khi chứng minh vi phạm.
Không chạy Scenario 3 Whole-target, Stage 4 hoặc target/model bên ngoài.

## Baseline và phạm vi

Source bàn giao khớp 714 files, SHA-256
`1013d5c2366faad3f3b49353f951f8e823772502251f9136c67049a88ca65b07`.
Đã đọc AGENTS.md, review Stage 1/2/3, artifacts Stage 3, implementation/tests
liên quan và SQL-injection playbook/allowed-tools khi điều tra finalization.
Các thay đổi chưa commit của Stage 1/2/3 được giữ nguyên. Không cài package,
reset/clean/restore worktree, stage, commit hoặc push.

Thay đổi của lượt này: `src/agent/agent.py`, `tests/ui/test_light_theme_app.py`,
và file mới `tests/agent/test_target_request_intent.py`. 712 source files giữ
nguyên byte; không có source bị xóa. [Preservation](verification-milestone-c/preservation.json)
và [diff chỉ của lượt này](verification-milestone-c/README.md#local-archive)
được đối chiếu với baseline, không dùng toàn git diff để quy công các sửa cũ.

## A — Timeout validation finalization: chưa xác định root cause

Không sửa Agent finalization, deadline, sleep, skips, xfail, pytest config hoặc
session persistence. Không có controlled reproducer của timeout lịch sử 10s.
Không đủ bằng chứng quy nguyên nhân cho Stage 3 hoặc kết luận hoàn toàn do môi trường.

Trên baseline: predecessor/module 214 passed, 20,06s pytest. Lặp cả module ba
lần trong cùng process: 93 passed, 67,55s, không thay timeout. Observer chỉ ghi
metadata timing/resource, không body/traffic/secret và không thay quyết định
runtime. Ba stall samples của lượt lặp hợp lệ mất 6,035s / 5,200s / 3,419s,
đều đến step 14. Có 31 checkpoints mỗi case; tổng save time 5,180s / 4,279s /
2,847s. CPU gần wall time trong các samples này. Đây chỉ là vị trí chi phí ở
những lượt PASS, không phải bằng chứng nguyên nhân timeout trong full cũ.

Kiểm tra lifecycle: case chạy real Agent trong cùng process pytest với mock
HTTP và scripted client; không chạy scanner/subprocess/model ngoài. Harness dùng
`asyncio.timeout`, chờ cancellation của Agent và drain các background tasks
trước freeze. Session worker được shield/join trước khi cancellation thoát;
không tìm thấy bằng chứng writer mồ côi trong samples. Observer ghi thread count
1 trước/sau, GC/RSS/load và checkpoint durations. Không dừng hoặc chỉnh các
service có sẵn trên máy; số đo không loại trừ contention trong full lịch sử.

Một lượt observer ban đầu có lỗi fixture do generator không yield cho cases
khác (3 passed/90 errors); giữ `a-observed.*` như diagnostic INVALID cho module
verdict. Đã sửa observer ngoài source và chạy lại bằng prefix `a-repeated` mới;
không dùng JUnit lỗi hoặc counts cũ làm acceptance. Ba stall observations đầu
thuộc diagnostic lỗi này; ba observations sau thuộc lượt 93 tests hợp lệ.

Bằng chứng: [a-before-result](verification-milestone-c/a-before-result.json),
[a-repeated-result](verification-milestone-c/a-repeated-result.json),
[timing/resource summary](verification-milestone-c/a-observation-summary.json).
Các pass trên baseline không được dùng thay verification source mới.

## B — First-frame light theme: sửa test harness đúng capability

Reproducer gốc: 1 failed, `paints=[]`, TERM=xterm-256color và COLORTERM unset.
Textual App tạo Rich Console với COLOR_SYSTEM=auto. Rich chọn 256 từ TERM;
RecordingDriver chỉ ghi output, không quảng bá truecolor. First paint thực tế
có `48;5;231` (light Screen), không thiếu paint. Assertion chỉ tìm `48;2;` đã
áp giả định truecolor lên terminal 256 màu. Đây là lỗi harness tồn tại từ trước,
không phải production light-theme/Stage 3 regression đã được chứng minh.

Test nay mô phỏng riêng truecolor và 256 trước khi tạo App, assert console
capability rồi kiểm first paint đúng encoding. Giữ exact RGB assertion
`48;2;250;248;242` và không-dark-flash cho truecolor; thêm index 231 và không-dark
index 233 cho 256. Chỉ monkeypatch trong từng case, không ép COLORTERM toàn cục,
không đổi renderer/palette/driver production. Focused B + input rendering:
22 passed. Full verification chạy với COLORTERM unset.

## C/S1 — URL trong nội dung trích dẫn tự đổi target: đã sửa

Reproducer trên production trước fix: 27 failed / 9 passed trong nhóm regression
ban đầu; gồm gọi initialize_target trực tiếp và Agent.run thực. Có cả target rỗng
và target đã chọn. Root cause: tìm một từ thao tác ở bất kỳ đâu và đúng một URL
trong toàn message, không kiểm tra URL thuộc chỉ thị nào. Quote có thể gọi
apply_target_base_url, đổi scope và clear workflow hiện tại.

Sửa cục bộ intent nhận target: loại Markdown blockquote/fenced/indented code và
inline example khỏi phần dùng để nhận diện; URL đơn trong inline span vẫn dùng
được làm operand rõ ràng. Chỉ lấy URL trong clause bắt đầu bằng chỉ thị thao tác
trực tiếp; explanation/negation và URL ở clause khác không tự chọn target.
Không thay message gốc gửi model. Mơ hồ nhiều URL vẫn không tự chọn target;
same-origin không reset workflow. Natural language vẫn là heuristic bảo thủ,
không phải bộ hiểu ngôn ngữ tổng quát hoặc nguồn cấp quyền.

Regression cuối có 51 cases: từ chối quote/code/explanation/negation/unrelated
URLs, giữ workflow/target revision/scope; chọn và chuyển target bằng chỉ thị rõ
ràng, Direct/Whole-target, inline URL, quote phụ và same-origin; một case qua
Agent.run. Registry, HTTP/private-host/exact-origin guards, execution policy,
workflow/validation/evidence/finding và skill contracts không đổi.

Audit bổ sung trước full tìm thấy hai cạnh chưa đúng: lazy blockquote continuation
không có dấu `>` vẫn đổi target, và URL operand ở dòng kế tiếp chưa được nhận.
Regression trước sửa bổ sung: 6 failed/45 passed. Fix giữ paragraph của quote
qua dòng tiếp nối đến blank line và nối URL operand của chỉ thị rõ ràng.
Đọc quote rồi có chỉ thị mới sau blank line vẫn chuyển target đúng.
Lượt targeted 1.290 passed và integration 6.723 passed/1 skipped trên freeze
đầu được giữ ở `intermediate-first-correction/`; không dùng cho verdict cuối.
Focused trên freeze cuối: 118 passed; các nhóm lớn chạy lại từ đầu.

## D/M2 — Goal reconciliation: tái hiện mutation, chưa chứng minh defect

Đã áp dụng lưu ý bổ sung: không mặc định pending→in_progress là lỗi hoặc refactor
chỉ để đổi tên/biến hàm thành read-only. `_reconcile_requested_goals` ghi rõ
“Recompute persisted goal summaries from objective-owned records”; tests lifecycle
hiện có yêu cầu link candidate theo objective, phản ánh unresolved/missing evidence
và giữ các blocker thay vì tin summary cũ. `_workflow_request_view` có contract
“Reconcile first, then derive”, chạy dưới mutation lock trước checkpoint/request.

Ở thiết kế này, pending là goal chưa có tiến triển/disposition hiện hành;
in_progress là summary có candidate-owned work chưa có validation result hợp lệ.
Nó không chứng nhận test đã bắt đầu, HTTP đã chạy hoặc vulnerability đã xác nhận.
Candidate status/attempt/result vẫn là nguồn cho các điều kiện đó.

Offline audit tái hiện trên source hiện tại: khi thêm candidate cùng objective
mà summary chưa sync, `_whole_target_state()` đổi đúng `objective.requested_goals`:
status pending→in_progress, candidate_ids []→[ID thật], reason null→“no validation
result”, committed_revision +1. Không đổi candidate status (vẫn new), không tạo
attempt/result/finding hoặc phase completion. Không có candidate thì goal vẫn
pending; đọc lặp lại sau sync không mutation thêm. `_finish_tool_results()` nhận
dirty revision và lưu summary đúng; saved workflow khớp state, không mất checkpoint.

Chưa tìm thấy hậu quả vi phạm readiness/completion/persistence trong điều tra có
giới hạn. Vì vậy không sửa production M2, không thêm assertion ép hàm reconciliation
thành pure read. Không tuyên bố Agent helper này read-only. Canonical
WorkflowState vẫn là nguồn duy nhất; các tests requested-goal lifecycle/state
được chạy lại để kiểm chuyển trạng thái hợp lệ. Nếu cần thay semantics API đọc,
đó cần evidence/contract cụ thể hơn, không được tự suy ra từ tên hàm.

Bằng chứng: [audit script](verification-milestone-c/m2_audit.py),
[delta/checkpoint](verification-milestone-c/m2-audit.json).

## Verification trên freeze cuối

715 files; SHA-256
`76168e98a362ef43f4636dc745fc356cfa57a425e59f89ec842b5b174bce653c`.
Runner lưu exact argv/cwd/env, exit code, thời gian UTC/wall, log/JUnit hash,
summary/skips và manifest trước/sau. Không tái sử dụng XML từ lượt ngắt.
Docs/artifacts không nằm trong source manifest (cùng định nghĩa baseline).

| Nhóm trên source cuối | Kết quả | Pytest time / wall time | Exit |
| --- | --- | --- | --- |
| Focused regressions | 118 passed | 24,08s / 25,342s | 0 |
| Targeted Stage 1/2/3 | 1.296 passed | 70,70s / 72,263s | 0 |
| Responsibility integration (có Agent) | 6.729 passed, 1 skipped, 34 warnings | 511,72s / 515,557s | 0 |
| Pyright toàn repository | 0 errors, 0 warnings, 0 informations | 66,431s wall | 0 |
| Full configured suite | 8.490 passed, 12 skipped, 79 warnings; 0 failures/errors | 1.146,89s / 1.150,748s | 0 |

Các nhóm overlap, không cộng counts. Focused/targeted/integration/pyright đều có
manifest trước/sau khớp freeze cuối. Exact argv, môi trường, start/end UTC,
log/JUnit hash và skip reasons nằm trong từng `*-result.json` ở
[artifact directory](verification-milestone-c/README.md#local-archive).
Pyright giữ nguyên thông báo có phiên bản mới; không cài/update package.
Các diagnostics trước freeze chỉ là reproducer, không thay thế kiểm thử cuối.
Không chạy Scenario 3.


## Nghiệm thu và giới hạn cuối

Full chạy một lượt hoàn chỉnh, không ngắt, với TERM=xterm-256color/COLORTERM
unset; không thêm observer plugin. Có 8.502 test cases được collect:
8.490 passed, 12 skipped, 0 failures/errors. Start 08:04:45.588446 UTC, finish
08:23:56.257985 UTC ngày 18/10/2026 (15:04:45–15:23:56 giờ Việt Nam).

[Acceptance audit](verification-milestone-c/results.json)
xác nhận current source và mọi before/after manifest của focused-final, targeted,
integration, pyright và full khớp 715 files/freeze cuối. Hash log/JUnit khớp,
XML được ghi trong khoảng thời gian của từng lượt chạy, counts XML khớp result;
không đọc XML cũ. `git diff --check` sạch; đã inspect git diff/status và diff riêng
của corrections. `final.diff/status`, `preservation.json` giữ snapshot bàn giao.

| Vấn đề | Kết luận có bằng chứng |
| --- | --- |
| A — finalization timeout | Full mới pass stall (3,597s), reader (1,195s), mixed (2,848s). Timeout cũ chưa tái hiện; root cause vẫn chưa xác định. Không có production fix cho A và không quy cho Stage 3/môi trường. |
| B — light first-frame | Hai cases truecolor/256 đều pass trong full (0,129s / 0,119s). Sửa lỗi giả định capability của harness tồn tại từ trước; RGB assertion vẫn giữ. |
| C/S1 — quoted URL | 51 regressions đều pass trong full; bao gồm từ chối quote/code/explanation và chọn/chuyển target hợp lệ. Đã sửa production auto-target inference, không nới quyền hoặc scope guards. |
| D/M2 — goal read/reconciliation | Mutation đã tái hiện và đo chính xác. Không chứng minh contract violation/hậu quả sai; giữ production reconciliation. Tests lifecycle/state hiện có pass; không tuyên bố helper Agent là pure read. |

Hai session_save responsiveness cases cũng pass trong full mới (0,627s / 0,635s);
không coi đây là fix của timing failure lịch sử Stage 1. Chi tiết case/timing và
phân loại nằm ở [failure-classification.json](verification-milestone-c/failure-classification.json).

79 warnings được giữ nguyên trong log/JUnit run; không suppress. 12 skips theo
repo: 9 Java gate cần cached offline WAR/Tomcat, 1 prepared-existing-lab operator
case, 1 live-system opt-in, 1 live-model characterization opt-in. Exact IDs và
reasons có trong [full-result.json](verification-milestone-c/README.md#local-archive).
Burp integration vẫn bị ignore theo pytest.ini: not run, không tính là pass.
Không lấy skips làm bằng chứng cho live/external-model/Java paths.

**Dừng sau verification/báo cáo.** Không chạy Scenario 3 Whole-target, Stage 4,
scanner/framework mới, live target/model, package installation, stage, commit
hoặc push. Full-suite gate đạt trên freeze này; A là điều tra còn unresolved,
Không sửa M2 theo suy đoán chỉ vì tên hàm trông giống API đọc.
