Kiểm toán tập trung và sửa lỗi có điều kiện cho lan-23
===================================================

Mốc kiểm toán là `7a9b6d5786562c96e4aa209ed070939586c1cafe`; worktree sạch
trước khi bắt đầu. Chỉ xem xét ba vấn đề A/B/C. Tái hiện độc lập bằng các
implementation và fixture production hiện có, trước khi sửa production.
Toàn bộ HTTP tái hiện dùng `httpx.MockTransport` hoặc capture tổng hợp trong bộ
nhớ; không gọi target, scanner hay nhà cung cấp LLM bên ngoài.

| Vấn đề | Kết luận | Nguyên nhân gốc | Nguồn gốc | Quyết định |
|---|---|---|---|---|
| A — effects khi HTTP đang chạy | CONFIRMED | `validation_handoff` mới gọi `attempt_effects`, nhưng hàm đọc này từ chối trạng thái hợp lệ `dispatched`. Planner và Progress dùng chung handoff. | lan-23 (`7a9b6d5`) đưa kiểm tra cũ vào đường đọc. Kiểm tra in-flight vốn có từ `a03cf25` để bảo vệ finalization. | FIX đường đọc; KEEP điều kiện idle khi finalization. |
| B — access question và provenance | CONFIRMED | Gate dùng `input_provenance.kind == unverified` làm lý do chặn câu hỏi access. Provenance có nguồn vẫn luôn trả `authentication_requirement=unknown`; nó không chứng minh cần đăng nhập. | Gate và metadata dependency được thêm trong lan-23. | FIX hợp đồng hỏi/làm rõ và nhãn hiển thị; KEEP kiểm tra input, dependency, cache và permission. |
| C — phản hồi phục hồi evidence | CONFIRMED | Registration đánh đồng mọi source không usable với dependency bắt buộc và yêu cầu rewrite; terminal admission cho phép optional metadata không usable nếu không dùng body làm chứng cứ. Hint `UNUSABLE_PRIMARY_SOURCE` cũng yêu cầu rewrite vô điều kiện. | Receipt readiness và câu rewrite vô điều kiện được thêm trong lan-23. Optional-metadata admission và thông báo replace refs quá rộng đã có trước đó. | FIX feedback/readiness; KEEP toàn bộ admission và immutability. |

**Bằng chứng và đường gọi A.** Native HTTP gọi `begin_dispatch` ngay trước
`await client.send`, rồi `finish_dispatch` trong `finally`:
[http_tool.py](../src/tools/http/http_tool.py),
[assessment.py](../src/workflow/assessment.py).
Journal thực sự có `status=dispatched`, `observation_id=None` trong khoảng await.
Tái hiện giữ MockTransport bằng hai `asyncio.Event`, không dùng sleep hoặc
journal giả. Trên code ban đầu, cả `validation_handoff`, `Agent._planner_context`
và `runtime_facts` đều ném `ValueError: attempt dispatch still in flight`.
Handoff của `7a9b6d5^` chạy được trên cùng state đang giữ request.

Đường gọi đọc là
[`validation_handoff`](../src/tools/workflow/workflow_tool.py) → `attempt_effects`;
planner dùng handoff trong [`Agent._planner_context`](../src/agent/agent.py);
Progress dùng nó trong [`runtime_facts`](../src/ui/core/outcomes.py), được TUI
gọi từ `dispatch`/refresh trong [`app.py`](../src/ui/core/app.py).
Agent đợi tool batch kết thúc trước turn tiếp theo; tái hiện này chứng minh các
reader không an toàn khi đọc state in-flight, không khẳng định planner luôn chạy
đồng thời HTTP trong vòng lặp tuần tự. TUI và các reader có thể quan sát state
trong lúc await; không được coi state đó là lỗi bookkeeping.

Sửa nhỏ nhất là chuyển kiểm tra `dispatched` sang `require_idle_attempt`, đã được
các đường ghi effects, ghi result và đóng attempt gọi sẵn. Hàm đọc vẫn kiểm tra
cấu trúc journal và status lạ; pending không được tính là completed. Declaration
no-mutation vẫn bị invalidation, write đã được ghi nhận vẫn được giữ. Regression
bao phủ handoff/planner/Progress × completed/failed/cancelled × no-mutation/write,
cùng kiểm tra finalization bị chặn cả khi không có live policy.

**Bằng chứng và hợp đồng B.**
[`AskUserTool.run`](../src/tools/common/ask.py) chỉ nhận dependency kind/basis và
ID của các input đang blocked; basis là lời Agent khai báo.
[`input_provenance`](../src/workflow/discovery/input_view.py) phân biệt nguồn của
input và luôn để yêu cầu authentication là unknown. Request link, baseline hay
manual attribution không chứng thực server enforcement, nội dung tài liệu hoặc
nguồn gốc của câu khẳng định trong `dependency_basis`.

Tái hiện trước sửa: một input không có source link bị chặn dù câu hỏi nhằm làm
rõ access theo thông tin operator cung cấp; cùng loại câu hỏi được chấp nhận
cho input liên kết capture public HTTP 200, không có chứng cứ cần authentication.
Implementation trước lan-23 cho phép câu hỏi làm rõ đầu tiên. Regression bổ sung
các basis về operator/tài liệu, câu hỏi trung lập khi chưa biết access, capture
200 và capture 401 có thông điệp yêu cầu authentication. Các thông tin tổng hợp
đó kiểm tra hợp đồng runtime; chúng không được gọi là runtime authentication
verification. Câu hỏi scope/exclusion độc lập và câu hỏi không bind input vẫn
được kiểm tra bằng các regression hiện có.

Không thêm bộ suy luận authentication hoặc gate dựa trên prose. Runtime cho phép
operator làm rõ access ngay cả khi provenance chưa đủ; mọi câu hỏi bind input đều
ghi rõ basis/dependency là Agent-reported và authentication chưa được runtime xác
minh. Vẫn bắt buộc đúng objective/input blocked, kind hợp lệ và basis có giới hạn;
vẫn kiểm tra cả batch trước khi hỏi, giữ cache/retry, không tự drop input hoặc cấp
permission. Một test cũ mã hóa gate sai được thay bằng test giữ cùng mục đích:
không trình bày giả định access như sự thật do runtime xác minh.

**Bằng chứng và hợp đồng C.**
[`check_source_requirements`](../src/workflow/assessment.py) buộc required source
usable khi terminal; `check_excerpts` buộc source của mọi terminal body excerpt
usable, kể cả optional. `accepted_result` giữ kiểm tra integrity/ownership,
required evidence và ít nhất một HTTP primary usable.
[`check_proof_references`](../src/workflow/evidence/artifacts.py) giữ binding của
các parent claim có cấu trúc; không biến incidental diagnostic prose thành body
claim. Parent đã đăng ký không được rebind.

Tái hiện dùng primary complete và HTTP auxiliary `required=false` bị truncated.
Proof chỉ dựa primary tốt; reference lịch sử chỉ là diagnostic prose/metadata.
Trước sửa, receipt trả `unusable-primary-sources` và `Rewrite proof`, nhưng
`record_result` chấp nhận chính `ev_...` đó và `accepted_result` trả true.
Khi auxiliary là required, hoặc assessment trích body của capture truncated,
terminal result bị từ chối đúng bằng `UNUSABLE_PRIMARY_SOURCE`. Failed diagnostic
output optional cũng được thử qua `ObservationStore.capture_output`; nó chỉ được
giữ làm metadata và không thể thay primary usable.
Đối chiếu thêm bằng chính `_record_evidence`/`_record_result` của `7a9b6d5^`
cho thấy cùng case optional truncated metadata đã được chấp nhận trước lan-23,
khi chưa có receipt yêu cầu rewrite (`pre-lan23-evidence.txt`: **1 passed**).

Receipt hiện phân biệt required unusable với optional diagnostic; vẫn liệt kê
tất cả source unusable và lý do, vẫn trả `terminal_assessment_accepted=false`.
Status về capture readiness không bảo đảm terminal admission. Chỉ đổi source
proof/parents khi chúng thực sự sai; nếu chỉ proposed assessment excerpt sai,
có thể sửa assessment với cùng snapshot và parents. Regression kiểm tra nguyên
bytes snapshot, parent binding, resume, không thêm HTTP phục hồi, không Finding
hoặc coverage khi terminal evidence sai. Không sửa admission, evidence hash,
ownership, limits, recovery budget hoặc snapshot store.

**Chính xác các file sửa.**

| File | Lý do |
|---|---|
| `src/workflow/assessment.py` | Chuyển in-flight rejection từ reader sang finalization guard; làm điều kiện thay evidence refs rõ ràng trong thông báo unusable source. |
| `src/tools/common/ask.py` | Bỏ proxy provenance→access; làm rõ contract và nhãn Agent-reported/unknown. |
| `src/tools/workflow/workflow_tool.py` | Tính readiness theo required/optional và đưa feedback rewrite có điều kiện. |
| `src/workflow/evidence/errors.py` | Phân biệt sửa assessment excerpt với sửa proof/parents; giữ immutability. |
| `tests/integration/test_lan23_audit_regressions.py` | Regression bằng runtime thực cho A/B/C và các case biên. |
| `tests/tools/test_lan23_input_context.py` | Thay assertion của gate sai bằng kiểm tra uncertainty; thêm negative batch/dependency checks. |
| `docs/lan23-focused-audit.md` | Báo cáo và bằng chứng kiểm toán này. |

**Xác minh.** Các log thô nằm tại `/tmp/kagent-focused-audit/`.
`phase1.txt` ghi năm tái hiện read-only thành công trước khi thay production.
`baseline_runtime.py` nạp nguyên bốn module production từ `git show 7a9b6d5:...`
trước khi collect cùng regression mới, không thay worktree và không dùng mô hình
giản lược. `red-final.txt`: **30 failed, 9 passed** — A có 18 failure, B có 6,
C có 6. `green-boundaries.txt`: **39 passed** với implementation đã sửa.
Các test âm đã pass trên code cũ vẫn được giữ.

`final-focused.txt`: **226 passed**, 178,16 giây. Run này gồm regression mới và
các test liên quan về lifecycle, assessment, finalization, recovery, observation
grounding, proof-parent feedback, candidate recovery integration, continuation,
input questions, AskUser và Progress. Chạy lại sau lần sửa thông báo cuối cùng.
`pyright-final.txt`: **0 errors, 0 warnings, 0 informations**, dùng cấu hình
`venv-linux` của repository; không cập nhật/cài package theo upgrade notice.

`responsibility.txt`: **7.022 passed, 6 failed, 1 skipped**, 789,54 giây. Lệnh:

```bash
KAGENT_RUN_LIVE_TOOL_CHARACTERIZATION=0 venv-linux/bin/python -m pytest \
  -p tests.system.offline_suite -q tests/security tests/tools tests/integration \
  tests/agent tests/ui tests/state tests/skills
```

Không cộng các run chồng lấp. Broad run bắt đầu trước hai boundary case diagnostic
cuối cùng và lần rút gọn/làm rõ thông báo cuối; `final-focused.txt` đã chạy lại
toàn bộ vùng bị ảnh hưởng trên code cuối cùng. Không chạy lại toàn bộ broad run.

Phân loại sáu failure, không sửa ngoài phạm vi A/B/C:

- Năm case tại `tests/agent/test_trial1_phase_guidance.py:126` yêu cầu chuỗi
  `immutable declaration and budget`, trong khi guidance không đổi trả
  `immutable declaration and recovery budget`. Cả baseline `7a9b6d5` lẫn code
  hiện tại đều tái hiện đúng năm failure này khi chạy lại nguyên module.
  `baseline-broad-failures.txt` và `current-broad-failures.txt` đều ghi
  **5 failed, 26 passed** cho hai module liên quan. Đây là failure có sẵn,
  không phải regression của bản sửa này; không đổi test để ép xanh.
- Một case shell cancellation ở
  `tests/security/test_shell_descendant_cleanup.py:153` quan sát child process
  state `R` thay vì `Z`. Tất cả tám case của module shell pass trong cả hai lần
  chạy cô lập cùng baseline/current nêu trên. Không tái hiện được failure này
  khi chạy lại, nên chưa kết luận nguyên nhân; giữ như giới hạn xác minh.
  Implementation shell, planner guidance và hai module test này đều không đổi.

Pyright, focused tests và Git whitespace checks pass; broad suite **chưa xanh
hoàn toàn**. Không chạy toàn bộ configured pytest suite ngoài bảy nhóm trên
(ví dụ các nhóm LLM, runtime, benchmarks, data). Live-model skip giữ nguyên.

`git diff --check` và whitespace checks cho hai file mới pass. Đã đọc final diff
và kiểm tra `git status --short`; chỉ có bảy file liệt kê ở trên, không stage.
SHA-256 kiểm tra **58/58** artifact lịch sử lan-22/lan-23 không đổi; manifest và
kết quả nằm trong `historical-hashes.json`/`historical-verification.json`.

**Giới hạn.** Đây là chứng minh offline về runtime contract và delivery, không
đo chất lượng suy luận của LLM trên target thật. Agent vẫn có thể diễn giải sai
auth hoặc proof prose; runtime không xác thực ngữ nghĩa từng câu. Các reader vẫn
báo lỗi nếu journal thực sự hỏng, không nuốt exception bất ngờ. Không thực hiện
thử nghiệm live để đo xác suất lỗi concurrency trong một phiên thực tế.

Giữ nguyên target/scope, registry permission gate, HTTP lifecycle/invalidation,
redaction, evidence admission, findings eligibility, recovery budget và immutable
proof. Không đổi workflow architecture, Context Guard, OpenAPI hoặc `document.py`;
không sửa artifact thử nghiệm lan-22/lan-23, không cài package, commit hay push.
