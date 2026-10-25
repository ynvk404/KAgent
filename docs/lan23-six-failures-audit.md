Kiểm toán sáu failure còn lại của suite offline lan-23
====================================================

Phạm vi chỉ gồm hai vấn đề: năm failure planner guidance và một failure shell
descendant cleanup. HEAD khi bắt đầu là `7a9b6d5`; bảy file chưa commit từ đợt
remediation trước được chụp SHA-256 riêng để bảo toàn. Không đổi production
trong đợt này. Không gọi target thật, scanner hoặc nhà cung cấp LLM.

| Vấn đề | Phân loại | Nguyên nhân được xác nhận | Quyết định |
|---|---|---|---|
| A — năm nhánh planner | CONFIRMED stale test assertion | Test đòi liền chuỗi `immutable declaration and budget`; guidance đúng hợp đồng thêm từ `recovery` trước `budget`. Một assertion được parameterize thành năm failure. | FIX test; KEEP production guidance. |
| B — descendant `R` thay vì `Z` | CONFIRMED test synchronization defect; không chứng minh được production cleanup defect | Test xem EOF và việc process trực tiếp kết thúc như barrier bảo đảm orphan đã hiện trạng thái terminal ngay lần đọc `/proc` đầu tiên. Native exit có cửa sổ ngắn giữa hai thời điểm này. | FIX phép quan sát trong test bằng polling có deadline; KEEP production shell. |

**A — contract và lịch sử.**
[`expert_attempt_preparation`](../src/agent/validation_guidance.py) hướng dẫn
đúng thứ tự: chuẩn bị request/association từ context hiện có, load skill trước
start, không đoán endpoint, không cấp quyền qua association, và giữ immutable
declaration cùng budget của owned active attempt. Commit `7a9b6d5` đổi câu:

```text
An owned active attempt follows resume/recovery with its immutable declaration and budget instead.
Owned active attempts keep their immutable declaration and recovery budget.
```

[`test_trial1_phase_guidance.py:126`](../tests/agent/test_trial1_phase_guidance.py)
vẫn đòi substring cũ trong năm nhánh `ready`, `actionable`, `goal`, `revalidation`,
`direct`. Không có thay đổi nghĩa cần sửa ở production. Test hiện kiểm tra owned
active attempt, immutable declaration và budget trong cùng instruction, cho phép
qualifier như `recovery`. Các assertion về thứ tự load/start, request associations,
không đoán endpoint và không cấp execution permission giữ nguyên.

**B — lifecycle và tiêu chuẩn cleanup.**
[`run_with_capture`](../src/tools/execution/shell.py) tạo process group riêng trên
POSIX. `completion` gồm `proc.wait()` và hai pump stdout/stderr đến EOF. Khi timeout,
abort hoặc cancellation, adapter gửi TERM, chờ grace hiện có, gửi KILL cho group,
rồi đợi completion. Cleanup được shield để cancellation lặp không làm mất handle
hoặc nhả receipt trước khi adapter hoàn tất. Những đường này không được thay đổi.

Contract đã ghi trong
[`lan-05-shell-contract-audit.md`](lan-05-shell-contract-audit.md): đợi process/pipes,
TERM/KILL/drain, không phải supervisor cho process tự detach. `proc.wait()` thu
status của process trực tiếp; runtime không `waitpid` toàn bộ orphan descendant.
Test cũ vốn chấp nhận `Z` hoặc PID biến mất: yêu cầu descendant đã chấm dứt thực
thi, không yêu cầu KAgent reap orphan thay parent mới của nó. Các kiểm tra direct
process returncode, EOF, cancellation propagation và active receipt vẫn giữ nguyên.

Tái hiện độc lập trước sửa:

- Hai module gốc: **5 failed, 26 passed**; năm failure đều là wording. Tám case
  shell gốc pass trong lượt này.
- Lặp case spawn cancellation gốc **40 lần**, luân phiên ShellTool/BashTool:
  **40 passed**. Chưa tái hiện failure với fixture gốc trong lượt lặp này.
- Fixture native mở rộng có giới hạn 32.768 descriptor `/dev/null`; child giữ
  output qua duplicate descriptor và vẫn kháng TERM. Không thay thuật toán shell,
  timeout, grace, permission, output capture hoặc retention. Descriptor layout
  làm lộ cửa sổ kernel giải phóng output trước khi hoàn tất exit.
- Với assertion gốc, **8/8 lần** fixture mở rộng fail do state `R`. Trước khi test
  `finally` gửi thêm kill, observer đọc lại cùng PID thấy nó tự biến mất trong
  **8,62–22,38 ms**. Không thấy descendant sống kéo dài trong các case này.
- Khi đưa bốn tổ hợp mở rộng vào module, giữ assertion tức thời: **4 failed,
  31 passed** cho hai module (planner assertion đã được sửa ở bước đó).

Kết quả native phù hợp với thứ tự
[`do_exit` trong Linux](https://github.com/torvalds/linux/blob/v6.12/kernel/exit.c#L879):
giải phóng file trước exit notification. Đây là nguồn tham khảo cho cơ chế; không
coi EOF là bằng chứng mọi descendant đã được reap, cũng không suy diễn mọi trạng
thái `R` đều vô hại.

Sửa ở test: `_assert_descendant_exited` đọc `/proc` cho đến khi PID biến mất hoặc
state là `Z`, với deadline **2 giây** và polling 10 ms. Không gửi thêm kill trong
checker, không chấp nhận `R`, `S` hay trạng thái live khác khi hết hạn. Không thêm
sleep cố định để che lỗi. Bỏ cặp `exists()`/`read_text()` để tránh thêm race khi PID
được reap giữa hai lần đọc; chỉ xử lý `FileNotFoundError`, không nuốt lỗi bất ngờ.

Hai case mới dùng process thật đang chờ stdin: checker phải tiếp tục chờ khi
process còn sống; khi không cho process exit, checker phải fail vì hết deadline;
khi cho exit, checker mới pass. Vì vậy một descendant thực sự sống sót không được
coi là cleanup thành công. Tất cả tám case shell gốc vẫn chạy; thêm bốn case exit
window cho hai shell và hai chế độ cancellation. Các case bổ sung cần Linux
`/proc` và descriptor limit đủ cao; chúng không bị skip trong môi trường audit.

**Chính xác các file sửa trong đợt này.**

| File | Lý do |
|---|---|
| `tests/agent/test_trial1_phase_guidance.py` | Thay một assertion wording cũ bằng kiểm tra cùng nghĩa trong owned-attempt instruction. |
| `tests/security/test_shell_descendant_cleanup.py` | Chờ terminal process state có deadline, thêm native exit-window regression và kiểm tra âm/dương cho checker. |
| `docs/lan23-six-failures-audit.md` | Báo cáo bằng chứng và kết quả xác minh của đợt này. |

Bảy file của đợt sửa A/B/C trước vẫn nguyên nội dung; không chỉnh report lịch sử
hoặc artifact thử nghiệm. Không đổi production guidance, shell, cancellation,
output capture/retention, evidence, scope hoặc permissions. Không thay Enumeration/
Input Analysis Option C, OpenAPI hay `document.py`. Không stage, commit hoặc push.

**Kết quả xác minh.** Log và manifest nằm tại
`/tmp/kagent-six-failures-lya7ksb9/`; không cộng các lượt chồng lấp.

| Lượt chạy | Kết quả |
|---|---|
| `before.txt` — hai module gốc | 5 failed, 26 passed |
| `repeat-before.txt` — lặp case spawn gốc | 40 passed |
| `exit-window-before-dup.txt` — observer với fixture exit window, assertion gốc | 8 failed; cùng PID tự biến mất sau 8,62–22,38 ms |
| `shell-regression-red.txt` — bốn regression native trước sửa checker | 4 failed, 31 passed |
| `after.txt` — hai module sau sửa | 37 passed |
| `final-targeted.txt` — hai module trên phiên bản test cuối | 37 passed, 15,07 giây |
| `repeat-after.txt` — năm lần cho mỗi tổ hợp shell/cancel/descriptor | 40 passed, 59,11 giây |
| `adjacent.txt` — capture, signal, shell tools, parallel cancellation, descendants | 213 passed, 40,80 giây |
| `prior-affected.txt` — bộ regression của remediation A/B/C trước | 226 passed, 196,77 giây |
| `pyright-final.txt` — cấu hình `venv-linux` của repository | 0 errors, 0 warnings, 0 informations |
| `extended.txt` — lượt mở rộng đầu | 7.036 passed, 0 failed, 1 skipped; 872,05 giây |
| `extended-final.txt` — lượt mở rộng trên đúng hash test cuối | **7.036 passed, 0 failed, 1 skipped; 702,60 giây** |

Lệnh extended suite giữ đúng yêu cầu:

```bash
KAGENT_RUN_LIVE_TOOL_CHARACTERIZATION=0 venv-linux/bin/python -m pytest \
  -p tests.system.offline_suite -q tests/security tests/tools tests/integration \
  tests/agent tests/ui tests/state tests/skills
```

Upgrade notice của Pyright được bỏ qua; không cài hoặc cập nhật package.
Lượt `extended-final.txt` dùng hash test đã chốt trong `final-test-hashes.json`;
không dùng kết quả lượt bắt đầu trước chỉnh lý timer phụ trong negative checker
để thay cho lượt xác minh cuối.
Tổng số case tăng tám so với log 7.022/6/1 cũ: hai diagnostic boundary case đã có
trong worktree lúc bắt đầu task này và sáu case shell mới trong đợt này. Không bỏ
case cũ để giảm failure count.

Một skip là `test_live_ambiguous_mutating_tool_characterization`, test model thật
opt-in đã có sẵn và được tắt bởi cờ môi trường yêu cầu. Không skip case nào trong
37 test planner/cleanup, các lượt lặp, adjacent tests hoặc bộ 226 regression.
Không chạy các nhóm ngoài bảy nhóm extended đã yêu cầu; đây không phải toàn bộ
configured pytest suite hoặc một experiment dùng model/target thật.

`git diff --check` và whitespace check cho report mới pass; đã xem diff của hai
test và `git status --short`. SHA-256 xác nhận **58/58** artifact lịch sử không
đổi, **7/7** file remediation trước không đổi và **2/2** file test khớp hash của
lượt extended cuối. Manifest/kết quả cuối nằm trong `verification.json` cùng
thư mục log. HEAD vẫn là `7a9b6d5`; không stage, commit hoặc push.

**Giới hạn và readiness.** Các tái hiện này kiểm tra runtime thật và process thật
trong fixture offline trên Linux. Không chứng minh mọi kiểu process tree, daemon
tự detach, cleanup trên Windows hoặc chất lượng suy luận của model. Không có
kernel trace của failure lịch sử để khẳng định duy nhất một nguyên nhân cho mọi
quan sát `R`; đã tái hiện ổn định cùng lỗi assertion và giữ điều kiện fail khi
process không chấm dứt trong thời hạn.

**READY cho bước thử nghiệm Direct Validation và Whole-target có kiểm soát**,
dựa trên kết quả hồi quy offline nêu trên. Target/scope và các gate của phiên
experiment vẫn dùng cơ chế hiện có. Task này không chạy experiment live, không
đánh giá độ chính xác phát hiện hoặc chất lượng suy luận của LLM trên target thật.
