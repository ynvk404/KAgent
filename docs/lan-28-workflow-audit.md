# Audit lan-28: mất handoff từ input sang SQLi validation

Audit ngoại tuyến trên artifacts của `experiments/scenario3/runs/lan-28/`
và worktree hiện tại. Không gửi HTTP, gọi provider, sửa session gốc hay thay đổi
production code. Các thay đổi có sẵn trong worktree được giữ nguyên.

Kết luận: phiên không hoàn tất yêu cầu whole-target SQLi. Có hai lỗi handoff
rõ ràng và một khoảng trống enumeration. Không có bằng chứng validator SQLi
đã chạy rồi thất bại.

## Nguồn và kết quả được lưu

- Session: `profile-home/.kagent/sessions/58ceb1a9-b744-4cce-894d-23e9d211f040.json`
  trong thư mục run.
- Debug events: `logs/session.jsonl`; HTTP captures:
  `project/.kagent/observations/58ceb1a9-b744-4cce-894d-23e9d211f040.json`.
- Inventory: `project/artifacts/web-enumeration/juice-lab-8081/inventory.md`.
- Bản playbook trong run của `web-enumeration`, `web-input-analysis` và
  `sql-injection` trùng byte với worktree tại thời điểm audit. Run không lưu
  toàn bộ mã runtime, nên việc quy lỗi cho code được củng cố bằng tái hiện
  ngoại tuyến trên implementation hiện tại.

State cuối: Recon và Enumeration hoàn tất; Input Analysis chưa hoàn tất.
Trong 7 inputs có 5 `analyzed`, 1 `dropped`, 1 `blocked`; mọi `candidate_ids`
đều rỗng. Không có Candidate, Attempt, ValidationResult, Evidence hay finding
được ghi vào workflow. Canonical `candidates.md` chưa được tạo.

Event `done` ở dòng 1092 ghi `workflow_blocked`, 60 agent-loop calls và 1
final-synthesis call, trong khi `max_outer_iterations=200`. Hai debug-drop
records báo mất tổng cộng 190 records; audit đối chiếu thêm session đã lưu,
không coi log streaming là transcript đầy đủ.

## 1. [P1] Giới hạn hai lượt cắt ngang việc áp dụng câu trả lời của operator

Timeline dưới đây dùng số dòng vật lý trong `logs/session.jsonl`:

| Iteration | Dòng | Hành động/kết quả |
|---|---|---|
| 54–55 | 487, 494 | Đặt `cid` và `orderLinesData` của B2B thành `blocked` |
| 56–57 | 520, 522, 529, 531 | Đặt `q`, `sort`, hai path inputs thành `analyzed` |
| 58 | 538–540 | Đóng input pending cuối; runtime chuyển thành blocked, 0 actionable |
| 59 | 545–547 | `ask_user` bind **cả hai** B2B input IDs; answer là **"Exclude these inputs"** |
| 60 | 565–567 | Chỉ `cid` được chuyển sang `dropped`; runtime vẫn blocked và chuyển sang synthesis |

Nguyên nhân trực tiếp trong code:

- `src/workflow/state.py:2035`: khi hết pending inputs nhưng vẫn còn blocked
  input, phase không còn được liệt kê là actionable. Những việc còn lại như
  viết partial handoff hay hoàn tất áp dụng câu trả lời không có obligation
  riêng trong phép chiếu này.
- `src/agent/agent.py:4060`: `blocked_handoff_turns` cho hai lượt phối hợp.
  Nhánh sau tool execution tại dòng 4522–4533 tăng counter bất kể vừa nhận
  câu trả lời hay vừa commit được tiến độ. Khi hết hai lượt, runtime gọi
  synthesis dù còn dư global iteration budget. Nhánh phản hồi không có tool
  tại dòng 4271 có cùng giới hạn.

Iteration 58 mở cơ hội handoff thứ nhất, iteration 59 dùng cơ hội thứ hai;
iteration 60 chỉ đủ commit một input. Một cập nhật ở mỗi lượt là cách dùng
tool hợp lệ, nên không thể dựa vào việc model phải batch mọi thay đổi.

Tái hiện bằng scripted client, real Agent/WorkflowTool/AskUserTool và
ExecutionPolicy trong thư mục tạm: chuẩn bị hai blocked inputs và một public
input pending; lần lượt analyze public input, hỏi operator cho cả hai IDs,
drop input thứ nhất, drop input thứ hai, record Candidate, viết artifact.
Operator trả lời exclude cả hai. Với `max_steps=20`, chỉ ba tool turns đầu
được chạy, tất cả thành công; runtime dừng `workflow_blocked`, input thứ hai
vẫn blocked, Candidate và artifact chưa được tạo. Không có network call.

Final summary của run nói `orderLinesData` chưa có recorded decision và đề
nghị quyết định tiếp. Điều này lẫn **answer đã có cho cả hai IDs** với
**disposition chưa commit cho ID thứ hai**. Cần áp dụng quyết định đã nhận;
không cần hỏi lại operator.

Hướng sửa: biểu diễn việc áp dụng quyết định và hoàn tất handoff như công
việc còn lại; cho phép tiến độ này tiếp tục trong global budget. Giữ bounded
stop cho việc lặp lại không tiến triển. Chỉ tăng hằng số hai lượt sẽ không
giải quyết tổng quát trường hợp nhiều inputs. Câu trả lời vẫn không tự động
commit disposition hoặc cấp quyền execution.

## 2. [P1] Search có giả thuyết được chọn nhưng không được ghi thành Candidate

Iteration 56, dòng 520: agent mô tả `q=apple` trả HTTP 200, JSON gồm các
products phù hợp; giữ SQL LIKE-style lookup là giả thuyết và kết luận
**"Handed to the sql-injection validator."** Tuy nhiên tool được gọi chỉ là
`set_input_disposition(analyzed, analysis_complete=true)`. Không có
`record_candidate` nào trong toàn bộ session. Hai inputs `sort` và track-order
id cũng được agent mô tả như hướng SQLi cần tiếp tục mà không tạo record.

Đây là thiếu bước của agent, trái contract ở
`skills/web-input-analysis/SKILL.md:515`: mọi Candidate được chọn để handoff
phải được ghi qua `record_candidate` và liên kết bằng `input_id`.
`src/tools/workflow/workflow_tool.py:1241` chỉ kiểm tra khai báo
`analysis_complete`; nó không tạo Candidate. Điều đó đúng với ý nghĩa
`analyzed` là triage, nhưng không đảm bảo lời hứa handoff đã được thực hiện.
Khi pending input cuối đóng, phép chiếu runtime chỉ còn nhìn thấy blocker
B2B và kích hoạt giới hạn ở finding 1.

Không nên bắt mọi input analyzed phải có Candidate, hoặc suy ra Candidate
bằng cách parse `disposition_reason`. Cần giữ quyết định triage có cấu trúc:
nếu đã chọn một giả thuyết để validate, phải commit Candidate và linkage;
nếu không chọn, ghi đúng lý do và giới hạn chưa kiểm thử. Đặc biệt, tên
`sort` hay việc echo một path value chưa tự chứng minh SQL implementation;
audit không xác nhận cả ba giả thuyết đều đủ căn cứ.

Hướng sửa trước mắt: ghi Candidate ngay khi chọn giả thuyết cho Search `q`,
viết canonical partial handoff trước khi đóng hết pending inputs, rồi tiếp
tục validator qua admission hiện có. Regression cần kiểm tra Candidate ID,
linkage, artifact và attempt được mở; không chỉ kiểm tra câu chữ playbook.

## 3. [P2] Login dừng ở endpoint clue, không có request-contract discovery

HTTP store chỉ có một request tới login: **GET `/rest/user/login` → 500**,
observation `obs_0c3f12e963694141a48a125eebcd3a4a`, từ content-discovery pass
ở iteration 21 (dòng 207). Không có POST login, `email` input, schema hay
frontend call-site được ghi nhận. Inventory xếp login chung với nhóm GET
errors rồi Enumeration hoàn tất ở iteration 49 (dòng 449).

Một yếu tố góp phần được quan sát: root HTML chỉ được capture 8192/9903 bytes.
Agent đọc một số cửa sổ đầu, tìm literal `main.js` không thấy trong phần đã
giữ, rồi không fetch frontend bundle. API document thu được chỉ mô tả B2B
`/orders`, nên không giải quyết request contract của login. Đây là khoảng
trống discovery có thật; chưa đủ bằng chứng để quy riêng cho một parser bug.

GET 500 **không chứng minh** login cần POST hoặc có trường `email`.
`skills/web-enumeration/SKILL.md:134` yêu cầu tách route clue, inferred method
và field được chứng minh bằng request/form/schema/call-site. Không nên vá
bằng cách hard-code Juice Shop hoặc tự biến mọi GET 500 thành POST email.

Hướng sửa: ưu tiên điều tra method/body cho clue có giá trị trong bounds,
chọn capture ban đầu phù hợp cho nguồn định đọc, và ghi omission reason cụ
thể nếu không giải quyết được. Khi có request-contract evidence, record các
inputs rồi chuyển sang triage. Giữ các giới hạn đọc/capture và permission
gates; không refetch tăng cap để phục hồi phần đã bị cắt.

Một dấu hiệu enumeration khác cần regression: agent tạo `captchaId` làm
path input của GET `/rest/captcha`, viện dẫn một OpenAPI template, trong khi
spec được thu chỉ có `/orders` và request captcha thực tế không có id segment.
Response field không đủ để tạo request input. Vì vậy không nên sửa thiếu
Login bằng cách chấp nhận thêm các input chỉ được đoán từ response.

## Gate cho validation độc lập hiện đã hoạt động

`src/tools/workflow/workflow_tool.py:1314` cho phép partial analysis handoff:
cần Recon/Enumeration đã hoàn tất, canonical analysis artifact và compatible
analyzed input liên kết đúng Candidate. Independent blocked inputs vẫn mở.
`src/agent/decision_planner.py:483` ưu tiên Candidate được admission chấp nhận.

Kiểm tra ngoại tuyến riêng với SQLi: cùng một public input và một private
blocked input, sau `analyzed` đơn thuần thì status là blocked, không có action.
Sau `record_candidate(input_id=...)` và viết partial canonical artifact,
`validation_admission_error` trả `None`, status thành actionable với
`candidate:<id>`, dù private input vẫn blocked và phase Input Analysis chưa
complete. Vì vậy `lan-28` không chứng minh scheduler bỏ qua một Candidate
độc lập đã tồn tại: thực tế không có Candidate nào để schedule.

Không cần nới phase-completion gate, permission gate, yêu cầu evidence hay
finding eligibility để sửa các lỗi trên.

## Verification và phần chưa kiểm tra

Chạy bằng `venv-linux/bin/python -m pytest -q` với:

- `tests/agent/test_lan2021_blocked_handoff.py`
- `tests/integration/test_lan2021_partial_admission.py`
- `tests/integration/test_trial1_phase_admission.py`
- `tests/skills/test_web_enumeration.py`
- `tests/skills/test_web_input_analysis.py`

Kết quả: **114 passed**. Bộ này chưa kiểm tra apply một group answer qua
nhiều tool turns trước khi viết artifact, nên pass không phủ nhận finding 1.
Hai reproductions ở trên chạy riêng bằng script tạm, không sửa tests hiện có.
`git diff --check` pass. Chưa chạy full suite, pyright, live target hay live
LLM; audit này không đo tỷ lệ model thực hiện đúng sau một bản sửa tương lai.
