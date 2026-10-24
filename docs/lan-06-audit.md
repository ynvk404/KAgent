# Phân tích toàn bộ lỗi quan sát được trong lan-06

Phạm vi: phân tích offline transcript được cung cấp, dữ liệu gốc tại
`experiments/scenario3/runs/lan-06/`, profile tương ứng, implementation và tests.
Không chạy lại Agent/model, không gửi request đến target, không sửa dữ liệu
thực nghiệm hoặc mã production. Các mức P1–P3 bên dưới là ưu tiên sửa lỗi
KAgent, không phải mức độ nghiêm trọng của lỗ hổng trên target.

## 1. Kết luận và dữ liệu kiểm chứng

**lan-06 thất bại ở bước chuyển Input Analysis sang SQLi validation.** Model
ghi cả bốn Candidate thành `deferred`, mặc dù validator khả dụng. Runtime
chấp nhận trạng thái này, rồi kết luận không còn actionable work khi ba phase
đầu hoàn tất. Đây là nguyên nhân trực tiếp của `workflow_blocked`, không phải
hết bước, anti-stall hay thiếu quyền được chứng minh.

Một lỗi độc lập khiến hai Candidate dạng path không đủ điều kiện bắt đầu
validation: model đổi endpoint cụ thể thành template, gặp lỗi source binding,
rồi bỏ `input_id` và nguồn kế thừa. Candidate được tạo nhưng không liên kết
với input đã phân tích.

Ngoài điều phối, có nhiều kết luận trong inventory/candidates trái với HTTP
đã lưu. Đáng kể nhất là phân loại sai cả nhóm 19 route `/api/*`, bịa một
baseline rỗng cho order tracking, và nâng những phản chiếu/empty-result thông
thường thành tín hiệu SQLi.

| Mục | Dữ liệu thực tế |
| --- | --- |
| Session | `7262ac7a-9da0-4871-8f9c-00031c3b2832` |
| Objective | `0cdbead5efb34b02bcf7cd3c79a72606`, whole-target, chỉ SQLi |
| Target | `http://127.0.0.1:8081` |
| Provider/model ghi trong run | `deepseek` / `deepseek-flash` |
| Turn bắt đầu/kết thúc | 23/10/2026, 13:45:37–13:48:06, UTC+7; theo sự kiện turn/done |
| Lý do dừng | `workflow_blocked`, log sequence 1599 |
| Outer iterations | 31/60; `no_progress=0`; không chạm stall threshold |
| LLM calls | 31 agent-loop + 1 final synthesis = 32; compaction calls = 0 |
| Phase hoàn tất | recon, enumeration, input_analysis |
| Input | 6: 4 analyzed, 2 dropped |
| Candidate | 4; tất cả `deferred`; tất cả resolve được SQLi validator |
| Attempt/result/evidence/finding | Đều 0 |
| Tool invocation | 71; có 5 kết quả tool lỗi |
| Native HTTP observations | 71: 29 HTTP trực tiếp + 42 request của content discovery |
| HTTP status | 37 × 200, 19 × 500, 11 × 401, 3 × 404, 1 × 400 |
| Shell observations | 3; một lệnh có thêm GET `/main.js` ngoài native HTTP |

Đã đối chiếu SHA-256 của **226 runtime files** với profile lan-06: không có
sai khác. Ba snapshot skill Enumeration, Input Analysis và SQLi cũng khớp
checkout hiện tại. Vì vậy các đường code được phân tích đúng với phiên bản
đã chạy, thay vì suy luận từ một phiên bản mới khác.

## 2. Nguyên nhân dừng và lỗi handoff

### L01 — P1: supported Candidate bị tạo thành deferred không có blocker

Log seq 696, 698, 700, 702 cho thấy cả bốn `record_candidate` chủ động truyền
`status: deferred`. Hai lần tạo lại ở seq 736 và 738 vẫn truyền như vậy.
Không có attempt/result nào ghi lý do hoãn.

`candidate_proposal()` ở `src/tools/workflow/workflow_tool.py:689` mặc định
`queued`, nhưng nhận nguyên trạng thái model gửi. `_record_candidate()` ở
dòng 701 chỉ buộc defer khi không hỗ trợ/generic không được admission; với
expert validator hợp lệ, Candidate mới vẫn có thể giữ `deferred` vô cớ.

`src/workflow/state.py:2048` chỉ đưa expert Candidate `new/queued/validating`
vào actionable work. Deferred không có result đi vào blocker
`condition not recorded`. Sau `complete_skill` ở seq 857, phase obligations
đóng hết; seq 859 chuyển sang `blocked`, actionable_count=0, blocker_count=5.
Bốn blocker là Candidate, blocker thứ năm là requested goal chưa có result.
`src/agent/agent.py:5047` sau đó đi thẳng vào final synthesis.

**Bất nhất runtime tái hiện offline:** tạo một SQLi Candidate supported với
`status: deferred` lần đầu trả `created=true, deferred`; gửi lại cùng arguments
trả `created=false, queued`. Nhánh promotion ở
`src/tools/workflow/workflow_tool.py:749` chỉ áp dụng với record đã tồn tại.
Một lỗi trạng thái do model vì vậy biến thành điểm dừng của cả objective.

Hướng sửa: phân biệt Candidate chưa validate với một quyết định hoãn thực sự;
trả lỗi có hướng sửa khi có expert validator nhưng deferred không có dependency
hợp lệ. Đồng bộ ngữ nghĩa tạo/enrich. Không tự động mở lại những lần hoãn có
chủ đích hoặc unresolved result, không bỏ gate để cứu một run.

### L02 — P1: đổi path identity rồi bỏ linkage để tránh lỗi source_ref

| Input đã ghi | Candidate model đề xuất | Kết quả |
| --- | --- | --- |
| `/rest/track-order/0000-0000` | `/rest/track-order/{orderId}` | Source path mismatch |
| `/rest/products/PRODUCT_ID/reviews` | `/rest/products/{productId}/reviews` | Source path mismatch |

`source_ref` kế thừa trỏ đúng request cụ thể. Model đổi endpoint nhưng giữ
nguồn của endpoint cũ. `_validate_input_http_source()` tại
`src/tools/workflow/workflow_tool.py:1013` từ chối đúng theo contract; không
có bằng chứng nguồn bị runtime gán nhầm.

Model sửa bằng cách bỏ `input_id` và không truyền `source_ref`. Hai Candidate
được nhận, nhưng input orderId/productId trong saved state có
`candidate_ids: []`. Không có `link_input_candidate` nào sau đó, dù chúng được
đánh dấu `analyzed` và prose nói đã có Candidate.

`validation_admission_error()` tại dòng 1057 yêu cầu liên kết input analyzed
tương thích. Kiểm tra trực tiếp trên bản sao saved state cho kết quả:

- Search q: không có lỗi prerequisite.
- API Products q: không có lỗi prerequisite.
- Tracking orderId: thiếu compatible analyzed input linked.
- Reviews productId: thiếu compatible analyzed input linked.

Chỉ sửa `deferred` vẫn không làm hai Candidate path đủ điều kiện validation.
Đổi prose hoặc thêm liên kết với endpoint template hiện tại cũng không đủ:
`src/workflow/state.py:1742` kiểm cả canonical endpoint identity.

Hướng sửa: kế thừa endpoint/input geometry đã kiểm chứng bằng `input_id`, giữ
path cụ thể và mô tả trường cần thay qua template thích hợp; nếu input thật sự
sai, dùng disposition/replacement có attribution đúng. Không nới path binding
hoặc tự coi template và mọi instance là cùng một nguồn bằng chứng.

### L03 — P2: dùng sai reader, dùng reference không có trong store, rồi fetch lại

Hai lần `read_http_observation` ở seq 605/606 đều fail:

- `obs_fe819ecbe33e43c78336e054d98b7fb2` có thật, body đủ 921 byte,
  không truncated, nhưng chưa có Candidate/Attempt owner.
- `obs_f49a9fb0b4fa4cb1a4e2ea71bc6e5e2a` không có trong saved ObservationStore.
  Không đủ dữ liệu để khẳng định nguồn gốc reference này.

Reader trong `src/tools/common/tool_result.py:178` cố ý yêu cầu ownership.
Đây là từ chối đúng, không phải mất body hoặc quyền YOLO bị hỏng.
Discovery reader đã có sẵn: nguồn search tương ứng là
`ds_0141b732baa545fc89c768edfa68828a485a53006afd071cba3b57118f2ef719`.
`workflow list(view="sources")` rồi `read_discovery_source` là đường đọc
bounded được phép, dưới quyền hiện hành; không tạo terminal ownership.

Model không dùng đường này, không gọi workflow list, và ngay sau thông báo
“Do not ... rerun HTTP” lại gửi ba HTTP ở seq 637–639:

- `q=apple`: baseline cũ, body/hash giữ nguyên.
- `q=apple%27`: một syntax perturbation mới; đây không phải request trùng.
- Tracking `zzxm4rker`: lặp request cũ, body/hash giữ nguyên.

Phân biệt request mới có mục tiêu phân tích với hai lần fetch lại để bù lỗi
retrieval. Hướng sửa là recovery theo đúng loại nguồn, không mở ownership
giả hoặc biến lỗi đọc local thành lý do phát thêm traffic.

## 3. Chọn công cụ và ranh giới phase

### L04 — P1: tải lại JS bằng shell, vượt contract tải bounded và mô tả sai hành động

Native `/main.js` chỉ giữ 2.000 byte và có `truncated=true`. Model nói sẽ
phân tích response đã giữ, “rather than re-fetching”, nhưng seq 270 thực tế
chạy `curl -s --max-time 8 .../main.js -o .../tmp/main.js`.
Lệnh thành công, file **783.771 byte**, không có download cap.

`skills/web-enumeration/SKILL.md:55` chỉ cho shell HTTP khi native không diễn
đạt được chi tiết request cần thiết; không cho fetch thay thế nội dung bị omit.
Ngoại lệ new-source shell còn giới hạn 64 KiB. Một GET JS thông thường không
chứng minh native thiếu khả năng biểu diễn request.

Target của lệnh vẫn là origin được khai báo; không quan sát thấy mở rộng host
hoặc thao tác phá dữ liệu. Tuy nhiên shell không có native HTTP attestation,
scope/download enforcement tương đương. YOLO approval không làm lệnh tuân thủ
playbook. Chỉ stdout `ls` được ghi làm tool-output observation; toàn bộ JS lưu
ra file không trở thành native primary evidence.

Hướng sửa: đọc phần đã lưu qua reader đúng, ghi limitation cho phần thật sự
không capture; chọn nguồn JS nhỏ hơn hoặc một kế hoạch capture mới có lý do
và bounds phù hợp. Không dùng shell để bỏ cap của native tool.

### L05 — P2: gửi syntax probe trong Enumeration

Khi còn active `web-enumeration`, model đã gửi `q=%27` tới hai search endpoint
với `phase: recon`. Stop contract ở cuối Enumeration nói payload-based
probing thuộc Input Analysis/validator. Đây là phase drift; trường `phase`
của HTTP là annotation, không phải chứng nhận request chỉ làm recon.

Chưa thấy exploit hay bounded-impact validation xảy ra. Hướng sửa là giữ
Enumeration cho discovery/request structure, chuyển signal perturbation sang
Input Analysis rồi mới chuyển confirmation sang SQLi attempt.

## 4. Sai lệch bằng chứng và chất lượng triage

### L06 — P1: inventory phân loại sai 19 route /api/*

Mục F của inventory mô tả 19 route là SPA/chưa xác nhận JSON handler và đặt
`unknown_route_reference`. Dữ liệu gốc hoàn toàn khác:

| Nhóm response thực tế | Số | Ví dụ |
| --- | --- | --- |
| 200, JSON đầy đủ | 4 | Feedbacks, Recycles, SecurityQuestions, Deliverys |
| 200, body truncated | 2 | Challenges, Hints |
| 401 | 7 | Complaints, Users, BasketItems, Cards, Addresss... |
| 500 | 6 | Addresses, Quantities, Reviews, Memories, ProductReviews, v1/Products |

Không route nào trong nhóm này có baseline `200 text/html` của SPA trong
observations đã lưu. `401/500` không đủ xác nhận schema/method/implementation,
nhưng rõ ràng không phải bằng chứng rằng cả nhóm chỉ là SPA shell. Mâu thuẫn
còn nằm ngay trong inventory: phần normalization tự phân biệt 401/500 với SPA.

`content_discovery` hoàn tất 42 request/40 path nhưng output có
`truncated=true` và trả retained `tr_9157454bff254ee4b898be85d85fb641`.
Không có `read_tool_result` để kiểm phần kết quả bị omit trước khi model viết
kết luận toàn nhóm. Retained result hiện vẫn còn trong run.

Hướng sửa: reconcile từng row từ kết quả retained; ghi status/provenance riêng
cho JSON, partial body, unauthorized, error và wildcard. Không suy diễn thêm
parameter từ response object, cũng không bỏ observation thật thành unknown.

### L07 — P1: tín hiệu ghi trong Candidate/artifact trái với response

Ba ví dụ kiểm chứng trực tiếp:

1. **Tracking baseline sai:** `obs_9469a6641d80499a9b465fdde5b144df`
   trả `{"status":"success","data":[{"orderId":"0000-0000"}]}`.
   Model ghi `data: []` vào Candidate signals, inventory/candidates và dùng
   sự khác biệt không tồn tại để nâng độ ưu tiên.
2. **Products q bị mô tả không differential:** baseline `q=apple` là
   885 byte/3 product; quote là 370 byte/1 product; marker là 30 byte/0 product.
   Có khác biệt kết quả tìm kiếm. Artifact lại ghi quote “no differential
   observed”/“no shape change”. Khác biệt này phù hợp search thông thường,
   chưa phải SQL differential, nhưng không được sửa dữ liệu quan sát cho khớp
   kết luận mong muốn.
3. **Reviews bị thổi phồng:** `PRODUCT_ID` và `zzxm4rker` đều
   `200 {"status":"success","data":[]}`, cùng 30 byte và cùng body hash.
   “Non-numeric value accepted” không chứng minh server sử dụng input theo
   một SQL sink hay có differential. Mô tả “review list” cần giữ rõ là rỗng.

Hướng sửa: dựng signals từ đúng observation/baseline đã kiểm tra; giữ bằng
chứng bất lợi. Không chỉ sửa câu cuối của báo cáo trong khi structured state
vẫn lưu tín hiệu sai.

### L08 — P2: tạo SQLi Candidate từ reflection, tên route và sibling behavior

Search q có tín hiệu SQLite syntax error rõ, đủ ưu tiên **nghi vấn** để
validator xử lý. Ba Candidate còn lại yếu hơn đáng kể:

- Tracking chỉ phản chiếu một string. Một order ID có dạng chuỗi là bình
  thường; không có parser error hoặc SQL-specific differential.
- Reviews không có differential quan sát được và dựa vào việc cùng prefix
  `/rest/products` với endpoint khác.
- API Products q chứng minh search consumption, chưa chứng minh ghép SQL;
  lỗi của sibling `/rest/products/search` không xác nhận implementation này.

Input Analysis cho phép tạo giả thuyết có lý do, nhưng không cho coi requested
class hoặc sibling route là bằng chứng sink. Tracking `priority: high` và
reviews `medium` không được dữ liệu hiện có hỗ trợ tốt. Nên ghi rõ ambiguity,
không ép tất cả input thành SQLi candidate chỉ để phục vụ SQLi-only objective.

### L09 — P2: khẳng định query construction vượt bằng chứng

`q=apple%27` thực sự trả 500, 994 byte, có `SQLITE_ERROR` và syntax error.
Đây là tín hiệu giá trị. Tuy nhiên signals/disposition/final prose khẳng định
“proving ... concatenated into a quoted SQLite literal”. Không có constructed
query text trong bằng chứng được viện dẫn để chứng minh đúng shape/cách bind.

`skills/web-input-analysis/SKILL.md:195` và đầu SQLi playbook yêu cầu giữ SQL
shape là giả thuyết khi chỉ có parser error. Chưa có repeatable controlled
evaluation, accepted validation result hoặc finding.

Hướng sửa: mô tả đúng “quote-triggered SQLite syntax error, suspected SQLi;
query construction chưa xác minh”, rồi kiểm chứng trong attempt với proof
theo playbook. Không biến một error thành kết luận exploitability/impact.

## 5. Độ phủ, schema và báo cáo cuối

### L10 — P2: bỏ sót input đã có nguồn và suy diễn method/auth từ GET error

Bundle được tải xuống có call site rõ ở offset ký tự **460998**:
`/rest/user/security-question?email=`. Inventory nói không quan sát được tên
query parameter, nên không ghi input email. Đây là khoảng trống extraction
có thể kiểm chứng offline, không cần phỏng đoán Juice Shop từ kiến thức cũ.

Trong cùng bundle, đoạn login ở offset khoảng **512843–512913** gán
`user.email`, `user.password`, rồi gọi `userService.login(user)`. Reset form
cũng có cấu trúc field. Chúng là frontend structure, chưa tự xác nhận wire
method/URL/body media type, nhưng chứng minh nguồn có field-level evidence
để tiếp tục trace service. Không nên nói hoàn toàn không có visible
field-level evidence. Phần extraction đã dùng chỉ xem một tập network terms,
không phải kiểm hết schema hay flow liên quan.

Ngược lại, inventory gắn `POST` cho login/reset/reviews/chatbot và suy luận
GET 500 nghĩa là “expects body”, “requires session”. Method sai, handler bug
và auth dependency là những giả thuyết khác nhau; status 500 một mình không
phân biệt được. `GET /rest/order-history` 500 không chứng minh cần account;
không có account không chặn việc xác minh các Candidate public hiện có.

Bundle còn cho thấy review writes dùng `PUT`/`PATCH` ở các call site riêng;
đây là lý do phải trace method/URL từ nguồn, không tự chuyển mọi review route
thành POST. Phân tích này không yêu cầu thực thi bất kỳ write nào.

Tham số `sort` chỉ được append vào search và không đổi response; “accepted
without error” không chứng minh API hỗ trợ sorting. Loại nó khỏi candidate
list là hợp lý, nhưng inventory cần ghi đây là tham số đã thử/chưa quan sát
server tiêu thụ. Tương tự, 404 cho `/api/Products/1%27` không chứng minh
implementation “type-checked cleanly”; chỉ ghi 404/no SQL error trong bound
đã kiểm.

### L11 — P2: tổng số và confidence trong artifact không tự nhất quán

- Inventory summary ghi 32 route = 24 observed + 8 referenced-only, nhưng
  riêng mục F đã liệt kê 19 unknown/reference routes; 23 heading endpoint
  ở A–E còn chứa hai heading gộp nhiều route. Không có quy tắc đếm để hòa
  giải những con số này. Saved runtime có 64 endpoint records, nhưng không
  được lấy 64 thay cho một số route semantic đã deduplicate.
- Candidates summary/table nói 2 high + 2 medium, tracking đứng high; entry
  chi tiết của tracking ghi medium. Confidence và runtime priority cũng cần
  phân biệt, thay vì dùng thay nhau.
- Candidates artifact ghi “Deferred (no enabled validator): 0”. Con số đó
  đúng nếu chỉ đếm thiếu capability, nhưng cả bốn Candidate thực tế đều
  deferred vì status model đặt. Artifact che khuất trạng thái handoff gây
  dừng run.

Hướng sửa: tổng hợp từ danh sách canonical có định nghĩa rõ route/method,
observation, input, candidate; đối chiếu status cuối trước khi viết summary.

### L12 — P3: gửi coverage_phase không thuộc action schema

Seq 426/427: `record_phase_coverage` nhận cả `phase` và `coverage_phase`.
`ACTION_INPUTS` tại `src/tools/workflow/workflow_tool.py:137` chỉ nhận
`phase`, `coverage_dimension`, `coverage_status`, `coverage_reason`.
Runtime trả `invalid_args` đúng. Model sửa bằng cách bỏ `coverage_phase`,
gọi lại thành công và Enumeration vẫn complete.

Đây là lỗi model gọi tool đã được recovery, không phải nguyên nhân dừng cuối.
Không nên mở schema để chấp nhận field dư. Wording “runtime identities cannot
be assigned” dùng chung cho mọi unsupported arg hơi rộng, nhưng đã chỉ rõ
field phải bỏ.

### L13 — P2: lời giải thích “operator phải bắt đầu validation” thiếu căn cứ

Final synthesis nói operator action là bắt buộc để start bốn attempt. Saved
state không cho thấy permission denial, credential dependency hoặc một
runtime gate yêu cầu operator start hai Candidate public search q. Kiểm tra
prerequisite offline cho hai Candidate query đều trả không lỗi.

Điểm dừng thật là `deferred` do model ghi, cộng với lỗi liên kết cho hai path.
Không có `load_skill(sql-injection)` hoặc `start_validation` nào được thử;
vì vậy không được kể lại như một thao tác validation đã bị hệ thống quyền
từ chối. Yêu cầu whole-target tự động của operator vốn đã bao gồm bounded
SQLi validation; impact/high-impact work vẫn phải giữ gate riêng.

Final synthesis đã đúng ở các điểm: assessment incomplete, không có findings,
không coi discovery là kết quả âm tính. Cần giữ các giới hạn trung thực đó,
nhưng nêu đúng nguyên nhân và bước repair, thay vì đẩy lỗi trạng thái nội bộ
thành một yêu cầu authorization mới.

## 6. Năm tool errors hiển thị và ý nghĩa

| Log seq kết quả | Lỗi | Phân loại |
| --- | --- | --- |
| 427 | `record_phase_coverage` không nhận `coverage_phase` | Invalid args; đã sửa |
| 607 | Observation read ownership/scope unavailable | Dùng sai reader cho nguồn chưa owned |
| 608 | Observation read ownership/scope unavailable | Reference không có trong saved store |
| 699 | HTTP source_ref path does not match input | Thay endpoint cụ thể bằng template |
| 703 | HTTP source_ref path does not match input | Cùng lỗi với reviews |

19 HTTP 500 là response của target, không phải 19 exception của KAgent. Các
401/404/400 và truncation warning cũng phải đọc trong context riêng. Không
thể cộng tất cả warning/status vào số tool failures.

`content_discovery` có `complete=true` vì đã hoàn tất số request đã khai báo;
`truncated=true` nói về kết quả/body bị giới hạn. Hai cờ không mâu thuẫn.
Phase completion biểu thị contract bookkeeping đã đóng, không chứng nhận
mọi câu trong Markdown là đúng hoặc cả ứng dụng đã được test.

29 HTTP discovery source còn pending nhưng **đều unselected**. Contract hiện
hành không coi chúng là một backlog bắt buộc phải đóng; không quy chúng là
nguyên nhân block hoặc đề nghị auto-select hết để sửa run.

## 7. Giới hạn quan sát

- Debug log có hai record `debug_records_dropped`: 69 và 150, tổng 219.
  Không có archive đầy đủ của outbound provider requests. Phân tích dựa trên
  các call/result, saved session, retained observations và source hashes còn
  lưu; không khẳng định đã phục dựng toàn bộ prompt model nhìn thấy.
- Có context pressure: estimate cuối trước chuyển phase khoảng 46.998 token,
  sau đó khoảng 38.928; soft threshold 32.000. Log nói vẫn dưới hard input
  limit. Đây là áp lực/context noise có thể góp phần, chưa chứng minh là nguyên
  nhân model đặt deferred hoặc bịa dữ liệu. Không có bằng chứng provider lỗi
  API, timeout hay token budget exhaustion.
- Không suy ra chính xác SQL construction, DB sink của từng route, auth policy
  hay lỗ hổng đã confirmed từ tên ứng dụng/route. Không chạy target để lấp
  những khoảng trống này trong audit.
- Kiểm tra trên bản sao state với status đổi thành queued chỉ là phép đối
  chứng in-memory: chứng minh phân loại work đổi sang actionable; không cấp
  quyền, không tạo attempt và không sửa session gốc. Gate linkage của hai path
  vẫn còn nguyên.

## 8. Thứ tự sửa đề xuất

1. Sửa contract trạng thái Candidate mới/enrichment: không để deferred vô cớ
   trở thành blocker mơ hồ; bảo toàn quyết định hoãn thật và stop conditions.
2. Sửa guidance/recovery để giữ canonical input identity và linkage sau lỗi
   source binding; không cứu bằng cách bỏ provenance.
3. Đưa recovery đọc discovery/retained tool result vào đúng context cần dùng;
   giữ ownership, range permission, scope và cap.
4. Kiểm tra grounding của inventory/signals: reconcile native discovery rows,
   sửa baseline sai, bỏ SQLi inference chỉ từ reflection/sibling route, trích
   input có call-site evidence và ghi method/auth unknown trung thực.
5. Giữ shell/native selection và phase discipline; sửa summary totals và mô
   tả blocker. Sau khi có regression phù hợp mới đánh giá bằng một run mới
   được yêu cầu riêng; không sửa hồi tố kết quả lan-06.

## 9. Kiểm chứng thực hiện trong audit

Hai nhóm kiểm thử offline bằng `venv-linux/bin/python`:

```bash
python -m pytest -q \
  tests/tools/test_workflow.py \
  tests/tools/test_workflow_argument_contract.py \
  tests/integration/test_whole_target_workflow.py \
  tests/security/test_discovery_source_reader.py \
  tests/agent/test_phase_guidance.py --tb=short
# 167 passed

python -m pytest -q \
  tests/tools/test_workflow_sources.py \
  tests/skills/test_web_input_analysis.py \
  tests/skills/test_web_enumeration.py \
  tests/skills/test_sql_injection.py --tb=short
# 175 passed
```

Tổng **342 passed**. Tests hiện có pass không bác bỏ lỗi run: chúng kiểm
contract, không bảo đảm model sẽ chọn đúng status, nguồn hay diễn giải evidence.
Đã tái hiện riêng bất nhất deferred→queued khi ghi lại và kiểm prerequisite
của bốn Candidate bằng script offline, chỉ sửa object trong memory.

Không sửa production, không thêm/sửa test, không chạy toàn bộ suite, pyright,
live/external-model tests hoặc target assessment. Chỉ thêm báo cáo này.
`git diff --check` không báo lỗi; đã kiểm cả whitespace của file mới, nội dung
diff và `git status --short`. Worktree chỉ thêm `docs/lan-06-audit.md`.
