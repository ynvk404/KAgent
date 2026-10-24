# Đối chiếu SQLi Validation: lan-01 và lan-08

## Phạm vi và kết luận chính

Đây là audit offline trên bundle thực nghiệm và các snapshot lịch sử; không gửi request tới mục tiêu, không gọi LLM/provider, không sửa code, Skill, test hay dữ liệu của hai run. Nguồn chính là bundle dưới `experiments/scenario3/runs/lan-01/` và `experiments/scenario3/runs/lan-08/`, profile tương ứng trong `experiments/scenario3/profiles/`, cùng báo cáo lan-08 hiện có: [lan-08 RCA](lan-08-audit.md), [tool history](lan-08-tool-history.md), [acceptance](lan-08-acceptance.md).

**Kết luận:** lan-01 có bằng chứng HTTP đủ để xác nhận boolean SQL injection tại `GET /rest/products/search?q=`. Kết luận không dựa riêng vào lời Agent hay SQLite error: hai cặp predicate cùng ngữ cảnh cho kết quả khác nhau lặp lại, với response đầy đủ chứa dữ liệu ở nhánh TRUE và JSON rỗng ở nhánh FALSE; capture, attempt, proof và Finding liên kết với nhau. Mức tin cậy cao cho SQLi tại tham số này. Một số mô tả trong Finding lan-01 phóng đại số bản ghi và suy luận hình dạng SQL vượt quá điều captures chứng minh.

lan-08 xác nhận input làm phát sinh lỗi cú pháp SQLite, nhưng không xác lập oracle. Cặp TRUE/FALSE đầu tiên đều trả cùng JSON rỗng; những phép sau đổi đồng thời input, dấu nháy và cấu trúc biểu thức, hoặc đều trả lỗi/cùng kết quả. Vì vậy `not-confirmed` đã được runtime chấp nhận về mặt cấu trúc nhưng không phải negative test có oracle theo hợp đồng SQLi. Cách phân loại phù hợp với evidence là unresolved / insufficient evidence.

Điểm phân kỳ có ý nghĩa không phải số lượng tool call hay nhãn kết quả. Trên seed `apple`, các phép thử lan-01 chưa tạo differential: cặp ở i39 cùng trả lỗi, rồi một biến thể ở i40 trả JSON rỗng; lan-01 sau đó chuyển sang seed wildcard và giữ predicate pair có thể so sánh. Ở lan-08, cặp i48–49 đều trả JSON rỗng nhưng Agent không đổi seed theo hướng đó; thay vào đó tiếp tục giả thuyết suffix chưa được chứng minh và đổi nhiều phần của hai vế thử. Dù đã đọc payload guidance có cảnh báo đúng về wildcard và equal responses, lan-08 không vận dụng được cảnh báo sau cặp bằng nhau. Không có bằng chứng rằng giới hạn lượt, quyền, lỗi Context Reduction hoặc hồi quy trong Agent Core đã gây ra oracle thất bại. Model variance vẫn có thể góp phần, nhưng không thể tách riêng từ hai run.

## A. Xác minh lan-01: SQLi có thực sự được xác nhận?

| Trường | Dữ liệu đã xác minh |
|---|---|
| Target và scope | `http://127.0.0.1:8081`; trong lan-01, mục tiêu là đánh giá web app (SQLi và XSS). Không suy rộng kết luận ra origin khác. |
| Endpoint/input mạnh nhất | `GET /rest/products/search?q=`; candidate `cand_faa9ff1fdf18dc8bb99e`; attempt `attempt_a3939515092e47139494fd86475c3d8d`. |
| Validation result | `confirmed`; result `result_9bb7b039c35740a79adfb9e352afec40`. |
| Evidence / Finding | Registered evidence `ev_ae8ce77c58a14282fd63`; report `experiments/scenario3/runs/lan-01/project/artifacts/findings/boolean-based-sql-injection-in-product-search-parameter-q.md`. |
| Kết luận audit | **Confirmed với độ tin cậy cao** cho khả năng điều khiển kết quả truy vấn qua tham số `q`; không đồng nghĩa mọi câu SQL hoặc impact trong Finding đều đúng. |

Hai cặp HTTP được lưu đầy đủ sau khi hai TRUE capture ban đầu bị cắt ở giới hạn 4.096 byte và được chụp lại. Cặp thứ nhất giữ input và cấu trúc giống nhau, chỉ đổi predicate số học; cặp thứ hai giữ cấu trúc và chỉ đổi predicate chuỗi:

| Cặp | Observation | HTTP / body | Diễn giải |
|---|---|---|---|
| TRUE: wildcard search + predicate `1=1` | `obs_3ca4385860444722bfbc2f86067e1d18` (recapture ở i45; lần đầu `obs_69daefcb503b45b880ac5f4c6b62e016`, bị truncate) | 200; 21.581 bytes; JSON đầy đủ, `data` có 56 records | TRUE branch trả records. |
| FALSE: cùng input + predicate `1=2` | `obs_f2a8354f2b3b499c864ac2156202bfe2` (i41) | 200; 30 bytes; `{"status":"success","data":[]}` | Cùng khuôn request nhưng FALSE branch rỗng. |
| TRUE: cùng input + predicate `'1'='1` | `obs_bfe8070223ad4867b6f6e5d72eda75b1` (recapture ở i46; lần đầu `obs_ba2b02a1d016418ca74ddefd2a5c4bfa`, bị truncate) | 200; 21.581 bytes; JSON đầy đủ | Lặp lại nhánh TRUE bằng dạng predicate khác. |
| FALSE: cùng input + predicate `'1'='2` | `obs_ca1abc3893814b80a167f5ffe0a6f317` (i42) | 200; 30 bytes; JSON rỗng như trên | Lặp lại nhánh FALSE bằng dạng predicate khác. |

Các cặp được gửi trong cùng ngữ cảnh query; body là phép đo chính, không chỉ status code. Cả TRUE recapture và FALSE captures hoàn chỉnh, được attempt sở hữu và nằm trong manifest evidence. Bản proof immutable có mode read-only; hash của artifact, binding candidate/result và manifest được kiểm tra lại bằng snapshot workflow lịch sử. Do đó đây là evidence tái lập được từ bundle, không phải phát biểu đơn lẻ của Agent.

Có hai giới hạn cần giữ trong cách diễn đạt. Thứ nhất, Finding nói “all 30 products”, trong khi response TRUE có 56 records; 10 record có `deletedAt` khác null. Con số 30 không được body hỗ trợ và không nên dùng làm kết luận. Thứ hai, một số mô tả về câu SQL, dấu ngoặc và impact là suy luận của Agent; lỗi SQLite riêng lẻ chỉ cho thấy input ảnh hưởng parse/execution, không chứng minh một query shape cụ thể. Bằng chứng boolean differential cuối cùng chứng minh khả năng điều khiển kết quả mà không cần khẳng định chính xác source SQL.

lan-01 còn có candidate SQLi riêng trên `POST /rest/user/login` (`cand_5b1847d9b4a77ba6ed6d`, attempt `attempt_cce5cc0528cf463ebe11b49fc38320a9`, evidence `ev_5e269490cfbc2ab5bd56`). Một số request cho HTTP 200 với response khoảng 799 bytes, các request đối chứng cho 401/26 bytes. Đây là tín hiệu đáng chú ý, nhưng vế thứ hai của cặp cuối đổi thêm cấu trúc OR thành AND; vì vậy nó kém sạch hơn cặp search và không cần dựa vào nó để xác minh thành công. Evidence store có giá trị auth dạng token; báo cáo này không trích token, giải mã hoặc replay nó.

## B. Tái dựng hai phiên

### lan-01: từ lỗi cú pháp đến oracle boolean

Profile lan-01 ghi DeepSeek, model `deepseek-flash`, base URL `https://api.deepseek.com`, config fingerprint `8bc1c4ee9946db7136dc051bc048c69ea9d78b685e510c578f5fc58fd78d80fd`; SQLi Skill snapshot `experiments/scenario3/runs/lan-01/project/skills/sql-injection/SKILL.md` có SHA-256 `5db827c751bdcfd4fb472a5362b4bad93f664e8717c9ae714b712b2b7c78a4cc`. Bundle ghi target `http://127.0.0.1:8081`; giới hạn workflow là 60 outer iterations, rate 3/s, burst 3, concurrency 2 và response cap 65.536 bytes. Config fingerprint không tiết lộ API key hay xác định server-side model revision. Prompt của run bao gồm SQLi và XSS.

Chuỗi search SQLi dưới đây được đối chiếu giữa session/tool history, observation store, workflow và artifact. Số i là iteration lịch sử; observation ID là handle trong bundle:

| Iteration | Request / observation | Phản hồi thực tế | Vai trò trong diễn tiến |
|---|---|---|---|
| i10 | `q=apple'`, `obs_41060d38ae7d42cab9fef979de83319b` | 500, 994 bytes; lỗi SQL/SQLite trong body | Phát hiện dấu hiệu syntax-sensitive, đủ để tạo giả thuyết và candidate, chưa đủ xác nhận. |
| i11 | UNION-shaped probe, `obs_37edd5ffe3104b02a582bfe01e8eec0d` | 500, 982 bytes | Thử mở rộng kỹ thuật; lỗi tiếp tục không cho oracle. Payload không chép lại ở đây vì không cần để đánh giá nguyên nhân. |
| i39 | `apple')) AND '1'='1`, `obs_eb241100dee94519a101aeee40d959a3`; và `apple')) AND '1'='2`, `obs_63850bb17d5d44f88310ca7aefbc9502` | Cả hai 500, 974 bytes | Cặp predicate chưa thoát đúng query context; hai lỗi giống nhau không tạo boolean differential. |
| i40 | `apple')) AND 1=1--`, `obs_f0b8767f2a824a989e0ec6f0b6694d3e` | 200, 30 bytes, JSON rỗng | Sửa cú pháp nhưng vẫn không có TRUE output khác baseline. |
| i41 | Decoded `q=%')) AND 1=1--`, `obs_69daefcb503b45b880ac5f4c6b62e016`; đối chứng `q=%')) AND 1=2--`, `obs_f2a8354f2b3b499c864ac2156202bfe2` | TRUE ban đầu bị cắt ở 4.096 bytes; FALSE hoàn chỉnh, 200/30, JSON rỗng | Đổi seed để tương thích với khả năng tìm kiếm có wildcard; recapture TRUE sau đó cho thấy nhánh dữ liệu. |
| i42 | Cùng wildcard context, predicate `'1'='1` với `q=%')) AND '1'='1'--` (`obs_ba2b02a1d016418ca74ddefd2a5c4bfa`) và `'1'='2` với `q=%')) AND '1'='2'--` (`obs_ca1abc3893814b80a167f5ffe0a6f317`) | TRUE ban đầu bị cắt; FALSE 200/30, rỗng | Lặp bằng một dạng predicate khác; vẫn cần recapture TRUE để có bằng chứng body đầy đủ. |
| i45–46 | Recapture TRUE cho hai cặp: `obs_3ca4385860444722bfbc2f86067e1d18`, `obs_bfe8070223ad4867b6f6e5d72eda75b1` | Mỗi response 200/21.581 bytes, complete, 56 records | Hoàn tất chứng cứ TRUE/FALSE, tạo differential lặp lại. |
| i50 | Lưu evidence, record result, rồi Finding | Evidence đăng ký; result `confirmed`; Finding được tạo | Candidate search đóng với bằng chứng hợp lệ. |

Luồng quyết định quan trọng là phân biệt “syntax error” với “oracle”: quote errors và 500 khiến query-context hypothesis hợp lý, nhưng các cặp cùng trả lỗi/empty không xác nhận. Khi seed `apple` cho kết quả rỗng ở cả hai phía, Agent sau đó thử wildcard seed, giữ nguyên context giữa hai vế và chỉ đổi predicate. Các captures cuối cùng cho thấy nhánh TRUE có records trong khi FALSE rỗng. HTTP status 200 giống nhau ở cả hai nhánh, nên việc đọc body và dữ liệu trả về là thiết yếu.

Profile transcript không có lần gọi `read_payloads` cho lan-01. Không thể khẳng định Agent không biết một nguyên tắc từ system/Skill; chỉ có thể nói không có payload-guidance tool output trong log. Candidate search đã được ghi và validation hoàn tất; workflow result và Finding có liên kết evidence riêng. Search Finding được tạo tại i50; run tiếp tục xử lý candidate login riêng, ghi result ở i59 và Finding tại i60, sau đó kết thúc vì max_steps.

### lan-08: syntax signal nhưng chưa có oracle

lan-08 dùng cùng origin `http://127.0.0.1:8081`, cùng endpoint/parameter và cùng profile DeepSeek `deepseek-flash` với fingerprint cấu hình ở trên. Prompt chỉ tập trung SQLi. Runtime giới hạn 60 outer iterations; permissions status ghi YOLO true trong phiên, còn launch marker ghi false khi khởi chạy và không lưu event giải thích lúc toggle. Scope vẫn giới hạn ở origin trên; không có bằng chứng permission denial hay budget block. SQLi Skill snapshot hash là `cdcab163860bb018b8762c766e59c5687cc8373171ab9c312fa6035041f3f43a`; payload corpus có cùng content hash ở hai profile.

Input `q=apple'` ở input-analysis cho `obs_361146056883495089ff13eb2f4501`, HTTP 500/994 bytes; đây là tín hiệu khởi tạo candidate, không phải xác nhận. Agent load SQLi Skill ở i43, đọc payload guidance ở i44–45, bắt đầu attempt `attempt_716a1aa80f7348aa87c7c3b8c8f4e920` cho `cand_dc84353ab8934993b033` ở i46. Payload guidance có cảnh báo rõ rằng wildcard trong LIKE có thể làm thay đổi truth của equality predicate và hai response giống nhau là inconclusive.

| Iteration | Observation / input | HTTP response | Đối chiếu với suy luận |
|---|---|---|---|
| i47 | `apple`; `obs_8bbeb0c8568443688349af87498281b3` | 200/921 bytes, 3 rows | Baseline cho search seed. |
| i48 | `apple' AND '1'='1`; `obs_37b5c4549cbb414c95263930f502c815` | 200/30 bytes, `data: []` | Vế TRUE dự kiến không cho kết quả khác baseline. |
| i49 | `apple' AND '1'='2`; `obs_3953c680d581477786cd67ee211dae7f` | 200/30 bytes, `data: []` | Bằng vế i48; pair không tạo oracle. |
| i50 | `apple' AND '1'='1 AND '1'='1`; `obs_be08aba6d19c47198861d93be6ea2309`; đối chứng `' AND '1'='2 AND '`; `obs_8fad4a2dfdce46948e2021c9a7b3d6e6` | Cả hai 500/974 bytes, cùng response fingerprint gần như byte-for-byte | Hai vế không giữ nguyên input/prefix; cả hai lỗi nên không kiểm tra được truth. |
| i52 | `apple'-- `; `obs_bd56416560044f70822e317ad0eb6b2d` | 500/942 bytes, incomplete input | Comment probe không tạo response oracle. |
| i53 | controlled-expression probe; `obs_f78c247d5dd2458e90571a9de32ac50b` | 200/30 bytes, JSON rỗng | Không có biểu hiện computed value; không phân biệt TRUE/FALSE. |
| i54–58 | Proof ghi nhầm ba observation ID ở i54; record_evidence lỗi ở i55; ledger tra cứu i56; proof sửa và evidence đăng ký i57–58 | Không có HTTP mới; ID thật được khôi phục từ ledger | Context/handle issue ảnh hưởng proof bookkeeping sau các probe, không làm thay đổi response pair đã thu. |
| i59 | `record_result`, outcome `not-confirmed`; attempt complete, coverage synced | Candidate/result/evidence được runtime chấp nhận; không có Finding | Trạng thái kỹ thuật được lưu thành công nhưng oracle vẫn chưa established. |

Ở message 123 (sau i49), Agent nhận ra hai response bằng nhau khiến cặp chưa kết luận được, nhưng lại cho rằng giả thuyết suffix/wildcard đã đứng vững và diễn giải sai rằng riêng `apple'` đã cho kết quả rỗng. Baseline `apple` có 3 rows; quote-only probe trước đó trả 500. Ở message 126, cặp i50 được nhìn nhận là cùng lỗi, nhưng Agent đoán query có ngoặc bao quanh thay vì giữ một vế ổn định và điều chỉnh một yếu tố. Message 132 ghi nhận empty response của controlled expression nhưng cũng kết luận không có controlled evaluation; không hề có differential đủ để xác định truth. Transcript tiếp tục cho thấy việc phục hồi các ID evidence, không phải thêm kiểm chứng SQL.

Lan-08 hoàn tất ở iteration 59 với `workflow_completed`; hard cap là 60 và final synthesis là call riêng. Không có bằng chứng run bị dừng do lượt thử, anti-stall, quyền, mạng hoặc capture cap. Tool history đầy đủ 82 calls và 58 HTTP observations được lập chỉ mục trong [lan-08 tool history](lan-08-tool-history.md). Các 500 là observations thành công của HTTP tool, không phải tool exception.

## C. So sánh và điểm phân kỳ

### Những điểm tương đồng có ý nghĩa

- Cùng base origin, cùng `GET /rest/products/search?q=`, cùng seed baseline `apple`, cùng model label/profile backend và cùng payload corpus hash.
- Cả hai có quote-triggered SQLite syntax errors. Lỗi củng cố giả thuyết rằng input đi vào ngữ cảnh nhạy cú pháp, nhưng tự nó không xác nhận SQLi.
- Cả hai dùng seed `apple` nhưng không thu được truth differential: lan-01 có cặp predicate cùng trả 500 ở i39, rồi một biến thể đơn lẻ trả 200/rỗng ở i40; lan-08 có cặp trả 200/rỗng ở i48–49. Điều đó không chứng minh predicate tương thích với cách query ghép wildcard hoặc dấu nháy.
- Cả hai có giới hạn 60 outer iterations. Không có bằng chứng số lượt cản trở một hướng đang cho differential.

### Điểm phân kỳ trong chuỗi quyết định

Điểm phân kỳ đầu tiên có giá trị chẩn đoán là cách hai run phản ứng với các probe `apple` chưa tạo differential. Ở lan-01, hai vế i39 lỗi cùng cách; sau một biến thể i40 vẫn không cho thấy TRUE output, Agent đổi seed sang wildcard, rồi so sánh request giữ nguyên context và chỉ đổi predicate. Ở lan-08, cặp i48–49 cho cùng body rỗng; Agent thừa nhận pair chưa kết luận được nhưng tiếp tục giả thuyết suffix và không thử seed wildcard trong một pair có kiểm soát. Dữ liệu xác nhận điểm rẽ trong chuỗi quyết định, không xác nhận chính xác cấu trúc SQL nội bộ.

Lan-08 thay vì vậy gửi i50 với hai vế có input khác nhau: vế TRUE giữ `apple` và thêm nhiều điều kiện; vế FALSE bắt đầu bằng quote và đổi phần còn lại. Hai response 500 giống nhau không thể cho biết predicate đúng/sai. Sau đó comment và expression probe cũng không tạo positive/negative pair. Suy luận về query wrapping chưa được kiểm tra độc lập. Không thể biết chính xác truy vấn SQL backend đã dựng từ HTTP capture; vì thế báo cáo không gán một câu SQL cụ thể làm sự thật.

Sự khác biệt hướng dẫn cũng không ủng hộ giả thuyết “lan-08 thất bại vì thiếu payload guidance”. Lan-08 đã đọc cả hai trang payload trước khi bắt đầu attempt; nội dung cảnh báo wildcard/equal-response có mặt. Lan-01 không có lần gọi tool đọc payload trong log, nhưng hành vi thực nghiệm cuối cùng đã vô tình chọn được seed và cặp predicate hữu ích. Điều có thể kết luận là lan-08 không vận dụng được hướng dẫn đã đọc ở bước quyết định sau cặp bằng nhau; không thể khẳng định lý do nội tại của LLM.

Các điểm khác khác biệt nhưng không tự giải thích kết quả: lan-01 prompt bao gồm SQLi và XSS, lan-08 chỉ SQLi; lan-01 tạo được Finding search ở i50; lan-08 có một lần SQLi login candidate sớm trong history, nhưng không có bằng chứng nó làm lệch search reasoning. System prompt và toàn bộ outbound model request payload không được lưu nguyên văn theo từng call. Profile fingerprint chỉ xác định cấu hình, không xác định weights/revision thực tế của dịch vụ model.

## D. Root cause và các giả thuyết

| Giả thuyết | Phân loại | Bằng chứng / giới hạn |
|---|---|---|
| Lan-08 không có SQLi vì chỉ gặp 500 | **Bác bỏ** | Lan-01 dùng cùng target, endpoint và origin để thu boolean differential lặp lại; lan-08 cũng thấy syntax-sensitive input. Tuy nhiên không chứng minh backend/app build/data state hoàn toàn giống nhau giữa run. |
| Lan-08 không thiết lập được oracle vì các probe không chứng minh được cặp TRUE/FALSE tương thích và không giữ nguyên cấu trúc | **Cách validation thất bại đã xác nhận với độ tin cậy cao** | i48–49 cùng response; i50 đổi seed/quote/condition giữa hai vế và cả hai lỗi; các captures i52–53 cũng không phân biệt truth. Điều này xác nhận probe sequence không tạo oracle; không xác định được query shape hoặc tính đúng/sai nội tại của một predicate cụ thể. |
| LLM bỏ qua hướng dẫn cần thiết | **Có dấu hiệu rõ, động cơ không xác minh được** | Payload guidance được đọc trước probes và nói hai điểm then chốt; message 123 vẫn khẳng định suffix hypothesis mà chưa có positive control. Log không chứa nguyên văn mọi outbound prompt/state từng model call. |
| Context Reduction đã che mất thông tin cần thiết trước phép thử | **Không có bằng chứng là nguyên nhân oracle** | Lan-08 có lỗi reduction/handle đã tái hiện, nhưng xảy ra ở giai đoạn soạn proof sau các HTTP probe. Các probe và response đều tồn tại trong observation store; payload guidance đã được đọc trước attempt. Outbound prompt chính xác không được lưu nên không thể loại trừ mọi ảnh hưởng nhỏ của context. |
| Thay đổi Agent Core/Context Reduction từ lan-01 đến lan-08 gây hồi quy boolean testing | **Chưa được chứng minh; phần liên quan được loại trừ** | AST hash của `guard_working_context` giống nhau ở hai snapshot: `b0374caaa9ad6a2a91da7fa8204d8f195ca7acb9450cc2d30f99aeeda83d3e55`. Handle bug lan-08 gây ID đoán sai lúc đăng ký evidence, không làm biến đổi captures đã thực hiện. Không có đủ bằng chứng để loại trừ mọi thay đổi ngoài hàm này. |
| Payload guidance/SQLi Skill regression làm lan-08 thất bại | **Không được ủng hộ bởi dữ liệu** | Skill snapshot và profile hash khác nhau theo thời gian, nhưng lan-08 payload guidance đã nêu wildcard compatibility và equal responses. Không có bằng chứng cảnh báo bị thiếu tại thời điểm thử. |
| Workflow hoặc HTTP tool làm mất/đổi response khiến oracle không thấy được | **Đã loại trừ trong phạm vi captures** | Bảy observations thuộc attempt, body/status/bytes đầy đủ và được lưu. Hai TRUE/FALSE ở i48–49 đều 200/30; i50 đôi bên đều 500/974. HTTP 5xx không phải lỗi tool. |
| Giới hạn budget, permission hoặc stop condition cắt ngang validation | **Đã loại trừ** | Attempt bắt đầu và kết thúc; runtime kết thúc `workflow_completed` ở i59/60, không có block/denial hay hết lượt. Hướng tiếp theo hợp lý là sửa cặp oracle, không phải tăng budget mặc định. |
| Khác model/server revision giải thích chênh lệch | **Không thể xác minh / không đủ chứng cứ** | Cùng provider/model label và config fingerprint, nhưng không có model revision, per-call outbound request, seed hay replay. Hai run không phải đối chứng có kiểm soát để cô lập model variance. |
| Lan-08 result `not-confirmed` là một negative kỹ thuật hợp lệ | **Không được hỗ trợ bởi oracle** | Session khai báo `completed_attempt=true`, workflow lưu `not-confirmed` và coverage `passed`, nhưng các response không thiết lập oracle. Current SQLi playbook định nghĩa unresolved oracle là `insufficient-evidence`; xem [SKILL.md, 863–870 và 917–925](../skills/sql-injection/SKILL.md). |

**Root cause tóm tắt:** thất bại thực nghiệm được giải thích tốt nhất bởi lựa chọn và diễn giải probe của agent: sau cặp bằng nhau, agent không xây lại cặp TRUE/FALSE trong cùng ngữ cảnh và thay đổi nhiều biến đồng thời. Đây là root cause ở chuỗi quyết định của phiên, không đủ để quy thành lỗi phần mềm deterministically gây ra. Các lần đọc SQL error không chứng minh khả năng điều khiển predicate; result label cuối cùng mạnh hơn evidence.

Một vấn đề contract riêng: workflow runtime xác minh ownership, evidence refs, attempt và cờ khai báo `completed_attempt`, nhưng không phân tích ngữ nghĩa để tự xác định “oracle established”. Tại [workflow_tool.py:1712–1743](../src/tools/workflow/workflow_tool.py), nhánh `not-confirmed` yêu cầu attempt hoàn tất được khai báo và registered evidence hợp lệ; nó không thể suy ra tính tương thích của predicate từ nội dung do model nộp. Vì thế runtime acceptance chứng minh state/provenance hợp lệ, không chứng minh model chọn đúng outcome. Không nên gọi đây là hồi quy so với lan-01 nếu không có thay đổi lịch sử cụ thể nối với hành vi này.

## E. Đánh giá hồi quy phần mềm

Các manifest/profile snapshot được so khớp read-only với Git object database: 243/243 runtime file của lan-01 và 226/226 runtime file của lan-08 tìm thấy blob có SHA-256 tương ứng. Điều này cho phép kiểm tra source lịch sử mà không checkout/reset/restore worktree. Hàm `guard_working_context` của Agent có cùng AST digest giữa hai run. Kết quả này chống lại giả thuyết cụ thể rằng chính thay đổi gần lan-08 của hàm reducer đã làm hỏng tạo oracle.

Các run không dùng cùng một file set hoàn toàn giống nhau, và không có bằng chứng commit đơn lẻ nào được chỉ ra là nguyên nhân. Lan-08 có lỗi context handle thật khi tạo proof; nó khiến ba ID bị đoán và lần `record_evidence` đầu bị từ chối, sau đó agent tra ledger, sửa proof cục bộ và đăng ký thành công. Sai sót xuất hiện sau probes nên là lỗi bookkeeping, không giải thích pair không phân biệt.

Workflow tại thời điểm lan-08 cho phép lưu `not-confirmed` dựa trên khai báo hoàn tất. Current source kiểm tra provenance/evidence và terminal schema, song không tự đánh giá logic SQL oracle. Current SQLi Skill đã được sửa sau run để phân biệt rõ `not-confirmed` với `insufficient-evidence`, nêu oracle/predicate compatibility unresolved phải dùng outcome chưa xác nhận; điều đó có thể ngăn overclaim nếu Agent tuân thủ, nhưng không tự sinh ra oracle đúng. Thay đổi này là cải thiện outcome discipline, không phải bằng chứng rằng skill cũ đã khiến các probe sai.

Do đó: **không có bằng chứng hồi quy thực nghiệm về khả năng SQLi Validation sau lan-01; cũng không đủ dữ liệu để chứng minh không có bất kỳ hồi quy nào trong toàn bộ KAgent.** Các run không phải A/B test; target state, prompt, exact model revision và request payload khác biệt chưa được kiểm soát hoặc lưu đầy đủ.

## F. Đề xuất tối thiểu có căn cứ

| Vấn đề | Có phải lỗi hiện tại? / tác động | Đề xuất / kiểm chứng offline | Rủi ro tiêu chuẩn xác nhận |
|---|---|---|---|
| Agent kết luận `not-confirmed` dù oracle chưa thiết lập | Hành vi đã thấy ở lan-08; giảm độ đúng của phân loại. Skill hiện tại đã nói unresolved → `insufficient-evidence`, nhưng chỉ dẫn vẫn cần được áp dụng trong suy luận. | Giữ nguyên quy tắc hiện tại; nếu tiếp tục cải thiện, thêm kiểm tra offline tập trung vào tình huống hai predicate trả cùng response: expected unresolved, không phải negative. Kiểm tra outcome contract và câu trả lời model giả lập, không gọi LLM/live target. | Không làm giảm ngưỡng `confirmed`; không được đổi thành “500 là SQLi”. |
| TRUE/FALSE pair đổi nhiều phần của input | Lỗi chiến lược trong transcript, chưa chỉ ra một code defect. | Trong hướng dẫn đang có, nhấn vào giữ seed, quote/context, encoding và mọi yếu tố khác cố định, chỉ đổi predicate; xác minh positive control và baseline trước khi diễn giải pair. Khi response bằng nhau hoặc cả hai lỗi, báo unresolved và dừng hoặc nêu bước thiếu cụ thể. | Tránh ép mọi kỹ thuật phải chạy; tránh coi một cặp bất tương thích là negative. |
| Suy query shape từ thông báo SQLite | Lỗi diễn giải trong run, không chứng minh thiếu tool capability. | Ghi riêng “syntax sensitivity” và “oracle”; coi thông báo lỗi như tín hiệu tạo giả thuyết, rồi kiểm tra giả thuyết với response differential thay vì chốt SQL string. | Không overclaim câu truy vấn nội bộ hoặc severity. |
| Proof IDs bị đoán do context reduction | Lỗi code thực đã được lan-08 RCA/acceptance xử lý; tác động đến evidence registration sau probe, không đến oracle. | Giữ regression coverage hiện có về giữ handles/ledger lookup; không thêm payload engine hoặc tăng context chỉ để giải quyết SQLi validation. | Giữ nguyên evidence resolver và immutable proof checks. |
| Runtime không thể tự hiểu oracle | Giới hạn của structured workflow hiện tại; trạng thái `not-confirmed` có thể syntactically valid nhưng semantically sai. | Dùng Skill/agent decision rule hiện có và test nó bằng fixture HTTP offline. Chỉ cân nhắc validator nếu có representation machine-checkable cho predicate pair; chưa có căn cứ để thêm semantic solver. | Không nới điều kiện finding; không biến metadata thành xác nhận. |
| Model variance / exact model revision | Có thể ảnh hưởng nhưng hiện không cô lập. | Lan-09 có thể ghi lại profile, prompt, Skill hash, call/observation sequence và outcome trong một lần authorized lab run để so sánh; không cần gọi lại model ngoài thực nghiệm đã định. | Không dùng lan-01 thành payload recipe, không tăng phạm vi hay impact. |

Chiến lược tổng quát được lịch sử hỗ trợ: xây dựng một cặp đối chứng tương thích với ngữ cảnh input và ngữ nghĩa endpoint; giữ request giống nhau trừ điều kiện boolean; kiểm tra baseline/positive control; so response body hoặc marker dữ liệu hoàn chỉnh, không chỉ status; lặp lại bằng dạng predicate tương đương. Equal responses, lỗi ở cả hai vế, response bị truncate hoặc thiếu predicate compatibility đều không phải negative proof. Đây là nguyên tắc kiểm soát biến, không phải payload cố định cho Juice Shop.

Không có căn cứ để bổ sung solver, payload engine, quyền, budget, hay chức năng mới. Cũng không nên thay đổi điều kiện Finding: lan-01 minh họa cách bằng chứng tốt phải đủ, còn lan-08 cho thấy status/provenance hợp lệ chưa thay được oracle.

## G. Quyết định cho lan-09

**Giữ code hiện tại và chạy lan-09 trong điều kiện lab được khai báo; chưa cần sửa thêm trước run chỉ để “đảm bảo thành công”.** Current SQLi Skill đã nêu rõ unresolved oracle không phải `not-confirmed`; lan-08 RCA/acceptance đã xử lý lỗi context handles ảnh hưởng proof. Không có bằng chứng cần tăng lượt hoặc thay đổi permission. Sửa thêm dựa trên lan-01 bằng cách hardcode payload/query shape sẽ vượt quá bằng chứng và có nguy cơ làm validation kém tổng quát.

Trong lan-09, tiêu chí dừng nên được áp dụng trực tiếp: sau một cặp cùng context, nếu hai response bằng nhau hoặc cả hai lỗi thì chưa có oracle; ghi giới hạn và dùng `insufficient-evidence` nếu context-compatible pair chưa được xác lập. Nếu xuất hiện differential, recapture response đầy đủ, giữ attempt ownership/evidence binding và xác nhận bằng cặp độc lập trước khi tạo Finding. Ghi lại Skill/profile hashes và response completeness để lần sau phân biệt biến thể model với thay đổi phần mềm. Không cần chạy payload trên mục tiêu ngoài phiên lan-09 được ủy quyền.

### Nguồn và giới hạn kiểm toán

- lan-01: session/tool events, observation captures, workflow candidate/attempt/results, immutable evidence và Finding trong `experiments/scenario3/runs/lan-01/`; đặc biệt search candidate `cand_faa9ff1fdf18dc8bb99e`, attempt `attempt_a3939515092e47139494fd86475c3d8d` và evidence `ev_ae8ce77c58a14282fd63`.
- lan-08: `experiments/scenario3/runs/lan-08/logs/session.jsonl`, profile snapshot, `project/.kagent/observations/`, `project/.kagent/evidence/`, workflow state, `project/artifacts/` và các báo cáo lan-08 dẫn ở đầu tài liệu. Tái dựng chi tiết 82 tool calls và 58 HTTP observations nằm trong `docs/lan-08-tool-history.md`.
- Code và hướng dẫn hiện tại: `skills/sql-injection/SKILL.md` lines 863–870, 917–932; `src/tools/workflow/workflow_tool.py` lines 1712–1743. Các line hiện tại giải thích contract hôm nay; chúng không được dùng thay cho snapshot lan-01/lan-08.
- Không có nguyên văn request body đã gửi cho provider ở từng model call, không có model server revision/seed, và không có source SQL backend. Vì vậy không thể kết luận chính xác vì sao model tạo lựa chọn đó, hoặc gán chênh lệch cho một thay đổi commit cụ thể.
