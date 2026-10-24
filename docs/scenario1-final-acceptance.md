# Kịch bản 1 — Audit nghiệm thu Burp Suite Integration + SQLi Validation

**Kết luận: PASS WITH LIMITATIONS.** Luồng chọn Burp request → Candidate → HTTP validation → registered evidence → confirmed ValidationResult → Finding đã hoàn tất và có bằng chứng runtime phù hợp. Không phát hiện blocker buộc chạy lại kịch bản 1 hoặc sửa code trước lan-09. Kết quả dùng được cho mục 3.3.1 với phạm vi và giới hạn dưới đây; không trình bày đây là thí nghiệm đã chứng minh độc lập hoàn toàn với tri thức có trước.

Audit chỉ đọc dữ liệu và kiểm tra offline; thay đổi duy nhất do audit tạo ra là báo cáo này. Không HTTP probe, không gọi LLM/provider, không chạy Shell/curl trong Finding, không sửa Intelligence, Memory, cấu hình, session, proof, Finding hoặc workflow. Không audit lại lan-01/lan-08. Worktree đã có thay đổi từ trước, được giữ nguyên.

## 1. Định danh phiên và nguồn kiểm chứng

Chỉ một session lưu được chứa result ID được yêu cầu:

| Thành phần | Giá trị |
|---|---|
| Session TUI | `3c0efc1d-d87d-40f1-8aaa-a38b4303e7cd` |
| User prompt | `TEST the selected Burp request for SQL Injection in the email parameter` |
| Target / origin | `http://juice.lab:8081` |
| Selected capture | `burp:burp-23f8b54efef80eed` |
| Imported observation | `obs_4f86b6218a9d4d2c9c892330496f1f19` |
| Candidate | `cand_4f27f08929fcdaf962ef` |
| Objective | `7aee2c4a7a144fd1aa02887adf5dd4ca`, mode `direct` |
| Attempt | `attempt_8bf09ce5e2334917846f6e4c5a53b716` |
| ValidationResult | `result_bedbd0103acd4b3fb26c21cb1b559923` |
| Registered evidence | `ev_c76dd8e0919859765724` |

Nguồn chính, ưu tiên hơn lời tóm tắt của Agent:

- [Session JSON](/home/khainguyen/.kagent/sessions/3c0efc1d-d87d-40f1-8aaa-a38b4303e7cd.json): 38 messages, 18 tool calls và workflow cuối. Tham chiếu `messages[n]` trong báo cáo dùng chỉ số **bắt đầu từ 0**.
- [Observations](../.kagent/observations/3c0efc1d-d87d-40f1-8aaa-a38b4303e7cd.json): bảy observations, gồm một capture nhập từ Burp và sáu native HTTP observations.
- [Coverage](../.kagent/coverage/3c0efc1d-d87d-40f1-8aaa-a38b4303e7cd.json) và [permission snapshot](../.kagent/permissions/3c0efc1d-d87d-40f1-8aaa-a38b4303e7cd.json).
- [Registered proof](../.kagent/evidence/69001294e83b73a8f870f9a3/1822974edf5b478bfe4858a50e36c2d28bb4d11519723e74c81e3f356761f13a.proof), [proof nguồn](../artifacts/sql-injection/juice-lab-8081/cand_4f27f08929fcdaf962ef-proof.md), [Finding](../artifacts/findings/sql-injection-in-login-email-parameter-allows-authentication-byp.md), [compact Finding](../artifacts/reports/findings/sql-injection-in-login-email-parameter-allows-authentication-byp.md).
- [Context snapshot](/home/khainguyen/.kagent/context/3c0efc1d-d87d-40f1-8aaa-a38b4303e7cd.md), reason `periodic 5 minute snapshot`, cập nhật `2026-10-23T15:40:54.892127+00:00`.
- [Application log](/home/khainguyen/.kagent/logs/kagent.log), dòng 8339–8343: process PID `222192`, startup và Burp bridge lúc `15:25:54Z`, hai lỗi workflow lúc `15:36:00Z` và `15:36:54Z` ngày 23/10/2026. Các mốc này tương ứng 22:25 và 22:36 giờ Việt Nam cùng ngày.
- Hai bản text người dùng gửi: bản transcript TUI và yêu cầu audit gốc. Transcript là nguồn cho banner; không coi lời Agent trong đó là bằng chứng HTTP độc lập.

Không tìm thấy debug log mang session ID này hoặc nội dung tham chiếu session này trong thư mục debug hiện có. Application log có ít sự kiện, không chứa toàn bộ outbound model context hay các dialog permission. Source được đối chiếu là worktree hiện tại, có thay đổi chưa commit; session không lưu một bản đóng băng source/config/Intelligence đầu phiên. Vì vậy, phân tích cơ chế source và dựng lại retrieval được ghi rõ là kiểm chứng offline, không phải trace lịch sử đầy đủ.

## 2. Tool-call history của đúng phiên

| Messages call → result | Tool / action | Call ID | Kết quả |
|---|---|---|---|
| 3 → 4 | `browser_capture_get` | `call_00_Z1p5mqXXXRA4kctcJ4bh4273` | Đúng selected capture và baseline ref |
| 3 → 5 | `load_skill(sql-injection)` | `call_01_d06GnYn7mdCgqeolwR592214` | Skill body được đưa vào tool response |
| 6 → 7 | `permissions_status` | `call_00_aXzS2Z7k9JqE1nCKdUJf4656` | YOLO false, không broad HTTP grant |
| 6 → 8 | `workflow.list(validating)` | `call_01_TPOJpyYA0pjrpFStotWd2635` | Chưa có active attempt/Candidate |
| 9 → 10 | `workflow.record_candidate` | `call_00_iSJQU0mJbw94brSfhZP68489` | Từ chối sai source reference |
| 11 → 12 | `workflow.record_candidate` | `call_00_X8MvP4UNowkOWLs63P830181` | Tạo một Candidate đúng binding |
| 13 → 14 | `workflow.start_validation` | `call_00_KyHuti6kI4oWZzTnIw9U5980` | Bắt đầu attempt |
| 15 → 16 | `http`, baseline | `call_00_d6o1NEWBsN9fQEZp4QgO9011` | 401 |
| 17 → 18 | `http`, syntax probe | `call_00_TJr4DZNRA9s0LN5dgnfc4902` | 500 / SQLite error |
| 19 → 20 | `http`, TRUE 1 | `call_00_SuJcY837ODSPefYNj4bo7246` | 200 / token marker |
| 21 → 22 | `http`, FALSE 1 | `call_00_FJZEmkrpfHxFX2c8e8hA8151` | 401 |
| 23 → 24 | `http`, TRUE 2 | `call_00_dMkaRBoXWR9EqNL8DNwY8461` | 200 / token marker |
| 25 → 26 | `http`, FALSE 2 | `call_00_TEv4MGZAQT7jsR5WPfRx7775` | 401 |
| 27 → 28 | `file_write`, proof nguồn | `call_00_404nroHdT19Rvq19gWwT0028` | Ghi proof |
| 29 → 30 | `workflow.record_evidence` | `call_00_6jOwGNqxPoJCJgUTbJFe8954` | Đăng ký một immutable snapshot |
| 31 → 32 | `workflow.record_result` | `call_00_M7dXDdAN0ppQJe0YWmO99190` | Từ chối hai field không hợp lệ |
| 33 → 34 | `workflow.record_result` | `call_00_Tyxu8HdFDkzhUaU6iHcY1708` | Accepted, confirmed, coverage synced |
| 35 → 36 | `confirm_finding` | `call_00_rwpCAan8EEkDS9Gn5E7Y0419` | Persist Finding và compact report |

Không có `shell`, `bash`, `curl`, `file_read`, `grep`, `glob`, `read_payloads`, công cụ tìm Intelligence hay thao tác Memory trong 18 calls này. Điều này chỉ loại trừ **truy xuất qua các tool đã lưu**, không loại trừ cơ chế tự động chèn context ngoài tool history (§8).

## 3. Burp provenance, input và phạm vi HTTP

`messages[4]` lưu capture có source `burp`, method `POST`, URL `http://juice.lab:8081/rest/user/login`, content type JSON, body có `email` và password đã redact. Không đưa lại địa chỉ email người dùng trong capture vào báo cáo này. Capture nhận lúc `2026-10-23T15:32:37.278Z`; không có response/status nhập kèm. Do đó, bản thân imported capture không chứng minh kết quả login hoặc SQLi.

Baseline reference được giữ trong Candidate cuối:

```text
baseline:6d5485c9f3cd4387a10a00501592f5b9:a478a5d1b3604ad5b53a86d079eeb99e:459855f77dd76b67aed868b985dabbd07c6b94ca42b19c54d9640c5b0d7171e1
```

Candidate có `source_ref=burp:burp-23f8b54efef80eed`, endpoint `/rest/user/login`, method `POST`, parameter `email`, location `body`, media type `application/json`, đúng objective và target. Không có Candidate thứ hai hoặc chứng cứ chuyển sang ba requests Burp còn lại. Bốn request trong danh sách ban đầu chỉ được xác nhận bởi transcript; session giữ được chi tiết request đã chọn.

**Phân biệt provenance với replay:** sáu calls `http` truyền trực tiếp `url/method/headers/body`; không dùng chế độ `http(candidate_id, mutation_value)` để replay nguyên capture. Agent thay email capture bằng benign control rồi các payload, dùng request JSON tự tạo với password đã redact. Vì vậy, có thể kết luận giữ đúng endpoint/input và provenance; không thể tuyên bố đã replay byte-for-byte request Burp hoặc bảo toàn toàn bộ browser/authentication context. Đây là giới hạn về độ trung thành của replay và tuân thủ hướng dẫn replay, không làm mất differential thực tế trên endpoint login không kèm Authorization/Cookie trong các request preview.

Scope lưu trong `engagement_state.allowed_origins` chỉ gồm `http://juice.lab:8081`; sáu observations đều có đúng origin/path/method này. `permissions_status` ghi YOLO false, không có broad grant; mỗi HTTP tool response có note private-host independently approved. Permission snapshot ghi origin constraint `used=6`, không session deny hay revoked tool. Các dispatch/admission trong attempt đều completed. Không có dấu vết HTTP ngoài origin hoặc replay token. Không lưu đầy đủ nội dung từng dialog để tái dựng chính xác câu chữ phê duyệt; không suy ra quyền từ Intelligence hay từ việc request được chọn.

## 4. Ledger HTTP và chất lượng bằng chứng

Toàn bộ sáu observations dưới đây có `producer=http`, `source_kind=native-http`, `execution_status=completed`, `complete=true`, `truncated=false`, `request_preview_complete=true`. Chúng cùng thuộc session, Candidate, objective và attempt ở §1; candidate binding đều là `de4323e124f8d52df05d83ff5e50172467b10408abc4d0caa7ec4380fbfdcc73`.

| Vai trò | Observation ID | Giá trị `email` trong request preview | Status | Response bytes | Marker kiểm tra được |
|---|---|---|---:|---:|---|
| Baseline | `obs_f68f85aede304905a983a92e489ee09c` | `nobody-sqli-control-9917@example.invalid` | 401 | 26 | `Invalid email or password.` |
| Syntax | `obs_9821b4c997c04983b50ae0e369d39007` | `nobody-sqli-control-9917@example.invalid'` | 500 | 1284 | `SequelizeDatabaseError`, `SQLITE_ERROR`, query text |
| TRUE 1 | `obs_1d34c24af15d4849b88afdf6fdd1720e` | `' OR 1=1--` | 200 | 799 | `authentication.token` không rỗng, `umail` mang admin marker, `bid=1` |
| FALSE 1 | `obs_410aad4474d7430289d9e9805fdbd895` | `' OR 1=2--` | 401 | 26 | `Invalid email or password.` |
| TRUE 2 | `obs_5ae2be9aa21948cb803bd97dc70f3412` | `' OR 1=1--` | 200 | 799 | Cùng loại token/admin marker, `bid=1` |
| FALSE 2 | `obs_0d15a997ac4148f5b6a4179ca50e620b` | `' OR 1=2--` | 401 | 26 | `Invalid email or password.` |

Thời điểm sáu observations theo UTC lần lượt: `15:36:19.240019`, `15:36:21.954110`, `15:36:25.017473`, `15:36:29.634183`, `15:36:32.493614`, `15:36:34.907292` ngày 23/10/2026, tức 22:36 giờ Việt Nam. Bốn boolean executions có observation và invocation IDs khác nhau, không phải đếm lại cùng capture. Hai TRUE có request hash giống nhau; hai FALSE cũng vậy. Chúng là hai lần thực thi cặp trong **cùng phiên/cùng lab**, không phải hai thực nghiệm độc lập về môi trường hoặc tri thức.

Bytes được kiểm tra bằng cách giải mã trường body hex rồi đếm bytes, đối chiếu SHA-256 với `response_hash`; cả sáu khớp. Hai phía boolean có cap 8192 bytes, baseline/syntax 16384 bytes, đủ giữ các body tương ứng. Các source rows trong result manifest khớp observations store và retained hashes của chúng. Password trong request preview/tool arguments đã redact, nên không khôi phục hoặc khẳng định biết literal password gốc.

SQL thật trong syntax response, chỉ thay giá trị băm bằng placeholder an toàn:

```sql
SELECT * FROM Users WHERE email = 'nobody-sqli-control-9917@example.invalid'' AND password = '[REDACTED_HASH]' AND deletedAt IS NULL
```

Query này hỗ trợ vị trí chuỗi quoted của email và việc comment suffix bỏ qua các điều kiện sau đó. Chính bốn boolean observations, không chỉ lỗi parser, chứng minh controlled evaluation và authentication bypass. Không cần UNION, enumeration, Phase 3 hay dùng token để chứng minh differential này.

### Registered proof và ownership

`workflow.evidence` có đúng một artifact, parent map `evidence_sources[ev_c76dd8e0919859765724]` chứa đúng sáu observations trong bảng. Imported Burp observation không bị dùng như một positive execution.

- Snapshot: `.kagent/evidence/69001294e83b73a8f870f9a3/1822974edf5b478bfe4858a50e36c2d28bb4d11519723e74c81e3f356761f13a.proof`.
- SHA-256 đọc lại: `1822974edf5b478bfe4858a50e36c2d28bb4d11519723e74c81e3f356761f13a`, đúng metadata; kích thước **3755 bytes**.
- Proof nguồn và snapshot khác bytes do redaction lúc đăng ký. Kiểm tra offline `apply_evidence(source_text).encode() == snapshot_bytes` trả về **true**. Khác biệt ở placeholder token bị redact thêm và password minh họa trong curl; không phải bằng chứng snapshot bị sửa.
- Không có orphan registered evidence, parent thiếu, source thuộc attempt khác hoặc evidence recovery đang mở trong trạng thái lưu được.

Proof đủ phục vụ kết luận boolean differential, nhưng đoạn được trình bày như query có alias `` `Users` AS `User` `` không phải bản chép nguyên văn query thực tế ở trên. `...` trong excerpt cũng là lược trích của người viết proof, không phải cờ capture truncation. Khi viết 3.3.1, dùng query đã kiểm chứng hoặc chỉ mô tả injection context; không chép đoạn có alias như raw SQL. Không sửa proof đã đăng ký.

## 5. Hai lỗi tool và kết quả phục hồi

### 5.1. Candidate binding: arguments của Agent sai, runtime từ chối đúng

Call đầu (`messages[9]`, result `[10]`) gửi đúng endpoint, method, target và baseline ref, nhưng gửi:

```text
source_ref = obs_4f86b6218a9d4d2c9c892330496f1f19
```

Đó là **runtime observation ID**, trong khi `_selected_capture_workflow_args` ở [agent.py](../src/agent/agent.py) so `source_ref` với selected capture retrieval ID `burp:burp-23f8b54efef80eed`. Các điều kiện source/baseline được kết hợp; đúng baseline không bù cho sai source. Danh sách matching selection rỗng nên runtime ném `ValueError` trước khi tạo Candidate. Thông báo chung nhắc endpoint khác không có nghĩa endpoint trong call này sai.

Call phục hồi (`messages[11]`, result `[12]`) bỏ `source_ref`, `baseline_request_ref` và `signals`, giữ nguyên hình học Candidate và test case. Với đúng một matching selection, controller tự điền source/baseline canonical. Receipt ghi `created=true`, Candidate ID đúng như §1. Trạng thái cuối chỉ có một Candidate `validated`; không có Candidate rác hay thay đổi selection sang endpoint khác.

**Phân loại: non-blocking.** Sai loại reference do Agent; gate bảo vệ provenance hoạt động đúng. Lời “Candidate registered with capture provenance bound” chỉ đúng sau call phục hồi.

### 5.2. `record_result`: sai schema, không hỏng evidence

Call đầu (`messages[31]`, result `[32]`) truyền `mutation_state` và `effect_basis` cho `record_result`. Runtime trả:

```text
record_result does not accept effect_basis, mutation_state; omit these arguments.
```

Trong [ACTION_INPUTS](../src/tools/workflow/workflow_tool.py), hai field này thuộc `record_attempt_state`; không thuộc schema `record_result`. Log dòng 8343 ghi `invalid_args`, không phải lỗi HTTP hay evidence-admissibility.

Call cuối (`messages[33]`, result `[34]`) bỏ đúng hai field bị từ chối và thêm `notes`. So sánh arguments cho thấy các field chung còn lại **không đổi**, gồm candidate/attempt, assessment, confirmation, evidence refs, observation IDs, outcome, repeatable và cleanup. Không cần sửa primary evidence hoặc đăng ký proof khác để phục hồi lỗi này.

Receipt cuối: `ok=true`, `created=true`, `eligible_for_confirm_finding=true`, `coverage_sync=synced`, `coverage_error=null`. Result có assessment contract version 2, source `agent`, đúng ID ở §1. Kiểm tra offline bằng implementation hiện tại:

- `accepted_result(state, candidate, result)` → **true**.
- Candidate binding, assessment seal và sáu manifest source hashes → **khớp**.
- `eligible_for_finding(candidate_id)` → **true**.
- Persisted finding fingerprint → **khớp** `validation_result_fingerprint(result)`.

Runtime xác thực tính toàn vẹn, ownership và contract; đánh giá ý nghĩa SQLi vẫn mang `assessment_source=agent`. Audit này kiểm tra riêng HTTP differential ở §4 để tránh coi “runtime accepted” là chứng minh ngữ nghĩa SQLi tự động.

**Phân loại: non-blocking.** Call đầu không tạo result sai; cuối phiên có đúng một result hợp lệ, một proof đúng parent và một attempt completed. Confirmation ghi hai cặp và template chung; nó không tự gắn observation ID vào từng pair, nên audit dùng requests/manifest/proof để xác định bốn association cụ thể.

## 6. Banner kết thúc và trạng thái còn lại

Transcript ghi `Turn ended · work remains; 1 finding saved; 1 unresolved operation issue`. Dữ liệu cuối cho thấy:

| Hạng mục | Trạng thái đã lưu |
|---|---|
| Requested SQLi goal | `tested_confirmed`, gắn đúng Candidate |
| Candidate | `validated` |
| Attempt | `completed`, cả sáu dispatch completed |
| Active candidate IDs | Rỗng |
| ValidationResult | `confirmed`, accepted contract v2 |
| Coverage | Một entry, `coverage_synced=true` |
| Finding | File tồn tại và persisted fingerprint khớp |
| Deferred reason / evidence recovery | `null` / rỗng |
| Cleanup | `mutation_performed=false`, `cleanup_state=not-required` |

Coverage `status=failed` có nghĩa kiểm tra bảo mật **phát hiện lỗ hổng**: `_coverage_status` trong [workflow_tool.py](../src/tools/workflow/workflow_tool.py) ánh xạ `confirmed → failed`, `not-confirmed → passed`. Đây không phải lỗi đồng bộ coverage. Mode `direct` cũng không yêu cầu hoàn tất ba phase reconnaissance/enumeration/input analysis của whole-target workflow. Zero phase completions không tạo việc còn thiếu cho yêu cầu này.

Nguồn operation issue còn lại là lỗi `record_candidate` ở §5.1. TUI giữ operation identity và recovery identity để ghép retry ([admission.py](../src/ui/core/admission.py), [outcomes.py](../src/ui/core/outcomes.py), [state.py](../src/ui/core/state.py)). Call Candidate bị từ chối không tạo được proposal canonical do source sai; call đã sửa có binding/arguments khác. Vì vậy, một thao tác thành công về nghiệp vụ vẫn có thể không khớp recovery identity của lỗi trước. Kiểm tra offline call metadata cũng cho thấy hai Candidate calls có recovery hashes khác nhau. Với `record_result`, identity phục hồi được giữ ổn định theo cùng Candidate/attempt; transcript xác nhận “Recovered after 1 failed attempt”.

`_finish_outcome` thêm unresolved issue vào residual rồi, ở nhánh `final_response`, đổi nhãn thành “work remains”, kể cả khi không có workflow residual. Không có event log để replay nguyên AppState hoặc chứng nhận stop reason; banner này phù hợp cơ chế đó và hai lỗi duy nhất đã lưu. Không có cơ sở diễn giải con số 1 thành một validation đang pending. TUI `TurnDetails` không được serialize vào session.

**Phân loại: non-blocking về trình bày/lịch sử thao tác.** Lỗi Candidate đã được sửa ở mức nghiệp vụ; ledger hiển thị chưa ghép retry. Không xóa lịch sử lỗi và không tuyên bố cơ chế correlation đã được sửa. Câu hỏi gợi ý tiếp tục ở final response cũng không phải `ask_user` đang chờ hay một deferred task được đăng ký.

Cleanup là khai báo không có mutation được thiết lập, không phải bằng chứng tuyệt đối endpoint không có side effect. Token được phát hành trong response; không có quan sát ghi DB hoặc readback để chứng minh toàn bộ hành vi phía server “chỉ đọc”. Giới hạn này không tạo cleanup pending trong workflow lưu được, nhưng 3.3.1 nên viết “không thực hiện phép thử ghi/xóa dữ liệu hoặc sử dụng token”, tránh “server hoàn toàn không đổi trạng thái”.

## 7. Finding, mức ảnh hưởng và dữ liệu nhạy cảm

Finding canonical tồn tại ở đường dẫn yêu cầu, chứa đúng Candidate, evidence ID, result, attempt, URL/method/input, CWE-89, OWASP A03:2021 và assessment binding. Thời điểm report `2026-10-23T15:37:06.854880+00:00` tương ứng 22:37:06 ngày 23/10/2026 giờ Việt Nam. Compact report thực tế nằm trong **`artifacts/reports/findings/`**, không phải trực tiếp `artifacts/reports/` như cây thư mục trong final response của Agent.

Payload Finding `' OR 1=1--` khớp hai TRUE requests; FALSE control `' OR 1=2--` khớp hai requests còn lại. Lệnh curl trong Reproduce là nội dung do `confirm_finding` persist; không có Shell/curl call trong history. Phân tích tĩnh bằng `shlex` và parse JSON cho thấy shell quoting tái tạo đúng email payload; không thực thi lệnh. Password đã redact, không coi curl là bản tái hiện literal credential gốc.

HTTP evidence chứng minh SQLi authentication bypass và response cấp token gắn với admin email marker. Finding đặt khả năng dùng token tới chức năng admin/đọc dữ liệu trong **Potential impact**, nêu rõ chưa replay/decode/dùng token; không tuyên bố đã vào admin panel, trích xuất DB, RCE hay sửa database. Vì vậy, không có overclaim lớn làm vô hiệu kết luận SQLi.

Các giới hạn cần sửa trong cách diễn giải của đồ án, không sửa Finding đã persist:

1. Response JSON trực tiếp có **`bid=1`**, không có trường `id=1` ngoài token. Không decode token trong audit này. Vì vậy, “user id 1”/“id:1” trong assessment/proof không được xác minh độc lập từ các trường JSON ngoài token. Dùng “response cấp token với admin email marker”; không đồng nhất `bid` với user ID.
2. Nhãn **`critical` là severity do Agent đánh giá và persist**. Authentication bypass với admin marker là cơ sở nghiêm trọng, nhưng quyền sử dụng token và admin functionality chưa được thử; không có vector CVSS được kiểm chứng. Có thể báo cáo nhãn này kèm observed impact chính xác; không diễn giải thành đã chứng minh toàn quyền quản trị hoặc account takeover.
3. Proof có query alias không khớp nguyên văn HTTP error (§4), và khẳng định endpoint “only reads” mạnh hơn quan sát (§6). Chúng không thay đổi payload, status, bytes hoặc kết luận boolean differential.
4. Không có `read_payloads` trong history. Skill body đã được load, nhưng không chứng minh Agent đọc file payload reference riêng theo mọi chỉ dẫn của playbook. Đây là giới hạn về tuân thủ quy trình, không phải thiếu bốn executions xác nhận.

Finding và registered proof không chứa chuỗi JWT hoàn chỉnh theo kiểm tra mẫu; password đã redact. Tuy nhiên **session/context snapshot và HTTP body retention vẫn chứa token response**, còn body hex trong observations/manifest cũng giữ thông tin nhạy cảm có thể giải mã. Không kết luận toàn bộ dữ liệu phiên đã được redact chỉ vì Finding an toàn. Báo cáo này không chép token, hash password, cookies hay dữ liệu credential; ảnh TUI và trích xuất đưa vào đồ án chỉ dùng marker đã che. Không xuất nguyên session/context/observations làm phụ lục công khai. Audit không sửa cơ chế retention hoặc dữ liệu đã lưu.

## 8. Intelligence và Memory từ các phiên trước

### 8.1. Cấu hình và đường nạp thực tế trong implementation

[runtime.py](../src/cli/runtime.py) khởi tạo `IntelligenceStore()` và `MemoryStore()` rồi truyền cả hai vào `AgentOptions`; không thấy cờ bật/tắt riêng cho hai store trong [Config](../src/config/config.py) hoặc JSON cấu hình đang lưu. [config.json](/home/khainguyen/.kagent/config.json) hiện có `session_path=""`, `auto_compact_threshold=16000`; đây là cấu hình tại lúc audit, không chứng minh flags/effective config đầu run. Snapshot ghi provider/model `deepseek` / `deepseek-flash` nhưng không lưu request payload gửi provider.

Các nguồn phải phân biệt:

| Loại | Đường dẫn / trạng thái tại audit | Vai trò |
|---|---|---|
| Project Intelligence | `.kagent/intelligence/scenarios.jsonl`, **619 records** | Kho tri thức tích lũy, có cả lịch sử chưa đủ điều kiện hướng dẫn |
| Personal Intelligence | `~/.kagent/intelligence/scenarios.jsonl`, **509 records** | Kho tích lũy cá nhân, nhiều nội dung trùng project |
| Builtin Intelligence | `BUILTIN_SCENARIOS` trong `src/intelligence/store.py`, **5 records** | Tri thức viết sẵn trong source, không phải học từ run trước |
| Durable curated Memory | `.kagent/memory/`, `~/.kagent/memory/` đều không tồn tại | `MemoryStore.list/index/search` hiện trả 0 / rỗng |
| Session Memory | `session.memory=null`; snapshot ghi session memory empty | Không có structured compaction memory lưu được |
| Conversation/workflow | Một user turn trong history; list đầu chưa có Candidate/attempt | Có tri thức từ chính captures/tools của run này; không thấy history run trước |

Không có bằng chứng restore/resume một phiên có nội dung cũ hoặc compaction trong history hiện có. Tuy nhiên không có startup/debug trace riêng của session để chứng nhận invocation hoàn toàn mới hoặc trạng thái Memory ở mọi thời điểm. `memory=null` cuối phiên không thay thế trace đầu phiên.

Trong [agent.py](../src/agent/agent.py), `run_inner` gọi **tự động**, trước model turn:

1. `build_intelligence_context(user_msg)`: query gồm prompt, target URL/name và các mục session memory; `search(..., limit=5, target_origin=origin, include_history=False)`, rồi giữ score `>=6`.
2. `recall_curated_memory`: search top 5 durable facts; nếu có sẽ emit `memory-recall` và chèn recall text.
3. `_snapshot_context` còn lấy catalog Memory; `_projection_request` đưa injections/catalog/session observations vào messages dùng cho working request.

Retrieval Intelligence tự động không cần tool call và không emit sự kiện riêng trong đoạn code này. Hơn nữa reducer TUI xử lý `MemoryRecallEvent` bằng cách không thêm dòng transcript. Vì vậy, không thấy dòng “Memory/Intelligence” trong TUI hay tool history **không phải** bằng chứng retrieval không diễn ra.

### 8.2. Mức 1 — Intelligence cũ tồn tại trên ổ đĩa: có

Project có **616 records từ trước**, cộng **3 records sinh từ chính session đang audit** sau final response; personal có 509 records, không record nào từ session này. Đây là số dòng ở hai store hiện có, không phải số kiến thức duy nhất hay snapshot lịch sử bất biến.

Nội dung cũ liên quan trực tiếp tồn tại, không chỉ kiến thức web chung. Ví dụ:

- Project **dòng 465**, personal **dòng 482**, ID `learned-finding-pattern-631aa2a0`, source session `6da49758-b690-4bf8-a3c9-599104c141cf`, tạo ngày 28/09/2026: mô tả auth bypass tại `POST /rest/user/login`, parameter email, payload có `OR 1=1--` và admin token marker.
- Project dòng 454 / personal dòng 471, ID `learned-tool-config-8ab09a82`: mô tả login endpoint, JSON `{email,password}` và vị trí `.authentication.token`.

Đếm tìm chuỗi trên records cũ: `/rest/user/login` xuất hiện trong 108 project / 109 personal records; `email` 52 / 51; `sqli` hoặc `sql-injection` 326 / 229; `OR 1=1` 7 / 6. Các nhóm chồng lấn, có bản trùng và tham chiếu lab/run cũ; số này **không phải số finding**, không chứng nhận đúng origin/version hiện tại và không chứng minh đã nạp context.

### 8.3. Mức 2 — Đã được truy xuất/nạp context: chỉ dựng lại được, chưa có trace outbound

Kiểm tra read-only bằng chính `IntelligenceStore.search` và `guidance_eligibility` hiện tại, không gọi `learn/append/clear`, cho kết quả:

| Metadata / eligibility | Số records từ store + builtin hiện tại | Automatic guidance |
|---|---:|---|
| Thiếu metadata, `applicability unknown` | 1120 | Bị loại |
| `derived`, `sourceRole=summary`, target applicable | 5 | Bị loại: `unverified model-derived history` |
| `sourceRole=assistant`, `applicability=session` | 3 | Bị loại: `session-bound state` |
| Builtin curated generic | 5 | Đủ điều kiện, vẫn phải qua matching/score |

Như vậy, **toàn bộ 1125 records từ các phiên trước trong hai store hiện có bị loại khỏi automatic guidance** bởi metadata, trước bước ngưỡng điểm. Không phải vì không có SQLi/login knowledge hoặc không match query.

Dựng lại query từ prompt thật + `http://juice.lab:8081` + target name rỗng/session memory rỗng:

| Kết quả automatic search | Score | Qua ngưỡng `>=6` |
|---|---:|---|
| `builtin-sqli-testing-pattern` | 60.95 | Có |
| `builtin-xss-testing-pattern` | 2.95 | Không |
| `builtin-auth-testing` | 2.90 | Không |

Khối được formatter dựng lại dài **961 ký tự**, chỉ chứa mẫu SQLi builtin. Bỏ ba records thuộc session này và lọc records theo mốc trước HTTP validation trong một view **chỉ tồn tại trong bộ nhớ audit** cho cùng kết quả. Đây là kiểm tra suy luận theo code và dữ liệu hiện còn; không gọi retrieval của Agent đang chạy, không thay đổi store thật và không tái lập hoàn hảo cache/metadata tại thời điểm run.

Để đối chứng, `include_history=True` có thể trả các learned records SQLi với điểm cao; nhưng đó **không phải** tham số của automatic injection trong `build_intelligence_context`. Không dùng kết quả lookup lịch sử do audit thực hiện để tuyên bố phiên thử đã đọc chúng.

**Kết luận mức 2:** implementation và dữ liệu hiện có dự đoán builtin SQLi được chèn, learned Intelligence cũ không được chèn, durable Memory không có nội dung để recall. Không có bản lưu outbound context để xác nhận trực tiếp điều đó ở thời điểm model thực nhận request. Vì vậy không ghi “đã chứng minh không dùng Intelligence”; cũng không ghi “Agent dùng tri thức các phiên trước” chỉ vì store có dữ liệu.

### 8.4. Mức 3 — Nội dung liên quan endpoint/email/SQLi/payload

Các learned records cũ ở §8.2 **liên quan trực tiếp endpoint, email, SQLi và payload authentication bypass**, nhưng hiện không đủ điều kiện automatic context. Không có tool call đọc chúng từ file hoặc gọi historical lookup trong phiên.

Builtin duy nhất vượt ngưỡng là `builtin-sqli-testing-pattern`: statement nói kiểm thử tham số do người dùng điều khiển cho SQLi; related checks có single quote, boolean/time/UNION và sqlmap verification. Nó **không** chứa endpoint `/rest/user/login`, tên input `email`, payload xác thực cụ thể, kết quả admin hay chi tiết query của run này. Đây là liên quan **kỹ thuật SQLi chung**, không phải đáp án tích lũy riêng của endpoint. Việc builtin nhắc automated tools cũng không chứng minh đã chạy chúng; history cho thấy chỉ sáu native HTTP calls.

Ngoài Intelligence, Agent đã có user intent SQLi/email, selected capture và toàn bộ `load_skill` response trong history. Những nguồn này tự đủ để giải thích việc chọn quote probe rồi boolean pair. Phải tách tri thức builtin/playbook khỏi learned knowledge của các phiên trước khi mô tả thiết kế thí nghiệm.

### 8.5. Mức 4 — Bằng chứng Agent sử dụng tri thức cũ để quyết định Validation

**Không tìm thấy bằng chứng trực tiếp.** Không call historical lookup/Memory/file read; không lời giải thích trích một learned record ID hay bài học của session cũ; không context snapshot chứa khối learned Intelligence được chèn. Các bước Agent phát biểu được neo vào capture, quote-error response, rồi hai cặp boolean trong chính phiên này. Payload SQLi thông dụng trùng lịch sử không đủ chứng minh quan hệ nhân quả.

Giới hạn quan trọng: `save_context_snapshot` lấy `get_history()` và format history; nó **không serialize `context.injections` của working request**. `run_inner` xây Intelligence/recall injection riêng rồi `_projection_request` mới ghép chúng vào request. Session JSON cũng lưu history/workflow, không phải bản đầy đủ từng request sau admission gửi model. System message trong session là prompt đã rebuild, không phải bản prompt bất biến đầu turn. Application log không ghi retrieval IDs/content. Vì vậy, không có khối “Local KAgent Intelligence” trong session/context snapshot không chứng minh khối đó vắng khỏi model context.

Không quan sát được toàn bộ context gửi model nên không xác nhận hoặc bác bỏ tuyệt đối việc model nhận, chú ý hay sử dụng một nội dung cụ thể. Dựng lại search chỉ hỗ trợ kết luận có giới hạn: **không có bằng chứng sử dụng learned Intelligence cũ; đường automatic hiện tại loại các records cũ; builtin SQLi vẫn là nguồn context dự kiến**.

Project Intelligence dòng **617–619** được tạo lúc `15:37:12.110866Z`–`15:37:12.112724Z`, sau result (`15:37:01Z`) và Finding (`15:37:06Z`). Chúng có `sourceSessionId` đúng phiên này, source role assistant, applicability session. Đây là **đầu ra học sau turn**, không phải chứng cứ đầu vào gây ra quyết định validation trước đó. Không cộng chúng vào tri thức có trước hoặc nói chúng đã giúp tìm lỗ hổng của chính run này.

## 9. Quyết định nghiệm thu và phân loại

| Vấn đề | Mức | Ảnh hưởng đến quyết định |
|---|---|---|
| Candidate gửi nhầm observation ID làm `source_ref` | Non-blocking | Gate từ chối đúng; retry tạo đúng một Candidate/provenance |
| Hai field sai action trong `record_result` | Non-blocking | Từ chối trước commit; result cuối và evidence không đổi/hỏng |
| Banner một issue chưa ghép retry → “work remains” | Non-blocking | Lịch sử thao tác/TUI; không có validation, goal hoặc coverage pending trong dữ liệu cuối |
| Proof query alias, “user id 1”, “only reads” và đường compact report trong lời Agent | Non-blocking về độ chính xác diễn đạt | Dùng ledger/JSON thực và cách viết hạn chế trong đồ án; không lấy lời Agent làm raw evidence |
| HTTP tự tạo thay vì captured replay; không thấy `read_payloads` | Limitation | Không tuyên bố replay nguyên capture hay hoàn thành từng chỉ dẫn playbook |
| Token chưa được dùng để kiểm chứng admin functionality; severity do Agent chấm | Limitation | Chứng minh authentication bypass/token marker, không chứng minh toàn quyền admin/CVSS |
| Learned Intelligence liên quan có trên đĩa, không có outbound/retrieval trace đầy đủ | Limitation | Không chứng nhận thí nghiệm cold start hoặc tác động nhân quả của Intelligence |
| Raw token còn trong dữ liệu phiên/observations | Limitation của dữ liệu nguồn | Chỉ đưa marker đã redact vào báo cáo/ảnh; không công bố nguyên kho raw |
| Blocker đối với evidence/Finding hoặc scope trong phiên này | **Không phát hiện** | Không có lý do bắt buộc chạy lại hoặc mở vòng phát triển |

1. **Đủ điều kiện nghiệm thu:** có, với giới hạn đã nêu. SQLi authentication bypass được xác nhận bằng hai cặp requests khác nhau, responses đầy đủ và proof/result/Finding ràng buộc nhất quán.
2. **Cần chạy lại kịch bản 1:** không, để chứng minh tích hợp Burp và validation có evidence. Phiên này không đủ làm bằng chứng cho một tuyên bố mạnh hơn về cold start hoặc đo đóng góp riêng của Intelligence; giới hạn tuyên bố trong đồ án là đủ cho nghiệm thu hiện tại.
3. **Lỗi bắt buộc sửa trước lan-09:** không phát hiện. Không đề xuất refactor, reset knowledge hay thay đổi dữ liệu nghiệm thu để làm đẹp kết quả.
4. **Tính độc lập:** bằng chứng HTTP mới có ownership của chính run; không dùng finding cũ thay cho bằng chứng mới. Tuy nhiên không chứng minh độc lập hoàn toàn về đầu vào tri thức: playbook/builtin có sẵn, kho learned knowledge tồn tại, và outbound context không được lưu đầy đủ. “Không chứng minh dùng learned history” khác với “chứng minh không chịu ảnh hưởng của learned history”.

## 10. Dữ liệu và cách trình bày cho mục 3.3.1

Nên dùng chuỗi minh họa: danh sách bốn Burp requests → chọn đúng login capture → Candidate/validation milestone → bảng sáu HTTP observations ở §4 → accepted result/evidence → Finding canonical. Ảnh TUI chỉ dùng ảnh có thật từ run hoặc transcript được chú thích là transcript; audit không tạo ảnh chụp lịch sử giả. Nếu ảnh chứa banner cuối, giải thích issue correlation theo §6, không cắt bỏ để tuyên bố phiên không từng có lỗi.

Số liệu có thể đưa vào báo cáo: **1 selected request, 1 Candidate, 1 completed attempt, 6 executed HTTP requests, 2 cặp TRUE/FALSE, 1 registered proof, 1 confirmed result, 1 persisted Finding; 2 tool calls bị từ chối rồi có call phục hồi**. HTTP TRUE: `200 / 799 bytes` hai lần; FALSE: `401 / 26 bytes` hai lần; syntax: `500 / 1284 bytes`; baseline: `401 / 26 bytes`. Không dùng “HTTP activity” rút gọn của TUI để đếm tổng responses. Không coi ~43450 “Approx tokens” trong snapshot là actual input tokens/billed usage hay tổng context Intelligence.

Đoạn có thể dùng trực tiếp, sau khi điều chỉnh văn phong đồ án:

> Kịch bản được thực hiện trực tiếp trên KAgent TUI với một request Burp được chọn: POST /rest/user/login, tham số email trong JSON body. Agent tạo Candidate có provenance liên kết với capture và thực hiện sáu HTTP requests trên cùng origin. Hai lần kiểm tra cặp boolean cho kết quả TRUE trả HTTP 200, body 799 bytes cùng marker cấp token gắn với tài khoản quản trị; FALSE trả HTTP 401, body 26 bytes và thông báo đăng nhập không hợp lệ. Bằng chứng được đăng ký, kết quả validation được chấp nhận và Finding được lưu. Token không được sử dụng để kiểm chứng chức năng quản trị, nên kết luận thực nghiệm giới hạn ở SQLi authentication bypass và phản hồi cấp token.

> Môi trường có sẵn kho Intelligence từ các phiên trước, gồm nội dung liên quan login SQLi. Kiểm tra metadata và dựng lại truy xuất bằng implementation hiện có cho thấy các bản ghi học cũ bị loại khỏi automatic guidance; chỉ mẫu SQLi tổng quát tích hợp sẵn vượt ngưỡng chèn context. Durable Memory không có dữ liệu và session không có structured Memory được lưu. Không có bằng chứng trực tiếp cho thấy Agent đã sử dụng tri thức học từ các phiên trước để quyết định validation. Do không lưu đầy đủ context gửi model và trace retrieval tại thời điểm chạy, nghiên cứu không khẳng định phiên hoàn toàn độc lập với tri thức có trước và không dùng phiên này để định lượng hiệu quả riêng của Intelligence.

Khi trích Finding, ghi “Agent đánh giá critical” cùng observed impact; tránh “đã truy cập admin”, “user ID 1 đã được xác minh”, “thực thi mọi SQL tùy ý”, “database không đổi trạng thái”, “replay nguyên request Burp” hoặc “thực nghiệm không dùng Intelligence”.

## 11. Phương pháp kiểm tra và giới hạn xác minh

Đã đọc implementation, persisted `load_skill` body và các tests liên quan hợp đồng Intelligence/Memory, assessment, SQLi repetitions và TUI recovery. Chạy kiểm tra offline với `venv-linux/bin/python -B` chỉ trên dữ liệu đọc và objects trong bộ nhớ: hash/size proof, redaction transform, sáu response hashes, manifest/store equality, accepted-result seal, finding fingerprint, schema diff, call correlation metadata, static curl parse và retrieval reconstruction. Không tạo fixture, cache bytecode hay dữ liệu runtime mới.

Không chạy pytest/pyright hoặc live integration tests: không thay đổi production behavior, và audit được giới hạn không tác động dữ liệu phiên/target/provider. Không kiểm chứng token signature/quyền admin, tổng side effects server, request secrets đã redact, toàn bộ permission dialogs, startup flags thực tế, cache Intelligence đầu phiên hay từng outbound context của provider. Các hạn chế này đã được đưa vào quyết định **PASS WITH LIMITATIONS**, không được lấp bằng suy đoán từ lời Agent.

Đối chiếu hash trước/sau bước lập báo cáo xác nhận session JSON, observations, coverage, permissions, cấu hình, hai kho Intelligence, proof nguồn/snapshot, Finding và các source files đã theo dõi không đổi; diff tracked của worktree cũng không đổi. Riêng context snapshot được tiến trình TUI còn chạy cập nhật nền: header đọc lại là `2026-10-23T15:50:55.188453+00:00`, vẫn ghi `periodic 5 minute snapshot`, cùng 129538 ký tự, một user turn và 18 tool responses. Audit không viết snapshot này; đây là giới hạn của việc đọc một môi trường chưa đóng băng. Kiểm tra cuối `git diff --check` và kiểm tra whitespace cho báo cáo mới đều không báo lỗi; status chỉ thêm báo cáo này so với trạng thái đã ghi nhận.
