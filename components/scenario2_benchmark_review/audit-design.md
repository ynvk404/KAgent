# KAgent — Scenario 2: 40-case benchmark design readiness audit

**Quyết định: `READY WITH REQUIRED FIXES`.** Có đủ 40 cases thật, đúng bốn strata và ánh xạ request thành công offline. Hạ tầng hiện có đủ để tái sử dụng. Chưa đủ cơ sở tuyên bố sẵn sàng chạy ngay: cần chốt đường chạy smoke 3–5 cases, điều kiện admission/reset của deployment, cấu hình thí nghiệm thống nhất và quy trình xét evidence theo tiêu chí SQLi/XSS trước khi công bố kết quả.

**Phạm vi:** audit và đề xuất thiết kế; ngày 13/10/2026, Asia/Saigon. Repository thực tế `D:\DOANTOTNGHIEP\kagent` (WSL: `/mnt/d/DOANTOTNGHIEP/kagent`), tương ứng repository được yêu cầu. Đã đọc `AGENTS.md`. Không sửa production, tests, runner, definitions, cấu hình, Skill hoặc ground truth; không chạy target, Docker, live benchmark hay external LLM. Tệp mới duy nhất của phiên là báo cáo này.

## A. Current State

### A1. Những gì đã có

| Thành phần | Source và trạng thái kiểm tra | Nhận định |
|---|---|---|
| Dataset có positive/negative | `../benchmark-targets/BenchmarkJava/expectedresults-1.2.csv`; `benchmarks/scenario1/core/dataset.py:41–59` | Dataset 1.2 có 2.740 truth rows; SQLi/XSS có 959 rows. CSV chuẩn là oracle, lời Agent là dự đoán. |
| Request mapping | `core/dataset.py:95–195` | Đối chiếu crawler, servlet annotation, request reader và HTML form. Ánh xạ GET/POST, query/form/header/cookie, input name/value. Mơ hồ thì fail, không thay case âm thầm. |
| Chọn 40 cases | `core/dataset.py:246–273`; `benchmarks/common/contracts.py:174–208` | `official` ánh xạ sang wire mode `reduced`: 10 cases mỗi stratum, seed 1729, SHA256 rank. 40 rows và schedule thật đã tái dựng offline thành công. |
| Runtime thật | `core/runtime.py:268–345,365–445` | Dùng Agent, registry, permission và native HTTP hiện có; tạo Candidate qua tool; chỉ nạp hai expert Skills. Không dùng stub để đo khả năng LLM. |
| Cách ly mỗi case | `core/runner.py:190–202`; `core/worker.py:17–40`; `core/runtime.py:338–344` | Worker/workspace/session/workflow/observations/coverage mới, project và personal memory mới. Truth nằm ở parent. |
| Execution ownership | `core/runtime.py:191–242,318–329` | Giữ method/route, chỉ đổi designated input; native exact-origin grant; giữ registry gates. Redirect follow bị tắt riêng trong harness. |
| Evidence và result export | `core/canonical.py:16–26,59–118,121–244`; `src/workflow/assessment.py:246–358` | Freeze workflow, result/attempt/source identity, epoch, hash, seal và acceptance; scorer kiểm tra lại exact method/route/input component/ownership. |
| Findings | `src/tools/workflow/finding.py:275–319`; `reporting/findings.py:19–98` | Finding cần latest accepted confirmed + registered evidence. Export kiểm tra Candidate, result, attempt, class, endpoint, method, parameter. Không tạo Finding từ văn bản trả lời. |
| Scoring | `core/evaluate.py:18–49,115–153` | Tách evaluable/unresolved/execution-failed/invalid-result/not-run; TP/FP/TN/FN chỉ từ completed + accepted terminal result. |
| Metrics và report | `benchmarks/common/metrics.py:9–34`; `reporting/aggregate.py:8–46`; `reporting/thesis.py:134–176`; `reporting/tables.py:30–43`; `reporting/writer.py:125–129` | Có counts, denominator, recall/FPR/precision/evaluability, mean/median/p95, token completeness, CSV/JSON/Markdown/SVG và bảng Chương 3. |
| Logical reset | `scenario1/reset/README.md:13–20,53–63,93–118`; `core/runner.py:125–127,171–189,239–267` | Có before/authorize/after/idle, identity, receipt và fail-closed. Production launcher bắt buộc reset controller. Phạm vi reset vẫn PARTIAL. |

Các đường dẫn `core/...`, `reporting/...` và `scenario1/reset/...` trong báo cáo lần lượt thuộc `benchmarks/scenario1/core/`, `benchmarks/scenario1/reporting/` và `benchmarks/scenario1/reset/`.

**Không có class tên `CanonicalCase` trong contract được kiểm tra.** Khái niệm này hiện được thực hiện bởi `GroundTruth` + `OperationalCaseInput`, nối bằng `case_id` trong `RunManifest`. `CanonicalResultExport` là export kết quả, không phải input case. Không cần thêm class/framework chỉ để trùng tên kiến trúc.

### A2. Inventory dataset và mức đủ dữ liệu

| Stratum | Số rows thật trong CSV | Quota đề xuất | Thiếu source rows |
|---|---:|---:|---:|
| SQLi positive, CWE-89 | 272 | 10 | 0 |
| SQLi negative, CWE-89 | 232 | 10 | 0 |
| XSS positive, CWE-79 | 246 | 10 | 0 |
| XSS negative, CWE-79 | 209 | 10 | 0 |
| Tổng | 959 | 40 | 0 |

Dataset commit từ inspection: `8b67a88d73b2594570fc21150705283de884620b`, dirty `false`. 40 selected mappings đều thành công. Đây là chứng minh về source/request mapping, **không phải 40 cases đã có response fidelity, deployment readiness hoặc exploitability được xác minh live**. Chưa có case bị loại theo contract tĩnh; các case đặc biệt ở B3 cần xác minh trước full run.

Ngoài BenchmarkJava, workspace có `xbow-validation-benchmarks`. Đã đọc README và inspection metadata `benchmarks/*/benchmark.json`: ví dụ `XBEN-001-24` có `win_condition: flag`, description chung và canaries; lượt tìm tags SQLi/XSS trong các metadata này không cho pool phân loại. README mô tả CTF white-box lấy flag. Không suy ra nhãn negative hoặc request contract từ mô tả này, không đưa IDs XBOW vào 40 cases. Không cần audit toàn bộ XBOW khi nguồn BenchmarkJava đã đủ và có adapter tương ứng.

### A3. Regression `body=None`: source hiện tại khác handoff cũ

Lab Fidelity handoff `components/redaction_simplification_review/implementation-handoff.md:116` và independent verification `.../independent-verification.md:102,139` ghi builder luôn gửi `body=None`, gây 44 failures + 13 fixture errors tại checkpoint lịch sử. **Không được dùng số đó để mô tả lỗi hiện tại.**

Source hiện tại `core/runtime.py:27–41` đã chỉ thêm `body` khi có form pairs; `reset/verify.py:60–65` đọc optional body, encode chỉ khi body khác `None`. Có regression tests tại `tests/benchmarks/test_scenario1_request_body.py`. Không tìm thấy handoff chuyên biệt của bản sửa trong nhóm Markdown đã kiểm tra; trạng thái handoff đó là **không tìm thấy**, không giả định đã có nghiệm thu toàn benchmark.

Đã kiểm chứng trực tiếp bằng đúng file tests offline này: **9 passed in 4.14s**. Tests chỉ validate/prepare native requests và dùng OfflineOpener cho reset consumer; không kết nối target. Điều kiện `body=None` ở boundary này đã sửa và kiểm chứng tập trung; **không còn là blocker hiện tại**, nhưng chưa chứng nhận các failures khác của family đã hết.

| Input HTTP args | Contract hiện tại | Ý nghĩa |
|---|---|---|
| Không có khóa `body` | Hợp lệ; builder tạo dạng này khi `op.body=[]` | Absent body argument; native prepared content rỗng. |
| `"body": ""` | Native nhận string rỗng | Explicit empty body; khác về intent, dù prepared content cũng rỗng. |
| `"body": "q="` | Hợp lệ | Có form field `q` với value rỗng; không được bỏ field. |
| `"body": None` | Native validator từ chối | Không phải optional field đã được omit; không đưa vào fixture. |

`OperationalCaseInput.body` là list form pairs, chưa thể biểu diễn riêng raw JSON body hay explicit empty raw body. Với 40 selected cases điều này chấp nhận được: body thực tế là URL-encoded forms, absent body của header/query cases và blank ancillary fields. Native tool hỗ trợ body string không đồng nghĩa dataset adapter hỗ trợ JSON.

### A4. Thiếu hoặc chưa đạt yêu cầu

- Chế độ public `smoke` là **12**, không phải 3–5 cases; `single` chỉ còn ở internal API/historical reader (`config.py:122–127`; `core/dataset.py:254–262`; `benchmarks/docs/scenario1.md:49–68`). Chưa có public mini-smoke batch hợp lệ.
- Runtime kiểm tra evidence integrity/provenance, **không tự phán quyết SQLi semantics hay JavaScript execution**. Một accepted Agent assessment vẫn có thể kết luận sai. Cần review rubric và ledger riêng, không coi seal là exploit proof.
- Provider/config được đọc lại mỗi worker (`core/worker.py:28–40`), nhưng chưa có admission invariant bảo đảm model/generation không đổi giữa cases. Metadata có ghi nhận, chưa cưỡng chế đồng nhất.
- Reset PARTIAL: không chứng nhận mọi filesystem/LDAP/external effect; fresh Hibernate cache và reset cache khác nhau theo handoff. Không suy ra toàn bộ 40 cases đã có baseline parity.
- Chưa có frozen 40-case selection file tìm thấy dưới `.kagent/benchmarks/scenario1/selections` tại inspection; report này chỉ đề xuất và tái dựng trong RAM, không ghi manifest/definitions.
- Reporting và contracts vẫn ghi `scenario1`, `supplied-input-v1`; không được gọi kết quả là thí nghiệm discovery tự động hoặc official OWASP score chỉ vì chương đồ án đặt tên Kịch bản 2.

Có hai historical smoke runs trong `.kagent/benchmarks/scenario1/runs/` (IDs `8e8a2d5d747c4f31bc3fc06da6794cbf`, `a789f1020fa249e8baff9bf71c0a81f6`), mỗi run 12 cases. Đã đọc inventory, manifest, execution metadata và evaluation summaries sẵn có; không chạy lại evaluator/Agent. Chúng tham chiếu commits khác và dirty snapshots, cùng runtime hash khác source audit. Vì vậy chúng chứng minh đã có artifacts thực tế, **không chứng nhận current source hay thay thế thực nghiệm 40 cases**. Không dùng tỷ lệ lịch sử làm kết quả của phiên này.

### A5. Những giới hạn chấp nhận được

40 cases trên một nền Java/HSQLDB, direct supplied-input, HTTP-only, phản xạ HTML và SQL có observable HTTP effects là phạm vi phù hợp nguyên mẫu. Không cần browser runtime, nhiều dataset, automated semantic oracle hoặc full-framework refactor nếu báo cáo công bố chính xác phạm vi đó. Không có shell/MCP/OOB/DOM browser proof là capability limit, không tự động là lỗi kiến trúc.

## B. 40-Case Selection Proposal

### B1. Chính sách chọn

Giữ lựa chọn hiện có: BenchmarkJava 1.2, seed **1729**, public `official`/internal `reduced`, 10 positive + 10 negative mỗi loại. Không thay seed sau khi xem kết quả và không chọn lại để loại FN, timeout, unsupported proof hoặc case khó. Smoke là development; không lấy smoke outcomes để quyết định case nào còn trong full run.

SHA256 ranking giảm lựa chọn chủ quan nhưng **không bảo đảm độ đa dạng**. Bảng dưới bổ sung review source/sink để biết đang đo gì; không sửa selector. Nếu quyết định thu hẹp scope hoặc phân tầng variants, cần công bố selection version/quy tắc mới trước experiment, chọn deterministic trước khi chạy và giữ manifest cũ; đó là follow-up, không thực hiện ở đây.

### B2. Bảng 40 IDs thật

Nguồn mọi row là BenchmarkJava CSV + servlet cùng ID + crawler, không phải Agent output. `CSV:L` là line number 1-based trong `expectedresults-1.2.csv`. Cột request ghi servlet path thật; URL thực thi là **origin được operator khai báo + context_path + path**. Không bịa hostname hoặc endpoint đã live.

Ký hiệu dependency/suitability:

- **H**: servlet HTTP; HTML response phải đủ bytes, đúng content type/CSP/context.
- **D**: HSQLDB/helper baseline; reset/identity của deployment vẫn bắt buộc.
- **W**: source có INSERT; ngay baseline có thể ghi DB; reset before/after, mutation/cleanup ledger bắt buộc, kể cả negative.
- **T**: ThingFactory/Thing2 và `thing.properties`; source hiện tại trả input, cần cùng deployment build.
- **A**: mapping đúng và phù hợp static HTTP scope, còn điều kiện live admission.
- **R**: giữ trong selection, cần review riêng về observable proof/biến đổi input trước full run.

| Case ID | Benchmark source | SQLi/XSS | Positive/Negative | Variant từ source | Request context | Dependency | Suitability |
|---|---|---|---|---|---|---|---|
| BenchmarkTest00200 | Java 1.2 CSV:201 | SQLi | Negative | List chọn constant; Spring batchUpdate với SELECT | POST `/sqli-00/BenchmarkTest00200`; header `BenchmarkTest00200` | D | R: SQL error/row count không tự chứng minh injection |
| BenchmarkTest00338 | Java 1.2 CSV:339 | SQLi | Negative | Constant branch; Spring queryForObject | POST `/sqli-00/BenchmarkTest00338`; header cùng ID | D | A |
| BenchmarkTest00390 | Java 1.2 CSV:391 | XSS | Positive | Base64 round-trip; raw HTML println | POST `/xss-00/BenchmarkTest00390`; form cùng ID | H | A: deterministic HTTP proof, không claim đã thấy browser chạy |
| BenchmarkTest00441 | Java 1.2 CSV:442 | SQLi | Positive | Thing passthrough; JDBC INSERT | POST `/sqli-00/BenchmarkTest00441`; form cùng ID | D,W,T | R: controlled evaluation, không chỉ quote error |
| BenchmarkTest00712 | Java 1.2 CSV:713 | XSS | Negative | Constant branch; HTML paragraph formatter | POST `/xss-01/BenchmarkTest00712`; form cùng ID | H | A |
| BenchmarkTest00722 | Java 1.2 CSV:723 | XSS | Negative | Map overwrite bằng constant; printf | POST `/xss-01/BenchmarkTest00722`; form cùng ID | H | A |
| BenchmarkTest00725 | Java 1.2 CSV:726 | XSS | Positive | StringBuilder/substring/split + Thing; raw HTML | POST `/xss-01/BenchmarkTest00725`; form cùng ID; password/email rỗng | H,T | R: inspect output thật; space-sensitive |
| BenchmarkTest01048 | Java 1.2 CSV:1049 | XSS | Negative | URLDecode header + HtmlUtils.htmlEscape | POST `/xss-02/BenchmarkTest01048`; header `Referer`; absent body | H | A: escaped reflection hard negative |
| BenchmarkTest01215 | Java 1.2 CSV:1216 | SQLi | Negative | Constant switch; Spring queryForObject | POST `/sqli-02/BenchmarkTest01215`; header cùng ID | D | A |
| BenchmarkTest01221 | Java 1.2 CSV:1222 | SQLi | Positive | Header decode/Base64; JDBC INSERT | POST `/sqli-02/BenchmarkTest01221`; header cùng ID; absent body | D,W | R |
| BenchmarkTest01257 | Java 1.2 CSV:1258 | XSS | Positive | Inner helper Thing; raw HTML print | POST `/xss-02/BenchmarkTest01257`; form cùng ID | H,T | A |
| BenchmarkTest01302 | Java 1.2 CSV:1303 | SQLi | Positive | CallableStatement, attacker-controlled call text | POST `/sqli-02/BenchmarkTest01302`; form cùng ID; benign `verifyUserPassword('foo','bar')` | D; procedure inventory | R: khác SELECT-string; không dùng boolean recipe máy móc |
| BenchmarkTest01389 | Java 1.2 CSV:1390 | SQLi | Negative | getParameterMap + constant switch; queryForList | POST `/sqli-02/BenchmarkTest01389`; form cùng ID; password/email rỗng | D | A |
| BenchmarkTest01394 | Java 1.2 CSV:1395 | SQLi | Positive | getParameterMap + tainted switch; JDBC INSERT | POST `/sqli-03/BenchmarkTest01394`; form cùng ID; password/email rỗng | D,W | R: write baseline |
| BenchmarkTest01418 | Java 1.2 CSV:1419 | XSS | Positive | Parameter NAME tainted; Base64; HTML format | POST `/xss-02/BenchmarkTest01418`; form name `SafeText`, value `BenchmarkTest01418`; `answer=` | H | R: mutate NAME, giữ marker value |
| BenchmarkTest01631 | Java 1.2 CSV:1632 | SQLi | Positive | Tainted branch; JDBC INSERT | GET `/sqli-03/BenchmarkTest01631`; query cùng ID; password/username rỗng | D,W | R: GET vẫn ghi DB |
| BenchmarkTest01659 | Java 1.2 CSV:1660 | XSS | Negative | getQueryString/decode + HtmlUtils.htmlEscape | GET `/xss-03/BenchmarkTest01659`; query cùng ID; password/username rỗng | H | A: escaped reflection |
| BenchmarkTest01660 | Java 1.2 CSV:1661 | XSS | Positive | getQueryString/decode + Thing; raw HTML | GET `/xss-03/BenchmarkTest01660`; query cùng ID; password/username rỗng | H,T | A |
| BenchmarkTest01663 | Java 1.2 CSV:1664 | XSS | Negative | getQueryString/decode; map overwrite constant | GET `/xss-03/BenchmarkTest01663`; query cùng ID; password/username rỗng | H | A |
| BenchmarkTest01729 | Java 1.2 CSV:1730 | SQLi | Negative | Constant switch; addBatch/executeBatch SELECT | GET `/sqli-03/BenchmarkTest01729`; query cùng ID; password/username rỗng | D | R: batch API semantics/error baseline |
| BenchmarkTest01777 | Java 1.2 CSV:1778 | XSS | Negative | getTheValue constant + constant branch; raw writer | POST `/xss-03/BenchmarkTest01777`; form cùng ID; password/email rỗng | H | A |
| BenchmarkTest01811 | Java 1.2 CSV:1812 | SQLi | Negative | getQueryString + map overwrite; Spring SELECT | GET `/sqli-03/BenchmarkTest01811`; query cùng ID; password/username rỗng | D | A |
| BenchmarkTest01818 | Java 1.2 CSV:1819 | SQLi | Negative | SeparateClassRequest.getTheValue trả constant; JDBC SELECT | POST `/sqli-04/BenchmarkTest01818`; form cùng ID; productID/secure rỗng, foo=foo | D | A: input gửi có thật nhưng helper không dùng value |
| BenchmarkTest01919 | Java 1.2 CSV:1920 | XSS | Positive | Header decode + tainted branch; HTML printf | POST `/xss-03/BenchmarkTest01919`; `Referer`; absent body | H | A: xét header-to-response scope |
| BenchmarkTest01923 | Java 1.2 CSV:1924 | XSS | Positive | Header decode + Thing; HTML printf | POST `/xss-03/BenchmarkTest01923`; `Referer`; absent body | H,T | A |
| BenchmarkTest01924 | Java 1.2 CSV:1925 | XSS | Negative | Header decode + HtmlUtils.htmlEscape | POST `/xss-03/BenchmarkTest01924`; `Referer`; absent body | H | A: comparable với 01923 |
| BenchmarkTest02129 | Java 1.2 CSV:2130 | XSS | Positive | split space; HTML formatter | POST `/xss-04/BenchmarkTest02129`; form cùng ID; password/email rỗng | H | R: whitespace transformation |
| BenchmarkTest02131 | Java 1.2 CSV:2132 | XSS | Positive | Bỏ ký tự cuối; HTML printf | POST `/xss-04/BenchmarkTest02131`; form cùng ID | H | R: incomplete closing delimiter không phải confirmed |
| BenchmarkTest02176 | Java 1.2 CSV:2177 | SQLi | Negative | Constant branch; Spring execute SELECT | POST `/sqli-04/BenchmarkTest02176`; form cùng ID | D | A |
| BenchmarkTest02178 | Java 1.2 CSV:2179 | SQLi | Positive | Map passthrough; Spring queryForList SELECT | GET `/sqli-04/BenchmarkTest02178`; query cùng ID; password/username rỗng | D | A: result differential có thể observable |
| BenchmarkTest02186 | Java 1.2 CSV:2187 | SQLi | Positive | Thing passthrough; JDBC SELECT execute | POST `/sqli-04/BenchmarkTest02186`; form cùng ID | D,T | A |
| BenchmarkTest02282 | Java 1.2 CSV:2283 | SQLi | Negative | Constant ternary; Spring batchUpdate SELECT | POST `/sqli-05/BenchmarkTest02282`; form cùng ID | D | R: baseline error không phải injection |
| BenchmarkTest02357 | Java 1.2 CSV:2358 | SQLi | Positive | Parameter NAME tainted; list passthrough; Spring SELECT | POST `/sqli-05/BenchmarkTest02357`; form name `bar`, value `BenchmarkTest02357`; `answer=` | D | R: exact name mutation provenance |
| BenchmarkTest02490 | Java 1.2 CSV:2491 | XSS | Negative | Complex transform rồi overwrite constant; printf | POST `/xss-05/BenchmarkTest02490`; form cùng ID | H,T | A |
| BenchmarkTest02543 | Java 1.2 CSV:2544 | SQLi | Positive | Tainted branch; JDBC SELECT execute | POST `/sqli-05/BenchmarkTest02543`; form cùng ID; password/email rỗng | D | A: suitable smoke positive |
| BenchmarkTest02546 | Java 1.2 CSV:2547 | SQLi | Negative | Constant switch; JDBC INSERT | POST `/sqli-05/BenchmarkTest02546`; form cùng ID | D,W | R: negative vẫn ghi DB |
| BenchmarkTest02597 | Java 1.2 CSV:2598 | XSS | Positive | Query decode; thay ký tự cuối bằng Z; raw HTML | GET `/xss-05/BenchmarkTest02597`; query cùng ID; password/username rỗng | H | R: inspect delimiter/close variant |
| BenchmarkTest02654 | Java 1.2 CSV:2655 | SQLi | Positive | Query decode/list passthrough; JDBC INSERT | GET `/sqli-06/BenchmarkTest02654`; query cùng ID; password/username rỗng | D,W | R: GET write, reset bắt buộc |
| BenchmarkTest02692 | Java 1.2 CSV:2693 | XSS | Negative | getTheValue constant + constant ternary; char-array writer | GET `/xss-05/BenchmarkTest02692`; query cùng ID; password/username rỗng | H | A |
| BenchmarkTest02694 | Java 1.2 CSV:2695 | XSS | Negative | getTheValue constant; switch passthrough của constant | POST `/xss-05/BenchmarkTest02694`; form cùng ID; productID/secure rỗng, foo=foo | H | A |

Bảng đầy đủ **40 unique IDs: 20 SQLi, 20 XSS, đúng 10/10 mỗi loại**. Context phân bố: 22 POST form (20 value, 2 name), 10 GET query, 8 POST header; **0 cookie, 0 JSON**. 5 SQLi positives là INSERT, 4 SELECT và 1 procedure-call; một SQLi negative cũng INSERT. Không giả vờ bộ này kiểm tra mọi input location/content type.

### B3. Đại diện, tương đồng và case cần xác minh

**Negative đủ để đo FP trong scope này**, nhưng không đại diện toàn web: cả 10 SQLi negatives chặn taint bằng constant source/branch/overwrite, không có nhóm PreparedStatement parameter binding trong selection này. XSS negatives gồm encoded reflection và constant replacement; các đôi cùng kiểu HTTP giúp phân biệt reflection với executable syntax:

- XSS `01923`/`01924`: POST Referer, printf, passthrough so với htmlEscape.
- XSS `01660`/`01659`: GET query-string reader, raw output so với htmlEscape.
- SQLi `01394`/`02546`: cùng INSERT shape, switch tainted so với constant; khác input-reader, không gọi là exact paired experiment.
- SQLi `02178`/`01811`: GET + Spring queryForList, passthrough so với constant overwrite; khác dataflow.

Không có duplicate ID; có nhiều clones cùng sink/context. Dataflow source complexity không bằng HTTP difficulty. Phân loại parent-only đơn giản thành (1) output trực tiếp/constant, (2) encoding và transformations, (3) name-tainted, (4) SQL write/procedure/error-observability. Không tạo nhãn difficulty khách quan chưa được đo. XSS cùng reflected HTML, không có stored/DOM variety đã chứng minh trong 40 này.

**Danh sách bắt buộc review trước full run:**

1. `00441,01221,01394,01631,02546,02654`: baseline và probes có INSERT; reset receipts, observable control, readback/cleanup limitations. Positive không mặc nhiên được confirmed từ malformed quote/AND errors. `02546` negative vẫn phải reset.
2. `01302`: procedure inventory, source helper và response oracle phù hợp call-expression; không mặc định SELECT predicate payload tương thích. Nếu không có kỹ thuật confirmation khả dụng, giữ unresolved và denominator, không sửa nhãn true thành false.
3. `00200,01729,02282`: SQL batch/update API trên SELECT có thể lỗi dù không injection; đọc baseline và điều kiện negative thực sự. 5xx baseline không tự làm dataset label sai, nhưng có thể khiến case không đánh giá được.
4. `01418,02357`: input component là NAME. Baseline có observed source cùng attempt và mutation giữ marker VALUE; thay value cùng tên là test sai input.
5. `00725,02129,02131,02597`: kiểm tra bytes sau split/substring/end replacement; close variant theo Skill hiện có. Không gửi expected payload/đáp án biến đổi từ báo cáo này cho Agent.
6. `01919,01923`: header reflection chứng minh sink exploitability trong direct HTTP context; chưa chứng minh delivery chain từ victim browser hoặc impact ngoài sink.

Source cần xét cho mỗi item là servlet cùng ID; source lines ví dụ: `BenchmarkTest01394.java:43–58,71–89`, `BenchmarkTest01302.java:43–64`, `BenchmarkTest02131.java:46–61`, `BenchmarkTest02597.java:70–85`. Các `thing` dependencies đối chiếu `helpers/ThingFactory.java:26–49`, `Thing1.java:22–27`, `Thing2.java:22–27`, `resources/thing.properties` (`thing=Thing2`); `SeparateClassRequest.java:30–32,51–54` trả constant ở getTheValue.

Không có browser dependency bắt buộc được xác định từ các servlet selected ordinary HTML sinks; **không đồng nghĩa HTTP reflection tự đủ**. Nếu CSP, inert parsing context, delivery semantics hoặc actual response không cho deterministic proof, outcome đúng là `browser-required`/`insufficient-evidence`. DOM/stored/session-dependent cases từ nguồn khác nằm ngoài selection đề xuất.

## C. Scoring Contract

### C1. Ground truth và đơn vị đo

Ground truth là `(case_id, vulnerability_class, expected_vulnerable, CWE, CSV source_ref)`, gắn commit/hash dataset và deployed build. CSV true/false mô tả taint/source-sink vulnerability; không phải expected response, payload đáp án hay lời xác nhận của LLM. Source review kiểm tra tính phù hợp của case; phát hiện bất nhất phải lập issue/hold-out trước experiment, **không đổi truth dựa trên Agent output**.

Đơn vị primary: **một scheduled case trong một run**, exact endpoint/method/input location/name hoặc name component. Nhiều observations, result revisions hay Findings không làm tăng số case. Repetition là run/execution mới, báo riêng theo trial, không gộp duplicate vào 40 unique.

### C2. Mapping thực tế của KAgent và runner

| Trạng thái có thể nhận | Runtime/evaluator hiện tại | Diễn giải dùng trong đồ án |
|---|---|---|
| Latest accepted `confirmed`, completed, binding đúng | evaluable, TP nếu true / FP nếu false | Agent positive; cần semantic evidence review trước gọi confirmed exploitability. |
| Latest accepted `not-confirmed`, completed, bounded attempt đủ proof | evaluable, FN nếu true / TN nếu false | Negative trong phạm vi bounded attempt; không phải chứng minh tuyệt đối not_vulnerable. |
| `insufficient-evidence` | unresolved | Thiếu bằng chứng, không vào TN/FN. |
| `blocked`, `browser-required`, `deferred`, `authorization-required` | unresolved nếu execution completed và export hợp lệ | Ghi riêng reason. Browser gap không phải negative. |
| Timeout worker hoặc Agent | execution-failed, reason timeout | Timeout có ưu tiên hơn terminal record đã có; không chấm từ diagnostic result. |
| runtime/provider/setup error, budget-exhausted, crash | execution-failed | `execution_error` là tên nhóm trình bày; giữ subtype thực tế. |
| Completed nhưng không có canonical result | unresolved/missing-canonical-result | `no_result`; text final answer không thay result. |
| Export hỏng/stale, wrong ownership/endpoint/input | invalid-result | Không TP/TN/FP/FN; giữ nguyên artifact và reason. |
| Scheduled chưa started | not-run | Không âm thầm loại khỏi N=40. |
| Reset/admission chặn run | `blocked.json`; untouched cases not-run/fail-fast với block_reason | Run-level blocked tách khỏi Agent blocked; report phải hiện reset-blocked reason. |

Nguồn: `core/runtime.py:348–362`, `core/evaluate.py:77–141`, `core/runner.py:271–282`. `workflow_blocked` có thể là execution status `completed`, vì Agent dừng bình thường; evaluator vẫn xem unresolved result. **Completed ≠ evaluable ≠ confirmed.**

`not-confirmed` chỉ được record terminal khi có registered evidence, completed usable HTTP sources, assessment criteria/limitations và `completed_attempt=true` (`workflow_tool.py:1082–1102`). Đây là evidence/provenance và lời khai bounded attempt của Agent, chưa tự bảo đảm probes đã đủ ý nghĩa ứng dụng. Không rename thành universal `not_vulnerable`.

### C3. Confusion matrix, unresolved và denominator

| Truth | Agent confirmed | Agent not-confirmed có đủ điều kiện |
|---|---|---|
| Positive | TP | FN |
| Negative | FP | TN |

Giữ công thức evaluator hiện có:

- Recall/detection rate trên **evaluable positives** = TP / (TP + FN).
- FPR trên **evaluable negatives** = FP / (FP + TN).
- Precision = TP / (TP + FP), nếu denominator > 0.
- Evaluability = evaluable / scheduled; luôn công bố overall, từng class và từng stratum.
- Denominator bằng 0 → null/NA, không 0% hay 100%.
- Mọi run: `evaluable + unresolved + execution-failed + invalid-result + not-run = scheduled`; full run scheduled=40; matrix sum=evaluable.

**Bổ sung bắt buộc khi viết Chương 3, không cần thay core scorer:** công bố `confirmed-positive yield = TP / N_positive_scheduled` (20 overall, 10 mỗi class), `FP / N_negative_scheduled` kèm N_negative_evaluable và không gọi chỉ số này là canonical FPR. Kèm số unresolved/failure/invalid/not-run theo truth strata. Yield phản ánh khả năng đưa ra kết quả trong toàn workload, không âm thầm đổi unknown thành FN.

Có thể trình bày khoảng nhạy cảm do non-evaluable: gọi U+ và U− là toàn bộ non-evaluable positives/negatives, recall bounds `[TP/N+, (TP+U+)/N+]`, FPR bounds `[FP/N−, (FP+U−)/N−]`. Đây là bounds giả định kết quả unknown sẽ được resolve, **không phải confusion matrix đo được**, không thay canonical rates. Dùng bảng counts và yield là đủ cho đồ án; bounds tùy chọn.

Timeout/blocked không bị loại khỏi workload: giữ N=40, reason và coverage, không chạy bổ sung đến khi đủ 40 evaluable rồi che các attempts thất bại. Fail-fast giữ untouched scheduled cases. Resume tạo run mới và re-execute selection; không cộng best outcome của các attempts vào một trial.

### C4. Evidence/Finding eligibility và semantic review

**Hai lớp phải tách:** (a) runtime chấp nhận nguồn/kết quả; (b) evidence thực sự đáp ứng tiêu chí lỗ hổng. `accepted_result` xác minh source manifests, ownership, hashes, usable capture, registered artifacts; không đánh giá SQL/HTML execution semantics (`assessment.py:296–358`; `benchmarks/docs/scenario1.md:184–186`). `confirm_finding` dựa trên accepted assessment, không là independent semantic oracle.

Quy trình tối thiểu đề xuất: trước experiment chốt rubric; sau mỗi smoke và sau full run, reviewer đọc effective requests và retained HTTP sources của mọi terminal assessment, đánh dấu `supported / unsupported / needs-browser / not-assessable`, ghi reason và source IDs. Với 40 cases, review thủ công khả thi; không cần thêm validator framework. Nếu có thể, xét evidence trước khi mở CSV label để giảm confirmation bias. Không đưa ledger này vào Agent/session.

**SQLi eligible:** cùng method/route/designated slot, baseline/control đúng, proof SQLI-2 có controlled evaluation hoặc effect lặp lại phù hợp sink. Quote errors, raw query echo và INSERT acknowledgement đơn thuần không đủ. Boolean-based cần hai TRUE/FALSE pairs, ít nhất bốn distinct actually captured observations; time-based cần paired control/probe và timing thực; error-based cần evaluated non-sensitive expression, không chỉ đổi parser error. Không ép INSERT/call vào SELECT boolean recipe. Nguồn: `skills/sql-injection/SKILL.md:147–171,793–795,817–850`.

**XSS eligible:** captured response đầy đủ/untruncated, Content-Type thực, encoding, CSP và surrounding syntax chứng minh payload ở vị trí thực thi deterministic. HTTP deterministic exploitability được contract hiện có cho phép; phải ghi rõ **không quan sát browser execution**. Reflection marker, text/plain, JSON, escaped/inert context hoặc payload thiếu delimiter không confirmed. JS/DOM/execution phụ thuộc browser → browser-required nếu HTTP không chứng minh được. Nguồn: `skills/cross-site-scripting/SKILL.md:344–359,443–507`. Các hướng dẫn về trailing transformation và close variant **đã có trong Skill hiện tại**; không có lý do sửa Skill chỉ vì `02131`/`02597` khó.

**Negative eligible:** application logic thực sự được reached, baseline hợp lệ hoặc hạn chế baseline được lý giải, designated input thực sự đã thử, không lẫn WAF/redirect/auth/transport failure; criterion tương ứng technique/context được thực hiện. Không phản xạ không tự chứng minh mọi XSS negative nếu sink/context không reachable.

**Cách công bố review:** giữ matrix nguyên thủy của evaluator với tên “accepted Agent assessments vs source labels”, kèm số unsupported positive/negative claims và ledger. Chỉ gọi finding/evidence-confirmed khi reviewer đánh dấu supported. Nếu cần thêm matrix đã adjudicate, xuất riêng với version/rules và đầy đủ 40-case accounting; không overwrite export, ground truth hoặc canonical evaluation, không âm thầm xóa unsupported claims để giảm FP. FP nguyên thủy vẫn phản ánh overclaim trên safe cases. Không dùng tỷ lệ accepted labels như tỷ lệ exploit proof đã độc lập xác minh.

### C5. Edge cases

| Tình huống | Contract cần giữ |
|---|---|
| Một case nhiều Findings | Đếm case một lần từ latest designated Candidate result. Canonical finding export yêu cầu đúng một report khớp; ambiguous report là pending, không thêm TP. |
| Finding đúng class nhưng sai route/parameter/source | Không đủ điều kiện evidence/finding của case. Canonical scorer có method/route/input binding; Finding exporter có binding riêng. |
| Văn bản nói vulnerable nhưng không record_result | no_result/unresolved, không suy nhãn từ prose. |
| Accepted result confirmed nhưng chưa persist Finding | Assessment vẫn evaluable theo protocol hiện có; Finding status pending. Báo riêng completion của reporting, không tự tạo Finding. |
| Early final_response | completed nhưng latest result thiếu/unresolved; không coi negative. |
| Terminal record rồi crash/timeout | Parent final status thắng, execution-failed; giữ diagnostic export. |
| Retry transport/result submission | Một execution; request/tool/LLM metrics ghi thực tế, latest sealed result được chọn; không nhân case. |
| Explicit retest/duplicate case | Run mới, trial riêng. Immutable manifest/history kiểm soát duplicates. |
| Corrupt export/evidence | invalid-result, không chữa artifact hoặc đoán verdict trong audit. |

### C6. Thời gian và tài nguyên

Giữ `agent_seconds`: ngay trước Agent.run tới khi run và background tasks settle, loại setup/freeze; `first_terminal_seconds` là event-boundary time. Giữ parent `wall_seconds`: worker process launch tới terminate/drain, không gồm before/after reset. Reset internal/end-to-end durations nằm ở receipts riêng; elapsed cả run nếu muốn phải đo riêng, không gọi mean Agent time là total wall time.

Mean/median Agent time báo trên completed cohort, n/N rõ ràng; unresolved/invalid completed có time hợp lệ vẫn nằm trong cohort này. Timeout/crash/provider-error có cohort riêng; missing worker duration là NA, không gán timeout limit thành duration. Existing thesis reporting đã xử lý cơ bản (`reporting/thesis.py:155–176`).

LLM calls/tokens/retries từ production metrics, không suy từ chat turns hoặc tool proposals; partial token `observed_sum` không phải total. Tool proposed/result/executed là các counters khác nhau. `http_admitted` khác `http_dispatch_attempts`, đều không chứng minh server nhận đủ requests. Giữ các tên và null semantics hiện có.

## D. Architecture & Data Flow

```mermaid
flowchart LR
    S[BenchmarkJava CSV + crawler + servlet/form] --> C[GroundTruth + OperationalCaseInput]
    C --> R[Parent Runner + locked Manifest]
    R --> W[Fresh Worker: operational input only]
    W --> K[KAgent + SQLi/XSS expert Skill + native HTTP]
    K --> E[Owned Observations + Evidence + ValidationResult]
    E --> F[Optional persisted Finding]
    E --> X[Frozen CanonicalResultExport]
    X --> Q[Offline Scorer]
    R -->|Runner-only truth| Q
    Q --> P[Existing CSV / JSON / Markdown / SVG report]
    F --> P
```

Parent đọc mapping source, giữ oracle, schedule, reset credentials/receipts, run classification. Worker chỉ nhận operational/settings/workspace/output/run/execution IDs. Agent được cấp Candidate class và HTTP context để **direct validation**, không nhận expected finding. Dataset target URL không trở thành authorization; absolute URLs được rebound sang exact declared origin/context.

### D1. Ground truth isolation — từng kênh

| Kênh | Source hiện tại | Kết luận / điều kiện |
|---|---|---|
| Prompt | `core/runtime.py:172–188` | Có opaque Candidate ID, class, designated name/location/component và scope. Không expected_vulnerable/exploit answer/scoring outcome. Class SQLi/XSS là input hợp lệ của direct benchmark. |
| Tool arguments | `core/runtime.py:44–51` | Candidate args có legitimate request template, neutral source_ref `operator-supplied-input`; không CSV oracle. Baseline call text của `01302` là fixture source, không exploit đáp án. |
| Worker envelope | `core/runner.py:68–71`; `core/worker.py:17–23` | GroundTruth không được truyền; strict exact-key decode ngăn thêm expected_vulnerable. `case_id` có trong internal operational envelope. |
| Workflow/session | Fresh state và Candidate tạo qua registry; `runtime.py:303–344,371–378` | Không inject prior result hoặc expected finding. Session chỉ chứa case hiện tại. |
| Scenario memory | `runtime.py:338–344` | Personal + project memory/intelligence nằm dưới per-case workspace. Không học từ case trước qua stores bình thường. Không hydrate previous sessions. |
| File tools | `src/permission/runtime/execution.py:213–216,495–500`; `src/tools/execution/file.py:101–111` | Reads nằm trong workspace; parent manifest, dataset source, previous workspaces và ground-truth reports ngoài root bị gate. `.kagent` protected. Không sao chép oracle/audit vào workspace được Agent đọc. |
| Case filenames/URLs | `dataset.py:99–108,180–191` | BenchmarkTest ID nằm sẵn trong endpoint/input names/marker values, không thể che bằng cách bỏ field case_id mà vẫn giữ target contract. `/sqli-*`/`xss-*` chỉ lộ class đã được phép. |
| Observation metadata | `runtime.py:127–158`; `src/workflow/state.py:923–931` | `scenario1_case_binding.case_id` còn trong source_details và được public_dict trả về Agent. Không có true/false label, nhưng ID không hoàn toàn runner-only. |
| Logs/errors | Mapping ở parent, worker chỉ types + bounded stack metadata; `worker.py:41–60` | Mapping source/CSV lỗi không đưa vào Agent; không truyền scoring errors về validation conversation. |
| Previous-case context | Sequential fresh worker + workspace | Không thấy đường memory/session nhập previous answer. Không mở previous reports trong Agent workspace. |

**Nhận định về ID:** không thấy field nào mã hóa true/false; numerical IDs và URL shape xuất hiện ở cả positive/negative (ví dụ gần nhau `01923` true/`01924` false; `01659` false/`01660` true). Điều này chứng minh không có obvious label encoding trong request shape, **không chứng minh LLM chưa từng thấy public benchmark**. Selection còn có correlation nhỏ như name-tainted rows đều positive; không được công bố rule đó trong Agent prompt.

Mặc định giữ explicit runner case_id khỏi Agent views nếu không cần, nhưng đừng đổi actual endpoint/parameter để giả blind. Minimal follow-up là loại redundant case_id khỏi **benchmark-facing public metadata projection**, giữ sealed runner binding; chưa làm ở đây. Bắt buộc công bố public-dataset contamination risk, giữ source/truth files ngoài worker access, không gửi B-table/labels/selection rationale hoặc reviewer ledger cho Agent. Không có browser/research/shell trong profile nên không có đường tự tra CSV online bằng những capabilities đó.

### D2. Request/execution coverage

| Contract | Có gì | Giới hạn |
|---|---|---|
| GET/POST | Được map, validate form method và GET delegation | PUT/PATCH/DELETE không có trong OperationalCaseInput. Không cần mở rộng cho 40 này. |
| Absent/empty/blank field | body regression đã kiểm tra; blank values giữ trong pairs/encoding | Canonical input chưa tách explicit empty raw body; disclose nếu đổi dataset. |
| Form/encoding | urlencode list pairs; URL query parse giữ blanks; header decode theo servlet | HTTP-equivalent representation, không wire-identical original crawler encoding; literal/double decoding phải đối chiếu source. |
| Duplicate parameters | Builder giữ pairs và regression có duplicate | Dataset mapper reject ambiguous duplicates; runtime designated slot đòi đúng một. Chưa có occurrence selector, nên không coi duplicate test là benchmark duplicate support end-to-end. |
| JSON | Native nhận string body | Mapper/guard đều form pairs; không phù hợp JSON cases nếu chưa có adapter riêng. |
| Headers/cookies/auth | Envelope có headers/cookies; ancillary fields giữ baseline | Selected 40 không cookie/auth workflow. password/email rỗng là fields, không chứng minh authentication. Dynamic CSRF/login refresh chưa nằm trong experiment. |
| Payload insertion | Guard so method/URL/form/query/header/cookie; name/value discipline | Agent phải đọc component; name tests không mutate value. |
| URL/context | Absolute fixture = origin + context + servlet | Relative native URL append base URL; dùng absolute tránh `/benchmark` bị lặp. |
| Redirects | Harness reject max_redirects>0; giữ 3xx observation | Login/redirect-dependent cases không được tự coi negative; outside scope hoặc unresolved. |
| Timeouts/retries | HTTP timeout 60s; Agent default 180s; parent +60s watchdog grace; transport attempts counter | Không suy response timeout là non-vulnerable; delay technique cần real timing/control. |
| Scope/ownership | Exact origin grant, bounded budgets, yolo false, ownership source/attempt | Target không ready/permission denied phải giữ blocked/error, không đổi tool để bypass. |

### D3. Fairness và reproducibility

Giữ dataset/source/skill/runtime hashes, commit/dirty, Python/dependency snapshot, seed/order, IDs và UTC lifecycle timestamps hiện có. Report ngày theo Asia/Saigon, artifacts UTC giữ nguyên. `core/runner.py:26–50` pin files lúc startup, không khóa chúng khỏi thay đổi trong run.

**Minimum experiment controls:** cùng provider/model ID, temperature, max_tokens/thinking setting, tool profile, timeout=180s, HTTP requests=24, tool_calls=80, agent_calls=24 hoặc bộ budgets khác đã đăng ký trước; không thay giữa groups. Chọn một cấu hình có đủ budget cho proof+evidence+Finding, kiểm tra ở smoke rồi freeze. Không sửa budget chỉ cho case đang fail.

Hiện worker đọc secure config mỗi case, metadata ghi actual provider/model/generation. Cần freeze operational config bằng quy trình operator và đối chiếu metadata từng case; nếu thay đổi thì mark trial deviation, tách run/re-run theo quy tắc đã đăng ký. Minimal code follow-up nếu cần tự động hóa là expected non-secret config fingerprint tại runner và fail-closed khi mismatch, không sửa Provider hay tạo config store mới. Không đọc/in key/config secrets vào report này.

Không dùng existing historical smoke làm mẫu chọn case “dễ”. Đề xuất **một full 40-case run**, rồi lặp **4 cases đại diện một lần** (4 executions thêm) để quan sát sự ổn định; nếu smoke là 5 cases thì chọn 4 cân bằng cho repeats. Tổng chi phí không cần 3 full runs. Báo repetition agreements/outcome/time theo trial; không best-of và không gộp repeats vào matrix chính. Nếu model/version đổi hoặc smoke dẫn tới sửa source, full run phải freeze revision mới; không tiếp tục ghép kết quả khác implementation.

Nếu source thiếu/hash đổi, dừng selection/admission với tên stratum hoặc artifact; không fabricate/relabel/substitute. Nếu container/installation/WAR chưa sẵn, giữ planned selection, không chạy, báo run blocked/not-run. Audit này không kết nối container để phán live readiness. Windows PowerShell workspace đọc source được, nhưng production launcher dùng `os.killpg`/POSIX signals (`runner.py:74–96`) và reporting có POSIX filesystem operations; **thực nghiệm chạy trong WSL/Linux đã cấu hình**, không mặc định Windows native được hỗ trợ.

## E. Risk & Gap Matrix

P0 = có thể đảo lộn oracle hoặc mất validity toàn experiment; P1 = phải giải quyết trong quy trình trước run/publication tương ứng; P2 = hạn chế/khả năng tái lập cần xử lý hoặc công bố; nice-to-have = trì hoãn được. **Không phát hiện P0 trực tiếp trong source đã đọc.** Không nâng mọi historical suite failure thành blocker của benchmark.

| Vấn đề | Mức độ | Bằng chứng source | Ảnh hưởng | Hướng sửa tối thiểu |
|---|---|---|---|---|
| Không có public smoke 3–5 cases | P1 trước mini-smoke | `config.py:122–127`; `dataset.py:262`; `test_scenario1_modes.py:51–106` | Không chạy được exact request bằng CLI hiện có; đổi mode hay cắt 12-case manifest vi phạm schema/verification | Development mini-smoke dùng internal single-case APIs hiện có qua wrapper nhỏ, hoặc chạy 4 direct sessions với cùng profile và ghi rõ demo; không giả là CLI smoke. |
| Acceptance không chứng minh vulnerability semantics | P1 trước công bố | `assessment.py:296–358`; `workflow_tool.py:1082–1102`; docs:184–186 | Weak evidence có thể vẫn thành confirmed/TN; rates đẹp nhưng thiếu proof | Chốt rubric C4, reviewer ledger cho terminal outcomes, giữ nguyên raw score; không cần viết lại validators. |
| INSERT positives dễ bị overclaim từ parser errors | P1 trước smoke SQL write/full | `BenchmarkTest01394.java:52–58`; SQLi Skill:821–845 | TP theo label nhưng chưa chứng minh controlled evaluation | Review proof theo sink; prefer read-only SELECT cho smoke đầu; giữ INSERT trong full với reset và limitations. |
| Unverified target/reset deployment hoặc reset unknown | P1 admission prerequisite | `runner.py:125–127`; reset README:53–63,151–154 | Có thể blocked hoặc contaminated responses | Operator xác minh exact target/installation, reset before/after và receipts; không bypass controller, không sửa target trong audit. |
| Baseline writes kể cả GET và negative | P1 full | `01631.java:50–56`; `02546.java:50–56`; dataset:193 | DB state phụ thuộc order dù không gửi exploit | Reset tất cả cases; mutation ledger; không dùng expected false hay GET để bỏ reset. |
| Model/generation đổi giữa workers | P1 full | `worker.py:28–40`; `runtime.py:436–439` | Strata không cùng treatment; metadata không ngăn thay đổi | Freeze config bằng operator procedure + review metadata; optional fingerprint admission tại runner. |
| XSS incomplete/escaped reflection được gọi confirmed | P1 review | `02131.java:56–58`; XSS Skill:443–507 | FP proof/overclaim browser execution | Review bytes/context/CSP, permitted close variant; browser-required khi không deterministic. Hướng dẫn đã có, không sửa Skill. |
| Name-tainted + procedure case cần khả năng tương thích | P1 full readiness | `01418.java:45–54`; `02357.java:45–54`; `01302.java:48–59`; canonical:201–240 | Sai component hoặc technique khiến non-evaluable/FN | Kiểm tra neutral request/proof path trước experiment; retain unknown thay vì ép verdict. |
| Conditional rates bị trình bày như full-workload performance | P1 publication | `evaluate.py:41–45`; reporting/thesis:140–154 | Loại unknown gián tiếp làm đẹp rates | Bắt buộc n/N, 5 partitions, per-stratum evaluability và TP/N+; không sửa matrix để gán negative. |
| Reset PARTIAL + ORM parity | P2, thành P1 nếu selected behavior phụ thuộc chưa phục hồi | reset README:99–118 | Baseline giữa cases khác fresh deployment; external effects không reset | Review selected dependencies; không claim universal reset. Không có selected servlet dùng ORM trực tiếp trong inspection này, nhưng giữ build/helper checks. |
| Source mutations regex không đầy đủ | P2 | dataset:193; docs:149–158 | Không-match bị hiểu sai là stateless; batch/helper writes bị bỏ sót | Vì reset tất cả đã có, giữ regex là warning indicator. Chỉ cần state-effects catalog nếu tương lai muốn loại/reset subset. |
| Redundant case_id tới Agent; public benchmark contamination | P2 | runtime:129,157; state:923–931 | ID không runner-only tuyệt đối; model có thể biết dataset | Bỏ redundant ID ở benchmark public view nếu cần; giữ actual endpoint/input; disclose contamination. Không lộ oracle. |
| 40 cases có nhiều clones, SQLi negatives chỉ constant-taint | P2 scope | B2 + servlet flows | Không đại diện SQL dialect/platform/mọi sanitization defenses | Giữ 40 cho prototype, báo variants/limitations; không cherry-pick sau kết quả. |
| Current body fix chưa có handoff riêng | P2 documentation, lỗi boundary đã resolved | runtime:37–40; request-body tests:23–93; historical review:102 | Có thể lặp lại chẩn đoán cũ hoặc suy whole-family green | Ghi 9-test evidence và source hash; pending broader acceptance riêng, không sửa validators hoặc baseline failures. |
| Shared helpers/resources không đều có selected-artifact hash | P2 reproducibility | dataset:75,79–84,155–160; ThingFactory + thing.properties | Selected source hash chưa tự pin mọi sink/helper behavior | Giữ clean exact dataset commit + trusted WAR identity; bổ sung dependency hash inventory parent-only nếu cần. |
| Tên artifacts Scenario 1 khác tên Kịch bản 2 | P2 presentation | contracts:13–16; thesis:134 | Người đọc hiểu sai mục tiêu hoặc schema | Caption đồ án “Kịch bản 2 dùng runner Scenario 1 supplied-input-v1”; giữ schema/CLI. |
| Native Windows launcher/report portability | P2 environment; P1 nếu cố chạy native Windows | runner:86–95; writer filesystem operations | Timeout cleanup/export có thể không tương thích | Dùng WSL/Linux có sẵn. Không refactor cross-platform trong task này. |
| Browser, JSON, cookie/auth coverage, nhiều dialect/dataset | Nice-to-have ngoài scope | runtime profile; B2 coverage | Scope hẹp nhưng công bố được | Trì hoãn; chỉ bổ sung khi mục tiêu nghiên cứu yêu cầu, không xây framework mới. |

Schema budget/provider retries/UI/CWE failures của historical Lab Fidelity verification không được sửa trong phiên này. Nếu chúng thực sự tái hiện ở production profile đã chọn, ghi đúng execution failure và xử lý ở follow-up riêng; không dùng audit này để khẳng định full suite xanh.

## F. Implementation Readiness

### F1. Bắt buộc trước 3–5 smoke cases

1. Chọn **đúng đường development mini-smoke**. Public smoke hiện có vẫn 12. Không cắt/sửa frozen manifest để bypass strata count; không đổi config hoặc runner trong audit.
2. Operator cung cấp declaration exact origin/context và deployment với reset controller compatible; identity/readback/route lease trước admission, reset after case. Source/WAR/helper behavior phải cùng BenchmarkJava đã pin. Không tự gọi health/reset/container trong phiên này.
3. Freeze model/generation/capability/budgets cho smoke; không source/config changes trong trial; riêng mini-batch 4–5 cases có run/execution/session IDs và receipts đầy đủ.
4. Chốt semantic rubric C4 và review ngay mỗi smoke case: structured result, source ownership, HTTP evidence đúng slot, no_result/unresolved/error được giữ, Finding được persist khi confirmed theo Skill.
5. Body absent regression boundary đã đạt 9/9; **không cần sửa lại `body=None`**. Bất kỳ changes tiếp theo đều cần focused acceptance riêng; không kéo full suite vào design audit.

### F2. Trước full 40 cases

1. Freeze official 40-case manifest bằng selector hiện có, CSV/crawler/servlet/form hashes, seed/order; verify authoritative dataset trước run. Scope là direct confirmation SQLi/XSS; operator gọi Kịch bản 2 nhưng artifact protocol giữ Scenario 1.
2. Hoàn thành review các groups B3: writes, CALL, batch-error baselines, name input và transformations. Không loại case vì không confirmed; nếu case không phù hợp mục tiêu đã quyết định, đăng ký selection change trước bất kỳ official results nào và nêu quota/source replacement thật.
3. Xác minh reset scope đủ cho selected operations; không dựa regex để bỏ reset. Record external-effects/ORM limitations. Reset failure giữ blocked.json và not-run, không clean artifacts.
4. Có cơ chế kiểm tra config thống nhất và source không đổi trong run. Một config/deployment không ready thì dừng, không chuyển provider/target âm thầm giữa cases.
5. Báo cáo chứa 40 scheduled rows, tất cả partitions, canonical matrix/rates với denominator, full-workload yield, duration coverage, raw vs semantic-reviewed conclusions và finding-persistence status.
6. Review terminal proof theo rubric trước công bố; preservation nguyên manifest/events/export/CSV và selection records. Reruns có run mới, không best-of aggregation.

### F3. Tùy chọn, trì hoãn được

Automated semantic oracle, browser proof, generalized CanonicalCase/new schema, JSON/duplicate-occurrence adapter, multi-dataset evaluation, confidence intervals, full 40 chạy 3–5 lần và refactor cross-platform đều không phải minimum. Repeats 4 cases một lần là đủ thăm dò stability; profile fingerprint admission và shared-helper hash inventory là bổ sung nhỏ hữu ích nếu muốn tự động hóa.

### F4. Giữ nguyên

Giữ Dataset mapper/CSV truth, deterministic ranking/order, `official`→`reduced` compatibility, immutable storage/lifecycle/evaluation IDs, fresh worker/personal store isolation, native permission/scope/ownership gates, Evidence hashes/seals và retained source bytes, confirmed-only Finding gate, canonical partitions, reporting loader/chart/table code và reset fail-closed. Không đổi Skill/Planner/HTTP validator/Redaction để làm benchmark dễ hoặc tests xanh.

### F5. Nhận xét phản biện đồ án

**40 cases hợp lý cho nguyên mẫu bậc đại học**, đủ minh họa quy trình và phát hiện một số FP/FN, không đủ suy rộng chất lượng AI pentest trên Internet. Cân bằng 20 SQLi/20 XSS và 10/10 mỗi lớp phù hợp mục tiêu so sánh có negative controls; tỷ lệ 50% vulnerable là artificial prevalence nên precision không đại diện deployment.

Chỉ tập trung SQLi/XSS vẫn bám mục tiêu nếu mục tiêu nghiên cứu là Agent điều phối workflow, kiểm chứng evidence và xác nhận hai nhóm web phổ biến. Nếu mục tiêu đồ án tuyên bố autonomous discovery/toàn web scan thì experiment này **chưa đo điều đó**: Candidate, class, endpoint và input đã được cung cấp. Không cần mở rộng đồ án chỉ để sửa cách diễn đạt.

Bảng Chương 3 tối thiểu: class/variant, N positive/negative, scheduled/started/completed và 5 partitions; TP/FP/TN/FN; recall/FPR/precision + n/d; evaluability từng stratum, TP/N+; Agent mean/median và n/N, parent wall/reset time riêng; LLM calls/tokens có completeness; unsupported claims và Finding pending. Dùng existing thesis tables và per-case.csv; chỉ bổ sung ledger/yield/captions nếu chưa có.

Giới hạn phải công bố: một Java/HSQLDB build, nhiều synthetic clones, negative constants chiếm ưu thế, labels từ source khác black-box observability, HTTP-only reflected XSS, không observed browser execution/DOM/stored chain, known exact endpoints/class, public benchmark contamination, finite budgets, stochastic/model-version variation, reset PARTIAL và không có live verification trong audit này. Không viết “độ chính xác 100% SQLi/XSS” từ conditional subset hoặc historical 12-case smoke.

Demo 3–5 cases phục vụ giải thích pipeline, quan sát request/evidence/Finding và lỗi kiểm soát. Thực nghiệm 40 phục vụ bảng counts/rates, chạy locked order/profile và giữ mọi abnormal cases. Demo không thay full experiment và không lấy successes trình diễn làm ước lượng thống kê.

## G. Smoke Test Proposal

### G1. 4 cases chính + 1 case khó tùy chọn

Những IDs sau đều thuộc source thật và frozen selection algorithm hiện tại. Cột truth/path chỉ **operator/reviewer đọc**; Agent nhận neutral Candidate và request baseline tương ứng, không nhận bảng, expected outcome hay expected proof.

| Case ID | Operator-only truth | Vì sao chọn | Expected execution path và điểm kiểm tra |
|---|---|---|---|
| BenchmarkTest02543 | SQLi positive | SELECT body, avoids INSERT baseline; kiểm tra proof observable | Candidate → SQLi expert → baseline/probes cùng body field → owned observations → repeatable supported SQLI-2 → evidence/result → Finding nếu confirmed. Không ép Agent positive khi evidence chưa đủ. |
| BenchmarkTest01389 | SQLi negative | POST form/context gần positive, branch constant; ancillary password/email blank | SQLi expert → baseline và bounded applicable validation → proof of completed attempt → not-confirmed nếu đủ; không Finding. Nếu baseline/error ngăn kiểm chứng thì unresolved, không gán TN. |
| BenchmarkTest00390 | XSS positive | Raw ordinary HTML response; đơn giản cho pipeline | XSS expert → inert marker → context-specific harmless execution marker → complete syntax/context/CSP review → deterministic HTTP exploitability nếu đủ → evidence/result/Finding. Không claim browser đã execute. |
| BenchmarkTest01048 | XSS negative | Escaped reflection qua Referer; POST absent body; bắt false positive và regression | XSS expert → native baseline không có body key → marker/header probe đúng Referer → thấy encoded inert context → supported not-confirmed nếu đủ. Reflection có mặt không được confirmed. |
| BenchmarkTest02131 (tùy chọn thứ 5) | XSS positive | Trailing-character removal; kiểm tra evidence discipline | XSS expert inspect actual response → không xác nhận fragment thiếu delimiter → một close variant được Skill cho phép → supported confirmed nếu syntax deterministic; nếu thiếu proof giữ browser-required/insufficient-evidence. Không đưa transformation answer cho Agent. |

Chọn đủ bốn strata giúp phát hiện false-positive/false-negative pipeline; negative `01048` đồng thời kiểm tra absent-body POST và encoded reflection, nên không cần thêm dummy case. Nếu muốn smoke GET thay case khó thứ 5, có thể dùng case thật `BenchmarkTest01660` (positive XSS GET/query) với rationale encoding/context; không tạo ID mới. Không chạy toàn 40 chỉ để kiểm tra thiết kế.

### G2. Đường thực thi tối thiểu, không giả public CLI hỗ trợ 4

Public `run --mode smoke` luôn cần frozen 12-case smoke manifest; `--case-id` và arbitrary small-manifest run không phải public paths được hỗ trợ. Hai lựa chọn operator sau audit:

1. **Mini-smoke có artifacts benchmark:** một development wrapper rất nhỏ gọi API hiện có `select(Dataset, ..., case_id=<real ID>)`, verify manifest rồi `core.runner.run` với production worker và verified reset controller cho từng case; mỗi case một immutable run directory. Internal single mode vẫn được contracts/evaluator hỗ trợ. Wrapper không inject verdict/MockTransport/FakeClient và không thay definitions. Đây là đề xuất follow-up, **chưa tạo/chạy**. Giữ profile, timing và reset receipts giống official; không tuyên bố mini-smoke là public smoke mode.
2. **Demo thủ công 4–5 sessions:** dùng direct supplied Candidates qua production flow và cùng HTTP-only tool profile. Ghi rõ không có toàn bộ parent-runner watchdog/export parity nếu đường UI/CLI thường khác harness. Không dùng demo đó để chứng nhận benchmark integration. Khi cần kiểm chứng exact runner, chạy locked 12-case smoke hiện có ở bước operator tiếp theo, và chỉ chọn 4–5 cases để trình bày.

Ưu tiên lựa chọn 1 nếu mục đích là smoke readiness chính xác và operator chấp nhận follow-up wrapper nhỏ. Nếu không muốn thêm code, giữ 12-case smoke hiện có và tách 4-case demo; không lách profile validation hoặc đổi selection quotas.

### G3. Dữ liệu và acceptance checklist của smoke

Ghi case/run/execution/session/Candidate/attempt/result IDs; source/build hashes; actual provider/model/generation; start/finish timestamps; exact baseline template và component; permission decisions; before/after reset receipts; HTTP status/content type/CSP/complete/truncated/source IDs; proof excerpts/parent associations; latest structured outcome và evaluation partition/reason; Finding persisted/pending/not-applicable; agent/setup/teardown/parent wall/reset durations; token/call/tool/dispatch counters cùng NA/coverage.

Smoke đạt mục tiêu integration khi request thật đúng field/route/method, không có `body=None` invalid args, không lộ oracle, ownership/completeness/export/scoring/report nhất quán và reviewer xác nhận được lý do outcome. Không bắt buộc mọi positive thành confirmed để “PASS smoke”: honest unresolved là contract hợp lệ nhưng phải tìm nguyên nhân và quyết định capability trước full run. Cấm xem 4 successful outcomes là accuracy estimate.

## Verification record và source snapshot

1. Read-only inspection `AGENTS.md`, focused benchmark modules/tests, SQLi/XSS integration/confirmation sections, Evidence/Finding boundary và Lab Fidelity implementation/verification. Không audit lại Provider/UI/Registry/Redaction toàn bộ.
2. Offline Python gọi Dataset/select trong RAM cho smoke 12 và official 40; không gọi runner/worker/reset/client/live target. First probe dùng Dataset.identity thật xác nhận commit/dirty; probe phụ tránh lặp git scan bằng identity projection cục bộ, không sửa implementation và không làm source of truth cho commit.
3. Đọc servlet flows 40 selected IDs và helper dependencies cần thiết; đối chiếu rows CSV/crawler/form để lập B-table. Đây là static source review, không có fabricated HTTP outcomes.
4. Chạy **duy nhất** focused offline body-boundary file bằng WSL virtualenv:

```text
PYTHONDONTWRITEBYTECODE=1
KAGENT_RUN_LIVE_TOOL_CHARACTERIZATION=0
KAGENT_S1_EXISTING_CONTAINER=
venv-linux/bin/python -B -m pytest -p no:cacheprovider --import-mode=importlib -q tests/benchmarks/test_scenario1_request_body.py
Result: 9 passed in 4.14s
```

Không chạy full suite, live/container tests, external LLM, official/smoke experiment hay reset verification tool. Tests body file tự dùng temp files/mock opener; không tạo benchmark results trong repository.

Source snapshot trước khi thêm báo cáo: KAgent HEAD `f4d5e1626c060c734baf4d47ad0052b3119d7a87`, `git status --short` rỗng. Hashes checkpoint của source được đọc (hash quan trọng hơn lịch sử summaries):

| File | SHA256 |
|---|---|
| `benchmarks/scenario1/core/runtime.py` | `a3f5aea3791f09167f851d8f0b615c9de2acc4ecdabdd05466e5502df03bb956` |
| `tests/benchmarks/test_scenario1_request_body.py` | `a8bdc3d17fe4850713432b086008bacff2304ea9599ee805ba0b92bba019c0cd` |
| `src/workflow/assessment.py` | `a4c9759459aff8f6da63616f91d6f5e0c8f8c77d4316a39dd3bffb9c6f79f760` |
| `src/tools/workflow/workflow_tool.py` | `930baae7513fb3b6a217399a99c358bb2dae7f275dc8653856d6aa3a3a330d3c` |
| Dataset `expectedresults-1.2.csv` | `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1` |
| Dataset `data/benchmark-crawler-http.xml` | `64c98d5bd13e199747467c4ec2d94a035b016c8d18d025e32cb89846ee623d40` |

Tests benchmark được đọc theo responsibility: `test_scenario1.py` (mapping/truth/isolation/metrics), `test_scenario1_request_body.py`, `test_scenario1_data_contracts.py`, `test_scenario1_modes.py`, `test_scenario1_reliability.py`, và focused finding/reporting test contracts. Các tests ngoài body file chỉ inspection, **không tuyên bố PASS**. Historical 426/609/241-pass Fidelity groups và 44+13 Scenario1 failures không được cộng vào verification hiện tại.

QA báo cáo: đủ A–G, 40 unique selection rows và chính xác 10 rows mỗi stratum, không trailing whitespace; source hashes ở checkpoint giữ nguyên. `git diff --check` đạt; tracked diff rỗng, `git status --short` chỉ có thư mục báo cáo mới. Không stage/commit/push/reset/clean/restore.

## Final Decision

**`READY WITH REQUIRED FIXES`**, vì dữ liệu nguồn đủ 40 và các thành phần chính đã tồn tại, nhưng exact 3–5-case execution path, deployment/reset admission, config consistency và semantic evidence adjudication cần chốt trước bước vận hành. Không `BLOCKED` do thiếu dataset; không `READY FOR SMOKE TEST` vô điều kiện khi current public smoke khác yêu cầu và target readiness chưa kiểm tra.

**Trước 3–5 cases:** development mini-smoke path hợp lệ hoặc demo scope được ghi rõ, verified target/reset, frozen profile/budgets, rubric + reviewer; body boundary hiện đã đạt focused checks. **Trước 40:** locked current 40-case manifest, review B3 và reset dependencies, consistency checks, đủ 40-row accounting và denominator, preserve raw scores và semantic-review ledger. Không cần benchmark framework mới hoặc sửa Skills/HTTP validators để đạt các điều kiện này.

Audit dừng sau khi lưu báo cáo; operator quyết định implementation/preflight/run ở bước tiếp theo. Báo cáo này không cho phép hay tuyên bố đã chạy benchmark thật.
