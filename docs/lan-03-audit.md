**Audit forensic `lan-03` — lỗi, thiếu sót và các guard hoạt động đúng**

Phạm vi: phân tích offline lần chạy `experiments/scenario3/runs/lan-03`, không sửa implementation hoặc dữ liệu thực nghiệm, không chạy lại target hay external model. Transcript được dùng để định vị; kết luận dưới đây dựa trên tool calls, persisted WorkflowState, observations, proof snapshots và implementation khớp manifest. Nội dung Agent viết trong artifacts/memory không mặc nhiên là sự thật.

**Kết quả thực tế và độ tin cậy của dữ liệu**

- Toàn phiên chưa hoàn tất. SQLi: `insufficient-evidence`, candidate/goal `deferred`, attempt `unresolved`. XSS: `not-confirmed`, goal `tested_not_confirmed`, giới hạn ở error-page sink của API. Confirmed findings: **0**.
- Lượt đầu: 60 agent iterations/LLM calls, dừng `max_steps`; thêm 1 final synthesis. Continue: 18 agent iterations/LLM calls, 1 compaction và 1 final synthesis, dừng `workflow_blocked`. Tổng các bộ đếm được lưu: **81 LLM calls**, không phải 81 HTTP requests.
- History lưu **108 tool-call và 108 tool-result**, trong đó có runtime-generated closure. Status: 66 success, 36 observation, 6 error. Observation store có **100 records: 90 HTTP và 10 shell output**. Các HTTP records gồm 34 native tool requests, 54 requests trong một content-discovery pass và 2 brokered shell fetches. Không cộng shell output như HTTP request mới.
- Cả 90 HTTP observations có origin `http://127.0.0.1:8081`. Có thêm TCP service discovery; bộ đếm HTTP không đại diện mọi network activity hoặc wire bytes.
- 243 runtime files hiện tại và 31 skill snapshot files khớp SHA256 trong manifest. Vì vậy implementation hiện tại dùng được để kiểm tra contract của lần chạy này.
- 100/100 retained body hashes và 3/3 immutable proof snapshot hashes khớp. Có 10 incomplete/truncated observations; tất cả observations có execution status `completed`. Cap truncation không tự có nghĩa execution failure.
- Không tìm thấy audit report `lan-03` riêng có sẵn. Đây là báo cáo mới từ dữ liệu gốc. History có 875 debug records bị drop; kết luận không bao phủ những nội dung không được lưu hoặc wire schemas không có snapshot.

**Các vấn đề đã xác minh**

1. **P1 — Hết ngân sách trước khi hoàn tất SQLi; whole-target bị chặn.**

   SQLi được load ở iteration 46 của lượt đầu; Recon bắt đầu ở 1, Enumeration ở 6, Input Analysis ở 37. Enumeration chiếm 31 iterations và 50 tool calls. SQLi còn 15 iterations, gồm đọc skill/payloads, khai báo attempt, 5 probes, readback, proof và finalization. Đây là lý do thực tế khiến không còn đủ chỗ hoàn tất handoff trước hard stop; không có bằng chứng hard limit chạy sai.

   Bốn iterations không tạo progress mới sau probe cuối dẫn tới `probing_stopped`/local finalization. Sau đó runtime đóng SQLi unresolved tại `seq=1580–1581`; `done(max_steps)` ở `seq=2760`. Continue thực hiện XSS, không reset SQLi attempt. Canonical SQLi deferred và mutation/cleanup unknown giữ whole-target blocked. Cần giảm thao tác lặp và hoàn tất effects/result sớm hơn; không tăng limits để làm assessment hợp lệ.

2. **P2 — Tải và trích xuất Swagger initializer lặp khi đã có bản đầy đủ.**

   `seq=266–267` đã lấy initializer **5.457 bytes, complete=true, truncated=false**. `seq=294–295` lấy lại cùng resource với cap lớn hơn; `seq=332–333` lại fetch qua shell. Tổng cộng resource này có 3 HTTP captures. Tám trong 10 BashTool calls dùng để xem/grep các phần của initializer, nhiều đoạn chồng lặp.

   Lời giải thích “truncated prefix” không khớp metadata của hai native captures. Bounded extraction là hợp lệ khi cần, nhưng resource này đã nằm trọn trong retained bytes. Hướng dẫn có `select_source`/`process_source` cho HTML/OpenAPI; raw initializer JS chưa được OpenAPI extractor hỗ trợ, nên cần ghi limitation đúng thay vì xem mọi thiếu hụt đọc là thiếu body và tải lại.

3. **P2 — Compound shell che exit code của download; partial `/main.js` cần đọc đúng ngữ cảnh.**

   `seq=550–551`: stdout ghi `exit=18`, file đúng 65.536 bytes; stderr là `curl: (18) transfer closed with outstanding read data remaining`, nhưng outer shell exit là 0 do các lệnh sau vẫn chạy. Pipeline no-match cũng không phản ánh exit của download. Vì vậy ToolOutput success chỉ chứng minh compound shell kết thúc với 0, không chứng minh download thành công đầy đủ.

   Brokered HTTP observation tương ứng có `complete=false`, `truncated=true`, `response_cap=65536`, execution `completed`. Broker implementation chủ động không phát chunk terminator khi body bị truncate, nhằm không giả lập full response. Curl 18 phù hợp với tình huống cap này; chưa có bằng chứng target bị lỗi. Native `/main.js` prefix và 64 KiB shell fetch nằm trong bounded strategy; không coi chưa đọc hết bundle là bug hoặc bắt buộc tải hết.

4. **Contract misuse / guard đúng — Dùng validation body reader cho unowned discovery observation.**

   `seq=259–260`: đọc `obs_eb40…` bị `reference_unavailable`. Observation thực sự tồn tại, complete, dài 3.106 ký tự, nhưng chưa có candidate/attempt ownership. `ReadHTTPObservation.validate_rights()` yêu cầu candidate và active/completed owned attempt; tests chủ ý reject unowned sources.

   Đây không phải observation loss hay redaction. `workflow(list)` tìm owned validation sources cũng không tự cấp ownership cho Recon capture. Discovery có selected-source extraction contract riêng; không mở reader bằng cách gán owner/attempt giả. Feedback hiện còn chung chung đối với discovery, nhưng rejection bảo vệ đúng contract.

5. **Contract misuse / guard đúng — Ba `source_ref` dùng path cụ thể cho endpoint đã tự khái quát thành `{id}`.**

   | Rejection seq | Endpoint được nộp | Path thực của source |
   | --- | --- | --- |
   | 659 | `/rest/products/{id}/reviews` | `/rest/products/1/reviews` |
   | 661 | `/rest/track-order/{id}` | `/rest/track-order/5267-1f2d-4a3b-9c8e` |
   | 839 | `/api/Products/{id}` | `/api/Products/1` |

   IDs có thật và đúng request cụ thể; lỗi không phải ID trỏ sang endpoint khác. `_validate_input_http_source()` so method/origin/path chính xác, không cấp wildcard/template authority từ một capture. Skill chỉ cho group route shape sau ít nhất hai observed values tương thích; không có cặp observation như vậy cho ba routes này trong run.

   Agent retry bỏ `source_ref`, nên admission thành công nhưng mất liên kết máy đọc được tới capture. Omit ref được contract cho phép đối với documented context; ở đây attribution chỉ còn prose, còn template vẫn chưa được chứng minh bằng nhiều observed paths. Không nên nới binding gate để sửa triệu chứng.

6. **P1 — Ghi schema và behavior login/feedback từ kiến thức chung, chưa có request evidence.**

   Inventory tự ghi login body chưa được submit, shape được infer từ “standard credential flow”; feedback POST shape cũng chưa submit. Không có native login POST hoặc feedback POST trong run; artifacts chỉ giữ hai worker files `main.js`/`swagger-init.js`, và không có JS call-site evidence cho hai write requests này.

   Dù vậy, canonical inputs chứa JSON samples login `email/password` và feedback `comment/rating/captchaId/captcha`. Input disposition còn khẳng định comment được persist/render và write path captcha-gated. GET collection có trường tương tự không chứng minh POST chấp nhận schema đó hoặc rendering path. Phải phân biệt clue/hypothesis với observed request schema; không biến sample suy đoán thành executable template.

7. **P1 — Structured inventory bỏ trường thực sự có trong OpenAPI; số “8 inputs” không chứng minh đầy đủ.**

   Parse offline chính initializer đã lưu xác nhận `/b2b/v2/orders`, schema `Order` có `cid` **required**, `orderLines`, `orderLinesData`; `OrderLine` còn có `productId`, `quantity`, `customerReference`. Canonical workflow chỉ có input `orderLinesData` cho operation này, thiếu riêng `cid` và `orderLines`. Schema fields nằm trong sample hoặc Markdown không thay thế record riêng theo input identity contract.

   Inventory cũng liệt kê password và các feedback fields ngoài comment nhưng thiếu records tương ứng. Riêng các trường suy đoán này cần xác minh provenance trước khi bổ sung; không “sửa completeness” bằng cách coi schema suy luận là đã quan sát. `8 analyzed` chỉ áp dụng tám records đang tồn tại, không đại diện mọi input của target.

8. **P1 — Disposition có reason sai input và blocker chưa được chứng minh.**

   `orderLinesData` có reason “Object identifier on read + write state-changing sibling; … Access-control requires supplied identities”, không khớp documented JSON serialization field. Đây là lỗi nội dung handoff do caller chọn/copy reason, không thấy runtime tráo ID.

   Login reason nói SQLi auth bypass cần supplied credentials/authorized login chưa có; chưa có test chứng minh credentials là prerequisite cho mọi kiểm tra input đó. Security-question chỉ trả `{}` cho một email, chưa đủ để khẳng định account-existence oracle hay loại nó khỏi SQLi/XSS chỉ bằng endpoint name. Feedback captcha/auth blocker cũng chưa được verify.

   `analyzed` có thể hợp lệ cho passive triage và không đồng nghĩa tested. Vấn đề là reason/certainty chưa đúng evidence và việc prose gọi các input “deferred” trong khi canonical disposition đều `analyzed`. Không nên đổi mọi record thành blocked hoặc ép tạo vulnerability Candidate để hợp thức hóa số liệu.

9. **Limitation — Structured discovery gần như chưa được đối chiếu và disposition.**

   Final workflow có 35 discovery sources: **34 pending, 1 processed, 0 selected**. Không có call `select_source`, `process_source`, `get_source`, `set_source_disposition` hoặc structured scanner triage. Phần lớn provenance vẫn là raw observations và manual inventory.

   Runtime contract không bắt buộc xử lý mọi unselected source; phase completion không kiểm chứng nội dung Markdown toàn diện. Vì vậy đây là coverage/handoff limitation, không bằng chứng gate bị bypass. Chưa có cơ sở nói toàn bộ known/discovered fields đã được reconcile. `/main.js` có 12 chunk references được trích ra nhưng không có chunk fetch trong run; cần giữ mức coverage partial, không yêu cầu full crawl hoặc recursive extraction.

10. **P1 — Nâng giả thuyết SQL shape thành sự thật.**

    Captured error cho `apple'` là `SQLITE_ERROR: near "'%'": syntax error`; không có constructed query hay `SELECT`, và stacktrace list rỗng. Candidate signals, proof và summary lại có các câu “proving value concatenated into quoted LIKE pattern”, “paren balanced”, “comment applies”. Chúng là giải thích có thể phù hợp, chưa phải observations chứng minh exact shape.

    Hai responses 200 cũng không tự chứng minh predicate `54=54`/`54=55` thực sự được evaluate như Agent dự định. Đúng mức kết luận là syntax sensitivity, boolean pair không có differential, shape còn hypothesis. Skill snapshot đã yêu cầu phân biệt như vậy; lỗi còn phụ thuộc model tuân thủ guidance, không cần runtime SQL keyword classifier.

11. **P1 — Boolean pair không tạo oracle; nguyên nhân cụ thể chưa được chứng minh.**

    SQLi attempt có 5 owned observations: hai initial pair requests đều complete 200, cùng `{"status":"success","data":[]}` (30 bytes), rồi ba syntax adjustments đều 500 `incomplete input`. Không có pair lặp hai lần với TRUE/FALSE khác nhau; SQLI-2 không established.

    Giải thích “wildcard suffix khiến seed không match” vẫn phụ thuộc query shape chưa thấy. Agent đã chọn pair mà chưa bảo đảm intended truth values sau prefix/suffix, dù playbook có Pair decision checkpoint. Không nên coi đây là tested negative, cũng không suy ra target an toàn từ các responses này.

12. **P2 — Giải thích sai comment termination, làm tốn một syntax adjustment.**

    `seq=1407` chỉ thêm space sau `--`; Agent gọi đó là kết thúc comment để suffix sống lại. Space không kết thúc SQLite line comment. Kiểm tra SQLite in-memory: `SELECT 1 -- + 1` và bản thêm space đều trả 1; thêm newline trước `+ 1` mới trả 2. Hai dạng thiếu closing parenthesis bị comment nuốt đều trả `incomplete input`.

    Reproducer chỉ xác minh comment syntax, không chứng minh target sử dụng query giả lập này. Không đổi request hashes hay gộp evidence binding của hai requests. Agent tự ghi ba adjustments rồi dừng; không có bằng chứng nó đổi tên technique để reset allowance, hoặc runtime bỏ qua hard limit.

13. **P1 — SQLi proof có đăng ký nhưng không được nối vào result cuối.**

    Agent đăng ký `ev_4be0bc6e4a59401b032d` thành công tại `seq=1577–1578`, với năm owned observations và snapshot 4.731 bytes. `seq=1580` có call ID `terminal-closure-None-attempt_…`: đây là **runtime-generated closure**, không phải result submission chủ động của model.

    Final SQLi result có `evidence_refs=[]`, `evidence_manifest=[]`, `techniques=[]`, assessment không có artifacts. Prose cuối lại trình bày proof/result như evidence đã liên kết. Proof không mất khỏi store; canonical result thiếu handoff. Runtime fallback chọn unresolved và không tự thay Agent lựa chọn evidence là bảo thủ đúng. Cần model hoàn tất explicit result trước hard stop; không auto-attach mọi proof đã đăng ký vì registration chưa chứng minh terminal eligibility.

14. **P1 — Không khai báo effects, dẫn tới cleanup unknown và blocker bổ sung.**

    SQLi `effects.declaration=null`; không có `record_attempt_state` trong cả run. Prose ghi mutation false/cleanup not required, nhưng runtime closure lưu `mutation_performed=null`, `cleanup_state=unknown` vì có target dispatch mà chưa có declaration. `attempt_effects()` cố ý không suy ra no mutation từ GET.

    Đây là thiếu structured bookkeeping; không phải bằng chứng target thật sự đã bị mutate, cũng không phải runtime quên một declaration đã commit. Không được set false chỉ từ method. Unknown cleanup giữ blocker đúng; ngay cả sửa bookkeeping hợp lệ, insufficient-evidence SQLi vẫn là unresolved và whole-target chưa hoàn tất.

15. **Contract misuse / guard đúng — XSS khai báo required baseline nhưng quên thực hiện.**

    `seq=2775` predeclare baseline chính xác `GET /rest/products/search?q=apple`. Agent sau đó gửi marker control khác URL và ba error probes, đăng ký proof bốn parents rồi nộp `not-confirmed`. `seq=2855` trả `MISSING_VALIDATION_STEP` vì required baseline chưa có completed evidence.

    Không được lấy pre-attempt `q=apple` làm owned baseline, hoặc tự xem marker control là đúng declared URL. Agent đã thực hiện missing baseline ở `seq=2861–2862`; response **921 bytes, complete, non-truncated**, cap 1024. Bước này là bổ sung request bắt buộc đang thiếu, không phải recapture một owned complete control đã tồn tại trong XSS attempt.

16. **Contract misuse / guard đúng — Đổi proof parent set khi source proof không đổi.**

    Sau baseline mới, `seq=2868` nộp cùng source proof với parent set thay đổi; `seq=2869` reject `IMMUTABLE_PARENT_CONFLICT`. Đây là protection đúng, không phải lỗi storage.

    Agent sau đó sửa source proof/claims (`seq=2875`), đăng ký snapshot mới (`2882–2883`) với cả năm observations và nộp result thành công (`2889–2890`). Hai XSS snapshots cũ/mới đều còn, hashes đúng. Repair cuối tuân thủ contract; hai lần rejection ban đầu và extra file write vẫn là overhead có thể tránh bằng kiểm tra ledger/declarations trước nộp.

17. **P2 — XSS proof diễn giải quá mức khả năng encoding/neutralization.**

    Raw bodies xác nhận quote-error fragment được entity-encode trong `<title>`/`<h2>`. Script payload chỉ làm SQLite echo token `/`, image payload echo `src`; toàn bộ payload không được reflect. Vì vậy câu “both vectors land fully encoded/neutralized” mạnh hơn evidence: không có bằng chứng full vectors đã đi tới sink rồi được encoder xử lý.

    Bounded `not-confirmed` cho tested API error-template sink phù hợp với captures; không có script execution evidence. Nó không loại trừ DOM/stored XSS hoặc chứng minh mọi ký tự/context đã được kiểm tra. Result cuối có limitation này; giữ nguyên bounded interpretation thay vì chuyển thành confirmed hoặc toàn-target negative.

18. **Unverified — Khẳng định không có browser execution capability chưa có readiness evidence đủ mạnh.**

    Không có browser execution tool call trong history; manifest không lưu exact model-visible tool schema của từng request. `permissions_status` mô tả worker có Browser MCP resource allowance, nhưng điều đó không chứng minh browser adapter active/ready; thiếu browser call cũng không chứng minh unavailable.

    Có thể kết luận DOM sink chưa được evaluate. Chưa đủ dữ liệu để xác nhận tuyệt đối câu “no browser-execution capability available”, hoặc quy nó là runtime capability bug. Không mở XSS allowlist/file_edit hoặc khởi chạy browser chỉ để làm audit này.

19. **P2 — Compaction giữ goals nhưng vẫn đóng gói hypothesis thành fact.**

    `last_summary` lần này nêu whole-target, SQLi deferred và XSS in_progress. Hydration giữ objective mode/requested goals; Continue planner thực sự chọn XSS. Không tái hiện mất XSS goal hoặc thu hẹp canonical workflow.

    Summary vẫn lặp “proving … quoted LIKE pattern”, “mutation_performed false”, trong khi canonical SQLi mutation unknown; còn đặt “finish main.js … to complete inventory” dù skill không bắt buộc full large-resource ingestion để handoff. Runtime goal/effect state không bị prose này ghi đè. Chất lượng tóm tắt cần cải thiện grounding; không có căn cứ viết semantic fact-checker hoặc compaction architecture mới.

20. **Historical quality issue, eligibility guard đúng — Hypothesis sai độ chắc chắn vẫn được lưu intelligence audit.**

    Run tạo một project-intelligence record: “SQLI-1 … proving value concatenated into quoted LIKE pattern”, source `derived-untrusted-summary`, role `summary`, confidence 0.4, applicability **session**. Nội dung vẫn quá chắc chắn so với body thực.

    Kiểm tra trực tiếp `guidance_eligibility(record, same_origin)` trả **`session-bound state`**, không phải eligible. Các tests liên quan cũng pass. Vì vậy vấn đề câu chữ còn ở historical audit record; lỗ hổng nâng summary thành automatic guidance không tái hiện ở run này. Không có bằng chứng record đã ảnh hưởng một phiên sau; không xóa/rewrite record lịch sử.

21. **Limitation — Context lớn hơn soft threshold, chưa có hard-limit failure.**

    Diagnostics của request projection ghi nhận: Enumeration ~33.227–44.258 estimated tokens; Input Analysis ~41.400–48.075; SQLi ~58.270–66.722; XSS sau Continue ~35.790–44.673. Soft threshold 32.000; hard input limit ghi trong diagnostics 602.931. Nhiều lần reason `below_hard_input_limit`, phần có thể giảm đã rất nhỏ.

    Compaction tại Continue ghi raw history estimate 97.751 → 12.215; trigger projection ~72.951. Đây là các representation/ước lượng khác nhau, không phải provider usage hoặc bằng chứng provider nhận đúng 97,8k tokens. Không có timeout/context-overflow event đủ để quy assessment failure cho hard context limit. Skills, authoritative workflow và preserved result metadata góp fixed floor; chưa có exact historical wire-schema breakdown để kết luận phần nào dư thừa an toàn.

22. **Limitation — 875 debug records bị drop; forensic trail không hoàn chỉnh.**

    Có bảy `debug_records_dropped`: 145, 212, 109, 129, 58, 3, 219; tổng 875, khớp seq gaps. Toàn bộ 108 tool-call IDs được lưu có matching tool-result; observation/proof hashes khớp. Sáu tool errors đều có một sanitized diagnostic tương ứng trong `kagent.log`.

    Đây là bounded asynchronous debug logging loss. Không được đổi tên thành “mất 875 HTTP observations”, cũng không chứng minh mọi event không lưu là assistant delta. Thiếu exact schema/usage/certain intermediate records giới hạn forensic completeness. Không có reproducer cho logging queue bug từ dữ liệu này; không nên đổi queue hoặc persistence chỉ vì số drop.

23. **P2 — Một claim Recon có trước bằng chứng của chính phiên.**

    Recon artifact được ghi `seq=94–95` và phase complete tại `101–102`, nhưng đã nói application-configuration reachable. Native request đầu tiên tới endpoint đó chỉ ở `seq=717–720`, trong Enumeration. Observation về sau xác nhận 200, không hợp thức hóa provenance tại thời điểm artifact Recon được viết.

    Cần viết “endpoint clue/chưa verify” cho đến khi có response. Tương tự, không thấy WAF indicators chỉ hỗ trợ “không quan sát thấy dấu hiệu”, không chứng minh không tồn tại WAF/intermediary. Các lỗi certainty/timestamp này không làm mất các fingerprint observations hợp lệ còn lại.

24. **Contract explanation sai — GET query vẫn có thể có request template.**

    Candidate artifact nói `request_template` không áp dụng vì GET không có body. Contract hỗ trợ query skeleton/template và marker; field này không chỉ dành cho body. Tuy nhiên cả hai candidates thực tế có content_type/template/baseline ref null, source_ref là observation có thật, đúng request path. Query-only candidates không bắt buộc phải có replay capture/template để gửi explicit native requests.

    Vì vậy không tái hiện lỗi template bị `[REDACTED]` hoặc baseline ref không tồn tại ở `lan-03`. Đồng thời run này không exercise constructor/persistence round-trip của GET request template, nên không thể dùng riêng nó để tuyên bố toàn bộ redaction regression đã được runtime chứng minh.

**Phân loại để tránh sửa nhầm guard**

| Nhóm | Kết luận |
| --- | --- |
| Confirmed implementation bug mới | Chưa có reproducer đủ để khẳng định từ sáu tool errors của run. Không đồng nghĩa toàn codebase không còn bug. |
| Agent contract misuse / reasoning / handoff | Có: references/template grouping; schema/SQL certainty; repeated extraction; required baseline; immutable-parent submission; thiếu explicit effects/result; reason sai input. |
| Correct security/evidence guards | Unowned reader refusal; exact source binding; required-step completeness; immutable proof parents; conservative effects; unresolved goal blocking; scope/caps/budgets; summary intelligence ineligibility. |
| Unverified / môi trường / thiếu snapshot | Browser readiness chính xác; target-side cause của transport prose; exact provider usage/wire schema; model behavior ngoài records đã lưu. |

HTTP 500 của syntax probes/`/api`/`/profile`, cap truncation, bounded negative và `insufficient-evidence` không tự là KAgent execution errors. Không có native `/ftp` transport exception trong run: `/ftp` trả 200 và truncated tại cap 4096. Không suy ra sự cố `/ftp` lịch sử đã được chữa. Awk thực sự chạy ra output trong worker; không có `awk: not found` trong các calls lần này.

**Ưu tiên xử lý tiếp theo**

1. Sửa handoff/Agent behavior trước: grounded schema/field inventory, reason đúng input, effects declaration và explicit result cùng evidence trước hard stop. Giữ unresolved khi oracle chưa hoàn tất.
2. Giảm phần extraction lặp: reuse retained/artifact data, đọc đúng exit/stdout/stderr, phân biệt raw initializer JS với JSON spec, giữ coverage partial trung thực.
3. Cải thiện SQL reasoning: exact query shape vẫn hypothesis, pair decision checkpoint, comment semantics, không cố thêm techniques để reset allowance.
4. Trước XSS result, đối chiếu required request ledger và immutable parent set; giới hạn kết luận ở sink thực sự được thử. Chỉ ghi browser-unavailable khi capability/readiness được xác minh.
5. Chỉ sửa production behavior mới sau reproducer offline chứng minh contract/invariant bị vi phạm; không nới guards, tăng budgets hoặc tạo completeness/semantic gate để chữa lỗi model.

**Verification của audit**

Đã chạy một responsibility group offline: **109 passed, 0 failed**, gồm `test_input_http_source`, `test_http_observation_reader`, `test_lan02_intelligence`, `test_lan02_evidence_controls`, `test_requested_goal_lifecycle`, `test_http_readback_lifecycle`, `test_accounting_lifecycle_regressions`. Dùng `venv-linux`, `PYTHONDONTWRITEBYTECODE=1` và pytest cache ở `/tmp`. Không gọi live target/external model. Tests pass xác minh guards/contract hiện tại, không chứng minh model tuân thủ guidance trong phiên này.

Đã hydrate WorkflowState trong memory, kiểm tra requested goals/results/attempts, source associations của 10 owned validation HTTP observations, body hashes, proof hashes, intelligence eligibility và SQLite comment behavior bằng database `:memory:`. Không ghi lại session hoặc stores. Không chạy full suite, live/browser/provider/Burp acceptance vì audit không thay đổi runtime và phạm vi yêu cầu offline.

Cuối audit kiểm tra lại hash toàn bộ run files và manifest, đối chiếu Git status/diff. Trong 56 paths được hash lúc bắt đầu, 54 giữ nguyên; `session.jsonl` được runtime đang mở append thêm ba periodic `context_snapshot` events (seq 3637–3639), và context Markdown được ghi periodic snapshot lại. SHA256 của prefix history ban đầu 1.303.626 bytes vẫn khớp; không có tool calls/turn mới trong phần append này. Session JSON, observations, artifacts, proof snapshots, intelligence, manifest và 243 runtime source hashes vẫn nguyên. Không dừng process đang mở hay ghi lại lịch sử để làm hash khớp.

Git status cuối audit còn xuất hiện 22 skill files bị xóa đồng thời bởi công việc khác; không thuộc thay đổi của audit và được để nguyên. Thay đổi duy nhất do audit tạo là báo cáo này. Không stage, commit, push hoặc sửa historical evidence.

**Nguồn kiểm chứng chính**

- [History JSONL](/home/khainguyen/kagent/experiments/scenario3/runs/lan-03/logs/session.jsonl): các `seq` trong báo cáo là event sequence, không phải số dòng sau logging drops.
- [Session và canonical WorkflowState](/home/khainguyen/kagent/experiments/scenario3/runs/lan-03/profile-home/.kagent/sessions/828464b7-0361-43bd-84e9-2cb60d1094ee.json).
- [Observation store](/home/khainguyen/kagent/experiments/scenario3/runs/lan-03/project/.kagent/observations/828464b7-0361-43bd-84e9-2cb60d1094ee.json).
- [Recon](/home/khainguyen/kagent/experiments/scenario3/runs/lan-03/project/artifacts/recon/127-0-0-1-8081/summary.md), [inventory](/home/khainguyen/kagent/experiments/scenario3/runs/lan-03/project/artifacts/web-enumeration/127-0-0-1-8081/inventory.md), [candidates](/home/khainguyen/kagent/experiments/scenario3/runs/lan-03/project/artifacts/web-input-analysis/127-0-0-1-8081/candidates.md).
- [SQLi proof source](/home/khainguyen/kagent/experiments/scenario3/runs/lan-03/project/artifacts/sql-injection/127-0-0-1-8081/results.md), [XSS proof source](/home/khainguyen/kagent/experiments/scenario3/runs/lan-03/project/artifacts/cross-site-scripting/127-0-0-1-8081/proof-cand_b0a524d313d4aecbe5c1.md), [retained OpenAPI initializer](/home/khainguyen/kagent/experiments/scenario3/runs/lan-03/project/artifacts/worker/swagger-init.js).
- [Compaction context](/home/khainguyen/kagent/experiments/scenario3/runs/lan-03/profile-home/.kagent/context/828464b7-0361-43bd-84e9-2cb60d1094ee.md), [intelligence audit record](/home/khainguyen/kagent/experiments/scenario3/runs/lan-03/project/.kagent/intelligence/scenarios.jsonl), [manifest](/home/khainguyen/kagent/experiments/scenario3/profiles/lan-03/profile.json).
- Contracts: [source binding](/home/khainguyen/kagent/src/tools/workflow/workflow_tool.py:982), [HTTP reader](/home/khainguyen/kagent/src/tools/common/tool_result.py:126), [effects](/home/khainguyen/kagent/src/workflow/assessment.py:321), [runtime closure](/home/khainguyen/kagent/src/agent/agent.py:5360), [broker truncation](/home/khainguyen/kagent/src/permission/worker/broker.py:120), [intelligence eligibility](/home/khainguyen/kagent/src/intelligence/store.py:298).
