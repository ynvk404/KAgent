# Official Run 02 — Root cause audit: permission readback và workflow closure

## 1. Tóm tắt kết luận

**Audit only.** Báo cáo này kiểm tra đúng 18 cases thiếu canonical `ValidationResult`, gồm **9 `all_tools_refused` và 9 `workflow_stalled`**. Không chạy benchmark, model, HTTP target hoặc test suite; không sửa source, tests, cấu hình, intelligence hay artifacts cũ. Chỉ tạo tài liệu này. Không đánh giá lại semantic evidence của `BenchmarkTest00441`/`BenchmarkTest02597`, không tối ưu payload hoặc dùng ground truth để quyết định kết luận.

Các kết luận đã xác nhận:

1. **Lỗi capability policy của benchmark harness:** `HeadlessPermissions.ask()` không có nhánh chấp nhận đọc HTTP observation hiện có, trong khi production reader luôn yêu cầu approval riêng, mức `high-impact`, cho từng range. Chín calls bị từ chối dù observation thuộc chính session/candidate/attempt hiện tại. HTTP grant không bao gồm quyền này. Không có bằng chứng grant propagation bị mất hoặc reader bị active skill chặn.
2. **`all_tools_refused` là nhãn của batch cuối, không phải mọi tool trong session đều bị từ chối.** Tám cases dừng trực tiếp sau batch chỉ gồm reader bị deny. Case thứ chín, `02282`, dừng sau `ask_user` ném `UserControlledRefusal` vì headless không có câu trả lời. `01389` có reader deny nhưng batch còn `workflow.list` thành công nên tiếp tục vào nhánh stall.
3. **Lỗi closure chung của production runtime:** các đường dừng refusal/stall không bảo đảm ghi disposition cho attempt đang active. Nhánh refusal trả về ngay; nhánh stall chuyển sang synthesis không có tools. Không nhánh nào gọi `record_result` trong 18 cases. Kết quả: candidate `validating`, attempt `active`, goal `in_progress`, reason `no validation result` được lưu và freeze nguyên trạng.
4. **Anti-stall đang phát hiện thiếu tiến triển có thật theo contract hiện tại.** Đối chiếu hash response trong journal và batch cuối giải thích được cả chín stall, kể cả bốn cases báo cáo trước chưa xác định được blocker cụ thể. Không có bằng chứng cần tăng ngưỡng, tăng `max_steps` hoặc tắt anti-stall. Thiếu cơ hội/đường closure sau khi ngừng probing là vấn đề riêng.
5. **Các gate evidence đang từ chối đúng:** `00338` nộp hai observation ID không tồn tại; `01221` có parent trong proof nhưng không nộp trong parent list; `01729`/`02654` dùng `obs_` với reader đòi `result_ref`; `01418` đổi value trong fixture yêu cầu đổi name. Không được sửa các gate để chấp nhận những submission này.
6. **Lỗi kiểm tra completion của harness:** `execution_status()` dùng stop label để trả `completed`, không kiểm tra attempt closure. `freeze()` chỉ xuất state, không finalization. Evaluator vẫn giữ 18 cases unresolved; nó không tự tạo TP/TN. Cần bổ sung invariant/diagnostic trước export, giữ phân biệt process completion và assessment completion.

**Có thể triển khai ngay:** quyền readback giới hạn từng case qua approval hiện có; đường closure có kiểm tra ownership và outcome unresolved; kiểm tra closure trước export. **Chưa đủ chứng cứ để sửa:** thuật toán novelty cho timing, retention/compaction mất ID, semantics proof hoặc fixture mapping. Không mặc định biến response giống nhau thành negative.

### Nguồn và khả năng tái kiểm tra

- Đặt `R = .kagent/benchmarks/scenario1/runs/3199be14f8304512b9f2f4412dd1223e`.
- Raw export mỗi case: `R/results/<Case ID>.json` (`CaseExecution`). Đọc `stop_reason`, `runtime_metadata.permission_decisions`, `result.workflow`, metrics.
- Session: `R/workspaces/<execution_id>/.kagent/sessions/<session_id>.json`. Hai ID lấy từ raw export; các chỉ số `mN` dưới đây là **index 0-based trong `messages`**, không phải số vòng Agent.
- Journal observations: cùng workspace, `.kagent/observations/<session_id>.json`; proof source nếu có: `artifacts/sql-injection/127.0.0.1_18080/results.md` trong workspace.
- Tên directory run không trùng `manifest.run_id`: manifest và raw exports dùng `ec1aa52923b94d1db09e2adf5c959799`. Đây không phải evidence identity mismatch.
- HEAD hiện tại và `manifest.reproducibility.kagent_commit` cùng là `e66c90c4c6718798ddd5d9ed0a6c8ce6bb1d8682`. SHA-256 của 12 source chính đã đọc khớp snapshot: Agent, tool_result, registry, execution policy, workflow tool, workflow evidence/assessment/evidence_recovery, runtime, canonical, runner, reporting loader. Hai SKILL.md SQLi/XSS cũng khớp hash manifest. Các dòng source trong báo cáo do đó áp dụng cho code của Run 02, không chỉ một bản code mới hơn.
- Báo cáo đầu vào đọc trong audit có SHA-256 `44e685360d0f12b09604f5f2ce40adb0452ad163063c9378e45106fb63d3bf2d`.
- Không có `direct_progress` telemetry trong `R/events.jsonl`. Worker bỏ `KAgent_TRACE_AGENT` tại `benchmarks/scenario1/core/worker.py:26`. Các bộ đếm ở mục 4 là **tái dựng từ artifacts và thuật toán đã đọc**, không trình bày như telemetry được ghi trong run.

## 2. Bảng 18 cases kèm stop reason đã xác minh

Tất cả 18 raw exports có `status=completed`, `error=null`, đúng một attempt `active`, candidate `validating`, `validation_results=[]`, `result_id=null`, `latest_position=null`, `accepted_at_freeze=false`. Không case nào gọi `workflow.record_result`; không có `ev_` đăng ký thành công hoặc selected sources. Proof Markdown được viết ở hai cases chưa phải canonical result.

`HTTP` dưới đây là requests đã admitted theo raw metrics. Tổng 95; 17 cases có HTTP, riêng `01418` bằng 0. `RHO` = `read_http_observation`, `RTR` = `read_tool_result`, `WF` = `workflow`. Các cell cuối giải thích vì sao không có result, không dùng stop label thay cho nguyên nhân.

| Case ID | Class | Raw stop reason | HTTP | Tool calls cuối cùng / transcript | Denial hoặc blocker đã xác minh | Candidate / attempt cuối | Vì sao thiếu ValidationResult |
|---|---|---|---:|---|---|---|---|
| `BenchmarkTest00200` | SQLi | `workflow_stalled` | 6 | m19/21/23: HTTP FALSE, TRUE repeat, FALSE repeat | 6 response cùng status/body hash, 205 bytes; không tool error | `validating` / `active` | 4 batch HTTP cuối không novelty; chuyển synthesis trước khi Agent submit result |
| `BenchmarkTest00338` | SQLi | `workflow_stalled` | 8 | m25: 2 RTR; m28: RTR + HTTP baseline; m31: 2 HTTP | HTTP m18 lỗi giữ method/route; `PRIMARY_REFERENCE_UNAVAILABLE` m22; RTR m26/27/29 unavailable | `validating` / `active` | Proof nộp 2 ID không có thật; repair bằng reader sai loại rồi recapture; không đăng ký lại thành công, không submit result |
| `BenchmarkTest01221` | SQLi | `workflow_stalled` | 14 | m36: HTTP repeat; m38: file_edit; m40: WF.record_evidence | `PROOF_PARENT_MISMATCH` m33 và m41; m35 `invalid_args`: không captured baseline | `validating` / `active` | Proof vẫn có parent ngoài submitted list; 2 rejections chưa đạt repair limit, anti-stall dừng mà không unresolved closure |
| `BenchmarkTest01302` | SQLi | `all_tools_refused` | 2 | m12: HTTP quote; m14: RHO offset 0/max 2000 | Reader `high-impact`, `allowed=false`, m15 `permission_denied` | `validating` / `active` | Batch chỉ có denied reader; return ngay, chưa có result |
| `BenchmarkTest01389` | SQLi | `workflow_stalled` | 12 | m22: 4 HTTP; m27: RHO offset 0/max 60 + WF.list | Reader deny m28; WF.list m29 thành công; 12 body cùng hash, 23 bytes | `validating` / `active` | Mixed batch không all-refused; là batch no-progress thứ 4, synthesis không có closure tool |
| `BenchmarkTest01394` | SQLi | `all_tools_refused` | 2 | m9: HTTP quote; m11: RHO offset 0/max 1600 | Reader `high-impact` deny m12 | `validating` / `active` | Return all-refused trước result; baseline có write acknowledgement, không được auto-đóng với mutation=false |
| `BenchmarkTest01418` | XSS | `workflow_stalled` | 0 | m13: HTTP với input_path; m15: permissions_status; m17: coverage.untested | m8/12/14: designated-component guard; m10: missing captured baseline | `validating` / `active` | Đổi value thay vì name theo fixture; chỉ kiểm tra state/coverage sau lỗi lặp, không submit insufficient-evidence |
| `BenchmarkTest01631` | SQLi | `all_tools_refused` | 2 | m9: HTTP baseline + quote; m12: RHO offset 0/max 2000 | Reader `high-impact` deny m13 | `validating` / `active` | Batch reader đơn bị deny; không result; baseline có write acknowledgement |
| `BenchmarkTest01729` | SQLi | `workflow_stalled` | 12 | m27/29/31: HTTP quote rồi boolean TRUE/FALSE | RTR m24 unavailable khi dùng `obs_`; 12 body cùng hash, 246 bytes | `validating` / `active` | Agent recapture để sửa readback, 4 batch sau diagnostic không novelty; không proof/result |
| `BenchmarkTest01818` | SQLi | `workflow_stalled` | 10 | m19: 2 HTTP canary/context; m22: HTTP SLEEP(0)/SLEEP(5) | 10 response cùng status/hash, 264 bytes; không tool error/permission denial | `validating` / `active` | Boolean/context/time batches không body novelty; final time pair trả về nhưng chưa ghi result |
| `BenchmarkTest02129` | XSS | `all_tools_refused` | 2 | m10: HTTP script marker; m12: RHO offset 0/max 200 | Reader `high-impact` deny m13 | `validating` / `active` | Agent muốn full-response confirmation rồi bị deny; đã có reflection capture nhưng chưa proof/result |
| `BenchmarkTest02176` | SQLi | `workflow_stalled` | 6 | m19/21/23: HTTP FALSE, TRUE repeat, FALSE repeat | 6 response cùng status/hash, 218 bytes; không tool error | `validating` / `active` | Như 00200: 4 batch HTTP cuối không novelty, synthesis trước closure |
| `BenchmarkTest02178` | SQLi | `all_tools_refused` | 2 | m12: HTTP baseline + quote; m15: RHO offset 0/max 2000 | Reader `high-impact` deny m16 | `validating` / `active` | Return ngay sau denied reader; chưa record_result |
| `BenchmarkTest02282` | SQLi | `all_tools_refused` | 4 | m13: HTTP Boolean pair; m16: ask_user lựa chọn bước tiếp | m17: `headless: operator input unavailable; record unresolved`, phân loại `permission_denied` | `validating` / `active` | MissingInput ném refusal thật ở batch đơn; Agent không được quay lại ghi disposition; không có reader denial |
| `BenchmarkTest02490` | XSS | `all_tools_refused` | 1 | m9: HTTP context marker; m11: RHO offset 0/max 2000 | Reader `high-impact` deny m12 | `validating` / `active` | Đã thấy body 22 bytes không marker, muốn đọc lại; return ngay trước result |
| `BenchmarkTest02543` | SQLi | `all_tools_refused` | 2 | m11: HTTP baseline + quote; m14: RHO offset 0/max 2000 | Reader `high-impact` deny m15 | `validating` / `active` | Denied reader đơn kết thúc turn trước result |
| `BenchmarkTest02546` | SQLi | `workflow_stalled` | 8 | m18: HTTP stacked sleep; m20: 2 HTTP inline sleep | 8 response cùng status/hash, 184 bytes; không tool error | `validating` / `active` | HTTP response không novelty; chưa proof/result; write acknowledgement cần giữ mutation/cleanup trung thực |
| `BenchmarkTest02654` | SQLi | `all_tools_refused` | 2 | m13: RTR với obs_; m15: RHO offset 400/max 1400 | RTR m14 unavailable; RHO m16 `high-impact` deny | `validating` / `active` | Đã chuyển reader đúng nhưng bị approval deny; chưa result; baseline có write acknowledgement |

### Đối chiếu Markdown và raw

**Bản `BENCHMARK_OFFICIAL_RUN_02_AUDIT.md` hiện có không còn ghi stop reason của 18 cases là `NOT OBSERVABLE`.** Executive summary dòng 17, giải thích nguồn dòng 44, bảng case và bảng closure dòng 108–115 đã ghi raw stop reasons đúng 9/9. `NOT OBSERVABLE` còn xuất hiện ở phạm vi causality của intelligence (dòng 138) hoặc nhận định thiếu canonical evidence (dòng 169), không phải giá trị stop reason. Không tìm thấy một bản Markdown cũ chứng minh trạng thái mà yêu cầu mô tả; không thể khẳng định lịch sử sửa của báo cáo chỉ từ file hiện tại.

Sự khác biệt **có thật** là projection public: `runner.py:225–237` không đưa `executed.stop_reason` vào event `runtime-finished`; `reporting/loader.py:321–332` tạo case row không có trường đó. Raw `CaseExecution` có stop reason tại `runtime.py:444`. Do đó “không có trong event/CSV” không đồng nghĩa “không observable trong run”. Không sửa báo cáo đầu vào hoặc projection cũ trong phiên này.

Chỉ tính subset này: 15 SQLi, 3 XSS. Tổng run có 10 `workflow_stalled`, nhưng case thứ mười đã có result và nằm ngoài 18 missing-result cases; không đưa nó vào bảng/thiết kế để mở rộng phạm vi.

## 3. Root cause của all_tools_refused

### 3.1. Đường đi read_http_observation

| Bước | File / function / dòng | Hành vi thực tế |
|---|---|---|
| Đăng ký controller-owned reader | `src/agent/agent.py:1164–1167`, Agent initialization | Policy-enabled Agent tạo scoped `ReadHTTPObservation(self)`; không phải tool bị thiếu trong harness |
| Skill admission | `Agent.is_tool_allowed():1686–1690` | Reader của controller hiện tại kế thừa capability `http` trong active skill. SQLi/XSS cho phép HTTP, dù không liệt kê tên derivative reader |
| Dispatch | `Agent.execute_tool_call():5687–5723` | Parse và skill check, rồi `self.tools.execute()` |
| Args + policy preflight | `Registry.execute():185–217`; `ExecutionPolicy.validate():310–312` | Validate bounded obs_ args; `policy.prepare` gọi reader.validate_rights(receipt=False) **trước approval** |
| Ownership/integrity | `ReadHTTPObservation.validate_rights():162–210` | Cùng policy, active/completed attempt hợp lệ, candidate binding, session, objective, epoch/revision, origin/scope, không revoked, HTTP skill, sealed sources, managed secret guard |
| Registry approval | `Registry._execute():244–332`; reader hints `tool_result.py:143–148` | Requires permission; `high-impact`, no session cache, key `observation:<obs_id>:<start>:<max>` |
| Headless decision | `HeadlessPermissions.ask():253–259` | Chỉ routine HTTP exact `private-declared://<origin>` hoặc routine file write/edit đúng artifacts root; reader không khớp → DENY |
| Denial output | `Registry._execute():327–332`; `Agent` error mapping `:424–425`, result `:5785–5792` | Ném `UserControlledRefusal('permission denied by user ...')`; output `status=error`, `error_kind=permission_denied`, terminal refusal=true |
| Nếu được approve | Registry `:335–345`; `_ExecutionPrompter.ask():57–66`; reader.run `:212–257` | Receipt hiện hành, check rights trước/sau await; nested approval cùng exact key được coalesce ALLOW_ONCE; trả range bounded của body đã giữ, không gửi HTTP |
| Turn stop | `Agent` loop `:4480–4481`; batch `:5624–5629` | Khi **mọi result của batch cuối** là terminal refusal, trả `all_tools_refused` ngay |

Chín observation bị đọc đều thực sự có trong journal, có `session_id` bằng export session, `candidate_id` bằng export candidate, `attempt_id` thuộc active attempt, `source_details.analysis_session` đúng session. Các raw permission decisions đều có reader `risk_tier=high-impact`, `allowed=false`; trước đó có HTTP `routine`, `allowed=true`. Registry đến được permission ask cũng có nghĩa preflight chưa từ chối rights của invocation ấy.

### 3.2. Loại lỗi và quan hệ nhân quả

**Root cause RC-P1: mismatch giữa capability profile headless và permission contract reader — chắc chắn cao, benchmark-specific.** Allow predicate tại `runtime.py:255–257` loại reader ở cả risk tier lẫn tool name. Đổi reader xuống routine **vẫn không đủ** vì predicate chỉ nhận HTTP/file write/edit. Không cần thay classification production, không cần kế thừa approval HTTP sang reader.

Quyền gửi request và quyền đọc derivative source được tách có chủ đích: HTTPLab grant là network authority; range read có thể làm dữ liệu đi vào context model và yêu cầu local read/export review riêng. `ReadToolResult.permission_hints():40–44` nói rõ original approval không trở thành cache cho derivative access. Metadata trong permission status cũng nói HTTP grant không cấp local read/export. Vì vậy đây là thiếu khai báo permission của harness, **không chứng minh classification high-impact là sai**.

Grant activation `build_agent():328–330`, AuthorizedExecutionTool branch `Registry:233–242`, private-host gate `private_host.py:92–137` giải thích HTTP được gửi: harness chủ động activate budget cho exact origin, rồi trả ALLOW_ONCE cho private-host routine request. Không có bước nào chuyển grant đó sang `observation:` key. Chưa thấy evidence về grant propagation lỗi.

Denial gây stop trực tiếp cho `01302`, `01394`, `01631`, `02129`, `02178`, `02490`, `02543`, `02654`: batch cuối chỉ một RHO. **Không thể nói denial luôn sinh all_tools_refused:** `01389` có WF.list success cùng batch; batch không all-refused rồi tăng no-progress từ 3 lên 4. Cũng không thể nói reader là nguyên nhân của cả chín all-refused: `02282` không gọi RHO.

**RC-P2: unavailable headless input được biểu diễn như explicit user refusal — chắc chắn cao về mechanics, harness-specific.** `MissingInput.ask():262–265` ném `UserControlledRefusal` mặc định `explicit_denial=True`. Agent `:5789–5790` đánh dấu terminal refusal. Đây là không có operator trả lời, không phải operator thật đã từ chối một approval. Caller vẫn phải dừng việc cần input; không được tự chọn option hoặc coi timeout là consent. Việc đổi exception sang non-explicit refusal có thể giúp diagnostic chính xác nhưng **không giải quyết closure riêng lẻ**; nếu không có đường closure, chỉ đổi stop thành stall.

### 3.3. Tool khác

`read_tool_result` cũng yêu cầu `high-impact` ALLOW_ONCE (`tool_result.py:37–44,66–95`), nên **một RTR hợp lệ sẽ bị cùng headless predicate deny**. Tuy nhiên các calls RTR quan sát ở `00338`, `01729`, `02654` thất bại **trước approval**, vì dùng `obs_` hoặc `sf_` thay vì producer-issued retained result capability. Raw decisions của 18 cases không có RTR denial. Phân biệt lỗi tiềm tàng cùng policy với nguyên nhân đã quan sát; không blanket-allow RTR để chữa nhầm reference.

Skill/payload readers và permission status chạy được; proof write/edit routine được allow trong `00338`/`01221`. Không có evidence tất cả công cụ local đều bị cùng denial.

### 3.4. Vì sao không ghi blocked/insufficient-evidence?

`all_refused` branch return trước evidence-recovery bookkeeping và direct progress tracking. Tool error được lưu, nhưng không gọi WF.record_result. Workflow không tự biến tool refusal thành result. Harness chỉ freeze state sau Agent return; không finalization. Đây là **RC-C1**, lỗi lifecycle chung trình bày ở mục 4, không phải lý do để bỏ registry gate.

## 4. Root cause của workflow_stalled

### 4.1. Contract và tracking thực tế

Direct trong báo cáo là nhánh `requested_goal_run and not whole_target`; raw objective cụ thể là `candidate_validation`, có requested goal SQLi/XSS. `Agent:4003–4009` quyết định hai nhánh này. Tracker được tạo mỗi turn tại `:4028`; no-progress threshold **4**, exploration allowance **8** (`:156–157`).

`WholeTargetStallTracker.record_validation_batch():804–897`:

- **Structured progress:** thay đổi `_requested_goal_progress_signature()` → reset no-progress, exploration count và seen fingerprints. Signature `:2709–2730` chứa goal/candidate statuses, latest result, evidence refs, cleanup/coverage/finding, attempt IDs/statuses và evidence digest. Start attempt và đăng ký evidence thành công có thể thay đổi signature; HTTP observation ID mới đơn thuần không đổi signature.
- **Novel HTTP exploration:** fingerprint từ `(status, response_hash, complete, truncated)` của captures. `response_hash` là SHA-256 body gốc (`observations.py:155–158`), không phải Date header. Tối đa hai samples cho một material: lần đầu và một verification repeat (`Agent:870–887`). Payload/URL đổi nhưng cùng body không tạo novelty mới. Batch có nhiều calls vẫn là một iteration.
- **Reader progress:** range mới, nonempty, đúng producer/source bounds; overlap/EOF không progress. RHO dedup theo `item.response_hash`, không theo obs ID mới. Page reader/RTR theo content hash. Pagination reset no-progress nhưng không cấp lại HTTP exploration allowance (`:861–897`).
- **Diagnostic exploration:** các error kind invalid_args/workflow_state/reference_unavailable/tool_exception có fingerprint `(kind, parsed[, code])`, nằm trong allowance 8; đổi args/error prose không renew. Permission/scope denial không nhận diagnostic novelty (`:816–831`).
- **Không tiến triển:** WF.list, permissions_status, coverage reads không mặc nhiên reset; file_write/file_edit novelty theo tool/path, vẫn bị allowance 8 chặn. Không dùng “LLM còn nói” hay “tool success” làm structured progress.

Tool batch Direct: `Agent:4655–4698` reconcile goal, cập nhật tracker, rồi nếu goal incomplete và counter >=4 thì gọi `_whole_target_synthesis(stop_reason='workflow_stalled')`. Tool-free branch `:4352–4410` so sánh goal signature, tăng/reset cùng counter. Synthesis `:4892–4943` tạo ChatRequest **không tools**, nên không thể submit `record_result`; `accept_response():4867–4869` thay prose bằng completion blocker khi chưa có result.

Whole-target dùng progress facts/normalized activity, có phase allowance, readiness recovery một lần (`:4551–4639`); không mặc định áp thuật toán Direct HTTP hash cho mọi Whole-target activity. Nhưng cùng synthesis và refusal return vẫn có khoảng trống lifecycle tương tự khi có attempt active.

### 4.2. Tái dựng chín stall theo batch và journal

Tái dựng dưới đây dùng transcript để ghép call/result, journal để lấy hash và returned source metadata, plus source thuật toán; không chạy Agent hay tests. `E` là exploration steps đã tiêu thụ, `N` là consecutive_no_progress sau batch. Các mốc cuối đều đạt `N=4`. Không công bố hash của secrets/body hoặc toàn traffic trong báo cáo.

| Case | Tiến triển trước stop | Bốn batch cuối không tiến triển | Đánh giá anti-stall và evidence closure |
|---|---|---|---|
| `00200` | Skill + payload 2 pages + attempt; baseline, quote, Boolean TRUE/FALSE lặp; 6 captures đều 200/205 bytes/cùng hash | m17,19,21,23 HTTP → N=1,2,3,4; E=2 | Đúng theo novelty contract. Có các so sánh usable để Agent đánh giá bounded negative, nhưng chưa proof hoặc completed-attempt declaration. Không runtime-infer TN |
| `00338` | 8 admitted captures 200/156 bytes cùng hash; Agent nói đủ bounded negative; viết proof và bị reject; tìm IDs bằng sai reader rồi recapture | m23 WF.list; m25 RTR×2; m28 RTR+HTTP; m31 HTTP×2 → N=1..4; E=4 | Đúng theo contract; distinct earlier HTTP/manifest diagnostics từng có allowance. Lỗi proof chưa xử lý, canonical evidence chưa hợp lệ; không phải thiếu network |
| `01221` | 14 captures với 6 distinct status/hash tuples; viết proof; register 2 lần bị parent mismatch; sửa một table row | m34 baseline-mutation call lỗi; m36 HTTP repeat; m38 file_edit; m40 rejected registration → N=1..4; E=8 | Allowance đã dùng hết; file_edit path không còn cứu counter. Không thấy một registration hợp lệ bị bỏ qua. Không đổi anti-stall để giúp proof sai được thông qua |
| `01389` | 12 captures 200/23 bytes cùng hash; baseline/quote, Boolean variants, control/delay; đọc 2 payload pages | m14 HTTP×2; m17 HTTP×4; m22 HTTP×4; m27 denied RHO + success WF.list → N=1..4; E=1 | Đúng theo contract. Reader denial là blocker bổ sung ở cuối, không phải nguyên nhân duy nhất của chuỗi lặp; chưa có semantic closure |
| `01418` | Skill/payload/attempt; 4 HTTP proposals bị chuẩn bị/gate reject, **0 admitted**; kiểm tra permission/coverage | m11 HTTP lỗi lặp; m13 HTTP lỗi lặp; m15 permissions_status; m17 coverage → N=1..4; E=2 | Đúng: hai diagnostic kinds đầu có allowance, lặp proposal không progress. Chỉ có thể insufficient-evidence/blocked/deferred có lý do; không negative |
| `01729` | 12 captures 200/246 bytes cùng hash; đọc payload; RTR lỗi cấp 1 diagnostic exploration; Agent thừa nhận hiểu nhầm response trước đó | m25 baseline recapture; m27 quote; m29 TRUE; m31 FALSE → N=1..4; E=2 | Đúng với body novelty. Recapture không sửa sai loại capability. Có thể đánh giá bounded negative từ usable captures nhưng chưa proof/result, không gán TN |
| `01818` | 10 captures 200/264 bytes cùng hash; numeric/quoted pairs, canary, time control/delay; payload reader tiến triển hữu hạn | m13 HTTP×2; m16 HTTP×2; m19 HTTP×2; m22 HTTP×2 → N=1..4; E=1 | Đúng theo thuật toán; last time pair đã trả về. Không đủ để khẳng định false-positive timing: control 17.23ms, delay 20.40ms, không 5s; chưa repeated timing proof |
| `02176` | Baseline, quote, TRUE/FALSE hai repetitions; 6 captures 200/218 bytes cùng hash | m17,19,21,23 HTTP → N=1..4; E=2 | Đúng theo novelty contract; missing submission là lỗi closure, không tool exception |
| `02546` | 8 captures 200/184 bytes cùng hash; quote/canary/TRUE, baseline repeat và sleep variants; chưa registered proof | m13 HTTP×2; m16 baseline; m18 stacked sleep; m20 inline HTTP×2 → N=1..4; E=2 | Đúng theo thuật toán. Timings cuối khoảng 6–40ms, không delay 5s được chứng minh. Có write acknowledgement; không auto-kết luận no mutation/no cleanup |

**Timing limitation chưa nên vá:** tracker không dùng `elapsed_ms` trong novelty material. Một valid time-based proof có thể cần same-body repeated responses. Đây là rủi ro chung cần offline test riêng với delay/control đã khai báo; Run 02 không chứng minh một timing signal có thật bị bỏ qua. Không thêm timing noise/date/payload novelty để kéo dài probing vô hạn. Trong phiên này chỉ đề xuất closure và ghi nhận giới hạn, không sửa tracker.

### 4.3. Các blockers có nguyên nhân riêng

**`00338`: invalid proof/reference handling, không phải integrity gate bug.** `resolve_sources():254–270` reject missing IDs. Submitted parents ở m21 gồm hai IDs không có trong journal (`obs_5984d1c5e1804e759d4cebb731b1f7a6`, `obs_8a1c9f7d2b6e4a0e9c3f5d7a1b2c4e60`); ba ID khác có thật. Proof source cũng chứa hai ID không thật đó. Không đủ chứng cứ để quy lỗi “store làm mất ID”: journal và HTTP envelopes đã có IDs thật; chưa có telemetry prompt mỗi turn để biết model nhìn thấy gì. Error HTTP m18 là thử khác method/route, đúng bị harness guard chặn. RTR m25 dùng obs_, m28 dùng sf_; đều không retained tool result capability.

**`01221`: proof-parent repair chưa đầy đủ.** Sau file_edit, proof source vẫn chứa `obs_dc13d313c8e7439e83bc6d9c6d5f15e6` có thật, nhưng cả submitted parent lists m32/m40 đều thiếu ID này. Gate `check_proof_references():100–121` phát hiện IDs trong heading/table thuộc proof section; sửa một row không sửa toàn proof/parent contract. Các IDs nộp là có thật: đây là thiếu parent, không store mất source. M34 chuyển sang candidate mutation interface dù `baseline_request_ref=null`; đã gửi baseline explicit không tự tạo captured replay reference. `HTTPTool:241,274` reject đúng. Không nhận định semantic SQLI-2 đủ chỉ vì Agent nói “definitive”.

Recovery state freeze:

- `00338`: `rejections=1`, `repair_turns=0`, `paused=true`, `closed=false`.
- `01221`: `rejections=2`, `repair_turns=0`, `paused=true`, `closed=false`.

`Agent:4496–4506` đếm registration rejections nhưng chưa bắt đầu terminal repair clock cho đến khi `record_result` bị reject. Limit là 3 rejections hoặc 6 terminal repair turns (`evidence_recovery.py:9–13`). Hai cases chưa đạt limit nên `_stop_evidence_recovery()` không được gọi trước stall. Đây giải thích được khoảng trống giữa anti-stall và repair closure; không cần tăng/decrease repair threshold để ép kết quả.

**`01418`: name-tainted fixture bị mutate value.** Candidate template là `answer=&SafeText=BenchmarkTest01418`; prompt yêu cầu component `name`. Agent giữ `SafeText` và thay value bằng canary. `_check_designated_request():203–215` chỉ cho name replacement giữ baseline value; m7/m11/m13 sai contract. Candidate-only mutation m9 không có captured baseline. Không có traffic/evidence target. Không cấp quyền cho request mới để vượt qua lỗi này, không đổi mapping/ground truth hoặc chuyển case thành value-tainted.

**`01729`/`02654`: wrong reference family.** `ReadToolResult.validate_args():49–64` và Agent skill admission `:1677–1684` lookup result_ref trước permission; obs_ không phải tr_ capability. Công cụ đúng cho existing observation là RHO, giữ permission riêng. Không thêm alias obs_→tr_ hoặc làm result_ref resolve mọi store.

### 4.4. Có evidence mà Agent không gọi result không?

**Có captured evidence; chưa có đủ hồ sơ terminal canonical trong bất kỳ case nào.** 17 cases có HTTP; `00338` Agent còn chủ động nói đủ bounded negative và viết report, nhưng report chứa sai IDs. `00200`/`01389`/`01729`/`01818`/`02176` có no-signal comparisons; `02546` có những comparison tương tự nhưng mutation/cleanup cần đánh giá. `02129` có script marker trong captured body và Agent nhận ra reflection. Những điều này đủ để nói có dữ liệu cho bước assessment, **không đủ để runtime thay Agent tự ghi confirmed/not-confirmed**.

Hai terminal outcomes cần accepted primary captures, immutable `ev_` proof, assessment fields; negative cần `completed_attempt=true` (`WorkflowTool:1139–1159`), cộng skill semantics riêng. Tất cả 18 thiếu registered proof; cả 18 không propose record_result, nên không phải “record_result đã bị từ chối rồi result biến mất”. Có thể ghi unresolved hợp lệ **mà không cần evidence refs**; không có nghĩa có thể kết luận absence of vulnerability.

### 4.5. Validation attempt lifecycle và closure gap

`start_attempt()` (`assessment.py:169–224`) tạo active attempt với session/objective/candidate binding, epoch, target_revision, result_position; `WorkflowTool._start_validation():877–886` đặt selector và observation owner. HTTP chỉ thêm captures. Tools lỗi/permission denied không tự close owner.

`WorkflowTool._record_result():1019–1212` là đường đóng hợp lệ:

1. Resolve validator duy nhất và current-objective candidate.
2. Kiểm tra attempt ownership/binding/session/epoch/revision/position và optional attempt_id equality (`:1075–1104`).
3. Terminal result cần proof và completed-attempt/assessment; unresolved không phải đáp ứng những điều kiện terminal, nhưng mọi reference được nộp vẫn kiểm tra.
4. Controller seal, set attempt `completed` nếu terminal, **`unresolved` nếu blocked/insufficient-evidence/deferred/...** (`:1170–1198`). Candidate thành `deferred` cho unresolved (`state.py:1917–1952`); goal vẫn outstanding; không eligible finding/coverage passed.

Taxonomy không có outcome literal `unresolved`: đó là **attempt status**. Outcome nên dùng `blocked` cho blocker thật hoặc `insufficient-evidence` khi thiếu assessment/proof, kèm deferred_reason/notes. Không thêm taxonomy mới.

**RC-C1 — stop paths không disposition active attempt, độ chắc chắn cao.** `all_tools_refused` trả trước closure; `workflow_stalled` synthesis không tools; `accept_response` chỉ thay prose, không state transition. Existing `_stop_evidence_recovery():4808–4851` đã làm đúng mẫu: gọi WF.record_result qua registry, không salvage IDs, kiểm tra commit, save, nếu thất bại raise. Nhưng mẫu đó chỉ được gọi khi evidence repair budget exhausted; không áp cho general stall/refusal.

Stop một turn và giữ attempt để Continue có thể hữu ích trong interactive production; vì vậy không blanket-close mọi pause/cancel/permission-pending. Tuy nhiên tại **stop cố định bởi bounded stall/terminal refusal**, trạng thái resumable phải có disposition hoặc interruption reason rõ ràng; headless worker không được xuất “hoàn tất hợp lệ” với active orphan. Giữ attempt active không có lý do bền vững là closure gap mà Run 02 xác nhận.

## 5. Phân biệt production lỗi và benchmark-specific lỗi

| Cơ chế | Phân loại / chắc chắn | Tác động Direct / Whole-target |
|---|---|---|
| RC-P1 headless không cho owned RHO | Harness config/policy thiếu capability; cao | Scenario1 Direct bị chặn; sửa harness không thay production interactive approvals hoặc Whole-target policy |
| RC-P2 MissingInput = explicit denial | Harness adapter diagnostic/contract; cao | Headless Direct không có opportunity ghi disposition; production operator refusal vẫn giữ nguyên |
| RC-C1 refusal/stall không close/disposition | Production lifecycle gap; cao | Direct đã chứng minh; shared refusal/synthesis paths có rủi ro Whole-target. Không tự close candidates khác hoặc tự continue sau denial |
| RC-H1 completed/export không kiểm tra closure | Harness invariant/observability gap; cao | Worker completion bị hiểu là assessment complete; evaluator hiện vẫn phân loại unresolved, không TP/TN sai từ thiếu result |
| Invalid source families/proof parents | Agent submission errors bị production guards chặn đúng; cao | Mọi mode phải giữ guards; có thể cải thiện repair handoff, không nới acceptance |
| Value mutation của 01418 trong name case | Harness contract interaction + Agent misuse; cao | Không phải production HTTP permission deny; chỉ fixture discipline Scenario1. Không đổi name contract |
| Anti-stall same-body loop | Production detector hoạt động theo thiết kế; cao về trigger | Các Direct stalls giải thích được; chưa có chứng cứ runtime false-positive cần đổi threshold |
| Elapsed-time novelty / mất reference trong prompt | Chưa xác nhận root cause Run 02 | Chỉ thêm tests để phân định; không speculative retention/compaction/semantic patch |

Worker path: `worker.main():36–51` chạy execute_case rồi write_new raw export. `execute_case():419–430` drain background tasks, chọn status, gọi `freeze`. `execution_status():348–362` chấp nhận refusal/stall/blocked là completed. `canonical.freeze():16–26` deepcopy state + latest result identity; **không closure side effect**. Runner `:205–237` tin exported status và xuất canonical summary với result_id/outcome null. Evaluator/canonical inspect vẫn trả missing-result unresolved (`canonical.py:82–87`), nên không sửa confusion partitions của run cũ.

## 6. Thiết kế bản sửa tối thiểu

### 6.1. Fix A — owned readback qua permission hiện có (RC-P1)

**File/function:** `benchmarks/scenario1/core/runtime.py`, `HeadlessPermissions.__init__/ask` (`:245–259`) và `build_agent` (`:268–345`) nếu cần bind expected candidate/session. Không sửa `Registry`, reader risk tier hoặc network grant.

**Thiết kế:** khai báo capability headless chỉ đọc existing **native-http** observation của case. Để registry vẫn yêu cầu permission, HeadlessPermissions nhận exact range request và trả **ALLOW_ONCE**, chỉ khi:

- Tool chính xác RHO; bounded cache key đúng `observation:<obs_>:<start>:<max>`; nguồn phải có sẵn, không lookup filesystem arbitrary hoặc tự capture.
- Observation thuộc policy/controller hiện tại, exact benchmark session/case candidate, objective, attempt hiện hành, candidate binding, epoch và target revision hợp lệ; source_kind native-http và exact declared origin. Case identity dùng operational binding đã có; không dùng truth.
- Gate tiền approval và rights revalidation của reader tiếp tục chạy nguyên vẹn; `request.is_current` còn hiệu lực; revocation/internal-secret/integrity guard tiếp tục fail-closed.
- Unknown key, malformed range, foreign session/candidate, imported capture hoặc không đủ trusted controller binding → DENY. Không allow theo prefix key hoặc private address đơn thuần.

Có thể bind expectation từ setup candidate admission (`execute_case:370–378`) vào headless adapter để đối chiếu khi ask; không lưu expectation/grant vào durable preference. Tận dụng `ReadHTTPObservation.validate_rights`, `policy.observations` và scoped reader thay vì viết verifier riêng chấp nhận yếu hơn. Approval nested được `_ExecutionPrompter` coalesce cho đúng invocation; không hỏi/cấp hai grants, không ALLOW_SESSION.

**Giữ nguyên:** yolo=false; routine HTTP exact-origin predicate; không tự approve HTTP mới, redirects, MCP/browser/shell, local path read hoặc generic RTR. Không viết journal authorization lâu dài. Production high-impact classification vẫn tồn tại.

**Regression risk:** overly broad headless grant đọc cross-case/cross-attempt hoặc bỏ stale review; verify bằng hai controllers cùng origin. Reader return không tăng http_admitted/dispatch count hoặc accepted result count; output vẫn bounded và có integrity/source metadata. Sửa này loại reader blocker đã xác nhận, **không bảo đảm cả chín case thành evaluable**.

### 6.2. Fix B — closure ở điểm stop, dùng workflow contract (RC-C1)

**File/function:** `src/agent/agent.py`, branches `:4480–4481`, Direct stall `:4391–4410`, `:4684–4698`; trích helper tối thiểu từ `_stop_evidence_recovery():4808–4851`. WorkflowTool `_record_result` và state status mapping giữ nguyên.

**Hành vi cần có:** khi đã quyết định terminal refusal hoặc bounded stall, ngừng probing rồi disposition **đúng active attempt của objective hiện tại** trước tool-free synthesis/Done. Không auto-kết luận vuln. Ưu tiên gọi `record_result` với `blocked` khi có blocker rõ hoặc `insufficient-evidence` khi không có admissible assessment, lý do chứa stop reason + sanitized blocker codes. Omit unusable observation_ids/evidence_refs; không salvage parents.

**Ràng buộc quan trọng cho implementation:** không copy nguyên helper rồi mặc định `mutation_performed=false` cho mọi case. Raw bodies của `01221`, `01394`, `01631`, `02546`, `02654` có baseline write acknowledgement; contract `state.py:868–905` tính đó là mutation, kể cả chưa chứng minh database persistence. Không dùng benchmark reset làm Agent cleanup, không đoán “succeeded”.

Phương án ít xâm lấn nhưng trung thực:

1. Tách helper submission/check/save từ existing evidence-recovery path; closure args chỉ lấy từ assessment/cleanup declaration đã có và đúng ownership. Runtime không đánh giá payload hoặc tạo TP/TN.
2. Nếu chưa có declaration đủ an toàn, dùng **một lượt closure riêng giới hạn**, chỉ schema WF.record_result cho active candidate, outcome unresolved; không HTTP/ask_user/proof writer/confirm_finding/skill switching. Lượt này chỉ ghi disposition từ observations/transcript hiện có và giữ mutation/cleanup theo contract; không quay lại agent probing loop và không reset counter/budget. Runtime kiểm tra cả tool name/action/candidate/outcome trước dispatch, không chỉ lọc LLM tools. Closure vẫn chịu timeout, configured call budgets, cancellation và registry admission; không mở budget mới khi đã exhausted.
3. Deterministic fallback chỉ khi metadata hiện hành đủ xác định declaration (ví dụ `01418` có 0 admitted traffic và không action khác có mutation). Khi mutation/ownership không đủ rõ, closure bị deny hoặc model không nộp đúng: **không giả result**. Xuất failure/interruption reason rõ, không báo closure thành công. Fix C phải chặn worker “completed hợp lệ” với orphan đó.
4. Execute closure qua `execute_tool_calls` → Registry → WorkflowTool. So `ok=true`, latest result thuộc attempt đang đóng, outcome unresolved, attempt.status=unresolved, candidate không validating; save hoàn tất trước Done/export. Khi selector stale/revoked/cancelled, không direct-mutate state để vượt gate.
5. Idempotent: bỏ qua attempt đã có result/đã close; không overwrite terminal assessment để chữa thiếu cleanup/finding. Giữ original stop_reason là cause; nói rõ assessment incomplete ngay cả khi disposition ghi thành công.

Lượt closure riêng tương tự cách synthesis là separate phase, **không tăng max_steps/probing threshold**, không gửi request target mới. Nếu cần giai đoạn schema phức tạp để metadata mutation đáng tin cậy, triển khai trước deterministic fallback cho cases đủ state và failure guard; không giả rằng chỉ vài dòng đủ safely close mọi trường hợp.

**Giữ nguyên:** Explicit deny tiếp tục terminal cho probing; permission pending/timeouts/cancel không tự trở thành deny; workflow revoked vẫn chặn closure. User Continue/retest và interrupted/resume contracts giữ ownership/epoch; no grant from stored reason. Goal unresolved vẫn outstanding, không coverage passed/finding. Closure chỉ current active owner, không all candidate bulk-close.

**Tác động Whole-target:** shared helper được scope theo objective/attempt; sau refusal không tự chạy candidate khác. Với stall, stop probing trước disposition; không lấy unrelated candidates để tạo tiến triển giả. Existing bounded evidence-recovery continuation cho independent candidates giữ nguyên; không nhân tiện mở rộng policy đó. Cần tests shared paths, nhưng không refactor toàn whole-target planner.

**RC-P2 kèm Fix B:** headless MissingInput có thể dùng subtype riêng `UserControlledRefusal` với `explicit_denial=False` (mẫu `PermissionPolicyBlocked`, `permission.py:27–30`), rồi route `input unavailable` vào blocked closure. Không chỉ đổi exception rồi cho Agent thử hỏi lại. Không sửa explicit refusal production hay tự trả lời options. Có thể giữ exception hiện tại trong patch đầu nếu closure reason phân biệt unavailable input chính xác.

### 6.3. Fix C — closure invariant trước worker export (RC-H1)

**File/function:** `benchmarks/scenario1/core/runtime.py`, sau background drain và trước status/freeze (`:419–430`); `execution_status` (`:348–362`) chỉ đổi khi thêm context thực cần thiết. `canonical.freeze()` vẫn pure projection. Worker/runner/reporting chỉ bổ sung projected diagnostic nếu cần, không đổi taxonomy.

Kiểm tra candidate/attempt của case trước một completed export: result có thể terminal hoặc unresolved hợp lệ, nhưng không active orphan. Nếu closure không commit, dùng execution status lỗi hiện có (`runtime-error`) và fixed sanitized reason/code trong error/runtime metadata; preserve actual stop_reason và workflow snapshot để debug/resume. Không sửa raw result file đã freeze, không add result trong evaluator hoặc parent worker. Process exit thành công vẫn có thể export runtime-error; không đồng nhất exit 0 với canonical success.

Scope invariant theo **case attempt**, không yêu cầu mọi case phải confirmed/not-confirmed. Recorded blocked/insufficient-evidence đúng contract vẫn completed về process, unresolved về assessment. Không đổi expected values hay TP/TN metrics. Old run artifacts remain immutable; new diagnostic trường có thể additive/backward-compatible, loader phải xử lý absent field như unknown chứ không success.

**Không đổi `completed` thành lỗi cho mọi stalled/refused label:** trước hết kiểm tra state. Stall với unresolved disposition không orphan và vẫn là process completion có lý do; stall với existing terminal result/cleanup blocker cần giữ result. Invariant này giải quyết silent orphan, không thay evaluator denominator để trông đẹp hơn.

### 6.4. Những sửa chưa có cơ sở thực hiện

- Không sửa source-reference parser hay proof-parent acceptance: artifacts chứng minh rejection đúng.
- Không “fix” retention/compaction dựa vào Agent nói IDs bị elided. Chưa có prompt telemetry exact từng turn chứng minh producer ID bị runtime mất. Có thể kiểm tra request projection với fixture offline, không cấp `read_tool_result` quyền chung hoặc recapture HTTP tự động.
- Không rewrite SQLi/XSS playbook, name-tainted fixture hay payloads để tránh stall.
- Không đưa `elapsed_ms` vào fingerprint thô: timing noise dễ cho endless novelty. Cần test chứng minh controlled time proof trước khi thiết kế riêng.

## 7. Test plan và acceptance criteria

**Các tests hiện có đã đọc, chưa chạy:** `tests/security/test_http_observation_reader.py`, `test_http_readback_lifecycle.py`, `tests/agent/test_bounded_validation_regressions.py`, các vùng liên quan trong `tests/benchmarks/test_scenario1.py` và `test_scenario1_reliability.py`. Đã đọc skill allowed-tools và structured workflow contracts. Tests hiện có giữ no-negative khi stall (`test_bounded_validation_regressions.py:71–80`, `test_http_readback_lifecycle.py:61–77`) và failed closure phải runtime-error (`test_scenario1_reliability.py:225–243`). Giữ invariant không fabricated terminal; chỉ cập nhật assertion “không có bất cứ result” khi case có active attempt được đóng bằng unresolved. Case chưa bắt đầu attempt vẫn không tạo giả attempt/result.

### Focused offline regressions

| Nhóm / nơi bổ sung | Test hành vi cần có | Acceptance criteria |
|---|---|---|
| Headless owned RHO — `tests/benchmarks/test_scenario1_reliability.py` hoặc file mới cùng group | Build production Agent + mocked HTTP; tạo candidate/start; capture; registry read range | ALLOW_ONCE thông qua HeadlessPermissions; riskTier high-impact/noSessionCache giữ nguyên; content/next offset/hash đúng; số HTTP sent/dispatch/admitted không đổi |
| Headless boundaries — benchmark + security reader tests | Hai isolated controllers cùng origin; read foreign session/case/attempt; corrupt hash; wrong epoch/revision; revoke HTTP/reader; stale review; malformed key/range; internal managed secret | Tất cả fail-closed, không body leak hoặc HTTP mới; không grant bền vững/cross-case; private origin đúng chưa đủ quyền |
| Denial classification — agent + benchmark tests | RHO deny batch đơn; deny+WF.list success batch; MissingInput unavailable | Batch đơn giữ refusal cause và có disposition/failure reason; mixed batch không all-refused; unavailable không ghi “operator chose deny” và không auto-trả lời |
| Identical-body stall — `test_bounded_validation_regressions.py`, `test_http_readback_lifecycle.py` | Scripted client giống 00200/02176 và batched 01389; known source hashes, repeated captures | Stop trước max_steps, threshold/allowance giữ nguyên; active current attempt có insufficient-evidence/blocked; không confirmed/not-confirmed, finding hoặc passed coverage; không HTTP trong closure |
| Evidence errors — benchmark reliability + workflow tests | 00338 nonexistent parents; 01221 proof có omitted real parent, 2 rejections rồi stall; RTR dùng obs_/sf_ | Reject codes vẫn đúng; registration không accepted; closure omit invalid refs; paused recovery budget không reset; attempt được disposition hoặc failure rõ, không recapture để sửa manifest |
| Designated input — `tests/benchmarks/test_scenario1_request_body.py` | Name fixture SafeText=CaseID, mutate value; candidate-only không baseline; stop after repeated errors | Zero admitted traffic; scope/component guard giữ nguyên; result insufficient-evidence/blocked, không tested negative; không sửa op/ground truth |
| Closure transaction — agent + workflow tests | Wrong candidate/session/epoch/selector, revoked workflow, no tools call, invalid closure output, save failure; cancellation khi dispatch/save; duplicate close | Không bypass registry hoặc direct state flip; không overwrite existing result; failed closure không thông báo success; cancellation không spawn detached closure/write; worker có explicit failure reason nếu còn active |
| Mutation/cleanup — agent closure tests dùng observed write acknowledgement fixture | Closure từ active attempt có write acknowledgement; Agent declaration unknown hoặc cleanup unavailable | Không mặc định false/not-required/succeeded; giữ true + unresolved cleanup khi đã có declaration đúng, hoặc fail explicit nếu không thể declare an toàn; external reset không biến thành Agent cleanup |
| Worker/export — benchmark reliability + reporting | Refusal/stall không result active; already unresolved; already terminal; no-start session | Active orphan không completed hợp lệ; result unresolved giữ partition unresolved; terminal giữ original result/seal/finding; freeze không mutate; stop_reason không bị thay bằng result outcome |
| Whole-target — `tests/integration/test_whole_target_workflow.py` | Một active owner + unrelated candidates, refusal/stall, recovery budget; existing cleanup blocker | Chỉ đúng attempt được disposition; không auto-continue sau deny, không đóng unrelated work; no_progress không reset do closure để resume probing; completion vẫn cần accepted result/cleanup/coverage/finding |
| Timing limitation — tracker fixture test, **không patch novelty trong change này** | Same-body controlled delay/no-delay samples với elapsed telemetry | Ghi nhận detector limit rõ; no automatic terminal semantics hoặc threshold change. Nếu cần sửa timing detector sau này, phải có reproduction riêng |

### Chạy kiểm tra trong session implementation sau

Chỉ fake/scripted model và mocked HTTP; cấm live target trong offline acceptance. Chạy targeted tests trước: responsibility groups `tests/security/test_http_observation_reader.py`, `tests/security/test_http_readback_lifecycle.py`, `tests/agent/test_bounded_validation_regressions.py`, `tests/benchmarks/test_scenario1_reliability.py`, `tests/benchmarks/test_scenario1_request_body.py`, tests closure mới. Sau đó rộng hơn `tests/agent`, `tests/tools`, `tests/state`, `tests/benchmarks`, integration workflow/requested-goal tests phù hợp vì thay loop và lifecycle. Giữ live/external skip semantics; pyright dùng `venv-linux` khi applicable. Không cần benchmark/provider API call để chứng minh acceptance này.

Offline exit criteria của patch:

1. Chín owned readback reproductions được admission đúng exact range, không network mới; mọi negative-boundary test tiếp tục deny.
2. Với fixtures của chín stalls, stop vẫn đạt threshold 4/allowance 8 theo cơ chế cũ; dừng probing; output là unresolved disposition hợp lệ hoặc explicit closure failure, không fabricated confirmed/not-confirmed.
3. Không export completed hợp lệ với case attempt còn active mà không ghi lý do/failure; thành công disposition cần saved result và attempt.status=unresolved trước freeze.
4. Foreign ownership/invalid proof/reference không thể trở thành accepted evidence nhờ closure; closure không ghi finding, passed coverage hoặc learned authorization.
5. Original stop reason và blocker giữ được; idempotence, cancellation, failed persistence kiểm tra rõ; không background write chưa await làm sai snapshot.
6. SQLi/XSS skill hash, taxonomy, ground truth, scope/network gate không thay; old artifacts/intelligence/config không đổi. `git diff --check`, diff/status review sạch trong scope.

Không đặt acceptance “18 cases chuyển TP/TN” hoặc “benchmark score tăng”. Offline tests xác nhận lifecycle/permission, không xác nhận vulnerability semantics hay stochastic model sẽ submit proof đúng sau fix.

## 8. Những phần không nên thay đổi

- Registry permission gate và AuthorizedExecutionTool/native HTTP grants; exact origin/private-host gate; session ownership, epoch/revision và invocation freshness.
- RHO/RTR high-impact/no-session-cache classification, bounded ranges, managed-secret guard, result retention capability family, redaction và HTTP outbound analysis metadata.
- Source seal/proof parents/immutable snapshots; every supplied reference vẫn kiểm tra kể cả unresolved. Không alias IDs, không làm missing parent “optional”.
- Anti-stall thresholds, max_steps, finite exploration/readback accounting; không đưa random IDs, request mutation hoặc timing noise thành progress.
- SQLi SQLI-1/SQLI-2 thresholds, XSS static/browser-required proof semantics, taxonomy, evaluator ground truth và confusion interpretation.
- Coverage/finding eligibility: unresolved không passed/confirmed; runtime closed attempt không có nghĩa validated objective. Không gọi confirm_finding khi chưa accepted confirmed.
- Authorization/operator answer/YOLO là session context, không durable intelligence/policy. Không global YOLO, bypass approval, cross-case grant hoặc auto-allow request mới.
- Existing run/publication artifacts và unrelated worktree file `BENCHMARK_OFFICIAL_RUN_02_AUDIT.md`; không commit/push/install packages.

## 9. Kết luận và implementation plan cho session tiếp theo

**Đủ bằng chứng để triển khai Fix A, Fix C và phần lifecycle đã giới hạn của Fix B.** Denial cause và stop/closure paths đã xác định bằng source snapshot khớp run, raw decisions, saved messages và observation journals. Không cần chạy lại target để thiết kế những fix đó.

**Điểm cần xử lý khi implementation, không được vá bằng suy đoán:** general closure phải bảo toàn mutation/cleanup khi chưa có result declaration. Existing helper mặc định boolean false không an toàn cho các write-acknowledgement cases đã nêu. Nếu không thu được declaration đủ an toàn qua bounded closure-only stage, giữ explicit runtime failure/interruption thay vì fake canonical result. Timing novelty và reference visibility chưa được xác nhận là root cause cần patch; chỉ dùng regression fixture để phân định, không mở rộng scope fix.

Audit handoff: không chạy tests vì đây là audit-only; chỉ kiểm tra dữ liệu JSON và tính hash bằng script read-only. Báo cáo đưa ra thiết kế và acceptance, **không tuyên bố các fix đã được thực hiện hoặc test đã pass**.

Implementation plan ngắn:

1. Trong `HeadlessPermissions`, bind current case/session/candidate và thêm exact owned-native-HTTP-range ALLOW_ONCE qua registry. Thêm tests same-origin foreign-session, stale/revoked/integrity/secret và zero-new-HTTP; không đổi reader/HTTP risk policy.
2. Tách submission/check/save của `_stop_evidence_recovery` thành helper nhỏ; route terminal refusal và Direct stall qua current-attempt unresolved closure trước synthesis/Done. Không mở probing loop; giới hạn closure proposal đến WF.record_result unresolved đúng owner, giữ metadata mutation/cleanup. Nếu không commit an toàn, emit failure rõ. Test đơn/mixed refusal, repeated bodies, proof-parent failure, zero-traffic name case, existing terminal result, cancellation/persistence.
3. Trong `execute_case`, sau drain và trước freeze, kiểm tra case active-orphan invariant; export runtime-error + sanitized diagnostic khi closure thất bại. Freeze vẫn pure, evaluator giữ taxonomy; MissingInput diagnostic phân biệt unavailable với explicit operator denial nếu adapter được thay.
4. Chạy targeted offline groups rồi broader workflow/benchmark suites và pyright trong môi trường dự án; review diff/status. Không rerun benchmark/live model/HTTP trong patch acceptance, không rewrite run cũ.
