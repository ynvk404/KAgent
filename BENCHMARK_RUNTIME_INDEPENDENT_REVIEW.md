# KAgent — Independent review bản sửa BenchmarkJava runtime

Ngày review: **14/10/2026, Asia/Saigon**. Repository: `D:\DOANTOTNGHIEP\kagent`.
HEAD: `b1466dc1e07d502d3ca75a1ed7a6bab08341f35c` cùng working diff hiện tại.

## 1. Executive summary

**Kết luận: đúng hướng, nhưng MINIMAL FIX REQUIRED; NOT READY để chạy lại Official 40 cases với bản hiện tại. Không cần REWORK kiến trúc.**

Review phát hiện **hai lỗi mới mức High**, đều được tái hiện offline bằng controller/registry hiện hữu, không dùng LLM hoặc target thật:

1. **D1 — Direct anti-stall có thể bị vô hiệu bằng chuỗi HTTP → đọc observation.** Reader progress dùng `retained_hash`, vốn bao gồm identity của observation, thay vì identity ổn định của nội dung response. Cùng một response được capture lại tạo một reader identity mới. Trong Agent.run thực tế với model giả, chuỗi này dùng hết **24 tool iterations / 25 model calls**, không ghi result, dừng `max_steps` thay vì `workflow_stalled`.
2. **D2 — HTTP reader chưa tích hợp đầy đủ với session serialization/hydration.** Session saver không bảo toàn response reader theo đường HTTP exact-content hiện hữu; loader loại `http_response_sources` của tool mới. Sau save/load, nội dung bị redaction lần nữa và guard bỏ qua nội dung reader khi HTTP bị revoke. Đây là regression về fidelity và revocation sau resume, không chỉ thiếu test.

Không xác nhận lỗi Critical hoặc việc reader tạo HTTP ngoài ý muốn. Không xác nhận blanket blocking đối với cookie/JWT của target: danh sách known secrets trong production chứa provider API keys và ingest token của KAgent, không tự thu thập tất cả token ứng dụng. Tuy nhiên, chặn cả retained body khi có một known internal secret thực sự loại cả range lành tính; đây là **trade-off bảo mật đã xác nhận**, cần điều kiện rõ khi nghiệm thu.

Một kết luận của báo cáo trước cần sửa: **3 failures evidence-repair và 2 failures grounding guidance chủ yếu đang kiểm tra budget cũ**. Source và hai playbook hiện cho phép initial submission + **2 repairs**, tức 3 rejections; các fixtures lỗi lại đòi closure sau 2 submissions hoặc literal “at most one repair submission”. Tại giới hạn hiện hữu, hai biến thể same-source/stale-parent đóng đúng `insufficient-evidence`, giữ `mutation_performed=true`, `cleanup_state=pending`, không thêm HTTP. Không có bằng chứng từ các failures này rằng repair vô hạn hay closure hiện tại hỏng.

Giữ nguyên page preservation/retirement, hard context admission, cleanup actionability, canonical text và kiểm tra proof parents. Sửa tối thiểu D1, D2 và bổ sung đúng tests tích hợp còn thiếu; đồng bộ repair tests theo một contract thống nhất. Không cần xây tracker mới, payload blacklist, semantic classifier tổng quát hoặc refactor lớn để hoàn thiện đồ án.

## 2. Phạm vi và phương pháp xác minh

Đã đọc hai báo cáo đầu vào, `AGENTS.md`, `git status --short`, `git diff --stat`, toàn bộ diff của 7 source files và thực tế cả 3 test files mới. Chỉ mở rộng sang contract trực tiếp của execution receipts, observation ownership, session store, evidence recovery, workflow completion, hai playbook SQLi/XSS và các tests/logs liên quan.

Working tree ban đầu có đúng 7 source sửa, 3 tests mới, hai báo cáo đầu vào và `kagent-changes.diff`. Diff copy khớp byte-for-byte với `git diff`. Không sửa source/tests, dataset, manifest, evaluator, results cũ; không commit/push, reset, live benchmark hoặc gọi provider thật. Tệp bổ sung duy nhất của review là báo cáo này. Các harness tạm chạy từ stdin, dữ liệu fixture nằm trong temporary directories của WSL.

Phân loại sử dụng:

| Nhãn | Ý nghĩa |
|---|---|
| CONFIRMED DEFECT | Vi phạm hành vi/contract được chứng minh bằng source và tái hiện cụ thể. |
| PLAUSIBLE RISK, NEEDS TEST | Có đường lỗi hợp lý nhưng chưa tái hiện đủ để kết luận lỗi. |
| ACCEPTABLE TRADE-OFF | Đánh đổi có giới hạn, được chấp nhận nếu điều kiện thực nghiệm phù hợp. |
| DEFERRED DESIGN DECISION | Contract cần quyết định riêng; không quy thành regression của diff này. |

### Kết quả do lượt review này thực hiện

| Kiểm tra offline | Kết quả |
|---|---|
| Cả 3 regression files mới | **45 PASS**, 21,93 giây. |
| Evidence recovery contract + payload + skill + C4 contracts + skill context policy | **106 PASS**, 20,39 giây. Đây là nhóm khác với “106 focused” của session trước. |
| 3 recovery instances + 4 guidance instances + 2 schema tests + nhánh scenario repair | **7 FAIL, 3 PASS**, 33,19 giây; đúng các 7 failures ưu tiên được yêu cầu kiểm tra. |
| D1 qua production registry và tracker | 24 batches, 1 response hash, 12 reader identities, exploration đã đạt 8, no-progress vẫn 0, không result. |
| D1 qua Agent.run và model giả | 24 tool iterations; 25 model calls gồm synthesis; 13 mocked HTTP captures gồm setup; goal `in_progress`; stop `max_steps`. |
| D2 qua Store.save/Store.load thật | Saved refs tồn tại; loaded refs `None`; content không còn exact. Live content bị loại khi revoke; resumed content còn lại. |
| Closure same-source/stale-parent ở budget hiện tại | Cả hai đóng sau 3 model submissions; không error; 2 mocked HTTP captures đã có; unresolved result giữ mutation và pending cleanup. |
| Body có target cookie/JWT, không trùng internal secret | Reader trả nguyên body fixture, không blanket reject. |
| Range lành tính trong body chứa internal secret ở chỗ khác | Bị từ chối toàn bộ bởi source-level guard. |
| Schema fixture trước/sau thêm HTTP reader | 30.163 → **30.835 characters**, tăng **672**; 30 → 31 tools. |
| `git diff --check` | PASS. |

Pytest dùng `--import-mode=importlib -p no:cacheprovider`, `PYTHONDONTWRITEBYTECODE=1`; bỏ bốn opt-in live/reset env vars được nêu trong implementation report. MockTransport tiếp nhận các HTTP calls của fixtures; không có traffic tới lab thật.

### Đối chiếu bằng chứng đã lưu

Đọc trực tiếp `/tmp/kagent-full-resumed.log`, `/tmp/kagent-baseline-snapshot.log`, `/tmp/kagent-focused-accepted.log`, `/tmp/kagent-pyright-accepted.log` và hash manifest:

- Final full log ghi **7.140 PASS, 12 FAIL, 18 SKIP, 3 XFAIL**, 2 warnings, 1.001,76 giây.
- Parse chính xác FAILED node IDs: baseline 18, final 12, **final − baseline rỗng**.
- Focused log ghi 106 PASS; Pyright ghi **0 errors, 0 warnings, 0 informations**. Có thông báo cập nhật phiên bản từ launcher; không phải diagnostic source của Pyright.
- SHA-256 của cả 7 source + 3 test files hiện tại khớp manifest verification trước.

Đây là xác minh logs và source hashes, **không phải chạy lại full suite, baseline hay Pyright** trong lượt này. “Không có node fail mới” không chứng minh không có regression: D1/D2 không được các tests cũ bao phủ.

## 3. Đánh giá từng nhóm thay đổi

### A. Context preservation và Skill Reader — KEEP

`ReadPayloadsTool.context_reduction_policy()` (`payloads.py:85`) và `ReadSkillFileTool.context_reduction_policy()` (`skill_file.py:87`) trả `preserve`. Agent reducer chỉ giảm tool text có policy `adaptive` (`agent.py:5206–5212`). Producer vẫn giới hạn source 256 KiB, page body 16 KiB và line limit. Không còn generic truncation lần hai trên recent page ở đường này.

`guard_working_context()` (`agent.py:5178–5195`) thay toàn bộ output reader cũ bằng pointer sau khi có hơn 4 reader messages, giữ 4 gần nhất **gộp cả hai loại reader**, không phải 4 mỗi loại. Replacement đặt ở working list, không sửa history tại đoạn retirement này. Regression kiểm tra history nguyên vẹn. Hard admission vẫn so estimate với `input_limit`, ném `ContextCapacityError` (`agent.py:1947–1969`); `preserve` không vượt được giới hạn provider.

`SkillFilePages.preview()` (`paths.py:128–179`) kiểm tra offset/ref, nội dung digest và source thay đổi; metadata luôn có Unicode range, source size và EOF, kể cả trang đầu hoàn chỉnh. Reread với limit nhỏ hơn giữ identity; continuation có cả vị trí trước body và footer. Byte cap không cắt dở UTF-8; offsets đếm decoded characters. Không thấy mất continuation do diff mới.

**ACCEPTABLE TRADE-OFF, Low:** 4 messages gồm cả list/error outputs của cùng tool; không chọn 4 trang “liên quan nhất”. Một trang hữu ích có thể bị retire và cần reread. Tracker coi range đã từng đọc là no-progress, nhưng cửa sổ 4 no-progress vẫn cho 1–2 rereads hợp lý. Không cần thêm state phức tạp để loại mọi reread. Nên thêm một test kết hợp retire → reread → legitimate result; chưa có bằng chứng false negative hiện tại.

**PLAUSIBLE RISK, NEEDS TEST, Low:** nhiều pages preserve lớn hoặc nhiều list outputs có thể gây context pressure. Hard cap chặn đúng; đó là failure rõ thay vì silent corruption. Không cần tăng quota/limit hay đổi sang adaptive truncation.

### B. Direct anti-stall — MINIMAL FIX REQUIRED

`record_validation_batch()` (`agent.py:804–893`) được gọi sau tool batch tại `4651–4694` khi có requested goals và không phải Whole-target. No-tool branch đồng bộ counter tại `4380–4387`. Whole-target tiếp tục dùng `record_iteration()` và `progress_facts()`; không gọi phương thức reader-progress mới. Không thấy Direct gọi nhầm `progress_facts()` hoặc lấy facts của candidate khác để làm progress.

Các phần đúng:

- HTTP observation ID và changed HTTP args không được dùng trực tiếp làm structured progress.
- HTTP response/status/completeness/timing novelty chỉ tiêu thụ exploration; tối đa 8 novel iterations trước 4 no-progress iterations nếu không có reader/facts reset.
- Một verification repeat cho mỗi response fingerprint; error prose/args mới không tự reset. Các controller error codes khác nhau chia sẻ allowance hữu hạn.
- Pagination mới không replenish `phase_exploration_steps`.
- Stop dùng tools-free synthesis, giữ evidence/findings/workflow unresolved; không tự tạo negative hoặc confirmed. Finding chưa persist được nêu trong summary.

Tuy nhiên, **D1 bên dưới phá giới hạn này qua identity của readback**. Trước khi sửa, không thể kết luận anti-stall chống được loop với native observations.

**ACCEPTABLE TRADE-OFF, Low:** `elapsed_ms` trong fingerprint (`870–872`) có thể khiến response giống nhau trông như exploration mới do jitter. Nó vẫn bị cap 8, không tạo proof hoặc structured facts. Có thể bỏ timing khỏi novelty mặc định, hoặc chỉ dùng khi controller/skill đang làm timing validation; không phải blocker độc lập và không nên loại bằng chứng timing hợp lệ một cách máy móc.

**PLAUSIBLE RISK, NEEDS TEST, Medium:** progress signature (`2705–2727`) reset theo thay đổi goal/candidate status, attempt IDs/status, evidence IDs/hash, finding persistence, cleanup và coverage. Artifact mới chưa chứng minh tiến triển về câu hỏi validation; chuỗi rewrite/register/retest có thể liên tục đổi signature. Cần một fixture nếu audit thực tế có loop dạng này. Không kết luận mọi artifact revision là progress giả: sửa proof/parents hợp lệ thực sự cần được phép.

**Giới hạn phạm vi, Low:** phương thức mới đòi `objective.requested_goals`; không áp dụng cho mọi workflow conversation không có goals. Không quảng cáo đây là global anti-stall cho toàn bộ candidate_validation/generic chat.

### C. HTTP Observation Reader — MINIMAL FIX REQUIRED ở session integration

Reader riêng cho `obs_` là phù hợp; không cần mở rộng `tr_` reader. `ReadHTTPObservation.run()` chỉ decode retained body và page nó; không gọi HTTP adapter/transport. `max_chars` là giới hạn tổng output ≤2.000 characters, nên body thực tế nhỏ hơn sau header; `next_start_char` nối đúng range. Test Unicode thực tế reconstruct toàn retained body sau observation-store persistence.

`validate_rights()` (`tool_result.py:162–210`) kiểm tra policy identity, active execution receipt khi dispatch, capability revocation, objective/candidate/attempt ownership, epoch, target revision/origin, candidate binding, latest completed attempt, active retest, analysis session, network scope và skill HTTP capability. `resolve_sources()` bổ sung integrity và ownership fields. Registry kiểm tra trước review và khi dispatch; reader kiểm tra lại sau await; Agent kiểm tra trước đưa output vào model. `_ExecutionPrompter` tái sử dụng đúng approval/cache key của invocation nên không hỏi permission hai lần cho cùng action.

Không thấy reader gán lại owner hoặc tạo quyền HTTP mới. Old objective/retest được từ chối trong regression. Một completed observation chỉ đọc được nếu vẫn là attempt latest hiện hành. Nguồn đã bị evict khỏi observation store bị từ chối, dù workflow còn historical manifest: đây là conservative availability boundary, không tự salvage provenance.

**D2 làm các đảm bảo outbound/resume không còn đúng sau session load.** Regression mới có “resume” nhưng chỉ hydrate `WorkflowState` và observation store, chưa gọi session Store cho reader Message. Cần sửa integration ở store; không cần thay schema workflow hoặc cơ chế receipt.

#### Internal secrets so với target application data

Nguồn danh sách known secrets: `agent.py:5859–5864` và `src/cli/runtime.py:812–815`. Production callback trả provider API keys, custom-provider keys và ingest token; cộng current client API key. Đây **không phải classifier** cho mọi cookie/session token/JWT trong response.

Harness xác nhận body chứa SQL diagnostic, reflected marker, `Cookie: sid=app-session` và JWT giả vẫn được đọc nguyên khi không trùng known internal secret. Vì vậy, không có cơ sở nói guard luôn chặn evidence Juice Shop/BenchmarkJava chỉ vì chứa authentication data.

**T1 — ACCEPTABLE TRADE-OFF, Medium:** tại `tool_result.py:204–208`, một known-secret substring ở bất kỳ đâu trong body làm toàn observation unreadable, kể cả range chỉ chứa “Safe SQL error…” ở phía trước. Đây là hành vi đã tái hiện; không phải rò secret. Có thể tạo false negative do thiếu evidence nếu target echo đúng key nội bộ hoặc key cấu hình ngắn/dummy trùng application text. Chưa có bằng chứng các Official 40 response thật chứa tình huống này; không gán false negative benchmark đã xảy ra.

**Khắc phục tối thiểu nếu cần mixed-body support:** tận dụng danh sách exact known internal secrets và HTTP outbound protection hiện hữu; tính toàn bộ secret spans **trước slicing**. Chỉ cho exact original ranges không giao secret span đi qua; range giao span phải bỏ trọn secret hoặc trả marker rõ `analysis is not exact`, không được trả từng mảnh để ghép secret. Giữ nguyên raw observation/hash và evidence gate; nếu dùng safe derivative để paging thì phải ghi rõ derivative offsets, không giả chúng là original excerpt offsets. Không blanket redact cookie/JWT của target và không bỏ source-level security guard. Nếu helper hiện tại chỉ biết bỏ cả body, giữ fail-closed cho case không thể biểu diễn an toàn.

Trước Official 40: **bắt buộc D2**, chưa bắt buộc selective mixed-body enhancement nếu operator xác nhận đây không phải nguồn evidence cần dùng; ghi limitation và dùng internal credentials không trùng dữ liệu lab. Trước áp dụng rộng sang authenticated/mixed-response targets: thêm success/denial fixtures tương ứng.

### D. Cleanup, canonical text và evidence — KEEP

`_has_actionable_requested_goal()` (`agent.py:2661–2688`) không coi accepted result có operator-only/failed cleanup là việc Agent tự giải quyết bằng thêm probes. Nó vẫn cho pending cleanup, coverage chưa sync và confirmed finding chưa persist là actionable; dismissed candidate chỉ tiếp tục khi có pending cleanup phù hợp. Unresolved assessment vẫn có thể sửa, không dừng chỉ vì candidate không còn validating.

Source và tests cho thấy cleanup không biến accepted assessment thành negative/confirmed khác. Cả ba cleanup states giữ obligation; not-confirmed có mutation chưa cleanup không được tuyên bố goal tested. Finding persistence còn actionable với operator cleanup. Chưa có test mới cho đầy đủ run-loop operator resolution hoặc kết hợp failed coverage + failed cleanup; đây là coverage gap, chưa có defect xác nhận.

`_text()` (`state.py:98–121`) normalize/redact trước cap, bỏ trailing whitespace và tìm stable prefix. Mỗi vòng giảm prefix, không có vòng lặp vô hạn. Tests cover Unicode whitespace, redaction boundary và binding qua workflow hydration. Không đổi assessment schema hoặc nới gate. Chấp nhận mất một ít note text tại boundary để round trip ổn định. **Không đánh đồng fix này với session-reader fidelity; D2 nằm ở integration khác.**

`check_proof_references()` (`evidence.py:29–120`) bổ sung handles trong headings/tables, trong candidate entry có scope đáng tin cậy. Parent accept/reject đều được test. Existing logic bỏ fences/quotes/indented examples và sections khác; ambiguous scope giữ structured excerpts contract.

**PLAUSIBLE RISK, NEEDS TEST, Low:** mọi pipe-prefixed row/heading trong entry đều được scan, nên bảng chú thích nhắc observation không phải primary proof có thể bị từ chối. Chưa tái hiện một artifact được contract coi là hợp lệ mà bị reject. Cách tối thiểu là dùng quoted/fenced examples hoặc tách commentary scope; chỉ thu hẹp regex khi có fixture chứng minh, không xây Markdown parser tổng quát.

## 4. Confirmed defects

### D1 — High — observation readback làm tiến triển giả và chạy hết 24 steps

**Nhãn:** CONFIRMED DEFECT, mới trong diff. **Bắt buộc sửa trước Official 40.**

**Vị trí:** `src/agent/agent.py`, `WholeTargetStallTracker.record_validation_batch()`, **841–844**, **856–864**, **888–892**; call site **4651–4681**. `ReadHTTPObservation.run()` xuất `retained_hash` tại `tool_result.py:236`; `src/workflow/assessment.py:42–46` hash toàn observation row.

**Nguyên nhân:** identity của HTTP reader lấy retained-representation hash. Row được hash chứa observation ID, invocation/receipt/request/ownership metadata, không chỉ response body. Capture cùng response một lần nữa tạo hash mới. Tracker xem range `[0, len(body))` của capture mới là chưa đọc và reset no-progress vô điều kiện, dù body identical. HTTP novelty cap vẫn đạt 8, nhưng reader reset không tiêu thụ thêm cap.

**Tình huống tái hiện:** candidate/attempt hiện hành, active XSS skill, requested goal Direct. Lặp HTTP GET `/fixture?q=fixture` nhận cùng body `fixture`, rồi đọc body của observation vừa tạo; không submit result/evidence mới. Cả HTTP và reader dùng production Registry/ExecutionPolicy, transport là MockTransport.

**Bằng chứng:** tracker harness có 1 `response_hash`, 12 read identities, 24 batches, no-progress=0. Agent harness dừng `max_steps` sau 24 tool iterations, có error “hit max steps (24) without finishing”, goal vẫn `in_progress`, không validation result. Do đó không chỉ là suy luận từ unit-test internals.

**Tác động:** Direct có thể tiêu hết step/HTTP allowance cho cùng dữ liệu; benchmark timeout/unresolved tiếp tục xảy ra dù anti-stall bật. Whole-target không trực tiếp dùng đường này. Không chứng minh false confirmation hoặc quyền HTTP bị bypass.

**Sửa tối thiểu:** tách integrity identity khỏi progress identity. Giữ `retained_hash` để admission; progress dùng body-content digest ổn định (chẳng hạn `response_hash`, hoặc hash decoded retained body với context candidate hiện hành), kết hợp ranges đã đọc. Không dùng request/obs ID/timing vào reader progress key. Giữ allowances, legitimate first read, Unicode pagination và 1–2 rereads. Thêm test full Agent.run cho HTTP → readback identical và test positive cho body mới/page mới. Không thêm tracking subsystem.

### D2 — High — HTTP readback mất source guard sau session save/load

**Nhãn:** CONFIRMED DEFECT, integration regression do capability mới. **Bắt buộc sửa trước benchmark/resume.**

**Vị trí thay đổi:** `src/agent/agent.py:5904–5912`, **5976–5989**, `record_tool_result():6033–6045`; reader `src/tools/common/tool_result.py:212–259`. **Contract liên quan trực tiếp:** `src/session/store.py`, `_message_from_dict():284–289`, `_serialize_session():564–567`. Store file không nằm trong diff nhưng phải được kiểm tra vì output mới đi qua nó.

**Nguyên nhân thứ nhất — fidelity:** saver exact HTTP-content exception chỉ nhận `http`/`browser_capture_get`. `read_http_observation` đi qua generic `redact_payload`; content có target cookie/token hoặc text giống secret field bị thay đổi, dù outbound HTTP analysis đã admit nội dung đó. Header offsets/hash vẫn mô tả original body nên resumed message không còn exact representation.

**Nguyên nhân thứ hai — revocation:** saver ghi `http_response_sources`, nhưng loader whitelist cũng chỉ nhận `http`/`browser_capture_get`, gán refs reader thành `None`. `_protect_http_context()` bỏ qua message không có refs. Sau resume, revoke HTTP/capability, đổi objective/retest, mất observation hoặc phát hiện internal secret mới không kích hoạt source guard cho message này.

**Bằng chứng:** đọc observation có body `Safe SQL evidence\nCookie: sid=target-session\nSafe reflected payload ...`, admit qua `_http_analysis_content()`, ghi Message với production metadata, Store.save/Store.load thật. Saved refs=True; loaded refs=None; body_exact=False; cookie bị redact. Revoke HTTP: original live message được thay bằng “HTTP analysis omitted”, loaded message vẫn có “Safe SQL evidence”.

**Tác động:** Direct và Whole-target dùng reader đều có thể gửi historical body text trong resumed prompt dù quyền nguồn hiện tại không còn; evidence context có thể bị sửa và gây model hiểu sai hoặc đọc lại không cần thiết. Không tự tạo một accepted finding: workflow evidence gate vẫn độc lập. Không chứng minh leak provider key hiện có, vì guard trước initial read vẫn hoạt động; vấn đề là stale-content outbound protection sau load.

**Sửa tối thiểu:** thêm reader vào **cả** HTTP exact-content save path và HTTP source-metadata hydration whitelist, dùng provenance đã được Agent admit. Tiếp tục không serialize execution rights/runtime stamp; sau load phải revalidate reader ownership/scope/epoch/objective/skill bằng guard hiện tại. Với reader message không còn metadata hợp lệ, bỏ body fail-closed thay vì giữ dưới dạng ordinary tool text. Không tắt generic redactor toàn session hoặc nới evidence acceptance.

**Tests cần:** round trip Store thật giữ body/refs; sau load HTTP/tool revoke, objective retest, epoch change, observation unavailable phải omit; target cookie/JWT benign phải giữ fidelity theo HTTP path; known internal secret vẫn không được admit. Test “resume” hiện tại chưa bao phủ các bước này.

## 5. Plausible risks và acceptable trade-offs

| ID / mức độ | Nhãn và bằng chứng | Tác động / khắc phục tối thiểu | Cần sửa trước thực nghiệm? |
|---|---|---|---|
| T1 / Medium | ACCEPTABLE TRADE-OFF; source-level known-secret gate từ chối cả safe range trong mixed body. | Có thể mất SQLi/XSS evidence lành tính. Giữ guard; selective exact-secret handling theo §3C chỉ khi cần, có denial + stitching tests. | Có nếu các cases thực sự cần mixed body; chưa có bằng chứng điều đó trong 40 cases. |
| R1 / Medium | PLAUSIBLE RISK, NEEDS TEST; arbitrary artifact/attempt revisions đổi Direct progress signature. | Có thể đổi bookkeeping để kéo dài run. Thêm targeted fixture, phân biệt usable proof repair với repeated bookkeeping nếu tái hiện. | Không bắt buộc redesign chưa có fixture. |
| T2 / Low | ACCEPTABLE TRADE-OFF; HTTP elapsed novelty bị jitter nhưng chung cap 8. | Chậm phát hiện stall vài iterations; không cấp evidence authority. Có thể bỏ timing khỏi default identity. | Không là blocker độc lập. |
| R2 / Low | PLAUSIBLE RISK, NEEDS TEST; retired page reread cùng range không progress. | 1–2 rereads nằm trong cửa sổ 4; test retire/reload/result để bảo vệ false negative. | Nên thêm khi sửa D1; chưa cần tracking mới. |
| T3 / Low | ACCEPTABLE TRADE-OFF; preserve 4 messages, hard capacity vẫn chặn. | Model có thể gặp context pressure với 4 pages lớn. Giữ bound và honest ContextCapacityError. | KEEP. |
| R3 / Medium | PLAUSIBLE RISK, NEEDS TEST; imported-capture valid path, state changes/eviction trong permission await chưa có reader-specific success tests. | Existing receipt/ownership checks giảm rủi ro; thêm fixtures khi sử dụng readback cho các modes đó. | Sau D2, ưu tiên trước Whole-target/capture usage rộng. |
| R4 / Low | PLAUSIBLE RISK, NEEDS TEST; headings/table commentary có obs handle bị coi là claim. | Possible false rejection; thêm concrete legitimate proof fixture trước sửa regex. | Không blocker khi artifact theo contract rõ. |
| T4 / Low | ACCEPTABLE TRADE-OFF; capped canonical notes có thể mất suffix quanh redaction atom. | Ít text hơn nhưng binding stable, secret không được phục hồi. | KEEP. |

Không báo R1–R4 như lỗi đã xảy ra trên benchmark. Với T1, hành vi mất safe range đã xác nhận; tần suất ảnh hưởng target thật chưa được xác minh.

## 6. Đánh giá độ đầy đủ của regression tests

| Tệp | Test instances / giá trị | Thiếu quan trọng |
|---|---|---|
| `tests/agent/test_bounded_validation_regressions.py` | 25; positive/negative parent refs, normalization, history preservation, hard capacity, overlapping/EOF ranges, finite feedback allowance; có test Agent.run thật với Echo loop. | Không kết hợp native HTTP IDs + HTTP reader. Fake observation trong repeated HTTP test thiếu `elapsed_ms`; HTTP response progression test dùng plain strings. Không test retire → reread → valid proof/result. |
| `tests/security/test_http_observation_reader.py` | 13; production registry + MockTransport, no extra traffic, integrity/owner/epoch/scope/revocation/permission deny, Unicode paging, old-attempt rejection, whole/partial internal-secret blocking. | “resume” chỉ save/load observations + WorkflowState; không serialize Message qua Session Store nên bỏ lọt D2. Thiếu benign target cookie/JWT positive case và safe range trong mixed-secret body; thiếu valid imported capture và changes trong permission await. |
| `tests/security/test_cleanup_actionability.py` | 7; đủ ba cleanup states, finding persistence còn actionable, accepted result binding sau workflow hydration. | Chủ yếu helper-level, chưa có full Agent.run operator cleanup resolution, coverage retry cùng cleanup và nhiều goals/candidates. |

Các tests không chỉ xác nhận implementation: no-network, retained ownership, honest outcome, hard capacity và immutable parents là hành vi thực. Tuy nhiên, một số assertions `reader_progress`/counter/raw private fields gắn với chi tiết tracker; chúng chưa thay thế integrated outcome test. Page test chỉ assert ≤4 full pages, nên có thể không bắt được việc vô tình giữ ít hơn 4; positive assertion cho cả bốn recent pages sẽ rõ hơn. Test secret rejection phù hợp confidentiality nhưng chưa chứng minh giữ evidence lành tính.

Khuyến nghị ít tests nhưng đúng boundary: D1 full loop; D2 real Session Store; một successful multi-turn evidence repair; một retire/reread; một mixed-body safe/denied case. Giữ tests hữu ích hiện có, không thêm hàng trăm assertions mô phỏng lại code.

## 7. Phân tích baseline failures liên quan

### 7.1 Ba bounded evidence-repair closure failures — mismatch budget đã xác định

**Mức độ Medium, CONFIRMED DEFECT trong tính nhất quán test/contract; không xác nhận runtime closure defect.**

`src/workflow/evidence_recovery.py:9–13`: `MAX_EVIDENCE_RECOVERY_RETRIES=2`, `MAX_EVIDENCE_REJECTIONS=3`, `MAX_TERMINAL_REPAIR_TURNS=6`. `EvidenceSubmissionError.repair_hint` và hai skills cũng nói retry tối đa twice sau initial submission. Existing `test_evidence_recovery_contract.py` kiểm tra hai lượt rewrite/register/submit và thành công ở boundary, cùng exhaustion/persistence.

Ngược lại:

- `tests/security/test_observation_grounding.py:196–200` script chỉ có initial + một repaired submission; line 216 đòi đúng 2 client requests và closure. Actual error là **FakeClient: script exhausted** ở request thứ ba; không phải closure đã chạy rồi bị primary gate từ chối.
- `tests/scenarios/test_recovery.py:269–274` tự phát AssertionError nếu runtime còn request sau hai submissions.

Hai harness dùng cùng sources/parents/submissions nhưng đủ **3 rejections** đều commit honest closure: outcome `insufficient-evidence`, attempt `unresolved`, mutation=True, cleanup pending, recovery maps trống, không HTTP thêm. Nhánh scenario `[repair]` cũng PASS trong rerun. Nhóm existing evidence-recovery contract PASS trong lượt này.

**Sửa tối thiểu:** thống nhất contract hiện hành “2 repair submissions sau initial”, điều chỉnh fixtures cũ để thử đủ ba submissions và vẫn assert không new HTTP, không salvage invalid parents, giữ cleanup, không fake terminal result. Nếu đồ án thực sự muốn chỉ một repair, đó là quyết định thay contract đồng bộ runtime/skills/tests, không phải việc sửa incidental failing assert. Hai repairs hợp lý cho write → register → submit nhiều turns; không cần rút xuống một chỉ để suite xanh.

**Điều kiện trước benchmark:** sửa mismatch và chạy lại đúng ba nodes; không giữ báo cáo khẳng định closure broken. Chưa chạy lại scenario `[budget-closure]` với fixture mới vì source/tests read-only, nên PASS của scenario sau đồng bộ vẫn là việc cần làm.

### 7.2 Hai grounding-guidance failures — literal budget cũ

**Mức độ Medium, CONFIRMED DEFECT trong test contract.**

`tests/skills/test_validation_grounding_contract.py:24` đòi literal `at most one repair submission`. SQLi skill **892–895** và XSS **529–533** đang nói **at most two** trong cùng attempt recovery budget. Kiểm tra tất cả phrases của test, không chỉ first failed assertion: mỗi skill chỉ thiếu phrase one-repair này; observation IDs, incomplete request preview, execution status, immutable snapshots, refs/parents và unresolved stop guidance đều có. Hai semantic/context guidance tests còn lại PASS.

Không thể từ hai failures này kết luận toàn bộ grounding guidance vắng mặt hoặc không an toàn. Sửa assertion theo budget đã thống nhất, giữ các clauses bảo vệ integrity. Tests này chỉ kiểm tra loaded instructions; không chứng minh LLM tuân thủ hoặc semantic proof đã đủ.

### 7.3 Hai schema-budget failures — vẫn là budget vượt thật và chưa đo reader mới

**Mức độ Medium, CONFIRMED DEFECT của budget acceptance hiện tại / coverage gap.**

`tests/integration/test_tool_schema_budget.py:82` đo 30.163 characters >28.000; node hybrid gọi helper này rồi fail trước khi kiểm tra projected guidance. Hai nodes **không phải hai bằng chứng độc lập** về projection sai. Default fixture đăng ký 30 tools, chưa tạo Agent nên chưa có `read_http_observation`.

Đo riêng cùng fixture thêm reader: **30.835**, +672 characters (khoảng 168 tokens theo phép characters/4 của test); Direct projection **30.341**, Whole-target **30.835**. Đây là cost tối thiểu của HTTP reader trên fixture, không tự nhận là toàn bộ actual Agent schema (Agent có thể có retained-result reader/configuration khác).

Tác động thực: schema chiếm thêm context budget; tests old failing value “không tăng” không chứng minh diff không tăng actual runtime inventory. Hard capacity vẫn có hiệu lực; chưa chứng minh provider overflow thực tế do 672 characters này.

Sửa tối thiểu: đo actual Agent inventory/projection dùng trong benchmark; rút verbose descriptions/duplicate schema prose khi không mất contract, không tăng 28.000 để giấu failure. Với provider đủ headroom có thể chấp nhận như giới hạn research nhưng phải ghi số đo actual context và bounded inputs. Không cần thiết kế schema infrastructure mới.

### 7.4 Năm failures còn lại

| Nodes / mức độ | Đánh giá độc lập trong phạm vi review |
|---|---|
| Provider retry projection `[anthropic]`, `[gemini]` / Medium | Log ghi request bodies retry khác nhau khi fixture đổi action view. Source transport ngoài 7-file diff; không mặc định vô hại. Cần focused review/rerun nếu Official run dùng hai backends này; không bắt tất cả providers phải sửa để chạy backend khác có contract đã kiểm tra. |
| Browser private namespace / Low, environment-specific | Log chỉ ra interpreter/helper dưới `/tmp` bị che bởi `bwrap --tmpfs /tmp`; separate workspace log ghi 1 PASS. Đây là bằng chứng environment failure, chưa phải sản phẩm lỗi. Không chạy lại namespace/browser trong lượt này. |
| Hai Markdown width nodes / Low | Log ghi widths 75>36 và 61>28. UI defect thật nhưng ngoài evidence/reader semantics; theo dõi riêng, không blocker Official40 khi logs/evidence còn đọc được. |

Không tuyên bố full suite xanh. Có 12 failing nodes; 5 nodes repair/guidance hiện lệch contract, 2 nodes budget cần disposition, 5 nodes còn lại cần xử lý theo backend/environment/product scope.

## 8. Deferred contracts và ảnh hưởng thực nghiệm

### HTTP intent/authority cho write/destructive — High, DEFERRED DESIGN DECISION

`src/permission/network/grants.py:29–34` công bố chấp nhận unknown HTTP effects; `_authorize_active():834–838` mint receipt khi có autonomous/yolo grant sau scope/capture checks. `test_yolo_new_endpoint_payload_and_effects_are_not_classifiers` xác nhận method/payload/phase không phải effect classifier. Đây là contract hiện hữu, không do HTTP reader gây ra; reader không gửi request.

Official local lab có thể chạy trong quyền lab disposable đã khai báo. Nếu muốn runtime tự bảo đảm không extra-write/destructive thì origin grant/receipt hiện tại chưa đủ; cần rõ action intent và allowed effects. Không suy ra DELETE luôn destructive hoặc GET luôn an toàn, không dùng payload blacklist. Trước Whole-target trên dữ liệu không disposable hoặc quyền bounded validation hẹp hơn origin grant, phải review/implement contract thích hợp. Đồ án chỉ dùng disposable authorized lab có thể ghi giới hạn này thay vì xây policy engine lớn ngay.

### Tiêu chuẩn SQLI-2 và XSS — High về validity, DEFERRED DESIGN DECISION

`src/workflow/assessment.py` chủ ý chỉ kiểm tra generic admissibility/bindings. `tests/tools/test_workflow.py:816–843` cho error-based confirmation tương thích với `confirmation=None`; test đó không chứng minh mọi parser error là SQLI-2. Structured source ownership/excerpts không tự chứng minh vulnerability semantics.

SQLi playbook phân biệt parser/type sensitivity với attacker-controlled SQL semantics; boolean SQLI-2 cần comparison/repetitions tương ứng. XSS playbook phân biệt reflection/context/exploitability với actual browser execution, có `browser-required` khi cần browser proof. Không browser capability hiện hữu để biến reflection thành execution giả.

**Trước experimental claims:** định nghĩa tiêu chí proof rõ và review evidence từng case confirmed; parser-error-only không được gọi SQLI-2, raw reflection không được gọi observed execution. Điều này có thể làm bằng structured artifact/checklist chuyên biệt và human evidence review trong phạm vi đồ án; không bắt buộc xây generic semantic validator trước diagnostic rerun. Nếu yêu cầu mọi automatic confirmed result phải tự bảo đảm ngữ nghĩa, cần implementation contract riêng trước tuyên bố đó. Không thay evaluator, label dataset hoặc nới evidence gate.

### Bounded evidence repair — Medium, contract đã có; đồng bộ tests là MINIMAL FIX

Giữ existing controller 2 repairs / 6 repair turns, immutable parents và no-new-probes-for-manifest. Không cần tracking mới. Phân biệt stop `workflow_stalled` giữ active/unresolved obligation với honest `insufficient-evidence` closure tại budget exhausted. Anti-stall không thay thế closure, nhưng ba failures stale cũng không chứng minh closure hỏng.

### Narrative claims chưa được nguồn tương ứng chứng minh — Medium, DEFERRED DESIGN DECISION

Heading/table fix chỉ bắt explicit source handles. Unscoped prose có thể nói quá impact hoặc dùng observation hợp lệ nhưng không tương ứng claim. Không có automatic entailment check. Trước Official40 được dùng làm kết luận hiệu quả/TP, reviewer phải đối chiếu request template, roles/status/body/completeness/repetitions với từng claim; giữ unknown/unresolved khi chưa đủ. Với research có thời gian hạn chế, manual evidence review và limitations minh bạch là phù hợp. General narrative verifier nằm ngoài diff.

## 9. Sửa chữa tối thiểu theo ưu tiên

1. **P1, bắt buộc — D2:** tích hợp reader với session saver/loader và fail-closed khi mất provenance; test real Store round trip + revoke/retest/epoch/source loss. Giữ internal-secret guard và existing receipt/evidence gates.
2. **P1, bắt buộc — D1:** stable content identity cho reader progress, integrity hash giữ nguyên; test full Direct HTTP/readback loop stop trước 24, vẫn cho legitimate new body/page và reread hữu hạn.
3. **P2, bắt buộc cho acceptance — repair/guidance contract:** giữ two-repair controller hợp lý, đồng bộ 5 stale nodes mà không bỏ no-network, immutable proof, honest unresolved và cleanup assertions. Rerun recovery/guidance + Direct lifecycle/safety liên quan.
4. **P2, disposition trước run — schema:** đo actual benchmark Agent inventory và provider input headroom; tối giản descriptions nếu cần đạt budget. Không tăng budget/quota/steps hoặc cam kết actual prompt fit chỉ từ test fixture.
5. **P2, điều kiện trước publication — semantic evidence:** thống nhất SQLI-2/XSS proof criteria và review confirmed evidence. Giới hạn lab intent/authority phải được operator hiểu theo contract hiện hữu; Whole-target ngoài disposable lab cần review riêng.
6. **P3, có điều kiện — mixed-secret body/readback:** nếu required evidence nằm trong body có internal secret, thêm selective known-secret handling tận dụng outbound path và tests chống ghép fragments; chưa cần broad redaction.
7. **P3 — coverage gaps:** thêm retire/reread/result, coverage+cleanup retry và imported-capture success nếu các modes được dùng. Provider retry chỉ ưu tiên khi dùng backend liên quan; UI widths xử lý riêng.

Không thực hiện bất kỳ implementation nào trong lượt review này.

## 10. Disposition và readiness

| Nhóm | Kết luận | Điều kiện |
|---|---|---|
| Context preservation / Skill paging | **KEEP** | Giữ producer bounds, 4 recent reader messages và hard admission; thêm combined reread test khi sửa tracker. |
| Direct anti-stall | **MINIMAL FIX REQUIRED** | D1; giữ existing controller và finite diagnostic/exploration allowances. |
| HTTP Observation Reader | **MINIMAL FIX REQUIRED** | D2 session integration; giữ quyền đọc/scope/ownership/integrity/no-network guard. Mixed-secret withholding ghi rõ limitation, enhancement có điều kiện. |
| Cleanup actionability | **KEEP** | Giữ pending cleanup/coverage/finding actionable, operator-only blockers honest. |
| `_text` serialization | **KEEP** | Stable prefix hợp lý, workflow binding tests PASS. |
| Proof headings/tables | **KEEP** | Structural parents đúng; không quảng cáo narrative entailment. |
| Bounded evidence repair | **KEEP runtime; MINIMAL FIX REQUIRED tests/contracts** | Hai repairs hữu hạn đã có bằng chứng closure; đồng bộ stale fixtures/guidance assertions. |
| Schema budget | **MINIMAL FIX REQUIRED hoặc explicit scoped disposition** | Actual Agent measure + provider headroom; không giấu failing cap. |
| Intent/effects + semantic confirmation | **DEFERRED DESIGN DECISION** | Xác định phạm vi lab và evidence criteria; implementation riêng chỉ khi yêu cầu auto-enforcement vượt contract hiện tại. |

**Không nhóm nào có bằng chứng cần REWORK lớn.**

**NOT READY với code hiện tại cho Official 40 rerun.** Điều kiện tối thiểu để READY cho một lượt diagnostic benchmark mới được cho phép: D1/D2 được sửa và regression tích hợp PASS; các tests repair/guidance thống nhất với contract; actual inventory/prompt được chứng minh còn context headroom hoặc budget issue được xử lý; backend dùng cho run có retry behavior đã xác minh; scope là authorized disposable lab và kết quả unresolved được giữ nguyên.

READY cho diagnostic rerun **khác** READY để tuyên bố mọi audited TP/SQLI-2/XSS được xác nhận đúng. Muốn dùng 40-case rerun cho kết luận khoa học cần evidence review theo tiêu chí semantic đã thống nhất và ghi rõ giới hạn authority/narrative. Không phải mọi baseline UI/environment failure đều phải sửa trước diagnostic run; không thể dùng baseline status để bỏ qua D1/D2 hoặc các vấn đề trực tiếp ảnh hưởng thực nghiệm.

Không chạy lại Official40 trong review này và không kết luận các cases cụ thể chắc chắn cải thiện sau sửa.
