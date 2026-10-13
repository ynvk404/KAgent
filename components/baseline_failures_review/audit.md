# Independent audit — 4 nhóm baseline test failures

Audit ngày 13/10/2026. **AUDIT ONLY**: không sửa production/tests, không triển khai đề xuất. HEAD: `f4d5e1626c060c734baf4d47ad0052b3119d7a87`. Source được đọc là worktree hiện tại có Phase 1 và thay đổi có trước/concurrent; không coi worktree là clean HEAD.

## Kết luận và ưu tiên

| Nhóm | Root cause | Production bug / Test bug / Contract / Environment | Ảnh hưởng thực tế | Có cần sửa? | Thời điểm |
|---|---|---|---|---|---|
| A — HTTP phase | Fixture gọi registry thiếu `phase`; argument validation chạy trước scope validation | **Test bug**, contract production đúng | Test chưa thực sự kiểm tra out-of-scope HTTP và các assertion phía sau; runner cung cấp `phase=validation` | **TEST ONLY** | Trước lần verification benchmark tiếp theo; không phải blocker runtime 40 cases |
| B — CWE receipt | Mock `prepare(tool, args)` không nhận `reviewing`/`signal` từ registry khi gọi MCP | **Test bug**, mock không khớp contract | Chỉ mock này làm enrichment dừng với `TypeError`; production classification và Evidence/Finding không lỗi trong probe | **TEST ONLY** | Khi sửa regression CWE; không bắt buộc trước Kịch bản 2 |
| C — Anthropic/Gemini retry | Encode nằm trong callback được retry; đọc lại mutable request mỗi lần | **Production bug có điều kiện** về snapshot/retry contract; test fault injection hợp lệ | Payload đổi nếu request bị sửa giữa hai sends; chưa chứng minh xảy ra trong đường Agent/benchmark chuẩn | **FIX LATER** với đường benchmark hiện tại; nâng ưu tiên nếu có caller sửa request đang in-flight | Trước khi hỗ trợ/chấp nhận shared mutable requests hoặc yêu cầu bảo đảm replay tuyệt đối trên các provider này |
| D — candidate recovery UI | UI thay lỗi đã phục hồi bằng summary; test vẫn đòi lỗi cũ trong transcript | **Test bug**, presentation contract đã đổi | Candidate/state/recovery/dedup đúng; không đổi validation result hoặc scoring | **TEST ONLY** | Khi cập nhật UI regression; không phải blocker benchmark |

- **FIX NOW:** Không có sửa production vô điều kiện được bằng chứng audit này chứng minh là bắt buộc trước Kịch bản 2. Nếu cấu hình thực nghiệm thực sự sửa request đang in-flight trên Anthropic/Gemini, C phải được sửa trước khi dùng cấu hình đó.
- **FIX LATER:** C là thiếu bảo đảm snapshot thật ở provider boundary, không nên xóa/weakening test để che lỗi.
- **TEST ONLY:** A, B, D cần cập nhật test có mục tiêu; không sửa gate/runtime để chiều assertion.
- **NO CHANGE:** Không cần đổi production ở A, B, D. Không có ca nào trong sáu ca đã tự hết lỗi.

## Phương pháp và bằng chứng

Đã đọc `AGENTS.md`, production/tests trực tiếp, [Phase 1 verification](../phase1_runtime_evidence/implementation-verification.md) và phần cấu hình/thực nghiệm liên quan trong [Scenario 2 review](../scenario2_benchmark_review/audit-design.md). Không audit lại nội dung Phase 1 hoặc ground truth/selection/scoring.

Tài liệu Phase 1 ghi nhận sáu ca cùng thất bại trên HEAD trong nguồn tạm độc lập. Đã kiểm tra artifact `/tmp/kagent-phase1-baseline-failures.xml`: có các failure tương ứng, đường source `/tmp/kagent-phase1-baseline-sns5oigg/`. Đây là đối chiếu với baseline verification đã có, không phải tuyên bố chạy lại toàn bộ HEAD trong phiên này. Các source chính của A/B/C/D như HTTP adapter, registry, CWE, providers và UI reducer không nằm trong diff Phase 1; diff `WorkflowTool` hiện tại tập trung evidence submission, không thay candidate creation/list; diff Agent không thay các vị trí request projection/event acceptance được viện dẫn ở đây.

Tái hiện bằng `venv-linux/bin/python -m pytest --import-mode=importlib -q` với đúng selectors:

```text
tests/benchmarks/test_scenario1.py::test_isolation_and_permission_boundaries
tests/cwe/test_enrichment.py::test_evidence_receipt_uses_existing_readonly_workflow_action
tests/llm/test_workflow_action_projection.py::test_transport_retry_keeps_encoded_projection_snapshot[anthropic]
tests/llm/test_workflow_action_projection.py::test_transport_retry_keeps_encoded_projection_snapshot[gemini]
tests/ui/test_candidate_recovery_contract.py::test_corrected_candidate_retry_recovers_owned_issue_once
```

Selector cuối sinh hai variants Direct/Whole-target: **6 failed, 27.52s**, cùng failure signatures baseline. Dùng importlib theo verification để tránh collection collision đã biết, không sửa pytest configuration.

Diagnostic probes ở `/tmp/kagent_baseline_audit_probes.py` dùng fixtures hiện có và fake transports, không chỉnh tests trong repository:

- A: hợp lệ hóa duy nhất `phase`; production registry chặn origin ngoài scope, không gửi HTTP.
- B: đối chiếu mock signature cũ và compatible; compatible forward kwargs vào production policy, không bypass receipt/permission.
- D: chạy đủ bad → corrected → duplicate, kiểm tra state và summary sau recovery.
- Đối chứng test hiện có: retry snapshot OpenAI-compatible/DeepSeek và CWE classification/retry/resume không patch `prepare`.

Nhóm này: **8 passed, 17.25s**. Hai probes bổ sung cho C giữ request ổn định qua 503: **2 passed, 12.27s**, body lần đầu và retry giống nhau trên cả Anthropic/Gemini. Tổng diagnostic/đối chứng: **10 passed**, tách biệt với sáu ca tái hiện thất bại. Không có live HTTP, Docker, external LLM, full suite hay benchmark 40 cases. Không chạy hai schema-budget tests và không phân tích/gợi ý thay ngưỡng hoặc tối ưu schema.

## A — Benchmark HTTP phase

**Contract:** `src/tools/http/http_tool.py:92,115,139` khai báo enum và required `phase`; `validate_args()` bác thiếu/khác `recon|validation|impact`. `Registry.execute()` trong `src/tools/common/registry.py:203–212` validate arguments trước khi `ExecutionPolicy.prepare()` tạo receipt. Sau đó policy ở `src/permission/runtime/execution.py:318` mới kiểm tra network origin. Vì vậy thiếu phase hợp lệ bị chặn trước scope là đúng.

Direct adapter callers lịch sử có thể omit phase trong một số đường `_validate_input_types()`; điều này không thay contract public registry mà test dùng. Không nên nới required field hoặc đảo thứ tự gates để test qua.

**Runner:** `benchmarks/scenario1/core/runtime.py:27–50` tạo `request_fixture` với `phase='validation'`; candidate `request_template` chứa fixture đó. `build_agent` dùng fixture cho baseline preparation; prompt yêu cầu dùng legitimate request fixture và production skill. Đây là runner dùng cho selection 40 cases trong review Kịch bản 2. Runner không omit phase ở fixture. Request do external model tự viết vẫn có thể sai; audit offline không chứng minh mọi model luôn tuân thủ contract.

**Probe:** Thêm duy nhất phase vào request ngoài scope trả `network origin http://127.0.0.2:3000 is outside the active engagement scope`; mock transport không nhận request. Không có dấu hiệu scope gate bị yếu hoặc traffic lọt ra ngoài.

**Ảnh hưởng:** Direct/native HTTP contract vẫn đúng. Burp MCP có schema/adapter riêng; failure này không chứng minh lỗi Burp. Whole-target phải truyền phase hợp lệ khi gọi native HTTP như các mode khác. Không có bằng chứng lỗi fixture này khiến 40 cases không chạy; nó làm mất coverage hữu ích của test boundary.

**Sửa tối thiểu đề xuất:** Tại `tests/benchmarks/test_scenario1.py:921`, thêm `'phase': 'validation'` cho HTTP call. Giữ các assertion origin, isolated stores, protected file writes và zero dispatch; ưu tiên assert exception cụ thể `ExecutionBlocked` nếu kiểm tra lại đúng type. Regression phải chứng minh lỗi scope với request hợp lệ và không gửi HTTP; không chỉ đổi expected text thành phase error. Không sửa runner/ground truth/scoring.

## B — CWE enrichment receipt

**Root cause chính xác:** `tests/cwe/test_enrichment.py:572` patch shared policy bằng `def prepare(tool, args)`. `Enrichment.evidence_receipt()` ở `src/findings/cwe_enrichment.py:215–230` gọi workflow `list` bằng hai positional args; bước này thành công và ghi `prepared`. Sau đó retrieval đi qua registry, gọi cùng method với `reviewing=True, signal=signal` (`registry.py:212`). Mock không nhận keywords nên `TypeError` xảy ra trước MCP RPC.

`src/ui/commands/cwe_enrichment.py:77` bắt exception, chỉ hiển thị tên loại lỗi cho exception không phải ValueError: `CWE enrichment: TypeError`, entry `error`. Mapping UI này đúng cho lỗi thật do mock tạo; đây **không phải** việc đổi success presentation từ system sang error, cũng không phải workflow `list` bị từ chối.

**Probe:** Mock cũ cho `error`, `prepared=[workflow list]`, remote calls rỗng. Mock compatible cho `system`, MCP `search_cwe` rồi `get_cwe`, persisted `CWE-862`, active receipts bằng 0. Log kwargs cho MCP đúng là `{'reviewing': True, 'signal': None}`; workflow evidence receipt nhận kwargs rỗng. Test production classification/retry/resume không patch method cũng qua.

**Ảnh hưởng:** Failure không thay kết quả validation, primary evidence hay finding eligibility. Enrichment là command operator tùy chọn trên finding đã persist, không phải điều kiện confirmation/benchmark. Finding chưa phân loại được bảo toàn khi retrieval thất bại. Các mode Direct/Burp/Whole-target không mất khả năng assessment vì lỗi mock này. Môi trường offline đã đáp ứng synthetic pinned component; không có chứng cứ lỗi packaging/environment ở ca này.

**Sửa tối thiểu đề xuất:** `tests/cwe/test_enrichment.py:572`: mock nhận `**kwargs`, chuyển nguyên kwargs sang `original(tool, args, **kwargs)`; tiếp tục assert workflow action `list`, readonly state, classification thành công và `policy.active == 0`. Có thể kiểm tra MCP dispatch giữ `reviewing=True` để mock không vô tình hạ review receipt thành dispatch receipt. Không đổi `evidence_receipt`, registry hoặc UI mapping.

## C — Provider transport retry projection

**Root cause:** Anthropic `chat()` (`src/llm/providers/anthropic.py:65–73`) retry `lambda: self._chat_once(request, signal)`; `_chat_once` mỗi lần tính model/options và encode. Gemini `chat()`/`_chat_once` (`src/llm/providers/gemini.py:129–138`) cùng cấu trúc. Gemini streaming retry `_open_stream(request, signal)` cũng encode bên trong (`:211–212,284–286`); đây là kết luận từ source, chưa phải streaming reproduction trong phiên này. Anthropic client không triển khai streaming interface.

Test responder nhận request đầu, đổi `request.tools` từ Direct projection sang Whole-target projection rồi trả 503. Retry đọc lại object đã đổi: action enum và mô tả thêm các whole-target actions. Không phải encoder tự sửa source hoặc provider trả schema khác; lỗi nằm ở re-encoding mutable input trong retry closure. `ActionView.project_tools()` deep-copy nguồn; `ChatRequest` vẫn mutable.

Đối chứng OpenAI-compatible/DeepSeek encode body trước `with_retry` (`src/llm/providers/openai.py:152,193`) và cùng test qua. Test C là fault injection có ý nghĩa cho snapshot contract; không coi là environment error chỉ vì mutation được fixture chủ động tạo.

**Contract và điều kiện:** Một lần gọi provider `chat` là một logical request; transport retry sau transient error nên replay payload của lần gọi đó. Implementation Anthropic/Gemini chỉ giữ payload tương đương khi request/options ổn định. 503 tự nó không đủ làm schema đổi; phải có mutation trước lần encode tiếp theo. Test chứng minh replacement `request.tools`, chưa chứng minh mọi dạng mutation hay mọi status. Request fields khác được đọc lại cũng có rủi ro theo cấu trúc source, nhưng không báo là đã tái hiện.

**Runtime chuẩn:** Agent derive projected view ở `_workflow_request_view()` và `_prepare_turn_request()`, rồi await provider trong `_chat_for_turn()` (`src/agent/agent.py:1730–1800,4720`). Provider retry không gọi planner/Agent để derive objective mới. Chưa tìm thấy đường này cập nhật `req.tools` trong lúc await provider. Objective live đổi cũng không tự đổi list projection đã deep-copy. Vì vậy không suy ra mọi retry trên benchmark đều đổi tool inventory. Scenario 2 review yêu cầu freeze provider/model/generation nhưng chưa xác định provider thực nghiệm; không được giả định dùng OpenAI/DeepSeek để tuyên bố C hoàn toàn không liên quan.

**Ảnh hưởng có điều kiện:** Nếu có caller/hook/concurrency thực sự sửa shared request, retry có thể quảng bá actions không phù hợp với objective snapshot, làm prompt/guidance và tool availability không nhất quán, ảnh hưởng quyết định assessment hoặc khả năng so sánh experiment. Projection chỉ là advertisement; tool execution vẫn đi qua registry, scope, workflow/evidence gates. Không chứng minh permission bypass, extra HTTP, finding sai hay scoring sai từ test này. Direct, Burp và Whole-target đều có thể dùng các provider này; rủi ro thuộc provider boundary, không phụ thuộc HTTP/MCP transport.

**Sửa tối thiểu đề xuất:** Snapshot payload và effective model/URL/options tại đầu public `chat()`; callback retry nhận snapshot đã encode, không đọc lại live `ChatRequest`. Với Gemini áp dụng cả `chat_stream()`/`_open_stream()` ở giai đoạn mở stream; không thay stream consumption/retry policy. Snapshot phải tách nested mutable dữ liệu (deep copy encoded body hoặc serialization một lần), không chỉ shallow copy request. Giữ retry counts, backoff, cancellation, status classification và permission hoàn toàn nguyên trạng.

Regression tối thiểu: giữ test hiện có cho hai provider, thêm mutation nested schema/message giữa 503 và retry để bảo đảm snapshot đầy đủ; đối chứng không mutation; Gemini stream-open 503 → successful stream với cùng body. Chỉ đánh giá payload/response và cancellation tại boundary, không đổi số retries hoặc tạo Agent attempt mới.

**Ưu tiên:** FIX LATER cho benchmark chuẩn hiện có do chưa thấy trigger mutation in-flight. Nếu experiment có trigger này hoặc yêu cầu chứng minh immutable replay cho Anthropic/Gemini, nâng thành FIX NOW trước experiment. Không chấp nhận bỏ test snapshot hoặc đổi assertion thành hai schema khác nhau là đúng.

## D — UI candidate recovery transcript

Test reject `objective_id` do runtime sở hữu, rồi retry đúng. Hai variants đều qua assertions trước dòng 62: receipt `ok`, đúng một candidate, issue đã recovered. Failure nằm ở expectation old error text trong transcript.

`src/ui/core/state.py:416–432` chủ động thay transcript entry của issue đã recovered thành `info`, dùng `presentation_label`, details `Recovered after 1 failed attempt`. Record issue vẫn giữ original error text, count và ownership. Đây là presentation contract hiện tại; không phải mất lỗi trong raw tool result hoặc structured issue.

Agent ở `_tool_result_event()` (`src/agent/agent.py:5529`) chỉ publish accepted candidate khi invocation scope khớp runtime, receipt success khớp candidate trong workflow và canonical proposal. UI dùng correlated owner để recover. Probe production bad → good → again xác nhận cả Direct và Whole-target: một candidate `queued`, objective đúng runtime, chưa có validation result; một recovered issue, lỗi cũ còn ở `issue.text`; transcript `info` với recovery detail. Duplicate không tạo thêm candidate/issue. Với Whole-target đã record input trước; không claim discovery/whole-target completion từ candidate creation.

**Ảnh hưởng:** Không regression candidate/state được quan sát. Recovery candidate creation không đồng nghĩa vulnerability confirmed hoặc evidence repair Phase 1. Direct/Whole-target không bị chặn benchmark bởi assertion wording. Burp không được tái hiện trong hai variants này; shared reducer/acceptance không có bằng chứng lỗi riêng Burp từ failure này. Benchmark thu structured exports/results, không lấy chuỗi lỗi UI làm ground truth.

**Sửa tối thiểu đề xuất:** `tests/ui/test_candidate_recovery_contract.py:62`: assert `issue.recovered`, original error trong `issue.text`, transcript `kind='info'` và recovery count/detail theo contract. Giữ/cho chạy tiếp duplicate assertions ở dòng 63–65. Bổ sung objective ownership và không có validation result nếu cần phân biệt creation recovery với assessment. Không assert toàn bộ label endpoint/wording; không khôi phục lỗi đỏ cũ sau success. Không đổi reducer, WorkflowState hay Phase 1 recovery.

## Giới hạn và trạng thái handoff

Đánh giá runtime dựa source và offline fixtures, không chứng minh hành vi external LLM/live target. Không chạy full suite, pyright, benchmark 40 cases, live HTTP, Docker hay external models. Hai schema-budget failures nằm ngoài phạm vi; không có kết luận hoặc đề xuất đối với chúng.

Worktree có thay đổi Phase 1 và thư mục Scenario 2 review khi bắt đầu. Trong audit còn quan sát thêm thay đổi ở `tests/benchmarks/test_scenario1_reliability.py` và `tests/security/test_agent_assessment.py` từ tác nhân khác; phiên này không chỉnh các files đó. Chỉ report này được tạo trong repository; diagnostic script nằm ở `/tmp`. Không commit/push/reset/clean/restore/install. Các đề xuất trên chưa được triển khai.

Handoff đã kiểm tra `git diff --check` (sạch), đọc diff report mới và xem diff/status worktree. Exit code 1 của `git diff --no-index /dev/null audit.md` chỉ biểu thị report mới có nội dung khác, không phải lỗi kiểm tra.
