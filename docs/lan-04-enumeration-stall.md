# lan-04 — Enumeration stall: điều tra và sửa offline

## Phạm vi và tính toàn vẹn

HEAD trước sửa: `742594f`. Worktree đã xóa `docs/lan-02-root-cause-verification.md`
và `docs/lan-03-audit.md`; giữ nguyên hai thay đổi đó. Trước sửa, SHA256 của
242 runtime files và 9 skill files khớp manifest
`experiments/scenario3/profiles/lan-04/profile.json`.

Nguồn điều tra: `runs/lan-04/logs/{session.jsonl,kagent.log}`, session
`8381259d-2ee8-4006-b808-93ead4fc95f4.json`, persisted WorkflowState,
observation store và artifacts trong chính run đó. Dữ liệu lịch sử chỉ được
đọc; không chạy lại target/model. Debug logger đã drop 339 records. Không có
snapshot toàn bộ wire request từng bước; không khẳng định có thể phục dựng
chính xác byte-for-byte mọi prompt đã gửi provider.

## Bằng chứng đã xác nhận

- History có 30 tool calls/results: 11 shell, 8 native HTTP, 4 result reads,
  2 load_skill và 5 calls khác. Chỉ một workflow call: hoàn tất Recon.
  Không có `record_input`, `record_phase_coverage` hoặc Enumeration completion
  call bị reject: agent chưa hề đề xuất chúng.
- `seq=139` load Enumeration; tool result được lưu có 37.516 ký tự, bao gồm
  yêu cầu ghi input ngay trước khi fetch tiếp. Không phải thiếu chỉ dẫn này
  trong playbook. Không có compaction trong run.
- `seq=381` shell đọc literal `swaggerDoc`; `seq=388,395,434` đọc thành công
  qua `tr_ce13351d9d5c44949103fe3f83817802`. Nội dung hiển thị xác lập server
  `/b2b/v2`, POST `/orders`, JSON body Order; `cid` required string,
  `orderLines` array và `orderLinesData` string cùng nested OrderLine schema.
  Read cuối kết thúc ở offset 4552/4562, còn thiếu 10 ký tự cuối của output;
  không gọi toàn bộ reader output là đã đọc hoàn chỉnh. Các trường trên đã
  nhìn thấy trước khi chuyển sang SPA, đủ để ghi documented inputs.
- Có hai HTTP observations initializer đầy đủ, mỗi bản 5.457 bytes:
  `obs_0e0a5d32093343199de84cf8806ea729` và
  `obs_1c3336282d324ae48d49961ef78c7f88`. Đây là brokered shell HTTP;
  không tự biến thành một admitted discovery source cho manual attribution.
- `seq=464` chuyển sang main.js, `509–510` tải 10 chunks và chỉ in route
  strings; `538–539`, `567–568` tìm tiếp nhưng không có endpoint context mới.
  Route strings `/rest/user/login`, `/api/Users`, `/api/Feedbacks` không tự
  chứng minh POST schema email/password/comment. Không dùng lời tổng kết của
  model để bổ sung những schema chưa có bằng chứng.
- Canonical state cuối: chỉ Recon hoàn tất, không inputs/candidates/attempts,
  8 discovery sources đều unselected/pending, Enumeration chỉ có coverage
  `html_navigation=performed`; không có inventory. Observation store có
  36 records (25 HTTP gồm cả shell broker, 11 shell output).
- `seq=469`: phase exploration credit đạt cap hiện có 8. Bốn iterations sau
  không có structured progress; `seq=1430` dừng `workflow_stalled` với
  `no_progress=4`, không phải max_steps=60 hoặc runtime crash. Tổng 23 loop
  calls + 1 synthesis, hai requested goals vẫn pending. Không thay cơ chế này.

## Guidance thực sự khả dụng và khoảng trống

`load_skill` cung cấp playbook có incremental handoff và bounded review.
`Agent._prepare_turn_request` gọi `_workflow_request_view` trước model dispatch,
thêm planner guidance, recorded workflow và action guidance. Với Enumeration
chưa ready, planner nhắc phase/artifact/coverage. `source_frontier_guidance`
chỉ đưa chỉ dẫn record_input trước reconcile khi **source đã selected**.
Trong run này không source nào selected, nên nhánh đó không phát ra.

Action guidance cũ chỉ nhắc “inventory endpoints/sources/inputs; inspect coverage
gaps”, cộng thông tin record_input *may* có manual attribution; không nhắc lại
thứ tự ghi input trước fetch tiếp hoặc chuyển giao với partial inventory.
Đây là khoảng trống trong lời nhắc tại request boundary, không phải lỗi gate
không cho record_input, không phải mất WorkflowState và không phải bắt buộc đọc
hết JS. Không thể suy ra nguyên nhân nội tại duy nhất khiến LLM bỏ qua playbook.

Bản sửa Enumeration chỉ đổi runtime tại `src/agent/action_guidance.py`: nhắc rõ
ghi từng input có bằng chứng trước resource tiếp theo kể cả source chưa selected;
phân biệt document attribution với request/replay authority; ghi inventory có
giới hạn, coverage trung thực và chỉ complete khi ready. Không parse/infer schema,
không tự ghi dữ liệu hoặc tự hoàn tất phase. Không thay planner, scheduler,
budget, tool, permissions, filesystem roots hay evidence guards.

## Ba lỗi tool

| Log | Kết luận |
| --- | --- |
| `seq=280–282`, read_tool_result nhận `obs_037c…` | Sai namespace: reader yêu cầu published `tr_…`. Guard đúng; không có bằng chứng cache mất. Ba reads đúng tr_ sau đó thành công. |
| `seq=342–343`, shell exit 133 | Stderr xác nhận Node/V8 `Failed to reserve virtual memory for CodeRange`. Shell worker có RLIMIT_AS 512 MiB. Lỗi chọn runtime không phù hợp giới hạn, không chứng minh máy hết RAM. Không nâng giới hạn; local sed/readback đã phục hồi được việc đọc schema. |
| `seq=373–374`, file_read `/work/artifacts/worker/swagger-ui-init.js` | `/work` là namespace worker, còn file_read kiểm tra host path trong profile root. Guard file-outside-profile đúng. Không cần mở root; dùng project path tương ứng hoặc local worker read dưới quyền hiện có. |

Các cảnh báo HTTP body truncated phản ánh retained prefix, không phải toàn bộ
dữ liệu nằm trong result cache. Bản sửa không refetch/increase caps để bù bytes.
HTTP 500 ở guessed Swagger URL không phải bằng chứng SQLi/XSS.

## Kiểm chứng

- Hai regression cases trước sửa fail đúng tại model-facing action guidance
  thiếu ưu tiên incremental recording; sau sửa pass. Có trường hợp hydrate
  state và request Continue, không dựa vào source selection hay candidate.
- Regression dispatch qua production Agent/registry: dùng literal OpenAPI
  lan-04 được copy làm offline fixture, cấp dưới dạng offline document capture;
  ghi ba top-level Order inputs với manual document attribution, không có
  baseline/replay authority; save/load, reload skill theo contract, file_write
  inventory, ghi coverage observed/skipped với lý do, complete Enumeration và
  chuyển input_analysis. Không tự tạo discovery-source IDs từ shell observations.
  Thiếu inventory hoặc coverage vẫn chưa ready. Không sinh Candidate/evidence.
- Fixture intentionally giới hạn ở top-level fields; ghi rõ nested fields và
  SPA coverage chưa xử lý. Không tuyên bố đây là enumeration đầy đủ của lab.
- Targeted suite: **228 passed** trên phase/planner/request preparation,
  regression lan-04, manual discovery, whole-target workflow offline,
  web-enumeration/inline OpenAPI và workflow tools.
- Pyright hai Python files thay đổi/thêm và toàn repository theo
  `pyrightconfig.json`: **0 errors, 0 warnings**.
- `git diff --check` và whitespace check cho các tệp mới: pass; đã inspect
  diff/status cuối, giữ nguyên hai docs bị xóa từ trước.

Không chạy LLM/API, live target hay live Whole-target. Các tests có whole-target
state đều offline. Không commit/push. Tests chứng minh guidance đến đúng request
và các hành động hợp lệ có thể hoàn tất phase; không chứng minh LLM thực tế sẽ
tuân thủ hoặc lịch sử lan-04 đã được sửa hồi tố.

## Sửa tiếp lỗi nhầm observation/result reference

Theo yêu cầu tiếp theo, đã sửa riêng reader contract và lỗi diagnostic:

- `src/tools/common/tool_result.py`: description và result_ref schema công bố
  chính xác định dạng `tr_` + 32 hex, phân biệt `obs_`, cấm đổi prefix/tự tạo ID.
- `src/agent/tool_results.py`: lookup trả lỗi an toàn riêng cho `obs_`; nếu không
  có published tr_ thì ghi limitation, không rerun hay tạo validation ownership.
- `src/agent/agent.py`: bảo toàn `InvalidResultReference` qua skill admission.
  Trước sửa, nhánh này bắt mọi ValueError và che lỗi sai namespace thành
  “tool result reference unavailable”; regression tái hiện được lỗi đó.
- `tests/agent/test_tool_result_offloading.py`: thêm bốn cases kiểm tra schema,
  lỗi qua Agent khi có/không active skill, không tự map ID cùng suffix, valid
  tr_ vẫn đọc được, unknown tr_ vẫn unavailable và không echo dữ liệu caller.

Kiểm chứng bổ sung: **150 passed** trên tool-result offloading/store, workflow
request preparation và regression Enumeration lan-04. Pyright bốn Python files
của bản sửa reader: **0 errors, 0 warnings**. Diff/whitespace check pass.
Không thay quyền đọc, cache ownership, session/scope checks hoặc observation
reader. Không chạy provider/live target. Không bảo đảm model sẽ không bao giờ
truyền nhầm, nhưng contract và lỗi trả về nay phân biệt rõ hai namespace.
