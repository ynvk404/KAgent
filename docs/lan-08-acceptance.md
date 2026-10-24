# Nghiệm thu lan-08 và quyết định lan-09

Đây là lượt nghiệm thu sau [RCA](lan-08-audit.md) và
[kiểm kê 82 tool calls](lan-08-tool-history.md). Kiểm tra offline bằng mã nguồn,
transcript, captures, state và regression; không chạy lại pentest hoặc gọi model.
Baseline nghiệm thu là worktree **sau** các bản sửa RCA, gồm các thay đổi có sẵn
từ lan-06/lan-07. Patch và SHA-256 đầu lượt được lưu riêng trong `/tmp` để phân
biệt phần sửa thêm; không lấy Git HEAD làm baseline duy nhất.

Kết luận kỹ thuật: bản sửa context trước đó đúng hướng nhưng chưa đầy đủ.
Đã chứng minh và sửa thêm hai trường hợp mất handle trong cùng cơ chế reduction:
HTTP redirect nhiều nguồn ở cửa sổ gần nhất, và imported HTTP capture bị lược
bỏ ở cửa sổ cũ. Các phần còn lại được giữ nguyên. Không thay đổi kết quả gốc
`not-confirmed`, 0 Finding. Mức sẵn sàng: **Ready with limitations**, theo G.

## A. Nghiệm thu từng bản sửa lan-08

| Bản sửa RCA | Kết quả nghiệm thu | Căn cứ và phạm vi |
|---|---|---|
| `agent.py`: giữ observation handles khi elide HTTP cũ | **Cần chỉnh nhỏ; đã chỉnh** | Test cũ đúng với native HTTP cũ, nhưng chỉ gọi reducer trực tiếp. Chưa bao phủ nhiều nguồn trong recent windows và imported capture cũ; B/E có tái hiện qua dispatch thật với HTTP/model giả lập. |
| `tool_result.py`: description/error của discovery reader | **Giữ nguyên** | ID sai vẫn bị từ chối; hint chỉ đúng `workflow(list, view=sources)`. Không thêm alias/resolver hoặc đổi pattern `ds_` 64 hex. |
| `workflow_tool.py`: descriptions của baseline/source | **Giữ nguyên** | Field descriptions xuất hiện trong schema được project. Resolver vẫn từ chối observation làm replay baseline; sửa bằng cách giữ matching provenance và bỏ baseline không tồn tại là hợp lệ. |
| `admission.py`: discovery pagination notice | **Giữ nguyên** | Chỉ phân trang của capture đầy đủ, metadata và độ dài trang hợp lệ mới thành “more available”. Capture thiếu, offsets/flags sai vẫn giữ cảnh báo. Không đổi `truncated` hay capture cap. |
| `state.py`: kết thúc workflow khác lịch sử lỗi | **Giữ nguyên** | Dùng completion facts hiện tại; không tự ghép retry khác arguments và không đánh dấu lỗi cũ recovered. Blocker, pending permission, unsaved finding và stop reasons vẫn có hiệu lực. |
| SQLi Skill: nhất quán negative/unresolved outcome | **Giữ nguyên** | Sửa đúng thiếu sót ở định nghĩa tổng quát, phù hợp hướng dẫn chi tiết đã có. Không cần thêm lời nhắc lặp lại, payload, classifier hoặc acceptance gate. |

Regression RCA đã ghi nhận red/green trước và sau các thay đổi đầu tiên. Lượt
này đọc lại toàn bộ delta và tests, rồi bổ sung kiểm chứng đường dispatch và
ma trận recovery; không coi số lượng tests là bằng chứng về suy luận của model.
Không thay đổi allowed-tools, registry permission gate, scope, ownership,
evidence acceptance, schema lưu trữ, resource limits hoặc các hunks lan-06/07.

Ba tool calls lỗi lịch sử vẫn được tính đầy đủ:

- `read_discovery_source`: Agent đổi prefix `obs_` thành `ds_`; validator đúng.
  List sources rồi đọc ID thật thành công. Cải thiện description/error là đủ.
- `record_input`: Agent dùng `obs_` làm replay baseline; resolver từ chối đúng.
  Retry giữ `source_ref`, bỏ baseline không tồn tại thành công. Cải thiện schema
  description là đủ; không được nới resolver.
- `record_evidence`: ba observation IDs do Agent dựng lại đã bị từ chối đúng.
  Agent list ledger, sửa proof nguồn và đăng ký lại thành công, không probe HTTP
  thêm. Snapshot thất bại vẫn là immutable orphan; không xóa hoặc “sửa” nó.
  Lỗi upstream mất handles có thật, nhưng không chứng minh được nó là nguyên
  nhân duy nhất khiến model dựng IDs. Model còn bỏ qua chỉ dẫn copy từ ledger.

Phân loại: mất handles là lỗi hệ thống đã xác nhận và đã sửa; hai namespace
mistakes là lỗi sử dụng tool đã phục hồi, được cải thiện hướng dẫn gần điểm gọi.
Evidence rejection/repair và việc không tạo Finding là cơ chế hoạt động đúng.
Semantic SQLi và một số diễn giải inventory vẫn là hạn chế chưa được bảo đảm.

## B. Context Reduction: đường dùng chung, giới hạn và bằng chứng

Đường thực thi được đối chiếu trong `src/agent/agent.py`:

1. `run_parsed_tool_call` thực thi qua Registry và policy receipts. Native HTTP
   hoặc capture reader tạo `ToolOutput` kèm nguồn do controller cung cấp.
2. `_tool_result_event` xuất bản sự kiện đã bảo vệ cho UI/log.
   `_http_analysis_content` kiểm tra đúng loại producer, source hash/body ranges,
   session/epoch/scope và secret policy trước khi cho nội dung HTTP vào analysis.
3. `record_tool_result` tạo Message trong history và working context; chỉ khi
   analysis được chấp nhận mới đặt `http_response_sources` và runtime stamp.
   HTTP dùng ObservationStore, không biến thành generic `tr_` offload.
4. `_chat_for_turn` gọi `_prepare_turn_request`, rồi `_admit_request`:
   `_protect_http_context` kiểm tra lại access; checkpoint/`guard_working_context`
   giảm nội dung; sau đó kiểm tra hard input limit trước `client.chat`.
5. Direct và Whole-target đều đi qua đường này. Workflow view khác theo mode,
   nhưng reducer/admission không tách thành hai bản. Synthesis không có tools
   cũng đi qua `_admit_request`. OpenAI encoder chuyển nguyên `Message.content`
   vào wire tool message (`src/llm/providers/openai.py`, `encode_request`).

Hai lỗi bổ sung đã chứng minh:

- **Recent response nhiều nguồn:** native `http(max_redirects=5)` có tối đa sáu
  observations trong một response. Giảm xuống floor 2.000 ký tự bằng năm cửa sổ
  văn bản không bảo đảm các IDs ở giữa đều còn. Với sáu responses 11.000 ký tự,
  test qua `_chat_for_turn` làm mất ba trong sáu IDs ở cả Direct và Whole-target.
  Một response đơn và native output cũ vẫn đạt.
- **Imported response cũ:** `browser_capture_get` tạo observation metadata đã
  qua cùng admission. Điều kiện cũ chỉ giữ handles khi `name == 'http'`, nên
  marker của imported capture cũ mất ID ở cả hai mode. Đây là cùng lỗi bảo toàn
  metadata, không phải thiếu quyền đọc hoặc hỏng ObservationStore.

Sửa trong **một hàm `guard_working_context`**:

- Dùng một local formatter `http_references` cho metadata hiện có, dùng chung
  ở old elision và recent bounding. Không tìm IDs trong body, không tạo ID hoặc
  đổi prefix, không lookup/adopt nguồn, không thêm persistent state.
- Old output giữ marker và handles, bỏ toàn bộ response body.
- Recent output trừ độ dài metadata khỏi **chính budget đã cấp** trước khi cắt
  body, rồi ghép handles. Floor tổng vẫn là 2.000 ký tự, không cộng một allowance
  riêng sau reduction. Không giữ cả response để bảo toàn ID.
- Readers `read_http_observation`/`read_discovery_source` vẫn có policy
  `preserve`: giữ nguyên bounded page và header để kiểm tra range/ownership.
  Không áp dụng cắt cửa sổ mới vào reader pages.

Chi phí theo estimator hiện tại, không phải tokenizer/provider billing:

| Số nguồn trong một native result | Metadata | Estimated tokens metadata | Marker + metadata cũ |
|---|---|---|---|
| 1 | 131 ký tự | 33 | 197 ký tự / khoảng 50 tokens |
| 6, tối đa hiện có | 321 ký tự | 81 | 387 ký tự / khoảng 98 tokens |

Độ dài marker thay đổi nhẹ theo số chữ số của byte count. Native old output đã
có metadata từ bản RCA. Phần thêm cho recent output nằm trong budget đang dùng;
imported old output thêm một handle. Không thêm tool/model calls hoặc bản sao
lưu trữ response. Lặp admission không nối thêm metadata lần nữa.

Giới hạn phải hiểu chính xác: đây là bound theo result, không phải tổng context
cố định khi thêm vô hạn messages. Tổng metadata tăng theo số messages; lifecycle
compaction, step/call limits và hard input admission hiện có vẫn chịu trách nhiệm
giới hạn request. Test 64 messages kiểm tra độ dài/idempotence, rồi xác nhận
request vượt hard limit bị chặn trước fake model. Soft threshold có thể không
đạt khi fixed context/floors quá lớn; provider không có hard input limit được
biết trước vẫn chịu giới hạn khả năng ước lượng cũ. Không tăng budget hay giả
vờ bảo đảm một giới hạn mà provider chưa khai báo.

Tests mới dùng producer thật, Registry, admission và fake-client request để kiểm
tra một/sáu nguồn, old/recent, native/imported và cả hai mode. So toàn bộ Message
metadata ngoài content: call ID, status, HTTP flags, provenance/stamp không đổi.
History HTTP gốc và workflow không bị rewrite. Sau revoke, handles bị gỡ ở
dispatch sau; không được dùng formatter để đưa lại nguồn đã mất quyền. Metadata
controller giữ trên Message không có nghĩa mọi field tự xuất hiện trong wire:
handles cần dùng đã được đưa vào content rõ là metadata, còn semantics/ownership
phải đọc ledger và đi qua gates bình thường.

## C. SQLi Validation: điều đã biết và chưa biết

| Nhóm nguyên nhân | Kết quả kiểm tra |
|---|---|
| Runtime/tool contract | Không thấy bug làm đổi payload, status hoặc body trong bảy owned captures. Runtime nhận completed negative theo khai báo `completed_attempt=true` và proof/parents hợp lệ; acceptance không phải SQL semantic classifier. Mất handle được sửa ở B, không tự sửa khả năng chọn oracle. |
| Skill chưa rõ/mâu thuẫn | Trước RCA, định nghĩa tổng quát `not-confirmed` dễ đồng nhất hết thử với test âm tính hoàn tất; `insufficient-evidence` nhấn mạnh thiếu proof. Bản RCA đã làm rõ oracle/context. Giữ bản sửa này. |
| Không tuân thủ hướng dẫn rõ | Skill/payloads trong profile lan-08 đã nói query shape là hypothesis khi không có query text; equal TRUE/FALSE không có differential; phải thích nghi seed/prefix/suffix; hết syntax adjustments cần chốt unresolved khi chưa có oracle. Model vẫn suy full shape, đổi templates trong “pair”, mô tả sai response và chọn negative. |
| Giới hạn suy luận model | Biết SQLite syntax sensitivity nhưng không thiết lập được compatible predicate/oracle là kết quả quan sát được của run. Không thể xác định cơ chế nội bộ model hoặc cam kết prompting mới sẽ sửa được. |
| Giới hạn kiểm thử hợp lệ | SQLite không có native sleep/OOB thích hợp trong môi trường này; không được giả lập bằng tác vụ nặng hoặc thêm capability. Không có oracle vẫn phải dừng với unresolved, không buộc tạo Finding. |

Đối chiếu bảy captures: benign `apple` trả 200/921 bytes/ba rows; intended TRUE
và FALSE đều 200/30 bytes/empty; hai requests syntax khác nhau cùng 500/974
bytes/hash giống nhau; comment probe 500/942 incomplete input; expression probe
200/30 empty. Không có query text chứng minh full SQL shape. Một cặp khác
template không thành phép thử chỉ khác predicate. Empty response không chứng
minh expression đã được hoặc không được evaluated.

Corpus đã cảnh báo LIKE suffix có thể đổi truth value của quoted equality và
equal responses là inconclusive. “No data read” trong mô tả mục đích payload
không biến các product rows thực nhận thành chưa từng được đọc. Báo cáo phải
phân biệt normal response data với extraction ngoài mục đích xác nhận.

Không có archive từng outbound request lịch sử, nên chưa chứng minh được mọi
đoạn hướng dẫn/response model thực thấy sau reduction hoặc tác động riêng của
context lên quyết định SQL. Những sai khác body/status đối chiếu capture là
chắc chắn; quan hệ nhân quả với suy luận LLM chỉ có giới hạn như RCA đã nêu.

Không sửa thêm Skill/payload corpus trong lượt nghiệm thu. Test unresolved
hiện có chạy synthetic equal pair + syntax errors, đăng ký proof đúng ownership,
ghi `insufficient-evidence` thành công và không cho Finding. Điều này chứng minh
runtime hỗ trợ kết luận trung thực, không dự đoán model sẽ chọn nó. Với cùng
bằng chứng, hướng dẫn hiện tại đòi unresolved; kết quả lan-08 gốc vẫn giữ nguyên.

## D. Discovery, Input Analysis, Coverage và các giới hạn khác

Không thấy một bug runtime chung có thể sửa để giải quyết các sai sót semantic
trong Markdown. `record_endpoint`/structured inputs có identity/dedup riêng;
42 inventory rows không đồng nghĩa 42 method/path khác nhau. Ngoài hai random
calibration paths, có 40 method/path khác nhau; trước Input Analysis có 43
method/full-URL khác nhau khi tính query. Không đổi đơn vị khi báo tổng.

Skill enumeration đã yêu cầu reconciliation giữa inventory, retained sources
và structured records, tính cả nested/secret field names với values redacted.
Input Analysis đã yêu cầu reason theo đúng từng input, không suy schema/auth
từ tên route hoặc 401, và phân biệt `analyzed` với exercised/tested behavior.
Các lời khẳng định sai về `/api/Products?name=apple`, B2B status, login body,
bundle size và các trường tài liệu chưa được record là lỗi diễn giải/tuân thủ
của Agent; không có căn cứ để sửa parser hoặc storage.

`set_input_disposition` xác minh active whole-target objective/origin, enum,
reason cho blocked/dropped và terminal transitions. `analyzed` là hoàn tất triage,
không yêu cầu mọi input có probe SQLi. `phase_completion_readiness` chặn nguồn
chưa xử lý, input pending/blocked, thiếu artifact/prerequisites/required coverage;
không đọc hiểu mọi Markdown row. Vì vậy sáu analyzed inputs của lan-08 không
chứng minh sáu tests SQLi, và cũng không được tự chuyển input chưa probe sang
blocked. Những dependency thực chưa giải quyết vẫn phải để blocked/pending.

Coverage Store là projection theo endpoint/parameter/class và context. Chỉ
accepted result có evidence integrity hợp lệ mới được sync: confirmed → failed,
not-confirmed → passed; unresolved không thành một terminal coverage mark.
Một passed subcase của lan-08 đúng mapping của result đã lưu, không chứng nhận
oracle hoặc exhaustive coverage. Không đổi mapping để sửa kết luận lịch sử.

| Giới hạn/reference | Cách hiểu sau nghiệm thu |
|---|---|
| HTTP capture cap | Bytes không giữ không thể đọc lại; complete/truncated flags vẫn có hiệu lực. Không tăng cap hoặc tự refetch. |
| Context omission | Chỉ bớt text khỏi working request; observation store/history vẫn có nguồn theo hợp đồng cũ. Handles không cấp quyền đọc lại hoặc ownership. |
| Output pagination | Trang có `next_start_char` không đồng nghĩa capture mất; UI chỉ diễn đạt “more available” khi metadata/capture hợp lệ. |
| `obs_` | Observation UUID; đọc response phải có current ownership/scope/permission; discovery chưa sở hữu không được đổi thành validation source. |
| `ds_` | Discovery provenance fingerprint; copy từ source ledger, dùng discovery reader riêng. Không đổi prefix từ obs_. |
| Replay baseline | Capture-store reference với request/identity binding đã resolve; không phải obs_/ds_ hoặc sanitized sample. |
| `tr_` | Retained sanitized tool result; reader có scope/integrity/permission riêng. Không tạo replay/evidence authority. |
| `ev_` | Registered immutable proof; dùng ID thật trong result, không dùng path hoặc obs_ thay thế. |

159 debug records mất thuộc ba sequence gaps đã đối chiếu với drop notices.
`BackgroundWriter` có queue 512 records/2 MiB, producer không chờ disk; overflow
được đếm và báo bằng drop record. Test slow writer xác nhận responsiveness,
bounds và accounting; không thấy căn cứ đổi logger hoặc tăng queue. Giới hạn
này làm chronology thiếu chi tiết, không xóa tool history: đủ 82 call/results,
và full final text còn trong session. Log không thể dùng làm archive wire đầy
đủ; giữ nguyên giới hạn audit này trong kết luận.

## E. Thay đổi bổ sung tối thiểu

| File/hàm | Delta so với đầu nghiệm thu | Regression |
|---|---|---|
| `src/agent/agent.py`, `guard_working_context` | Dùng local metadata formatter thay điều kiện name-only ở old elision; reserve metadata trong recent render budget. Chỉ sửa cơ chế reduction đang có. | Native six-source recent thất bại ở hai mode trước sửa; imported old thất bại ở hai mode trước nới điều kiện đúng metadata. |
| `tests/agent/test_lan08_context.py` | Giữ test cũ; thêm 12 producer/age/mode cases và hai tests many-message/hard-limit. | Exact source set, content length, toàn bộ metadata, history/state, repeat admission, revoke và không thêm HTTP. |
| `tests/ui/test_lan08_audit.py` | Giữ tests cũ; thêm 12 trường hợp mode/retry/stop. | Retry cùng args được recovered; khác args giữ unmatched; runtime completion/history khác current blocker; max steps, context capacity, permission refusal không bị đổi thành complete. |
| `docs/lan-08-acceptance.md` | Báo cáo nghiệm thu này. | Phân biệt baseline, bugs, limitations và điều kiện lan-09. |

Không chỉnh production file nào khác, không bổ sung state/layer/solver/technique,
không sửa lại các báo cáo hoặc artifacts gốc. Diff riêng production so baseline
đầu nghiệm thu là **18 dòng thêm, 3 dòng bỏ**, được lưu
`/tmp/lan08-acceptance-own.diff` để review.

## F. Kiểm chứng và toàn vẹn dữ liệu

Các test tái hiện đã sửa lỗi setup test trước khi quy lỗi production:
helper gọi tool dùng chung call ID, Message dùng slots, và admission có thể
refresh system prompt hợp lệ. Assertions cuối chọn đúng producer/tool result,
so metadata bằng dataclass và chỉ yêu cầu HTTP history không bị rewrite.
Một lỗi import ở test mới được sửa đúng module; không đổi production để né nó.

Red/green production được ghi riêng:

- Native dispatch matrix trước recent fix: **2 failed / 7 passed**, chỉ hai
  six-source recent cases mất IDs; log `/tmp/lan08-acceptance-context-before.log`.
- Sau recent fix, trước imported fix: **2 failed / 11 passed**, chỉ hai imported
  old cases mất ID; log `/tmp/lan08-acceptance-import-before.log`.
- Cuối cùng, context group: **15 passed**, gồm 14 tests thêm vào baseline.
- Focused recovery/contracts/SQLi-unresolved/lan-06/07/logger: **140 passed**,
  log `/tmp/lan08-acceptance-focused.log`.

Pyright toàn cấu hình: **0 errors, 0 warnings, 0 informations**. Notice có
phiên bản Pyright mới không phải diagnostic; không cài hoặc cập nhật công cụ.
Hồi quy rộng: **6.894 passed, 1 skipped**, 613,63 giây; baseline **6.868 passed,
1 skipped**. Tăng đúng 26 cases (14 context + 12 UI), không bỏ/sửa yếu assertions
cũ hoặc thay skip semantics. Log: `/tmp/lan08-acceptance-regression.log` và
`/tmp/lan08-acceptance-pyright.log`. `git diff --check` đạt; đã đọc diff riêng
lẫn diff worktree và kiểm tra `git status --short` trước bàn giao.
Lệnh so baseline giữ cùng tám responsibility groups và tắt các live opt-ins:

```bash
env -u KAGENT_RUN_LIVE_TOOL_CHARACTERIZATION \
    -u KAGENT_S1_EXISTING_CONTAINER -u KAGENT_SYSTEM_LIVE \
    venv-linux/bin/python -m pytest -q \
    tests/agent tests/skills tests/tools tests/state tests/integration \
    tests/llm tests/ui tests/security --tb=short
venv-linux/bin/pyright
git diff --check
```

Đối chiếu SHA-256 của 52 files baseline nghiệm thu và 27 files thực nghiệm:
chỉ ba code/test files thuộc E thay đổi bởi lượt này. 25/27 files thực nghiệm
giữ nguyên hash; JSONL/context Markdown được TUI ngoài tác vụ tiếp tục cập nhật.
Prefix JSONL gốc 1.012.767 bytes và prefix đầu nghiệm thu đều giữ nguyên hash;
events nối thêm ở lượt này chỉ là `context_snapshot`. Không restore các updates
đó hoặc khẳng định file đang được TUI ghi là byte-identical.

Session/observations/coverage/permissions/profile/skills/artifacts và cả hai
immutable proof snapshots giữ nguyên. Đọc lại runtime state: đúng một result
`not-confirmed`, candidate binding đúng, `accepted_result=true`,
`coverage_synced=true`, `eligible_for_finding=false`, persisted findings bằng 0.
Cả hai snapshot hash khớp tên và mode 0400. Không thêm authority hoặc sửa seal.

Không chạy `tests/live`, external model characterization hoặc target assessment;
HTTP trong tests dùng `httpx.MockTransport`, model dùng fake client. Không cài
package, commit/push hoặc stage/restore các thay đổi có sẵn.

## G. Quyết định lan-09

**Ready with limitations** cho một thực nghiệm có kiểm soát trên profile mới,
với code/skills sau nghiệm thu. Các cơ chế giữ references, evidence rejection
và recovery, workflow gates và TUI được kiểm tra offline; không có căn cứ yêu
cầu thay kiến trúc hay mở rộng quyền/budget để chạy tiếp.

Điều kiện cụ thể:

1. Giữ nguyên target/scope và authority mới của phiên lan-09; không lấy approvals,
   owned observations hoặc completed state của lan-08 làm quyền cho phiên mới.
2. Kiểm tra semantic conclusions theo captures: unresolved oracle/context phải
   ghi `insufficient-evidence`; `not-confirmed` cần bounded test hợp lệ với
   established oracle. Không buộc có Finding hoặc coi 0 Finding là thất bại.
3. Review reconciliation và counting unit; không diễn dịch analyzed inputs hoặc
   coverage passed thành số tests SQLi/exhaustive assessment.
4. Chấp nhận giới hạn capture/log/context được báo rõ. Metadata giữ được không
   chứng minh model đã đọc đúng body hay sẽ tuân thủ playbook. Test scripted không
   thay thế kiểm chứng chất lượng suy luận của một run mới.

Chưa có căn cứ kết luận sẵn sàng cho đánh giá tự động không review hoặc bảo đảm
kết luận SQLi luôn đúng. Hạn chế đó được để rõ, không che bằng test xanh, prompt
lặp lại hoặc chỉnh kết quả lan-08.
