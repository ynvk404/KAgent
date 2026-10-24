# lan-08: điều tra nguyên nhân gốc và hồi quy

## Kết luận

lan-08 lưu **1 Candidate, 1 ValidationAttempt, 1 EvidenceArtifact được đăng ký,
1 ValidationResult `not-confirmed`, 0 Finding**. Runtime kết thúc bằng
`workflow_completed`, không phải max steps, anti-stall hay permission denial.
Kết quả này có provenance/integrity hợp lệ; điều đó không chứng nhận kết luận
SQLi của LLM. Oracle chưa được xác lập nên cách gọi kết quả là “bounded negative”
mạnh hơn bằng chứng và trái với hướng dẫn chi tiết của playbook.

Đã xác nhận lỗi giảm context làm mất observation handles, lỗi TUI gộp lịch sử
operation errors vào công việc workflow, và cách trình bày pagination gây nhầm
với mất capture. Bổ sung hướng dẫn ngay tại schema/error của hai namespace
reference; làm rõ định nghĩa outcome sẵn có. Không thay đổi kết quả lịch sử,
ngưỡng xác nhận, quyền, scope, budget hay Finding acceptance.

Đây là kiểm toán offline. Không gửi HTTP tới mục tiêu, không gọi model/provider,
không chạy lại thực nghiệm, không cài package, commit hoặc push.

## A. Dữ liệu, phiên bản và khoảng thiếu

Root dữ liệu gốc: `experiments/scenario3/runs/lan-08/`. Profile:
`experiments/scenario3/profiles/lan-08/profile.json`.

Đã kiểm kê toàn cây, đọc JSON/JSONL, giải mã captures, đối chiếu transcript,
tool events, artifacts và workflow. [Chỉ mục đầy đủ](lan-08-tool-history.md)
liệt kê 82 lời gọi với iteration, thời gian, seq, tham số chính, kết quả và
toàn bộ 58 HTTP observations. Các tham số lỗi được ghi đầy đủ bên dưới.

| Nguồn | Nội dung và vai trò |
|---|---|
| `backup/project-intelligence.jsonl` | 689.130 bytes, 616 bản ghi; SHA-256 khớp profile |
| `backup/personal-intelligence.jsonl` | 560.070 bytes, 509 bản ghi; SHA-256 khớp profile |
| `logs/kagent.log` | Startup PID 195472 và đúng 3 lỗi tool; không có stack-watchdog dump trong cây |
| `logs/session.jsonl` | 82 tool-call / 82 tool-result; decisions, progress, assistant deltas, terminal event |
| `profile-home/.kagent/sessions/135686eb-ee21-4663-b266-c9e22827d7c5.json` | 145 messages, system/scope/user, tất cả calls/results, skill bodies, final answer; workflow và engagement state |
| `profile-home/.kagent/context/135686eb-ee21-4663-b266-c9e22827d7c5.md` | Bản chụp context định kỳ sau lượt chạy; bản trình bày từ history, không phải payload outbound mỗi request |
| `project/.kagent/observations/*.json` | 58 observations, 232.168 retained bytes; 51 unowned và 7 owned; 10 captures truncated |
| `project/.kagent/coverage/*.json` | 1 entry `passed`, đúng subcase của Candidate; đồng bộ từ `not-confirmed` |
| `project/.kagent/permissions/*.json` | Không revoke/deny còn lại; origin 127.0.0.1:8081, rate 3/s, burst 3, concurrency 2, response cap 65.536; 81 admitted tool calls |
| `project/.kagent/evidence/**` | Hai immutable snapshots 4.577 bytes, mode 0400, content hash khớp tên; chỉ bản sửa được đăng ký |
| `project/.kagent/tool-results/**` | 1 retained content-discovery result: 6.542 ký tự, hash `6748af48…`; `.lock` rỗng không phải transcript |
| `project/artifacts/**` | 4 tài liệu: recon summary, enumeration inventory, input-analysis candidates, SQLi proof; không có finding |
| `project/skills/**` | 9 tệp snapshot khớp profile; 4 playbook hoạt động là recon, enumeration, input analysis, SQLi |
| `launch-started.json` | v4 isolation, TUI, không prompt tự chạy, không max-steps override, YOLO false lúc launch |

Backup là bản sao intelligence **trước** thực nghiệm, ngoài project root mới;
không phải bản backup của session hay snapshot runtime sau chạy. Profile-home
không chứa bản Config riêng. Launcher dùng Config gốc được hash trong manifest,
chuyển storage root bằng adapter. Không suy ra credential hay toàn bộ Config
lịch sử từ Config hiện tại.

Launch marker ghi YOLO=false nhưng permissions_status ở iteration 1 ghi
YOLO=true, khớp banner người dùng cung cấp. Launcher ghi invocation ban đầu;
TUI có đường toggle YOLO trong phiên. Không có event lưu thao tác toggle để
khẳng định thời điểm/cách bật cụ thể. Đây không phải bằng chứng launcher đã
tự ý cấp quyền. Scope vẫn đúng một origin và permission/resource gates vẫn
được kiểm tra ở các calls.

Trước khi sửa, cả **226 runtime files, 9 skill files, 5 component files** đều
khớp SHA-256 trong profile; script `experiment_profile.py`, launcher
`run_experiment.sh` và profile hash trong launch marker cũng khớp. Vì vậy các
thay đổi lan-06/lan-07 đang có sẵn trong worktree **đã có khi chạy lan-08**.
Không dùng Git HEAD như thể đó là phiên bản đã chạy. Bản sửa lần này được phân
biệt với diff có sẵn từ đầu nhiệm vụ.

Ba khoảng thiếu seq trong debug log: **2176–2221 (46), 2223–2327 (105),
2329–2336 (8)**, tổng 159 records. Có đủ ba `debug_records_dropped` tương ứng.
Chúng nằm trong đoạn stream final synthesis; tất cả tool-call/result xảy ra
trước đó và đều có mặt trong cả log và session. Final answer hoàn chỉnh còn
trong message 144. Không thể khôi phục loại/nội dung/timestamp chính xác của
từng record bị drop; không tự điền chúng bằng delta suy đoán.

`FileSessionDebugLog` ghi các event đã redaction, không lưu request wire gửi
provider. Session lưu history, không lưu từng bản working request sau guard,
schema projection và chỉ dẫn planner tạm thời. Có thể đọc hướng dẫn gốc,
toàn bộ tool history và truy vết biến đổi bằng mã khớp hash; **không thể tuyên
bố đã thu được nguyên văn toàn bộ outbound LLM payload của từng bước**.
Không có per-call token usage hoặc bill trong bundle; context diagnostics là
ước lượng, không phải giá thành. Không có compaction model call: memory=null,
done event ghi compaction=0. Mid-turn reduction vẫn hoạt động.

Trong lúc kiểm toán, tiến trình TUI gốc vẫn ghi context snapshot định kỳ. Log
JSONL gốc 1.012.767 bytes còn nguyên như một prefix có SHA-256 khớp; các dòng
mới kiểm tra đều là context_snapshot. Tệp context Markdown cũng được tiến trình
đó cập nhật. Kiểm toán không ghi/restore các tệp này; session, captures, evidence,
coverage, skills, artifacts và backup gốc giữ nguyên hash. Không tuyên bố cả
cây đứng yên khi tiến trình ngoài vẫn đang chạy.

## B. Tái dựng theo thời gian

Thời gian dưới đây là **23/10/2026, UTC+07 (Asia/Saigon)**; JSONL gốc dùng UTC.

| Giờ / iterations | Diễn biến thực tế |
|---|---|
| 20:21:49 | Startup PID 195472, DeepSeek / deepseek-flash, streaming; fresh session, target đúng origin |
| 20:22:03 / 1–6 | User giao Whole-target SQLi. Load recon + permissions; 2 HTTP; ghi summary; 1 TCP discovery port 8081; complete recon |
| 20:22:19–20:23:44 / 7–32 | Load enumeration; HTTP metadata, products, bundle, Swagger; sai ds_ ở 14; đọc nguồn và initializer; ghi 6 inputs; baseline error ở 24, retry 25; content discovery ở 26; 2 retained-result pages; inventory/coverage; complete enumeration |
| 20:23:45–20:24:24 / 33–42 | Load input analysis; get 2 canonical inputs; 2 quote probes + 2 benign requests; ghi 1 SQLi Candidate; 6 dispositions analyzed; artifact; complete input analysis |
| 20:24:27–20:24:34 / 43–46 | Load SQLi; payload pages 0–8234 và 8234–13182; start validation thành công |
| 20:24:37–20:24:58 / 47–53 | 7 owned HTTP observations: control, TRUE/FALSE, 2 syntax changes, comment, controlled-expression attempt; 1 local response-range read |
| 20:25:08–20:25:30 / 54–59 | Ghi proof sai 3 IDs; evidence rejected ở 55; list ledger 56; sửa local proof 57; register evidence 58; record result 59, coverage synced |
| 20:25:37 | Tool-free final synthesis; done=`workflow_completed`, actionable=0, blockers=0; TUI báo sai “workflow work remains” do hai operation errors chưa ghép được retry |

59 outer iterations / 59 agent-loop calls + 1 final synthesis = **60 LLM
calls lịch sử**, không có compaction. Hard limit là 60 outer iterations;
final synthesis không phải iteration 60. Chưa hết step budget. Không có lần
thử tiếp tục hay closure tự động do max_steps trong lan-08.

| Tool | Calls | Outcome |
|---|---:|---|
| workflow | 31 | 29 success, 2 error |
| http | 26 | 26 observation |
| read_discovery_source | 8 | 7 success, 1 error |
| load_skill | 4 | success |
| file_write | 4 | success |
| read_tool_result / read_payloads | 2 / 2 | success |
| permissions_status / service_discovery / content_discovery / read_http_observation / file_edit | mỗi tool 1 | success hoặc observation |
| Tổng | 82 | 51 success + 28 observation + 3 error; không pending/cancelled |

HTTP thực tế: 26 direct + 32 trong discovery = **58**. Discovery gồm 2 random
wildcard controls và 30 paths, nhận 28 discovered / 2 rejected. Permission
counter 59 còn tính một TCP connection qua `socket_budget`, không phải mất
một HTTP capture. Tool quota 81 khác calls 82 vì invalid_args bị từ chối
trước policy admission. Không suy ra thất lạc dữ liệu từ hai bộ đếm này.

## C. Mọi lần gọi tool thất bại và phục hồi

Không đánh đồng HTTP 4xx/5xx với tool failure. Có 10 HTTP 500, 8 HTTP 401,
1 HTTP 403; chúng đều là captured observations. Chỉ **3** tool calls dưới
đây có status=error, khớp cả session, JSONL và application log.

### C1. read_discovery_source: ID được đổi prefix từ observation

**20:22:36.685, iteration 14, seq 277/278**, call
`call_00_2gQcojCAj55el4YFw0Fj5241`:

```json
{"discovery_source_id":"ds_9646bef611e44f8ea9ff9f9e3d554c15","start_char":0,"max_chars":2000}
```

Lỗi gốc: `ERROR: use an exact ds_ source ID and bounded integer character offsets`;
`invalid_args`, 0 ms. Agent lấy suffix của
`obs_9646bef611e44f8ea9ff9f9e3d554c15` (Swagger UI), đổi prefix thành ds_.
Discovery IDs là fingerprint 64 hex của provenance, không phải alias của UUID
observation. Schema pattern đã đúng và từ chối đúng, không cần nới validator.

Seq 284/285 (`list`, view=sources, limit=20) trả mapping thật. Seq 291/292
đọc thành công ds_ `e41e53a43a53cc9fd1196952cfaa11434e0de8c27187bb5ea304aee415b70848`,
start=2400, max=2000; nhận 2400–3106, next=null. Sau đó HTTP initializer hợp lệ.
Không refetch Swagger UI và không mất capture.

**Nguyên nhân:** LLM dùng sai namespace; description/error reader chỉ nói exact
ID, không chỉ cách tìm ID; playbook/action guidance có hướng dẫn nhưng không
được tuân thủ. Sửa tối thiểu description/error để chỉ `workflow(list,
view=sources)` và cấm đổi prefix obs_. Không thêm lookup tự động. Phục hồi dữ
liệu hoàn toàn; phát sinh một thất bại, một metadata lookup và một lần đọc lại
nội dung đã có. TUI không ghép retry vì request identity thay đổi, xem E.
Mức chắc chắn cao; khả năng tái diễn ở mọi discovery source có namespace này.

### C2. record_input: observation không phải captured replay baseline

**20:22:59.998, iteration 24, seq 476/477**, call
`call_00_XVZjUQtRDtP8VHyk6eLO1337`:

```json
{"action":"record_input","baseline_request_ref":"obs_055d264c9cbd4ba89855c289d448b501","content_type":"application/json","endpoint":"/rest/user/login","input_type":"string","location":"json","method":"POST","parameter":"email","sample_payload":"{\"email\":\"{INJECTION_POINT}\",\"password\":\"[REDACTED]\"}","source_ref":"obs_055d264c9cbd4ba89855c289d448b501"}
```

Lỗi gốc: `baseline_request_ref replay capture unavailable or request/identity
binding mismatch; use source_ref for observation provenance`; workflow_state,
6 ms. `_record_input` kiểm tra source HTTP đúng method/origin/path, rồi
`_validate_replay_baseline` gọi scoped capture-store resolver; obs_ không thuộc
replay namespace nên bị từ chối trước add input. Không phải capture bị mất,
auth bị hỏng hay binding của observation sai.

Call sibling password tại seq 478/479 không gắn baseline và thành công ngay.
Agent retry email tại **20:23:02.468, iteration 25, seq 485/486**, giữ nguyên
source_ref, bỏ riêng baseline không hợp lệ. `ok=true, created=true`, input
`input_225b4d9ff3ca21177449`, baseline=null. Đây là sửa đúng loại reference,
không phải bỏ provenance để né kiểm soát. Hai login input không bị tạo trùng.

**Nguyên nhân:** schema trường này không có description; enumeration chỉ nhắc
“separate request-context contracts”, trong khi input-analysis giải thích kỹ hơn
ở phase sau. Runtime rejection và hint đã đúng. Thêm hai descriptions sẵn có:
baseline phải từ capture-store, obs_ chỉ là matching request provenance;
document fields dùng attribution. Chỉ đổi lời giải thích, không schema shape,
resolver, scope hay permission. Phục hồi hoàn toàn; tốn một retry/outer step;
không đủ dữ liệu tính tiền. TUI vẫn giữ operation error vì recovery_identity
hash toàn bộ arguments, gồm baseline đã thay đổi.

### C3. record_evidence: ba IDs được dựng lại thay vì copy

**20:25:11.970, iteration 55, seq 1555/1556**, call
`call_00_RpJ2IvHr0BSFokFyQKX52060`:

```json
{"action":"record_evidence","candidate_id":"cand_dc84353ab8934993b033","evidence_path":"artifacts/sql-injection/127-0-0-1-8081/cand_dc84353ab8934993b033-proof.md","observation_ids":["obs_8bbeb0c8568443688349af87498281b3","obs_286765a8a51c4a0d9e9c8f2e0ebe8b6f","obs_70f6f8bd5378439086d9d328f9c7a4ad","obs_9f6a41f2ab764e4e8dd0e1cb3f3e62ff","obs_8fad4a2dfdce46948e2021c9a7b3d6e6","obs_bd56416560044f70822e317ad0eb6b2d","obs_f78c247d5dd2458e90571a9de32ac50b"]}
```

Lỗi gốc: `error: primary evidence reference unavailable`, structured code
`PRIMARY_REFERENCE_UNAVAILABLE`, repair_kind=manifest, workflow_state, 33 ms.
Hint yêu cầu đọc ledger, dùng đúng current owned references, sửa source proof
và phụ thuộc, đăng ký lại, không recapture HTTP, không sửa immutable snapshot,
không reset budget. Guard đã đúng; không hạ bất kỳ điều kiện nào.

| ID sai | ID thật cùng request |
|---|---|
| obs_286765a8a51c4a0d9e9c8f2e0ebe8b6f | obs_37b5c4549cbb414c95263930f502c815 |
| obs_70f6f8bd5378439086d9d328f9c7a4ad | obs_3953c680d581477786cd67ee211dae7f |
| obs_9f6a41f2ab764e4e8dd0e1cb3f3e62ff | obs_be08aba6d19c47198861d93be6ea2309 |

Ba ID sai xuất hiện lần đầu trong proof write (message 132, iteration 54),
không phải ID từ tool, examples hay nguồn của attempt khác. HTTP outputs
message 120/122/124 chứa ID thật; observation store và attempt effects giữ
nguyên. Agent thừa nhận “invented … from memory” tại message 136.

**Nguyên nhân runtime có thể tái hiện:** `guard_working_context` chỉ giữ bốn
tool outputs gần nhất, thay HTTP outputs cũ bằng marker tổng số bytes khi có
áp lực context. `http_response_sources` vẫn trên Message nhưng không nằm trong
content gửi LLM. Chính các HTTP outputs 120/122/124 đã thành outputs cũ trước
proof; control 118 cũng cũ nhưng ID được lặp lại trong assistant 119 nên còn
copy được. Outputs 125/127/129/131 gần hơn vẫn có handles. Có 53 context
diagnostics và áp lực trên soft threshold 32.000, không phải thiếu bytes trong
ObservationStore. Không có từng outbound snapshot nên không khẳng định biết
chính xác mọi ký tự của request lịch sử; việc mất handles do guard là lỗi
deterministic đã tái hiện và pattern phù hợp chặt chẽ với ba IDs bị đoán sai.
LLM còn bỏ qua chỉ dẫn inspect inventory trước proof, nên không thể quy toàn
bộ lựa chọn của model cho runtime hoặc bảo đảm metadata fix sẽ triệt tiêu nó.

**Bản sửa:** khi elide HTTP cũ, giữ danh sách exact handles từ trường controller
`http_response_sources` trong marker nhỏ, ghi rõ metadata only và inspect
workflow list. Không parse ID từ body, không giữ traffic cũ, không tạo source,
quyền hay ownership; outbound source checks và evidence validation giữ nguyên.
Không thêm store, state, API hay reader. ID giúp tra ledger, không phục hồi
response hoặc chứng nhận lời diễn giải.

**Phục hồi thực tế:** seq 1582/1583 list candidate/limit=25 trả đủ 7 observations
(next_observation_offset=null); seq 1607/1608 file_edit sửa đúng ba hàng local
proof; seq 1614/1615 đăng ký lại với ID thật, `ok=true`. Result tại seq
1653/1654 dùng `ev_e7af19831b8818e931b2` và cả 7 sources thật. Không có HTTP
mới sau iteration 53. TUI nhận diện lần phục hồi này bằng candidate/attempt
operation owner, đổi dòng thành “Recovered after 1 failed attempt”.

Snapshot từ lần thất bại có hash `2aff2349…`, vẫn tồn tại nhưng **không** nằm
trong evidence/evidence_sources của workflow. Snapshot mới `8b889e3a…` có đúng
parents. Đây là publish-before-registration staging, không phải evidence sai
được nhận hoặc snapshot bị ghi đè. Không xóa orphan trong kiểm toán. Chi phí
thực tế: thêm rejection/list/edit và 3 iterations so với registration thành
công trực tiếp; khoảng 4,6 KB snapshot thêm, một evidence rejection. Không mất
observation hoặc tăng HTTP. Không có dữ liệu giá thành model.

## D. Discovery, validation và các bất thường khác

### D1. Ba loại cắt dữ liệu khác nhau

1. **Capture cap hợp lệ:** `/main.js` wire Content-Length 783.506, retained body
   đúng **8.192 bytes**, complete=false. Khoảng 9,7 KB là cả tool output với
   headers/metadata, không phải body prefix. `/`, sitemap, ftp, Products và
   swagger.json cũng có direct captures truncated theo cap đã chọn. Discovery
   giữ tối đa 16 KiB/body; Challenges có thể dài hơn sau decode/redaction,
   vẫn flagged incomplete. Không có full bundle bí mật trong retained store
   để đọc tiếp ngoài capture. Không tăng cap hoặc tải lại.
2. **Context omission:** Swagger initializer có đủ 5.457 bytes, complete=true.
   Mid-turn guard bỏ nội dung inline cũ; reader đọc lại source hiện có dưới
   quyền từng range. Sáu pages 0–4700, không đọc tail 4700–5457 bằng reader;
   toàn bộ initializer từng được capture inline. Không thể gọi sáu pages là
   full-file read; phần paths, fields và security đã nằm trong các pages.
   TUI thấy `truncated=true` vì **còn trang**, dù adapter_truncated=false và
   capture complete=true. Sửa presentation để hiển thị range/total/more,
   chỉ khi metadata và capture flags hợp lệ; vẫn warning nếu capture thiếu,
   metadata sai hoặc tool failure. Không sửa output, offsets, flags hay caps.
3. **Output row pagination:** content_discovery preview chỉ có 20/28 rows,
   retained result đủ 28, 6.542 chars, hash đúng. Hai read_tool_result calls
   trả 5800–6542 và 4650–5750; không chứng nhận đã đọc byte gap 5750–5800.
   Không có collection loss. `complete=true` là operation đã chạy xong,
   `truncated=true` trong preview là thiếu rows, body_truncated là từng body.

Hai payload pages đọc đúng offsets do tool trả, đủ phần boolean cần dùng;
corpus còn tiếp không phải thiếu kỹ thuật đã chọn. Không có lý do tăng context
window, response cap, số pages hoặc giới hạn thử cho thực nghiệm này.

### D2. SQLi: tín hiệu thật, suy luận shape quá mạnh và negative chưa đủ cơ sở

Candidate `cand_dc84353ab8934993b033`, attempt
`attempt_716a1aa80f7348aa87c7c3b8c8f4e920`. Seven owned sources đều complete,
untruncated, execution_status=completed và cùng binding/epoch/session/objective.

| Iteration | Observation (suffix) | Request q sau decode | HTTP / bytes |
|---|---|---|---|
| 47 | 8bbeb0… | apple | 200 / 921, 3 rows |
| 48 | 37b5c4… | apple' AND '1'='1 | 200 / 30, empty |
| 49 | 3953c6… | apple' AND '1'='2 | 200 / 30, empty |
| 50 | be08ab… | apple' AND '1'='1' AND '1'='1 | 500 / 974, near 1 |
| 50 | 8fad4a… | ' AND '1'='2 AND ' | 500 / 974, near 1 |
| 52 | bd5641… | apple'-- (trailing space) | 500 / 942, incomplete input |
| 53 | f78c24… | apple'/CONCAT(CHAR(84,65,83,84))/' | 200 / 30, empty |

Analysis quote-error `obs_361146…` trước attempt là tín hiệu SQLI-1 hợp lệ để
hình thành hypothesis; **không** thuộc seven-source terminal manifest. Proof
kể lại sự kiện này và reproduction không biến nó thành owned source.

Đúng: load payloads trước probes, start attempt trước HTTP validation, có owned
benign control, thừa nhận pair bằng nhau, không claimed confirmed, không Finding,
không extraction/impact request. Sai: từ empty TRUE suy “trailing % hypothesis
holds”; từ parser fragment suy cấu trúc ngoặc cụ thể; message 123 còn nói
`apple'` tự nó empty dù analysis đã cho 500; gọi hai request shape khác nhau ở
iteration 50 là một boolean pair. Chúng không chỉ thay predicate và không
chứng minh oracle. Hai near-1 errors có cùng response hash `9814f5fc…`.
`incomplete input` không xác định duy nhất số ngoặc hoặc full query. Một
expression trả empty không chứng minh rằng expression “không được evaluated”.

Corpus đã cảnh báo suffix của LIKE có thể đổi truth value. Model dùng ví dụ
quoted equality mà không xác lập compatibility; sau đó tiếp tục speculative
shape changes và chọn expression technique trên cùng escape assumption chưa
giải quyết. Skill không cung cấp solver query shape và runtime không đếm
“syntax adjustments” theo semantic SQL; model tự ghi ba. Không được mô tả đây
là ba runtime debit hay dùng đổi tên technique để có allowance mới.

Skill có chỉ dẫn chi tiết rất đúng về unresolved oracle, song định nghĩa
`not-confirmed` tổng quát chỉ nói “techniques were tried … none produced signal”,
và định nghĩa insufficient-evidence chủ yếu nói thiếu sources/proof. Đây là
chỗ có thể đọc lệch giữa “đã hết thử” và “đã hoàn tất test hợp lệ”. Sửa chính
hai định nghĩa và đoạn terminal-negative để yêu cầu context-compatible test
có established oracle; exhaustion riêng nó không đủ. Không thêm techniques,
payload, classifier hay điều kiện runtime mới. Lỗi quyết định còn thuộc LLM;
hướng dẫn mới không chứng minh model sau này sẽ tuân thủ.

Historical result đã được runtime nhận vì completed_attempt=true, proof và
parents hợp lệ. `accepted_result` kiểm tra binding/seal/integrity, không tự
đọc SQL để phán đoán vulnerability. Kiểm toán đọc lại xác nhận binding và seal
đúng, accepted_result=true, eligible_for_finding=false. **Giữ nguyên result
gốc**; với cùng unresolved oracle, hướng dẫn hiện có yêu cầu insufficient-evidence,
không phải ép confirmed hay tuyên bố SQLi không có.

SQLite time probing và OOB bị loại đúng theo playbook/capability. Phase 3
không tới vì SQLI-2 chưa đạt; lời “not authorized” của model không mô tả đầy đủ
loader preface: YOLO auto-approves covered actions nhưng không bỏ skill
prerequisites. Không có cơ sở thêm ask_user hoặc quyền mới.

### D3. Inventory và coverage không đồng nghĩa exhaustive testing

- Enumeration summary ghi 42 “distinct method+path”, nhưng cộng các nhóm bị
  trùng. Từ capture có **40 distinct method+path** ngoài 2 random calibration
  paths, hoặc **43 distinct method+full-URL** trước analysis. Chọn rõ counting
  unit; không dùng 50 raw endpoint records trong final workflow như route total.
- `/api/Products?name=apple` thực tế 200/30/empty, không phải full unfiltered
  collection như inventory/candidates nói. Không chứng minh tham số bị bỏ qua
  hoặc query được parameterize an toàn.
- `/b2b/v2/orders` GET thực tế **401 “No Authorization header was found”**,
  không phải 500 handler error. POST contract có trong inline spec, chưa được
  invoke. `/rest/user/change-password` 401 “Password cannot be empty” không
  chứng minh missing session. `/profile` 500 báo blocked activity; Unexpected
  path ở các route khác không chứng minh backend handler tồn tại.
- POST login rejection là 26-byte text, không phải credentials-rejection HTML.
  Known nested `orderLines` fields và path input Products/1 đã được ghi nhận
  trong Markdown nhưng không có structured inputs riêng; vi phạm hướng dẫn
  reconciliation đã tồn tại. Không có automatic semantic completeness check.
- Sáu inputs “analyzed” là sáu structured triage dispositions, không phải sáu
  SQLi tests; bốn fields login/B2B chưa được exercise bằng signal probes. B2B
  missing JWT là documented dependency, không phải test finding. Nếu analysis
  thực sự không làm được phải giữ blocked; không được dùng analyzed để giải
  phóng gate. Bundle không có ask_user/exclusion cho các fields này; kiểm toán
  không tự suy ra operator đã loại chúng khỏi scope. Passive triage không
  bắt buộc mutation, nên không đổi runtime để auto-block mọi field không probe.
- Các reason được cap 300 chars, result notes cap 1000 chars; full prose còn
  trong transcript/artifact/assessment. Đây là contract bounded state hiện có,
  không đổi cap để lưu toàn văn. Nghĩa của reason phải ngắn và đúng ngay từ LLM.
- Content discovery request rate=10 là trần tool; effective origin grant 3/s
  vẫn áp dụng. Inventory “10 rps” không phải tốc độ thực đo được.
- “No data read” không đúng theo nghĩa literal vì control đã trả product rows;
  có thể nói chưa chứng minh SQLi data extraction. GET không tự chứng minh
  không có server effects; không thấy write acknowledgement trong bảy captures.
- Lời “highest-value sink deserialized to build rows” vượt quá implementation
  được kiểm chứng. Metadata/docs không chứng minh đường code hay severity.

Đây là lỗi diễn giải/reconciliation của LLM, dù có nguồn khả dụng. Chỉ dẫn
hiện tại đã yêu cầu exact observations và per-field records; không thêm parser,
semantic classifier hoặc gate mới chỉ để ép inventory của model đúng.

## E. Workflow completed đối lập với TUI work remains

Source path: `WorkflowTool._record_result` → accepted result + coverage sync →
`Agent._whole_target_state` / `WorkflowState.whole_target_status` → synthesis
và done → `runtime_facts` → `_finish_outcome`.

Cuối lượt có ba completed phases, 6 analyzed inputs, validated Candidate,
completed attempt, requested goal=tested_not_confirmed, no active candidates,
accepted proof/seal, coverage_synced=true, cleanup=not-required, không Finding
pending. 26 pending discovery sources **unselected** không phải backlog bắt
buộc. `selected_sources` bảy evidence parents cũng không phải selected discovery
obligations. `phase_coverage={}` là active rows đã chuyển vào PhaseCompletion,
không phải bị xóa coverage. Một coverage row `passed` là mapping của negative
result, không chứng nhận toàn endpoint hoặc tất cả sáu inputs an toàn.

TUI có hai unmatched failures C1/C2; C3 được recovered. `_finish_outcome` cộng
chúng vào pending rồi tính residual, và đổi nhãn workflow_completed thành
work remains. `not-confirmed` tự nó không tạo residual. Đây là lỗi trình bày
đã tái hiện, không phải workflow chưa đóng attempt.

Sửa đúng lớp UI: tính workflow residual từ authoritative facts; vẫn giữ
permission/export/finding work còn tồn tại; lịch sử unmatched errors được ghi
là “operation errors without matched retries” và giữ dòng lỗi cũ, không đánh
dấu recovered giả. Không nới `_recover_issues`, không ghép hai requests khác
nhau chỉ vì endpoint giống nhau, không sửa stop reason/gates. Khi facts thiếu,
inputs blocked, proof hỏng, coverage pending hoặc finding chưa lưu, UI vẫn
không công bố workflow complete. Kết thúc kỹ thuật này cũng không chứng minh
negative assessment của LLM đúng, xem D2.

## F. Phân loại, phạm vi sửa và giới hạn

| Vấn đề | Phân loại / ảnh hưởng | Quyết định / chắc chắn |
|---|---|---|
| HTTP handles bị elide | Trung bình — lỗi hệ thống; evidence finalization dễ đoán ID, ảnh hưởng mọi attempt dài | Sửa tại guard; tái hiện deterministic, quan hệ cụ thể với suy luận LLM là kết luận có giới hạn |
| Completed bị đổi thành work remains | Trung bình — lỗi TUI; trạng thái vận hành sai | Sửa presentation; chắc chắn cao |
| Discovery page còn tiếp bị gọi là mất output | Thấp — lỗi presentation; sáu warnings gây nhiễu | Hiển thị metadata pagination khi capture complete; chắc chắn cao |
| C1 namespace ds_/obs_ | Thấp — Agent tự phục hồi; thiếu hướng dẫn gần điểm sử dụng | Sửa description/error; validator giữ nguyên; chắc chắn cao |
| C2 replay/source | Thấp — Agent tự phục hồi; field descriptions bị thiếu | Bổ sung metadata mô tả; resolver/rejection đúng; chắc chắn cao |
| C3 evidence rejection/repair | Đúng thiết kế — rejection và phục hồi thành công; không mất observation | Không nới evidence; sửa upstream context handles và kiểm thử repair |
| SQLi chưa có oracle nhưng bounded negative | Cao về độ tin cậy — outcome reasoning ảnh hưởng result/completion/coverage; wording tổng quát dễ đọc lệch | Làm rõ cùng quy tắc ở definitions; không sửa lịch sử hoặc runtime SQL classifier |
| Inventory/body/schema/count claims | Trung bình — lỗi LLM/reconciliation còn trong artifacts lịch sử | Ghi rõ sai khác, không thêm chức năng tự chấm Markdown |
| Truncated bundle/native captures | Giới hạn hợp lệ, coverage gap thật | Không tăng cap/fetch/retry; chưa exercise phần không giữ |
| Dropped debug records | Thấp — bounded logger queue overflow trong final stream, ảnh hưởng audit chronology | Ghi thiếu 159 events; không đổi log subsystem/queue limit |
| No finding / SQLI-2 chưa đạt | Hành vi đúng | Giữ nguyên |

Mức độ trên đánh giá độ tin cậy/vận hành của KAgent, không phải severity lỗ hổng
của mục tiêu. Những sai khác trực tiếp từ response/status/IDs có độ chắc chắn
cao; không suy ra implementation target hoặc ý định nội bộ của LLM từ chúng.

Các tệp production thay đổi trong nhiệm vụ này:

- `src/agent/agent.py`: giữ controller source handles khi elide HTTP content.
- `src/ui/core/state.py`: phân biệt lịch sử lỗi với authoritative workflow work.
- `src/ui/core/admission.py`: page notice dùng metadata hiện có, giữ fallback.
- `src/tools/common/tool_result.py`: hướng dẫn lấy ds_ ID đúng trong description/error.
- `src/tools/workflow/workflow_tool.py`: descriptions của baseline và source.
- `skills/sql-injection/SKILL.md`: nhất quán điều kiện negative/unresolved hiện có.

Không đổi allowed-tools, field shape, outcome enum, persistent schema, evidence
acceptance, scope/private-host cache, admission, rate/call/step/recovery limits,
artifact locations hay redactor. Các thay đổi khác trong worktree đã tồn tại
trước task và được giữ nguyên.

Các điểm truy vết chính (line numbers của worktree sau sửa):

| Trách nhiệm | Vị trí |
|---|---|
| CLI và isolation | `scripts/experiment_profile.py:319` (storage adapter), `:370` (argv/launch marker); `src/cli/main.py` (runtime assembly) |
| Planner/skill projection | `src/agent/decision_planner.py`, `src/agent/agent.py:2066` (`_workflow_request_view`), `src/skills/registry.py`, `src/skills/load_skill.py:100` (runtime preface) |
| Dispatch và permission | `src/agent/agent.py:6359`, `src/tools/common/registry.py:185`; HTTP/private host/transport trong `src/tools/http/` và `src/permission/network/` |
| Capture, truncation, preview | `src/tools/http/http_tool.py:489` (`_dispatch`, capture_response); `src/tools/discovery/content.py:530`; `src/permission/runtime/observations.py` |
| Discovery fingerprints/read | `src/workflow/discovery/inventory.py:29`, `:299`; `src/tools/common/tool_result.py:281` |
| Source/baseline binding | `src/tools/workflow/workflow_tool.py:371`, `:884`, `:971`; `src/tools/http/request_builder.py` |
| Evidence đăng ký/parents | `src/tools/workflow/workflow_tool.py:1416`; `src/workflow/assessment.py:382`; `src/workflow/evidence/artifacts.py`, `source.py`, `publication.py` |
| Result/coverage/finding | `src/tools/workflow/workflow_tool.py:1599`, `:1828`; `src/workflow/assessment.py:432`; `src/tools/workflow/finding.py` |
| Completion/synthesis | `src/agent/agent.py:2756`, `:5564`; `src/workflow/state.py` (`whole_target_status`, Candidate/Input/ValidationResult/PhaseCompletion) |
| Context handle loss | `src/agent/agent.py:5843` (`guard_working_context`, replace_result/elidable); `src/agent/output_bounds.py`; `src/agent/tool_results.py` |
| Session vs outbound | `src/agent/agent.py:6806`; `src/session/store.py:451`; `src/agent/compaction.py`; `src/logger/session_debug.py:77`, `src/logger/writer.py:7` |
| TUI facts/status/pages | `src/ui/core/outcomes.py:89`, `src/ui/core/state.py:743`, `src/ui/core/admission.py:203` |

Đường thực thi thực tế: Agent parse/skill admission → Registry argument validation
→ policy receipt/permission/resource dispatch → native HTTP capture + discovery
handoff → ToolOutput classification + outbound guards → tool Message/history +
working-context reduction → workflow actions (binding/owned attempt/immutable
proof/result/coverage) → session checkpoint → completion projection/synthesis →
TUI facts/reducer. Discovery và validation readers giữ riêng quyền/ownership;
scanner/plugin/MCP không được rơi về host execution. Không đổi đường gọi này.

## G. Kiểm chứng và mức sẵn sàng lan-09

New regression files:

- `tests/agent/test_lan08_context.py`: elision giữ exact trusted handles, bỏ raw
  output, không lấy IDs trong body, không tạo ownership, lặp admission không
  làm metadata tăng vô hạn.
- `tests/ui/test_lan08_audit.py`: production facts/reducer với accepted negative
  và historical errors; current work vẫn chặn complete; complete/incomplete
  discovery captures và malformed pagination giữ phân biệt đúng.
- `tests/tools/test_lan08_contracts.py`: descriptions tồn tại trong projected
  schema, wrong discovery IDs vẫn bị từ chối; bad evidence parents không được
  đăng ký, sửa source+parents không gửi HTTP thêm và không sửa snapshots cũ.
- `tests/skills/test_lan08_outcomes.py`: loaded outcome definition chứa điều
  kiện oracle/context, không phải test dự đoán khả năng tuân thủ của LLM.

Trước production fixes, nhóm đầu **5 failed / 10 passed** ở đúng năm contract
và presentation checks. Sau sửa **15 passed**. Context-handle regression bổ
sung **failed trước sửa / passed sau sửa**. Focused responsibility group
**313 passed**; context/offloading/observation-reader group **93 passed**.
Một lần targeted command dùng nhầm tên test không tồn tại nên không collect;
đã chạy lại group đúng. Không coi đó là test production failure.

Nhóm hồi quy rộng cuối cùng: **6.868 passed, 1 skipped**, 635,20 giây. Bao gồm
tất cả Agent, Skills, Tools, State, Integration, LLM, UI và Security tests,
giữ nguyên skip/opt-in semantics:

```bash
env -u KAGENT_RUN_LIVE_TOOL_CHARACTERIZATION \
    -u KAGENT_S1_EXISTING_CONTAINER -u KAGENT_SYSTEM_LIVE \
    venv-linux/bin/python -m pytest -q \
    tests/agent tests/skills tests/tools tests/state tests/integration \
    tests/llm tests/ui tests/security --tb=short
venv-linux/bin/pyright
git diff --check
```

Full configured Pyright: **0 errors, 0 warnings, 0 informations**. Công cụ có
notice phiên bản mới nhưng không cài/cập nhật gì. Repository không cấu hình
một lint runner riêng trong pyproject; không tuyên bố đã chạy một linter khác.
Không chạy `tests/live`, model trả phí, container characterization hay assessment
mục tiêu; đây không phải full-repository pytest sweep ngoài các responsibility
groups đã nêu. Không thay đổi assertions để làm suite xanh.

Đã đọc diff cuối, chạy diff --check và status --short. Dựng lại baseline trước
task từ Git HEAD + patch được chụp đầu task trong thư mục tạm để review riêng
delta: bảy tệp có thay đổi lan-06/lan-07 nhưng không thuộc sửa lần này vẫn
byte-identical với baseline. Bốn tệp đã có diff được bổ sung đúng các hunks
liệt kê ở F; không restore/stage/delete bất cứ thay đổi có sẵn nào.

Kiểm tra read-only dữ liệu: Candidate binding, result seal và accepted_result
đều hợp lệ; cả hai immutable snapshot hashes/mode 0400 đúng; eligibility cho
Finding vẫn false. So hash toàn bộ 27 tệp gốc: chỉ JSONL/context snapshot đổi
do tiến trình TUI bên ngoài như đã giải thích ở A; log gốc còn nguyên prefix.
Không chỉnh lịch sử để biến unresolved oracle thành một kết quả thành công.

Readiness chỉ có thể là **có điều kiện**: bản sửa metadata/context/UI và wording
được kiểm chứng offline, còn oracle selection, per-field reconciliation và
semantic assessment của LLM chưa được kiểm chứng bằng một run mới. Không có
cam kết lan-09 sẽ xác nhận SQLi hay có coverage exhaustive. lan-09 phải dùng
code/skills mới trong profile mới; không tái sử dụng one-off authority hoặc
chỉnh seal/result của lan-08. Nếu oracle tiếp tục unresolved, kết quả đúng vẫn
phải là unresolved, không phải confirmed hoặc một negative giả.
