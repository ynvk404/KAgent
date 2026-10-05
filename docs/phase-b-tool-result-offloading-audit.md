# Phase B — independent audit and fix verification

**Current verdict: PARTIALLY FIXED.** All six B-01–B-06 fixes and 68 audit regressions pass; full suite passes. Final pyright has one error in the newly added unrelated token-accounting fixture, which remains unchanged. Details are in section G.

Sections A–F below preserve the historical audit and its pre-fix findings/counts.

Audit current worktree trên baseline `4c4bb63`, theo AGENTS.md và yêu cầu đính kèm. Source và reproduction là căn cứ; không dùng trạng thái READY của handoff làm bằng chứng. Không sửa production, test cũ hoặc measurements bàn giao; không install, stage, commit, push hay gọi external model APIs. Chỉ thêm báo cáo này và hai file regression audit.

## A. Historical pre-fix verdict

**NOT READY TO REVIEW.** Có **6 confirmed bugs**, được chứng minh bằng **8 failing regression cases**. Blocker chính là reader bị rebind giữa các Agent dùng chung Registry: vừa mất quyền truy cập ref của chính session, vừa chấp nhận ref của session/target khác. Cần sửa các finding bên dưới trước khi giữ verdict READY trong handoff.

Phase A prerequisite chạy lại đạt **78 passed**. Bộ Phase B hiện có đạt **110 passed**. Full suite hiện có đạt **3,896 passed, 1 skipped, 2 warnings**. Những kết quả này không bao phủ các reproduction mới và không chứng minh các invariant bị thiếu.

## B. Findings, theo severity

### B-01 — P1 — Shared Registry làm reader đọc nhầm session/target

- **Source:** `src/agent/agent.py:1003`; dispatch thực tế qua `src/tools/common/registry.py:149`, `src/tools/common/tool_result.py:58` và `src/agent/tool_results.py:248`.
- **Trigger:** Hai Agent còn sử dụng chung một Registry, cùng project nhưng session và target khác nhau. Agent thứ hai được khởi tạo sau khi Agent thứ nhất đã publish ref. Operator vẫn approve một ranged read; approval không cấp quyền vượt session/target.
- **Expected:** A vẫn đọc được ref của A và reject ref của B, dù ref B được đưa vào arguments.
- **Actual:** Constructor B thay `read_tool_result` trong Registry bằng reader bind với retention B. Ref A trước đó đọc được nay báo unavailable. Khi đưa ref B vào `A.run_parsed_tool_call`, kết quả là `success` và reader trả payload B. A trong reproduction có execution policy thật, đi qua Registry prepare/start với policy A; các project/path checks vẫn pass vì cùng root.
- **Root cause:** Registry là dependency có thể chia sẻ nhưng reader chứa state riêng của Agent. Constructor âm thầm thay dependency dùng chung. Lookup kiểm tra scope của B, không phải Agent đang dispatch A; receipt chỉ bind tool/arguments/resource policy, không bind retention session của caller.
- **Impact:** Vi phạm session/target isolation và làm mất retrieval cho Agent cũ. Không cần sửa artifact hoặc giả provenance. Đây không phải truy cập dữ liệu của OS user khác; điều kiện là shared Registry và biết một valid ref của B. CLI một Agent/Registry không kích hoạt reproduction này.
- **Reproduction:** `tests/agent/test_phase_b_audit_regressions.py::test_shared_registry_keeps_first_agent_reader_binding[own]` và `[foreign]`: **2 failed**, lần lượt unavailable và `success != error`. Cả ref đều được tạo bằng actual FileReadTool → Agent → Store; không dùng helper `record()`.
- **Minimal fix:** Cho mỗi Agent sở hữu view/Registry riêng trước khi đăng ký stateful reader, giữ đúng source adapter objects; hoặc bind reader với current controller invocation có identity session/target. Không overwrite reader của một Agent còn sống. Chỉ tắt retention của B là chưa đủ nếu B vẫn nhìn thấy reader A trong schemas/dispatch.
- **Regression cần giữ:** Own/foreign cases ở trên, có thêm control hai Registry độc lập và Agent B không có session store.
- **Status:** Confirmed in the audited tree; fixed in the current tree (see section G).

### B-02 — P2 — Active skill thay đổi trong approval nhưng ranged read vẫn thành công

- **Source:** `src/tools/common/tool_result.py:91`, `src/agent/tool_results.py:253`; preflight hiện có ở `src/agent/agent.py:1515`.
- **Trigger:** Có shell result thực tế đã offload; active skill cho phép shell lúc preflight. Trong callback review của `read_tool_result`, active skills đổi sang playbook không cho shell; operator approve ranged read.
- **Expected:** Kiểm tra current original-source capability sau suspended approval, block trước `resolve()` nếu skill không còn cho phép.
- **Actual:** `agent.is_tool_allowed('read_tool_result', args).ok` trở thành false nhưng actual `run_parsed_tool_call` vẫn trả `status='success'` cùng payload.
- **Root cause:** Post-approval `validate_rights()` kiểm tra policy/provenance/path/origin nhưng không kiểm tra current Agent active-skill boundary. Preflight ở Agent chạy trước approval và không được revalidate bởi reader.
- **Impact:** Reread vượt current skill allowed-tools contract; không chạy lại shell hay tạo external side effect. Reproduction dùng supported library path không có execution policy, actual ShellTool và actual reader. Không suy từ test này rằng worker hoặc process isolation bị bypass.
- **Reproduction:** `test_source_skill_rights_rechecked_after_reader_approval`: **1 failed**, `success != error`. Callback chỉ thay current skills trong khoảng review; không tạo trusted identity hay authorization bổ sung.
- **Minimal fix:** Kiểm tra source capability của owning Agent trong source-rights validator trước và sau mọi approval. Dùng helper kiểm tra source tool trực tiếp để tránh recursion qua derivative reader, và giữ generic validation gate hiện có.
- **Regression cần giữ:** Revoke skill trong ranged-read review và sensitive-path review; unchanged-skill control vẫn đọc được. Thêm bound-worker variant khi có runtime phù hợp.
- **Status:** Confirmed in the audited tree; fixed in the current tree (see section G).

### B-03 — P2 — Header-only provenance read nạp payload trước sensitive approval

- **Source:** `src/session/tool_results.py:230` và `:232`; được gọi từ Registry prepare qua `src/tools/common/tool_result.py:62`, trước gate ở `:85`.
- **Trigger:** Retained output từ sensitive file, header ngắn hơn buffer đọc mặc định. Sensitive reread bị operator DENY.
- **Expected:** Trước sensitive gate chỉ đọc controller header; không đọc payload bytes của artifact.
- **Actual:** `os.fdopen(..., 'rb')` tạo BufferedReader. `readline(8192)` lấy một block 8 KiB từ file, gồm header và phần đầu payload, rồi trả riêng dòng header. Reproduction quan sát raw `readinto()` và thấy payload marker dù sensitive gate cuối cùng DENY và full `resolve()` không chạy.
- **Root cause:** Bound số ký tự trả từ `readline` không bound phần payload bị buffered I/O đọc trước.
- **Impact:** Vi phạm gate-before-payload contract. Đây là nạp sanitized payload vào process memory trước authorization; chưa chứng minh disclosure ra model/UI hoặc raw-secret leak.
- **Reproduction:** `test_provenance_header_does_not_prefetch_payload_before_sensitive_gate`: **1 failed**. Source `.env` được đọc/publish qua real bound Agent/Registry. Instrumentation dùng actual FileIO và BufferedReader; chỉ quan sát bytes, không cho phép sensitive gate.
- **Minimal fix:** Đọc header bằng unbuffered bounded newline reader không vượt delimiter, hoặc dùng format có vùng header riêng có length được kiểm tra. Full payload vẫn chỉ được đọc sau gates.
- **Regression cần giữ:** DENY với short header, payload marker sát newline; assert raw reads chưa chứa payload. Thêm malformed/oversized header control.
- **Status:** Confirmed in the audited tree; fixed in the current tree (see section G).

### B-04 — P2 — Malformed descriptor làm session load crash

- **Source:** `src/session/tool_results.py:73` và `:77`, đi vào từ `src/session/store.py:274`.
- **Trigger:** Session JSON hợp lệ có descriptor với các trường khác hợp lệ nhưng `status=[]` hoặc `source_kind=[]` (dict cũng thuộc cùng lỗi kiểu dữ liệu).
- **Expected:** Reject/drop descriptor malformed và tiếp tục load preview/messages. Descriptor không phải authorization.
- **Actual:** `Store.load()` raise `TypeError: unhashable type: 'list'`; toàn session không load được. Có thể ảnh hưởng startup chọn resume khi caller coi session unreadable.
- **Root cause:** Dataclass constructor không runtime-validate annotations. Set-membership chạy trước type guard cho hai trường enum; try/except chỉ bọc constructor, không bọc validation expression.
- **Impact:** Một optional malformed field làm mất khả năng resume conversation/workflow hợp lệ. Không chứng minh attacker có quyền viết session file; malformed persistence là precondition.
- **Reproduction:** `test_malformed_descriptor_does_not_make_session_unreadable[status]` và `[source_kind]`: **2 failed**, đúng exception trên. Test sửa JSON của một session vừa được real Agent save, không sửa existing test.
- **Minimal fix:** Type-check string trước set-membership và bảo đảm `from_dict()` là total validator cho arbitrary JSON values.
- **Regression cần giữ:** List/dict/null/bool/numeric enum values, valid descriptor control, và assert preserved preview/workflow khi drop invalid descriptor.
- **Status:** Confirmed in the audited tree; fixed in the current tree (see section G).

### B-05 — P2 — Lock replacement tách writer transaction và vượt quota

- **Source:** `src/session/tool_results.py:140`–`:146`, quota ở `:182`–`:185`, publication ở `:206`.
- **Trigger:** Same-owner process đổi pathname `.lock` trong khi writer A đã acquire flock và qua quota check nhưng chưa publish. Writer B là store instance khác, mở `.lock` mới. Cả hai cùng session/project, `max_results=2` và đã có một result.
- **Expected:** Lock identity thay đổi phải reject transaction hoặc bảo đảm mọi writer vẫn dùng cùng khóa; không trả hai refs khiến count vượt 2.
- **Actual:** B acquire lock mới, thấy một existing result và publish. Sau đó A publish dưới lock cũ; cả hai trả ref, directory có **3 results** với quota **2**.
- **Root cause:** Inode equality chỉ được kiểm tra một lần ngay sau flock. Lock không được pin/revalidate trong critical transaction hoặc ở commit boundary; RLock chỉ bảo vệ từng instance.
- **Impact:** Quota/count invariant và claim serialization không giữ khi lock pathname bị thay. Threat cần same-UID quyền mutate private session directory, giống preconditions của filesystem replacement tests hiện có; không phải khả năng model tự ghi `.kagent` qua protected file tools.
- **Reproduction:** `tests/state/test_phase_b_store_audit_regressions.py::test_lock_replacement_cannot_split_writer_transaction`: **1 failed**. Event barriers giữ A đúng tại `os.link`, cho B hoàn tất transaction trước khi thả A; đây là critical overlap thực tế.
- **Minimal fix:** Bảo đảm lock không thể chia writer domain; pin/recheck lock identity trên transaction, phát hiện replacement trước ref escape và rollback publication an toàn. Nếu chỉ thêm một check, phải kiểm chứng timing replacement cả trước và sau check đó; không xem một check pathname là proof chống mọi same-UID race.
- **Regression cần giữ:** Overlap có barriers ở quota/publication, count và byte quotas, nhiều store instances, cùng stable-lock control. Revalidate owner/mode/nlink tại commit.
- **Status:** Confirmed in the audited tree; fixed in the current tree (see section G).

### B-06 — P2 — Directory bị thay trong publication nhưng ref unreachable vẫn escape

- **Source:** `src/session/tool_results.py:137`–`:139` và `:206`–`:212`.
- **Trigger:** Same-owner process rename session directory và tạo directory mới ở canonical path sau khi directory descriptors được mở, trước `os.link` publication.
- **Expected:** Không trả ref nếu publication không còn ở current scoped storage; Agent phải fallback sanitized inline.
- **Actual:** Link, unlink, private-file check và fsync đều thành công qua fd của directory đã detach; `put()` trả valid ref. Store operation tiếp theo mở canonical directory mới sẽ reject pinned inode. Offloading consumer có thể thay full inline content bằng preview của artifact không reread được qua scoped store.
- **Root cause:** Pinning chỉ kiểm tra binding lúc mở directory. Commit chỉ kiểm tra contents qua fd đã mở, không xác minh directory vẫn gắn với project/session pathname trước ref escape.
- **Impact:** Mất omitted output ở retention path và trái claim publication-before-reference. Không bypass integrity/read checks: reread sau đó fail closed. Cần same-owner filesystem mutation trong transaction; không suy ra remote attacker capability.
- **Reproduction:** `test_directory_replacement_during_publication_cannot_return_reference`: **1 failed**, `put()` trả ResultReference sau rename/replacement ngay tại actual link boundary.
- **Minimal fix:** Kiểm tra lại ancestor/session directory bindings ở commit boundary trước ref escape; rollback unpublished/unreachable result bằng held descriptors khi thất bại. Giữ fallback inline và không đụng evidence directories. Phải mô tả giới hạn same-UID concurrent mutation thay vì hứa chống mọi timing.
- **Regression cần giữ:** Replacement của session/tool-results/.kagent/project trong transaction; assert không ref escape và real Agent vẫn giữ tool success với inline fallback.
- **Status:** Confirmed in the audited tree; fixed in the current tree (see section G).

## C. Coverage gaps và review tests

Data flow đã trace: adapter execution/caps → sanitizer → full live event → retention admission → private artifact → preview/ref → save → guard/next turn/compaction/resume → Registry/current rights/range reader. Raw ToolCallResult vẫn ở controller transient path; observations/evidence không được thay bằng token artifact. Phase A marker spoofing, rebound, redaction, outcome metadata và structured compaction prerequisite đều pass.

Existing tests có giá trị nhưng còn các giới hạn cụ thể:

1. Nhiều agent tests dùng `record()` tự set generation và provenance thay vì execution. Negative adapter/scope tests đó không chứng minh snapshot của actual dispatch. Audit tests dùng actual FileReadTool/ShellTool, Agent, Registry, Store cho B-01 tới B-04. Cần thêm adapter rebind/freeze trong suspended real execution, path canonicalization và target đổi đi/quay lại không gọi refresh giữa hai lần.
2. Active-skill test cũ chỉ assert `is_tool_allowed(...).ok`; không thay skills trong approval hoặc assert actual denial. Sensitive-file test kiểm tra requests và denial nhưng không quan sát filesystem bytes đã đọc. B-02/B-03 bổ sung đúng các boundary đó.
3. Concurrent store test cũ có thread pool và nhiều instances nhưng không điều khiển overlap ở lock replacement/publication. B-05 có event barriers và real overlapping transactions. B-06 khác test directory-swap cũ ở chỗ swap xảy ra trước publication hoàn tất.
4. Publication cancellation test hiện tại inject ở checkpoint trước link; `fsync` failure inject gặp first file fsync. Chưa kiểm chứng cancellation/failure sau link, unlink failure, final directory fsync failure và cleanup failure kết hợp. Test tối thiểu: fault counter tại từng syscall, assert ref không escape; safe orphan được nhận diện riêng nếu cleanup cũng thất bại. Transaction synchronous không có background writer là điều đã xác minh qua source, không phải proof cho mọi OS failure.
5. Chưa chạy physical disk-full, remote/Windows filesystem, process-kill/crash recovery hoặc hostile same-UID stress. Cần process-level overlap/crash tests nếu muốn nâng guarantee. Không xem các POSIX limits đã được handoff ghi nhận là bug độc lập.
6. Ranges hiện có cover negative/large offsets, clamp, emoji/CJK, newline/quotes/backslash và valid total response bound. Chưa có focused actual-dispatch cases cho bool/non-int/extra args, combining characters và mọi control character. Test tối thiểu phải parse returned JSON, đối chiếu slice cùng actual offsets/next_offset và tổng bound.
7. Chưa reproduction riêng cho current network rights khi source ban đầu không có execution policy; policy replacement trong sensitive review; same-class adapter rebind; duplicate/conflicting session descriptors; save/resume đồng thời với target/session changes; cleanup TOCTOU với complete reachability sets. Cần real dispatch tests và counter/control cases trước khi khẳng định các boundary này an toàn. Đây là coverage gaps, không phải findings suy đoán.
8. Full suite kiểm tra workflow/evidence/permission/provider/UI responsibilities hiện có; chưa viết integration mới chứng minh token artifact không satisfy finding gate trên mọi validation route. Existing independent-evidence test và source không cho thấy Phase B thay evidence eligibility; không tuyên bố proof engine đã được audit toàn diện.

## D. Measurement review

Chạy lại `venv-linux/bin/python -m benchmarks.internal.tool_result_offloading` offline, output ở `/tmp/kagent-phase-b-audit-measurements.json`. So sánh toàn bộ non-latency fields của cả Phase A/B trong **12 cases** với JSON bàn giao: **khớp**. Reread argument/reply/count/gap outcomes cũng khớp; local elapsed time thay đổi như dự kiến.

- Baseline và B đều dùng real current Phase A guard. Baseline tắt retention store và reader schema, không dùng output simulation. Offline client deepcopy request trước mutable-history changes. Existing OpenAI encoder chỉ serialize, không gọi API.
- Immediate request, pre-turn trigger và post-compaction next/resume request được đo riêng. Disk snapshot session/artifact/context lấy cùng thời điểm trước next-turn compaction; không dùng post-compaction session để tạo savings giả.
- 100 KiB: pre-turn tokens **27,771 → 15,364**, session bytes **111,155 → 62,013**; total logical disk **111,155 → 165,263**. Immediate wire bytes **63,257 → 63,298**; next request tokens **2,690 → 15,768** vì A đã compact còn B giữ preview. Những tradeoffs được handoff mô tả đúng; không có căn cứ sửa thành claim mọi request/disk đều giảm.
- Reader schema **615 chars**, floor estimate ~153 tokens; small-inline actual delta ~154 tokens. Reread một bounded range thêm **1 call**, **92 argument chars**, **452–456 response chars**. Latency audit trong 5 cases có artifact: khoảng **4.094–7.074 ms**, chỉ local fake operator/runtime, không gồm model/operator/network latency.
- Head/mid/tail anchors được kiểm tra từng immediate result; offloaded-gap omission được ghi từng preview. Reread benchmark chỉ đọc **`results[-1]` của mỗi case**, không từng artifact của multi-result case. Handoff nói mỗi case đọc được gap là đúng; chưa có bằng chứng benchmark cho exact range fidelity của mọi result. Cần unique per-result canaries và reread từng ref để mở rộng claim.
- “Core inventory” chỉ góp schemas; executed source vẫn FileReadTool. Fixture dưới adapter cap nên fixture length bằng adapter-returned length trong các case hiện tại, nhưng `adapter_retained_chars` được lấy từ fixture trước execution. Nếu mở rộng sang truncation/other adapters, cần đo trực tiếp actual return để tên metric tiếp tục đúng.

Claims cần sửa sau audit: verdict READY; current-rights claim sau approval phải tính active skill; header-only/no-payload-before-gate claim; shared-session binding và filesystem replacement guarantees cần phản ánh findings. Không sửa measurements/handoff trong lượt audit này.

## E. Verification performed

Commands thực sự chạy, không tái trình bày baseline như kết quả audit:

```bash
venv-linux/bin/python -m pytest -q \
  tests/agent/test_output_pipeline.py tests/agent/test_sanitizer.py \
  tests/agent/test_tool_outcomes.py tests/agent/test_post_compaction.py \
  tests/agent/test_resume_after_compaction.py
# 78 passed in 13.12s

venv-linux/bin/python -m pytest -q \
  tests/agent/test_tool_result_offloading.py \
  tests/state/test_tool_result_store.py tests/ui/test_offloaded_transcript.py
# 110 passed in 15.16s

venv-linux/bin/python -m pytest -q \
  --ignore=tests/agent/test_phase_b_audit_regressions.py \
  --ignore=tests/state/test_phase_b_audit_regressions.py
# 3896 passed, 1 skipped, 2 warnings in 268.24s
# Launched/collected trước khi thêm audit tests; ignore path thứ hai là tên
# dự kiến ban đầu, sau đổi thành test_phase_b_store_audit_regressions.py.
# Đây là suite hiện có, không bao gồm reproduction tests mới.

venv-linux/bin/python -m pytest -q \
  tests/agent/test_phase_b_audit_regressions.py \
  tests/state/test_phase_b_store_audit_regressions.py
# 8 failed: expected invariants của 6 findings đang bị vi phạm.

venv-linux/bin/pyright --outputjson
# Trước audit additions: 372 files, 0 errors, 0 warnings.
# Sau hai audit test files: 374 files, 0 errors, 0 warnings.

venv-linux/bin/python -m benchmarks.internal.tool_result_offloading
# Offline 12 cases x 2 modes, stable measurements khớp JSON bàn giao.

git diff --check
git diff
git diff --no-index -- /dev/null tests/agent/test_phase_b_audit_regressions.py
git diff --no-index -- /dev/null tests/state/test_phase_b_store_audit_regressions.py
git status --short
```

Hai full-suite warnings là malformed custom-provider key/profile-ID sanitation trong `tests/runtime/test_config.py`, không suppress. Existing skip giữ nguyên. Full pytest trên final tree không thể green vì deliberately failing regressions; chưa chạy lại toàn bộ suite sau audit additions. Để tái lập suite cũ trên final tree, ignore cả hai **tên test hiện tại**, rồi chạy audit tests riêng.

Initial audit test collection có một lỗi trùng module basename giữa tests/agent và tests/state; đã đổi tên file audit state của chính lượt này, không sửa test cũ. Các lần regression chạy sau đó collect bình thường và fail tại production invariants đã mô tả.

Test logs, measurements và pyright JSON lưu tại `/tmp/kagent-phase-b-audit-*`; báo cáo/test files trong repo là artifacts bền hơn. Final inspection giữ nguyên bốn tracked production files và toàn bộ untracked implementation/handoff files đã tồn tại khi audit bắt đầu. Không stage/commit/push.

## F. Minimal fix plan

1. **B-01:** Sửa Agent-owned reader/Registry binding trong `src/agent/agent.py`, có thể cần small ownership helper ở reader. Chạy own/foreign regressions, session/reset/resume và existing Agent tests. Giữ Registry permission pipeline; không lấy permission làm session identity.
2. **B-02/B-03:** Revalidate owning-Agent source skills ở `src/agent/tool_results.py` / `src/tools/common/tool_result.py`; sửa pre-gate header read ở `src/session/tool_results.py`. Chạy sensitive reads, approval/revocation, generic-validation, active-skill và range/UI tests.
3. **B-04:** Total descriptor validation ở `src/session/tool_results.py`; thêm arbitrary-JSON type matrix và Store/resume controls.
4. **B-05/B-06:** Hardening commit/lock/directory identity trong `src/session/tool_results.py`; thêm barriers/process overlap và actual-Agent fallback regression. Cần xác định rõ same-UID threat guarantees; nếu chọn filesystem sandbox/broker hoặc format redesign lớn, đó là scope expansion và cần tách follow-up. Focused commit validation có thể giữ Phase B scope.
5. Chạy lại tám regression cases để chuyển từ failing sang passing; targeted Phase A/B groups, permission/security/state/UI responsibility groups, full suite và configured pyright. Chạy lại offline benchmark, cập nhật handoff claims/verdict theo final behavior. Không normalize toàn bộ ToolResult, triển khai Phase C hoặc redesign structured handoff để sửa các finding này.

**Chưa thực hiện production fixes trong lượt audit.**


## G. Fixes for B-01 through B-06

The sections above preserve the pre-fix audit evidence and counts. They are historical, not final verification of the fixes. No confirmed regression is excluded, skipped or marked xfail.

| Finding | Root cause | Production fix / files | Regression evidence |
| --- | --- | --- | --- |
| B-01 | Shared registration overwrote a stateful reader | `src/agent/agent.py`, `src/tools/common/registry.py`: owning live scoped view hides foreign reader even with no session store; `src/cli/runtime.py`: use owning view; benchmark baseline removes reader from Agent view | Own/foreign real execution; independent/shared registries; both construction orders; no-store controller; source object identity, late registration/schema controls; reset/resume isolation |
| B-02 | Post-review rights omitted owning active skills | `src/agent/tool_results.py`: direct original-source capability check; `src/tools/common/tool_result.py`: pre-Registry and post-range/post-sensitive checks, preserving policy/receipt gates | Real shell dispatch, library and real Linux worker; changed/unchanged skills; unavailable source rejected before review. Sensitive file review records recheck of changed skills and preserves non-permissioned file semantics |
| B-03 | Buffered header readline prefetched sanitized payload | `src/session/tool_results.py`: bounded unbuffered one-byte header reads stop exactly at newline; publication rejects header >8,192 bytes | Existing raw-buffer observer retained plus `os.read` observation; sensitive DENY without payload read; short, oversized, malformed, missing-delimiter and list headers |
| B-04 | Enum set membership accepted unhashable JSON values | `src/session/tool_results.py`: string type checks before enum membership | Both original load failures; list/dict/null/bool/number/invalid-string enums; valid control; mixed descriptors in actual resume preserve preview/messages and non-empty workflow |
| B-05 | Replaceable lock inode split writer domain after quota check | `src/session/tool_results.py`: flock held session-directory inode for complete transaction; revalidate lock owner/mode/nlink/binding | Barrier-controlled threaded count/byte quota overlap, stable/replaced locks; separately spawned-process overlap; lock replacement after link/unlink/fsync |
| B-06 | Detached directory fd was accepted as canonical publication | `src/session/tool_results.py`: verify every canonical ancestor edge at commit boundaries; rollback only transaction inode via held descriptors | Session/tool-results/.kagent/project replacement after link/unlink/fsync; original publication regression; unlink/directory-fsync errors and final cancellation; real Agent sanitized inline fallback preserves success/live UI and existing result |

The lock overlap reproduction now runs writer B in a separate worker. Directory flock correctly blocks B; the original synchronous controller could not release A while blocked in B. The test still forces the same replacement/overlap and rejects double admission or count/byte quota excess. It does not relax the invariant.

Filesystem guarantees are bounded to supported POSIX primitives and the observed binding checkpoints. A same-UID process can rename private directories, replace locks or directly mutate payloads; it is outside the protected tool interface. Directory locking keeps a single writer domain while that inode remains shared, independently of `.lock` pathname changes. Canonical edge checks detect the tested detach/replacement timings; inode-scoped rollback preserves other results. This is not immunity to arbitrary namespace mutation after the final check, hostile direct writes, cleanup failures, process death or unsupported filesystems. B-03 proves absence of pre-gate payload reads; the original audit did not prove disclosure to model/UI.

Remaining audit coverage gaps in section C still apply except the explicitly tested controls above. No Phase C, broad result normalization, evidence/finding changes or structured-handoff redesign was introduced.


Executed checkpoints and final verification:

```bash
venv-linux/bin/python -m pytest -q tests/agent/test_phase_b_audit_regressions.py tests/state/test_phase_b_store_audit_regressions.py
# 68 passed in 22.00s; no skips or warnings
venv-linux/bin/python -m pytest -q tests/agent/test_output_pipeline.py tests/agent/test_sanitizer.py tests/agent/test_tool_outcomes.py tests/agent/test_post_compaction.py tests/agent/test_resume_after_compaction.py tests/agent/test_tool_result_offloading.py tests/state/test_tool_result_store.py tests/ui/test_offloaded_transcript.py
# 188 passed in 26.20s; no skips or warnings
venv-linux/bin/python -m pytest -q tests/agent tests/state tests/runtime/test_cli_main.py tests/tools/test_tools_registry.py tests/tools/test_file.py tests/security
# 1462 passed, 1 skipped in 162.36s; no warnings. Collected before the unrelated token-accounting audit appeared.
venv-linux/bin/python -m benchmarks.internal.tool_result_offloading
# 12 offline cases; every non-latency field matches the handed-off measurements.
```

A first responsibility invocation used a nonexistent `tests/tools/test_registry_contracts.py` path (exit 4, no tests run); the corrected command above completed. Intermediate failing test iterations exposed fixture mistakes (exception wrapping, worker `/work` paths, non-permissioned file skill semantics and generic workflow restrictions); those were corrected without changing existing permission/receipt behavior or weakening the original negative cases. Pre-fix reproduction was run in this fix session: all 8 original audit cases failed in 18.16s.

During verification, unrelated `tests/agent/test_token_accounting_audit.py` appeared in the worktree. It is included in the final full suite and final pyright invocation. At the current checkpoint pyright analyzes 375 files and reports one `reportAbstractUsage` error in that new file: `DynamicTool` omits `Tool.requires_permission` and `Tool.run`; the prior 374-file check passed with 0 errors/warnings. It remains unchanged under the explicit instruction to preserve unrelated worktree changes. The scope question received no approval; the concrete minimal patch is `/tmp/kagent-token-accounting-fixture-fix.patch`. It only implements the fixture interface, without changing token-accounting production code or assertions.

The latest benchmark JSON is copied from the actual final implementation run. All 12 cases preserve immediate request, pre-turn, next/resume, session, artifact, context-snapshot and total logical disk observations. Local reread times are 12.516–17.838 ms for this run and are not an isolated causal measurement of fix overhead. Phase A → B tradeoffs remain: 100KiB immediate wire bytes 63,257 → 63,298; pre-turn approximate tokens 27,771 → 15,364; next/resume tokens 2,690/2,701 → 15,768/15,779; session bytes 111,155 → 62,013; artifact bytes 0 → 103,250; total logical disk 111,155 → 165,263. No claim that every request or total disk decreases.


Final required checks (no added exclusions):

```bash
venv-linux/bin/python -m pytest -q
# 3971 passed, 1 skipped, 2 warnings in 344.29s (0:05:44)
venv-linux/bin/pyright --outputjson
# 375 files; 1 error, 0 warnings. Only tests/agent/test_token_accounting_audit.py:185,
# DynamicTool omits Tool.requires_permission and Tool.run (reportAbstractUsage).
git diff --check
# passed
git diff
git status --short
# reviewed, including new files; no staging/commit/push
```

Both pytest warnings are existing malformed custom-provider config sanitation at `src/config/config.py:247`. The existing skip remains; no confirmed Phase B regression was skipped or excluded. No required final command was omitted. Physical disk exhaustion, cleanup-failure combinations, process death/crash recovery, Windows/remote filesystem stress and external model APIs were not run.

Verdict: **PARTIALLY FIXED — B-01–B-06 fixed and regression-tested; final pyright blocked by unrelated new test fixture.** Scope expansion: none. The minimal fixture patch is reviewable outside the worktree but not applied without authorization. All starting tracked/untracked work was preserved; the unrelated token-accounting audit added during the run was also preserved.

Final `git status --short` (6 modified, 13 untracked):

```text
 M src/agent/agent.py
 M src/cli/runtime.py
 M src/llm/core/types.py
 M src/permission/runtime/execution.py
 M src/session/store.py
 M src/tools/common/registry.py
?? benchmarks/internal/tool_result_offloading.py
?? docs/phase-b-tool-result-offloading-audit.md
?? docs/phase-b-tool-result-offloading-measurements.json
?? docs/phase-b-tool-result-offloading.md
?? src/agent/tool_results.py
?? src/session/tool_results.py
?? src/tools/common/tool_result.py
?? tests/agent/test_phase_b_audit_regressions.py
?? tests/agent/test_token_accounting_audit.py
?? tests/agent/test_tool_result_offloading.py
?? tests/state/test_phase_b_store_audit_regressions.py
?? tests/state/test_tool_result_store.py
?? tests/ui/test_offloaded_transcript.py
```
