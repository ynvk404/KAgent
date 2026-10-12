# C2 Minimal FD-bound FileWrite — feasibility proof

**Verdict: BLOCKED cho production patch dưới contract hiện tại.** FD-bound
write/close khả thi về kỹ thuật trên POSIX được thử, nhưng chưa chứng minh giữ
nguyên permission lifetime và containment khi namespace có thể bị di chuyển.
Không sửa production. Chỉ khảo sát C2; hai audit artifacts trước được giữ nguyên.

## 1. Current path và source anchors

| Source | Current behavior đã đối chiếu |
|---|---|
| `src/tools/common/registry.py:186–219, 254–366` | Private deep-copy args; prepare ExecutionReview; argument-aware permission hints; current decision checks; exchange dispatch receipt/start; finally stop và finish_review. |
| `src/permission/runtime/execution.py:34–70, 333–452` | Digest bind args + resolved resource dev/ino/size/mtime hoặc absent; start checks freshness/budget, consumes receipt. Active validity vẫn phụ thuộc stamp/owner, không running TTL 60s. |
| `src/permission/runtime/execution.py:134–146, 199–239` | Revoke/YOLO transition invalidate revision; root/protected path/type/hardlink guards vẫn áp dụng. Approval/YOLO không cho bypass scope. |
| `src/tools/execution/file.py:87–159` | Nested gate capture resource/review freshness, cancellation, require_path/nested_allowed; sensitive review checked lại sau await. Bound YOLO skips nested dialog, không skips policy scope/current receipt. |
| `src/tools/execution/file.py:327–390` | Validate args → resolve → await gate → revalidate → exists → mkdir → revalidate → write_text UTF-8 → best-effort chmod 0644 nếu file mới → success string. |

`mkdir` có thể tạo parents trước second revalidation. `write_text` mở pathname
ở write mode: truncate/create → buffered encode/write → close. Không explicit
flush/fsync/atomic replace, không per-destination lock, không owned-temp cleanup.
Write/close failure có thể để file empty/partial. Existing modes được giữ; new
mode áp dụng sau write, chmod OSError bị bỏ qua. Truncate không phải preparation.
Không có asyncio await từ final guard tới filesystem write hiện tại; external
filesystem actor vẫn có thể thay path. Offload thêm controller scheduling window.

`start()` là dispatch admission, không tự cấp irrevocable lease cho chưa-bắt-đầu
worker. `execution_is_current()` vẫn từ chối active receipt sau revoke/stamp
change/owner closure. Frozen args và review guards phải giữ nguyên trong mọi patch.

## 2. Minimal candidate và exact proposed source scope

Candidate production scope nếu các blockers được giải quyết:

- `src/tools/execution/file.py`: chỉ FileWrite execution handoff; giữ API/schema,
  permission hints, output, modes và aliases. Controller vẫn chạy mọi gates.
- New local helper `src/tools/execution/file_resource.py`: safe component-bound
  open/create, owned-handle lifecycle, shared destination ownership và joined
  write/close. Không sửa Registry hoặc ExecutionPolicy để giấu admission gap.
- Tests: FileWrite semantics, C2 lifecycle/FD regressions và existing mounted
  FileWrite oracle. Hiện chỉ thêm `tests/security/test_c2_fd_feasibility.py`.

Protocol candidate:

1. Controller freeze UTF-8 payload và approved canonical resource; giữ nested
   permission gate. Acquire shared destination ownership trước final checks.
2. Existing file: rooted component no-follow open **không O_TRUNC/O_CREAT**,
   fstat actual FD regular/single-link/expected identity. New file: chỉ bind parent
   handle + absent leaf name; không thể có FD của nonexistent file mà zero creation.
3. Controller check receipt/resource/owner/signal/task cancellation, rồi **explicit
   proposed admission**. Existing FD ftruncate hoặc new exclusive rooted create
   trên controller ngay sau admission, không await trước first mutation.
4. Transfer owned FD + detached bytes một lần cho write/close worker. No pathname
   reopen, policy, prompter, workflow, UI access. Shield/drain repeated cancellation
   dưới destination lock; Registry stop phải xảy ra sau joined completion.
5. Report actual write/close failure; không tuyên bố rollback/atomicity/durability.
   Chmod new file phải bind cùng resource, giữ best-effort semantics sau successful
   write. Worker close FD khiến cần retained metadata handle hoặc lifecycle khác
   nếu controller muốn fchmod sau completion; không dùng lại pathname cho chmod.

Prototype trong tests chỉ chứng minh các phần được ghi rõ: parents phải tồn tại,
POSIX no-follow/dir_fd, bytes write loop và drain. Nó không phải complete replacement:
thiếu mkdir/chmod parity, process-wide lock-key scheme và robust executor transfer.
Thread holds/Events là test instrumentation, không production permission arbiter.
Worker callable nhận int FD + bytes; `to_thread` vẫn copies ContextVar, vì vậy
purity/no-policy-access phải được enforce qua adapter/callable, không qua args alone.

## 3. Admission/revoke contract cần phê duyệt

**Đề xuất, chưa là contract production:** revoke/deny/cancel trước admission ⇒
zero create/truncate/write, gồm mkdir. Sau admission ⇒ một continuation đã nhận
quyền có thể hoàn tất và được drain; không cấp action thứ hai, không reuse receipt,
không rollback bytes đã ghi. Abort không được release ownership trước completion.

Candidate giảm gap bằng first mutation trên controller trước enqueue write/close.
Nhưng file có thể đã truncated trong lúc write worker vẫn đang chờ executor.
Probe giữ executor một slot xác nhận cancel/revoke khi queued vẫn được drain tới
write. Điều này chỉ hợp lệ **nếu admitted continuation được phê duyệt**. Receipt
current checks hôm nay không tự chứng minh điều đó. Nếu yêu cầu revoke trước first
actual write phải ngăn nó, FD-only worker không thể làm được với controller check
trước await; cần synchronized mutation-start arbiter và revoke participation,
vượt scope “không thay permission contract”. Không thêm bool check như một lease.

Resource-ready khác worker-ready: parent/leaf FD ready trên controller không bảo
đảm executor sẵn sàng. Ready-worker handshake riêng cần task/ticket lifecycle
phức tạp hơn; worker-waiting Event không tự giải quyết revoke hay pathname scope.
New file chỉ có parent/name ready; mkdir của missing parent cũng là mutation cần
admit từ safe existing ancestor. Prototype fail closed với missing parents,
không gọi đó là giữ nguyên current mkdir semantics.

## 4. Deterministic probes: đã chứng minh và counterexamples

Fresh `/tmp`, synthetic data, real policy/gates hoặc production Registry với fake
operator, network/DNS denied. Thread holds bound 5s, released/joined trong finally.
Không probe filesystem của người dùng, external target, live model/Burp.
**27 passing observation cases** bao gồm counterexamples; không phải 27 safety
guarantees. Scheduling unsafe windows dùng Events/hooks, không random timing.

| Initial state → controlled schedule | Result / oracle | Classification |
|---|---|---|
| Existing original / absent leaf → bind → revoke, signal abort hoặc task cancel trước admit (6 cases) | Existing bytes unchanged/new absent; handles cleaned. Không truncate/create tại bind. | Candidate safe cho schedule đã thử |
| New missing parent → production Registry deny | No parent/create, no active receipt leak | ALREADY MITIGATED |
| Existing leaf → hook before open leaf symlink, ancestor symlink hoặc regular replacement (3) | No-follow rejects symlinks; fstat rejects different inode; outside canary/original unchanged | Candidate safe cho substitution schedules |
| FD bound → rename original + outside symlink → final admission check | Current resource receipt rejects; old bytes/outside unchanged | Candidate + current guard |
| Admitted existing FD → leaf symlink swap | Worker writes pinned retired inode; outside symlink target untouched | FD eliminates pathname redirection; namespace containment not universal |
| Absent new leaf → proposed admission → competing symlink/regular creator (2) | O_EXCL rejects; canary/competing file unchanged | Candidate avoids unchecked overwrite on create race |
| Pinned parent/leaf → move directory outside root after admission → begin/write (2) | Existing write hoặc new create xảy ra tại `outside/moved/out` | **HYPOTHETICAL-OFFLOAD-ONLY counterexample**, blocks unconditional namespace containment |
| Last real guard → proposed admission hook revoke trước first mutation | Real revalidation now rejects, candidate still writes by proposed lease | **HYPOTHETICAL-OFFLOAD-ONLY**, contract chưa approved |
| Controller truncate → worker held → revoke | Active policy invalid; new prepare rejected; one worker still writes | Proposed continuation semantics only, no new action |
| Executor held → admitted FD queued → revoke + repeated cancel → release | Caller/lock drain; queued bytes still written; no false rollback | Proposed lease only, not proof unchanged policy |
| First writer held → cancel twice → second waits lock → release | Lock held; first writes; second stale receipt rejected; fresh retry serializes and succeeds | Ownership + receipt freshness preserved |
| Existing content → prefix write then error | OSError returned, prefix remains (`com`) | In-place failure, not atomic success |
| Complete write → injected close error | OSError returned although complete bytes visible | Accurate partial-effect reporting |
| UTF-8 payload → injected 2-byte short writes | Loop completes exact bytes on non-controller thread | Candidate byte-writing correctness on tested POSIX host |
| Capability false / safe-open EOPNOTSUPP (2) | Reject before mutation; no pathname fallback; safe-open error not swallowed | Candidate fail closed, not universal FS capability proof |
| Parent missing → bind | Reject without mkdir | Prototype limitation, not production parity |
| Controller truncate/FD transfer → executor submission failure | Candidate leaves empty file **and leaks detached FD**; probe explicitly closes it | **HYPOTHETICAL-OFFLOAD-ONLY lifecycle gap**, needs acknowledged transfer/cleanup |

Submission failure gap fix is feasible, but not proven here: controller must own
FD until executor/worker ownership is unambiguous, close it after joined failure
if worker never acquired it, never double-close a reused FD. Add fault-injected
acknowledgement/close tests before implementation, not just a generic finally.

Most important scope distinction: FD pins object identity, not its continued
membership in current root namespace. Pinned directory can be reparented;
existing inode can be renamed outside root while FD remains writable. Same-inode
external writer can also change bytes or add a hardlink after validation.
Cooperating asyncio locks cannot stop these actors. No remote exploit reachability
claim; counterexamples assume a local actor with filesystem mutation rights.

## 5. Alternatives và remaining blocking

| Option | Source change / risk | Permission correctness | Responsiveness |
|---|---|---|---|
| FD-bound write/close worker | FileWrite + resource/ownership helper + tests; missing-parent/chmod/executor-error lifecycle mean more than replacing one await | Requires approved continuation admission and root namespace threat model; currently BLOCKED | Can reduce slow data write/close; no full TUI guarantee |
| Keep synchronous C2 + FD pathname safety | Same bound-resource adapter, FileWrite calls write/close inline; fewer cancellation/thread lifecycle paths | Existing guard→mutation execution topology retained; external reparent assumptions still must be explicit | Data write/close still block; accepts residual TUI freezes |

Minimal offload leaves resolve/stat/exists, gate digest checks, component open,
mkdir, ftruncate/create, fchmod and some descriptor closes on controller. Controller
close may itself be slow. Worker GIL/encoding cost also unmeasured. No atomic
replace/fsync introduced; worker success does not imply crash durability.
POSIX prototype encoding does not prove Windows TextIO newline translation,
invalid-Unicode failure ordering, new-file umask/chmod or legitimate in-scope
symlink compatibility. Native Windows needs audited handle/reparse adapter;
presence of flags does not certify filesystem semantics. Fail closed supported
adapter errors rather than fallback, but record compatibility restriction.

Current mounted FileWrite oracle: **1 passed, 1 strict XFAIL, 9 deselected**.
Synthetic 401.1ms write: heartbeat gap **428.2ms**, Esc **356.2ms**, 0 operation
ticks; yielding control heartbeat **23.0ms**, Esc **1.7ms**. Original 120ms
thresholds unchanged. No mounted candidate PASS claimed: feasibility is blocked
before integration; this is not evidence every moved syscall is responsive.

## 6. Verification, stop và future entry gates

Commands/results:

```bash
PYTHONDONTWRITEBYTECODE=1 venv-linux/bin/python -m pytest -q -s --tb=short \
  -p no:cacheprovider tests/security/test_c2_fd_feasibility.py
# Final: 27 passed in 2.93s; observations/counterexamples only

PYTHONDONTWRITEBYTECODE=1 venv-linux/bin/python -m pytest -q -s --tb=short \
  -p no:cacheprovider tests/security/test_persistence_handoff_audit.py -k c2
# 11 passed, 24 deselected in 3.40s; C2 only

task_c2_scratch=$(mktemp -d /tmp/kagent-c2-regression.XXXXXX)
TMPDIR="$task_c2_scratch" PYTHONDONTWRITEBYTECODE=1 venv-linux/bin/python -m pytest \
  -q --tb=short -p no:cacheprovider -p tests.scenarios.offline_checkpoint \
  --basetemp="$task_c2_scratch" tests/tools/test_file.py \
  tests/security/test_c2_review_lifecycle.py \
  -k '(file or valid_queued or review_and_dispatch or old_cleanup or expired_review or nested_sensitive or delayed_nested) and not http and not browser'
# 33 passed, 24 deselected in 10.94s

PYTHONDONTWRITEBYTECODE=1 venv-linux/bin/python -m pytest -q -s --tb=short \
  -p no:cacheprovider tests/ui/test_persistence_responsiveness.py -k file_write
# 1 passed, 9 deselected, 1 xfailed in 15.05s

venv-linux/bin/pyright tests/security/test_c2_fd_feasibility.py
# 0 errors, 0 warnings, 0 informations; no dependency install
```

Initial prototype run: 18 passed, one failed expectation, one fixture teardown
error. Waiting writer correctly rejected a stale receipt; test now asserts rejection
and separately fresh retry, without changing production guards. Global os.open
fault patch affected TemporaryDirectory cleanup; narrowed fault scope to operation.
One early regression invocation was interrupted during plugin import before any
tests because selector could include unrelated mocked HTTP/browser cases; final
selector explicitly excludes them. No oracle lowered or production test changed.

Tracked `git diff` trống; `git diff --check` và explicit no-index whitespace checks
không có diagnostics. New probe diff đã review. Chỉ thêm báo cáo này và C2 probe
module; hai untracked deep-audit artifacts có từ đầu được giữ nguyên. Không chạy
full suite, native Windows/WSL filesystem conformance, live network hoặc integration.

**BLOCKED reasons:** (1) continuation lease not approved/proven against current
active receipt semantics; (2) descriptor binding alone fails strict namespace
containment under reparent; (3) full FileWrite parity/handle transfer not proved.
FD transfer failure is repairable locally, but does not solve the first two.

To re-enter implementation, first approve explicit admission/revoke contract and
declare/enforce root/ancestor/inode ownership threat model. Then prove shared
destination identity, missing-parent/create/modes/chmod/newline parity, executor
failure FD ownership, repeated-cancel/drain/error precedence, no policy access
in worker and mounted write/close oracle. Security resource binding first;
responsiveness handoff second, independent rollback. Unsupported platform or
remaining required scope race ⇒ stop, no unsafe fallback. No implementation is
authorized by this report. No C1/C3/C4/C5 tests or audits were rerun in this task.
