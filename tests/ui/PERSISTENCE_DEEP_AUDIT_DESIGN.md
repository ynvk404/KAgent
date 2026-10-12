# KAgent — Deep audit và safe persistence handoff design

Audit trên HEAD `a303731eece8a62de851e930cb30cfe7bf9043f9`. Ngày 2026-10-12.
Chỉ audit, probes cô lập và thiết kế; **không triển khai C2–C5**.
Worktree sạch lúc bắt đầu. Hai báo cáo trước ghi HEAD cũ; kết luận dưới đây
được đối chiếu source hiện tại và chạy lại probes, không mặc nhiên kế thừa.

## 1. Executive summary

| Boundary | Final readiness | Phần có thể làm tiếp sau phê duyệt implementation |
|---|---|---|
| C2 FileWrite | **BLOCKED** cho worker mutation | Chốt admission contract và resource binding trước. Locks + last pathname check chưa đủ. |
| C3 Evidence | **BLOCKED** cho toàn bộ worker read/publish | Security fix snapshot identity + complete publication đi trước offload. |
| C4 Finding post-read | **READY** cho patch nhỏ | Một worker write-or-reuse + canonical read/parse, shared lock giữ đến completion. |
| C5 Summary | **READY WITH CONDITIONS** cho post-replace fsync | Giữ replace trên controller; pin đúng directory cho durability worker. Worker replace **BLOCKED**. |

Kết quả mới có ý nghĩa nhất: source substitution C3 đã tái hiện qua **Registry,
ExecutionPolicy và WorkflowTool thật**, không chỉ low-level API. Synthetic bytes
ngoài project được snapshot và ghi vào workflow evidence metadata. Managed
verification sau đó từ chối source đã đổi, nhưng không đảo ngược việc đọc/lưu.
Threat model cần tác nhân có quyền thay path giữa check/open; chưa chứng minh
target HTTP từ xa có quyền đó. Không gán CVSS hay gọi đây là remote exploit.

Không phát hiện căn cứ regression C1, không audit lại C1. Không có production
diff, thay policy/Agent/Planner/WorkflowState, dependency install, live model,
Burp, external HTTP hoặc commit. Probes xanh có nghĩa **tái hiện đúng observation**,
bao gồm observation lỗi; không có nghĩa production đã an toàn.

## 2. Current architecture và authority/data-flow boundaries

Source anchors, tương đối với repo; số dòng tham chiếu source hiện tại:

| ID | Source | Điều được kiểm chứng |
|---|---|---|
| S1 | `src/tools/common/registry.py:186–219, 254–366` | deep-copy args, prepare review, permission decision/freshness, dispatch/start, finally stop/finish |
| S2 | `src/permission/runtime/execution.py:34–70, 333–452` | receipt/digest, dispatch TTL, consumption, revision/owner checks, active revalidation |
| S3 | `src/permission/runtime/execution.py:199–239, 254–272` | scope/protected paths/type/hardlink and managed evidence identity |
| S4 | `src/permission/runtime/invocations.py:39–123` | captured review owner, timeout/signal, parent closure cleanup |
| S5 | `src/tools/execution/file.py:94–159, 327–390` | nested sensitive gate, final guard, mkdir/write_text/chmod |
| S6 | `src/workflow/evidence.py:142–302` | capture/snapshot/redaction/storage/verification |
| S7 | `src/tools/workflow/workflow_tool.py:312–321, 875–943` | workflow lock, source gate, snapshots, proof claims, metadata adoption |
| S8 | `src/findings/store.py:39–41, 88–184, 258–378, 511–520` | project shared store lock, worker write + loop readback, summary transaction |
| S9 | `src/tools/workflow/finding.py:64–109, 420–466` | current-result/assessment guards, evidence verification, mark persisted, derivative errors |
| S10 | `src/findings/store.py:656–714` | destination checks, private temp/fsync, directory fsync |
| S11 | `src/workflow/review.py:15–41; src/workflow/state.py:1073–1079, 1993–2020` | snapshot fingerprint, bookkeeping revision, persisted mark/clear |
| S12 | `src/agent/agent.py:1905–1910, 2088–2117; src/ui/commands/result_review.py:117` | clear/reset không lấy mutation_lock tại đây; operator review có lock |

Luồng authority: operator intent/scope → Registry private args → ExecutionReview
→ exact current decision → dispatch receipt → start → active operation → nested
gate/revalidation. Receipt là authority session, không phải dữ liệu để worker
tự kiểm tra/cấp lại. `asyncio.to_thread` còn sao chép ContextVar: không được dựa
vào việc “không truyền policy trong args” để cho rằng ambient authority đã bị loại
bỏ. Worker callable phải thuần theo payload/handles, không gọi policy/UI/workflow.

Luồng evidence: source path → source gate → read/redact bytes → digest filename
→ storage → recapture metadata → proof/source-association checks → workflow
adoption. Permission approval khác với proof/assessment authority. Source_path
là provenance và sensitive-access restriction, không phải content lease.

Finding và summary: canonical report độc lập với derivative. Shared Store lock
theo project bảo vệ các cooperating instances trên cùng process/event loop;
không bảo vệ external writers, process khác hay mọi inode/path alias.
Workflow lock khác Store lock và không serialize policy revoke.

## 3. Root causes C2/C3/C4/C5

### C2

`file_resource_identity` resolve/stat pathname và bind dev/ino/size/mtime vào
digest. Registry không cho caller thay reviewed args. `start()` tiêu thụ receipt
và tính budget. TTL 60s áp dụng trước dispatch; active receipt không hết hạn
chỉ vì đã chạy hơn 60s. Active authority vẫn phụ thuộc stamp và review owner.
Revoke/retry/YOLO transition làm stamp đổi; nested gate và revalidate từ chối.

FileWrite có guard trước mkdir và guard sau mkdir, nhưng `Path(real).write_text`
mở lại pathname. Không có await giữa final guard và write hôm nay, nên một
asyncio task khác không chen vào đoạn đó. External filesystem mutation vẫn có
thể chen vào. Thêm await để dispatch worker tạo thêm cửa sổ controller revoke,
abort, workflow change và queued job; đó là lỗi **offload design**, không phải
bằng chứng production đang cho asyncio revoke chen vào đoạn synchronous.

Current write là open/truncate/write/close tại chỗ, không rename/replace/fsync.
Failure có thể để lại file bị truncate/partial. Không được mô tả production
FileWrite là atomic/durable. Atomic replacement sẽ đổi inode, permissions và
ngữ nghĩa người dùng; phải là correctness checkpoint riêng, không lén thêm vào
responsiveness patch. Parent mkdir đã là mutation trước content write; admission
design phải bao phủ nó. Chmod bằng pathname cũng cần resource binding.

### C3

`capture()` lấy size trước read, hash từ lần read, lấy stat sau read nhưng không
từ chối phiên bản đổi. Stat sau chỉ quyết định sensitive checksum-cache. Probe
growth xác nhận metadata size=5 trong khi digest lấy từ 2,000,001 bytes.
`capture_immutable_snapshot()` dùng len(snapshot) đúng lúc tạo digest, nhưng
source open vẫn bằng pathname sau containment check; read toàn file trước khi
enforce cap nên 2 MB là accepted-size bound, chưa là bounded-allocation bound.

Snapshot được redact trước digest cho UTF-8; binary fallback giữ raw bytes.
Final digest.proof được O_EXCL tạo **trước** write complete, không private temp,
không fsync. Write failure để prefix ở final name; retry coi đó là hash collision.
Recapture có thể adopt hash/size từ bytes khác với digest trong filename.
Managed `require_evidence` kiểm filename/id và chặn mismatch về sau (S3), nhưng
low-level recapture và metadata adoption không có cùng guarantee ở thời điểm
capture. Workflow lock không chặn actor ngoài filesystem hay policy changes.

FD pinning xử lý substitution, không xử lý writer cùng inode. Probe read nửa
đầu → overwrite same inode → read nửa sau nhận `AAAADDDD`, dù inode không đổi.
Phải phân biệt **identity của captured byte string** với **snapshot tại một
thời điểm của source**. fstat-before/after là detection best effort; không phải
chứng minh snapshot thời điểm khi writer adversarial có thể sửa cùng inode.

### C4

Store.save đã offload writer, shield/drain và giữ shared lock, nhưng
`read_report(Path(path))` cùng Markdown parse vẫn trên event loop (S8).
Root cause đúng một post-read boundary. Caller finalization đã kiểm result,
binding và evidence sau await; widening worker wait được guard này bao phủ.

Cancellation + worker OSError hiện trả OSError thay vì CancelledError; ownership
vẫn được drain đúng. Đây là error-precedence observation, không chứng minh
orphan worker. Patch nhỏ giữ semantics này; nếu muốn cancel thắng thì review
thành checkpoint riêng. `_write` cleanup partial khi lỗi nhưng dùng final O_EXCL
name trong lúc writing; arbitrary external reader có thể nhìn prefix. C4 patch
không thể hứa invariant “không có partial visible cho mọi reader/process” nếu
không đổi store publication. Contract READY là complete return + cooperating
locked operations + guarded workflow adoption, không global atomic publication.

### C5

Lookup/read/render/checks ở loop; worker chỉ tạo private fsynced temp. Controller
guard và canonical exact-byte comparison sau await, cancellation check,
destination check, replace, temp ownership=None, directory fsync. Store lock
giữ xuyên transaction; workflow có thể thay đổi lúc worker chạy.

Guard→replace hiện không await; async workflow mutation không chen vào đó.
Offload replace tạo gap sau guard và trước publication. Store lock không đóng
gap này. `mutation_lock` chưa là universal reservation: ConfirmFindingTool
mark_persisted và Agent clear/reset không đều tham gia (S9/S12).
`committed_revision` là checkpoint bookkeeping, không CAS/security lease (S11).
Chỉ check revision trước/sau worker không ngăn stale publication đã xảy ra.

## 4. Production vs hypothetical race matrix và impact

| Observation | Classification | Impact và reachability |
|---|---|---|
| C2 symlink substitution ngay sau last guard | **PRODUCTION-CONFIRMED** | Overwrite synthetic ngoài scope. Có thể high impact nếu actor local/path-controlling tồn tại; remote reachability chưa chứng minh. |
| C3 source substitution → outside snapshot/metadata | **PRODUCTION-CONFIRMED** | Confidentiality/scope và evidence provenance; full runtime gate reproduced. Điều kiện local mutable source như C2. |
| C3 old size/new digest, vượt accepted size ở capture | **PRODUCTION-CONFIRMED** | Integrity/bounds defect; không tự chứng minh finding sai được finalization chấp nhận. |
| C3 low-level filename/hash mismatch | **PRODUCTION-CONFIRMED** | Metadata/content-address integrity. Managed checks có mitigation về sau; không kết luận end-to-end confirmed finding forgery. |
| C3 prefix final proof + retry collision | **PRODUCTION-CONFIRMED** | Availability/integrity bug do ordinary I/O failure, không cần attacker. Ưu tiên correctness fix. |
| C2 stale worker revoke/abort/old overwrite; C3 stale read; C5 stale replace | **HYPOTHETICAL-OFFLOAD-ONLY** | Rejected naive worker proposals, chưa tồn tại production. |
| C3 concurrent partial-publication with proposed workers | **HYPOTHETICAL-OFFLOAD-ONLY** | New concurrent window được reproduce. Cross-process production schedule chưa được probe ở đây. |
| C2 pre-start revoke, expiry, deny/frozen args; nested cancel/resource changes | **ALREADY MITIGATED** | Guards/receipt identity/cleanup; không được bỏ khi offload. |
| C4 cancel drain, dedup retry, stale result; C5 preparation stale/queued cancel | **ALREADY MITIGATED** | Cooperating locks và post-await controller guards. |
| C2 revoke after completed write | **PRODUCTION-CONFIRMED** behavior; intended lifetime semantics **UNCONFIRMED** | Bytes remain, success returned. Revoke không phải rollback. |
| C4 cancellation error precedence | **PRODUCTION-CONFIRMED** behavior | OSError overrides cancel; không có chứng cứ security exploit. |
| C5 external ancestor rename at final replace; arbitrary raw finding reader partial | **UNCONFIRMED** exploit | Source cho thấy pathname/global-reader assumptions; chưa deterministic end-to-end reproduction trong audit này. |
| Native Windows, /mnt/d race/crash, power-loss guarantee | **UNCONFIRMED** | Probes /tmp trên host hiện tại không chứng minh portability hoặc durability trên mọi FS. |

Không điều chỉnh roadmap lên một “remote critical fix”: chưa đủ remote reachability.
Nếu môi trường cho untrusted local writers sửa project/source, C2/C3 containment
correctness phải lên trước performance C4/C5; không enable worker trước fix.

## 5. Security/concurrency invariants: owner, enforcement, oracle

| # | Required invariant | Owner / enforcement | Acceptance oracle |
|---|---|---|---|
| 1 | Chỉ resource được scope/approval cho phép | Controller policy + resource adapter, pinned root/parent/leaf at admission and use | Leaf/ancestor swap, hardlink/device/protected root, outside canary unchanged |
| 2 | Receipt current tại admission định nghĩa rõ | Controller, original review/dispatch checks + proposed operation admission | Fake-clock expiry, revision/revoke/owner-close trước admission ⇒ zero read/write |
| 3 | Deny/revoke không dispatch action mới | Registry + admission owner; spent one-operation token | Queued cancel/revoke before admitted ⇒ no mutation; after ⇒ no second action |
| 4 | Worker không cấp/renew permission | Callable uses detached payload/handles only; no policy API/ambient authority consumption | Instrument forbidden policy/prompter access and fail test |
| 5 | Không access live mutable controller objects | Controller owns workflow, permission, caches and snapshots | Mutate live state while worker held; worker output remains detached |
| 6 | Cancel không orphan/release ownership sớm | Controller repeatedly shields/drains; closes handles after join | Repeated cancel + blocked worker + second writer; second stays blocked |
| 7 | Chỉ complete artifact được authoritative adoption | Storage publisher + workflow finalizer | Partial write/flush/fsync failure ⇒ no registered partial; canonical retained |
| 8 | Hash/size/name/stored bytes cùng captured value | Snapshot worker computes from one redacted immutable bytes value | len/hash/readback/digest stem exact; mutate source between phases |
| 9 | Retry idempotent; collision là verified conflict | Per-resource ownership + no-clobber complete publisher; candidate dedup | Same bytes retry reuses; partial attempt cannot poison; differing existing bytes never overwritten |
| 10 | Redaction và sensitive provenance không mất | Existing redactor, controller prompt projection, scoped approval/cache | Synthetic tokens/passwords/cookies absent; sensitive alias remains gated |
| 11 | Resume/checkpoint/turn ownership giữ đúng | Controller finalization + immutable evidence refs; no ticket serialization | Cancel/stale result ⇒ historical file possibly retained, no false persisted mark; restored approval grants no authority |
| 12 | Heartbeat/Esc responsive | Offloaded I/O + unchanged mounted oracle | Original 120 ms thresholds, real Esc, I/O thread identity; test each moved syscall |

Invariant 7 cần nói rõ scope: evidence/summary design dùng atomic namespace
publication; C4 giữ existing complete-return contract, không chữa global partial
visibility của FindingStore. Strict global finding atomicity sẽ là security
checkpoint riêng ngoài patch post-read được đề nghị.

## 6. Alternatives A/B/C và trade-offs

| Criterion | A: existing locks + joined bounded worker | B: descriptor/handle resource binding | C: prepare/admit/commit protocol |
|---|---|---|---|
| Security correctness | Đủ cho C4 detached parse; chưa đủ C2/C3 authority | Binds actual object, chưa giải quyết revoke/content mutation | Defines authority lifetime/ownership; phải kết hợp B |
| TOCTOU | asyncio lock không chống external FS | Leaf no-follow + component-rooted open chống substitution trong supported namespace assumptions | Path-based commit vẫn race nếu không B |
| Cancellation | Drain giữ lock, nhưng queued writer vẫn có thể chạy | Own/close handles after join, chưa decide admission | Cancel trước admit ⇒ no mutation; sau admit ⇒ bounded drain/no new action |
| Atomicity/crash | Không tự tạo atomicity/durability | FD write in-place vẫn partial; handles chỉ resource identity | Private temp + fsync + atomic publish + directory fsync; power-loss behavior cần FS proof |
| Linux/WSL/Windows | Thread/async locks phổ biến; FS semantics vẫn khác | POSIX dir_fd/O_NOFOLLOW cần capability checks; Windows cần audited handle/reparse support | Atomic/no-clobber primitive phụ thuộc FS/platform |
| Complexity | Low, thay đổi nhỏ | Medium/high khi support ancestor protection và Windows | Medium với captured storage; high với admission/revision/all mutators |
| Offline testability | Held worker/drain/lock tests dễ | Symlink/rename/inode/same-inode deterministic tests | Stage hooks, failure injection, fake clocks, cancellation schedules |
| Architecture delta | Small | Local resource adapter, không new policy | C2 needs explicit operation contract; C5 reservation affects all relevant mutators |
| Responsiveness | Cao cho moved I/O; final checks còn blocking | Open/stat/traversal cũng phải offload safely | Cao sau khi ownership chứng minh; synchronous commit stage còn residual |

**C2:** A đơn lẻ reject; B đơn lẻ reject; C pathname-only reject. Recommend B+C,
với A cho serialization/drain. **C3:** B cho authorized bounded read + C cho
complete immutable publication, A cho workflow/storage cooperation. Không dùng
`asyncio.Lock` như filesystem sandbox.

Compatibility chưa được chứng minh bằng documentation/external calls hoặc native
Windows test trong audit offline. Thiết kế phải capability-detect và fail closed,
không silent fallback sang resolve→open. POSIX directory fd pinning không đảm bảo
directory vẫn nằm trong namespace ban đầu nếu actor có thể reparent nó. Root/parent
ownership hoặc isolation boundary phải được định nghĩa; fstat/path recheck không
thể loại mọi race với adversarial namespace mutation. Đây là entry gate, không
một assumption ẩn để gọi design “safe trên mọi platform”.

## 7. Recommended design theo boundary

### C2: resource binding + explicit admission, chưa implement

Đề xuất protocol cụ thể, không gọi đây là production semantics đã có:

1. Controller freeze path/content/encoding/mode và invocation identity; giữ mọi
   Registry/operator/nested gate hiện tại. Lấy per-destination ownership trước
   final revalidation. Lock phải dùng canonical resource key và giữ tới join;
   không thay receipt guard bằng lock.
2. Bounded preparation worker bind root/component/parent và existing leaf handle
   **không truncate/write**. Existing leaf phải regular, expected dev/ino/stat,
   nlink và supported scope; new leaf là explicit absent-name reservation.
   Sensitive spelling/provenance giữ riêng dù resolved resource bình thường.
   Worker ready trả detached identity, giữ handles; chưa nhận mutation permit.
   Việc open-read/source acquisition cũng phải nằm trong authorized operation;
   không đọc bytes “để chuẩn bị” trước approval.
3. Controller revalidate current args, active receipt, resource, review owner,
   abort, generic validation binding và pending cancellation. Chỉ sau khi worker
   **ready**, admit một bounded operation bằng one-shot immutable permit; không
   enqueue mutating I/O trước điểm này. Permit không serialized, không reusable,
   không chứa secret approval, không cho worker dispatch tool phụ.
4. Worker dùng handles đã bind. Existing inode: fd write tránh leaf symlink;
   new name: rooted exclusive/no-follow create để race tạo name làm failure.
   Missing directory creation phải được permit bao phủ, với component-bound
   mkdir/open và fail closed nếu root namespace chưa bảo vệ được. Chmod qua fd.
   Không replay resolve/open theo pathname đã review. Existing stat check tại
   worker vẫn cần vì filesystem actor có thể sửa same inode sau admission;
   không tự cho phép overwrite tài nguyên đã đổi ngoài operation contract.
5. Drain dưới resource ownership, close đúng once, trả detached result; controller
   báo completed/failed/cancelled-with-possible-effect đúng thực tế. Receipt stop
   chỉ sau drain. Retry phải review current object, không revive permit cũ.

Recommended revoke semantics: trước admit, zero mutation; sau admit, một operation
đã nhận quyền chạy được drain, revoke ngăn operation mới. Đây là **đề xuất explicit
lease cho admitted work**, cần phê duyệt contract trước implementation vì stamp
checks hiện tại chưa định nghĩa lease như vậy. `start()` không tự là lease đó.
Nếu yêu cầu revoke trước syscall phải chặn cả admitted work, cần thêm thread-safe
admission/commit arbiter serialize revoke với mutation-start. Worker chỉ dùng
arbiter token state, không live policy. Không thể đạt yêu cầu bằng revalidate
trên loop + await, hoặc bool cancelled unsynchronized; cũng không được block
controller chờ mutex held xuyên slow I/O. Strict contract này vẫn **BLOCKED**.

Security resource fix có thể làm đồng bộ trước threading. Atomic overwrite/durable
write là optional correctness checkpoint riêng; current in-place behavior giữ
nguyên trong minimal responsiveness proposal. Không hứa rollback truncate/write.
S1–S5 và old `test_c2_current_path_swap_after_last_guard_redirects_write`,
`test_c2_naive_worker_handoff_is_unsafe`, queued cancellation, old/new writer,
new nested/TTL/destination probes là bằng chứng cho các gates trên.

### C3: một captured byte value, complete immutable publication

Chia ba transactions: authorized capture, storage publication, workflow adoption.

**Capture:** sensitive/source approval trên controller; bounded reader bind
approved source descriptor sau scope/identity check, chỉ đọc tối đa cap+1 bytes.
Redact UTF-8 bằng existing `apply_evidence`; compute stored length/hash/name/id
từ **cùng một immutable redacted byte string**. Không stat-size làm artifact.size,
không recapture để replace expected identity. Stat-before/after phải dùng fstat
cùng fd; mutation detected ⇒ reject bounded attempt, không infinite retry.
Đó là consistency detection; nếu yêu cầu point-in-time source snapshot mạnh hơn,
cần cooperating writer exclusion hoặc filesystem snapshot/immutable producer.
Không claim same-inode adversary đã được giải quyết chỉ bằng FD và fstat.

**Publish:** dưới content-address destination ownership, tạo private same-directory
O_EXCL temp 0600, write complete, check write count, flush/fsync; set final intended
mode 0400 qua owned handle và sync metadata theo durability contract. Publish
no-clobber bằng primitive đã chứng minh trên filesystem đó. Existing final name:
open safe bound object và compare bounded stored bytes/hash/size với expected
snapshot; equal ⇒ reuse, mismatch ⇒ explicit integrity conflict, không overwrite.
Không unconditionally `os.replace` existing content-addressed proof.

Một POSIX candidate là link temp→final atomically no-clobber, unlink temp rồi verify
final nlink=1 trước managed adoption. Nó **chưa là universal solution**: giai đoạn
hai hardlinks tạm thời không được đưa vào workflow; crash giữa link/unlink có thể
để nlink=2 và cần recovery của owned temp. Native Windows/WSL mounted FS cần
capability proof; platform-specific no-replace rename là alternative, không
giả định stdlib portable support. Nếu primitive/ownership chưa hỗ trợ, stop.
Sync directory sau publication. Crash visibility và durable commit phải phân biệt.

**Adopt:** worker trả artifact DTO/proof bytes tối thiểu/durability outcome; controller
revalidate candidate/objective/route/target/policy và generic snapshot sau mỗi new
await, check source claims từ đúng captured bytes, enforce association, rồi
`add_evidence` trong existing workflow mutation ownership. Approval set là local
operation only; sensitive cache mutation ở controller sau checked success.
Complete proof có thể tồn tại mà chưa registered khi cancel/stale adoption; retry
verified reuse, không delete proof đã publish chỉ vì caller cancel. Failed temp
cleanup chỉ xóa đúng owned temp, không final file khác hoặc cạnh tranh winner.

Binary fallback hiện không redact bytes (S6). Không âm thầm bỏ binary support hoặc
gọi binary “sanitized”. Contract vẫn cần minimal evidence/operator-controlled
binary provenance; nếu yêu cầu bảo đảm secret-free binary tuyệt đối thì **BLOCKED**
đến khi có policy riêng. Raw authorized read và durable/redacted snapshot là hai
security boundaries khác nhau; redaction không sửa lỗi đọc ngoài phạm vi.

S3/S6/S7, old source/size/partial/retry probes và new end-to-end source/FD/growth
probes chứng minh lý do cần từng bước. No-clobber và recovery mới là design,
chưa có implementation test PASS được nhận là proof.

### C4: patch nhỏ write/reuse + read trong một worker

Capture candidate_id, slug, rendered content trước chờ lock. Giữ Store API,
validators, render/redaction contract, `_write_once_for_candidate` và existing
cleanup/dedup. Worker gọi existing writer, read canonical returned path và parse,
trả `(path, detached Finding)`; controller copy fields vào caller Finding **chỉ
sau joined success**, dưới cùng shared store lock. Không gửi mutable caller
Finding vào worker. Không separate await cho read, không thêm policy trong parser.

Keep current shield/repeated-cancel drain/error precedence; read failure giữ
canonical, no workflow persisted mark; retry đọc existing report, không duplicate.
Do not copy proposed retry title vào historical canonical. Caller S9 giữ tất cả
result/assessment/evidence revalidation trước mark persisted. External edits giữa
read và finalization vẫn thuộc trust assumption hiện có, không claim store CAS.
Render CPU và other Store APIs còn trên loop; mounted post-read PASS không chứng
minh toàn finding pipeline không block. S8/S9, `proposed_postread` và năm C4
design observations (stale/cancel/read-error/mounted + current guards) support READY.

### C5: offload durability trước; giữ publication owner hiện tại

Minimal C5.1: giữ lookup/prep/final guard/canonical compare/destination check/replace
như production. Bind/pin đúng directory handle và chuyển ownership của handle
cho joined fsync worker; không gọi pathname `_fsync_directory` trong worker như
thể path không đổi trong await. Initial minimal synchronous directory open có
thể vẫn block; đo riêng, không hứa loại toàn I/O. Nếu prep trả owned handle thay
pathname thì controller phải retain/close nó qua cancellation và assert cùng
destination directory used by publication; integration proof cần trước release.

Ngay replace success: controller đặt temp=None trước await fsync. Fsync error/cancel
⇒ derivative có thể visible nhưng durability unknown; canonical/persisted mark
không rollback. Joined cleanup retain lock/owned temp/handles. Old fsync prototype
chỉ chứng minh drain/shared lock, chưa chứng minh directory binding hoặc full
mounted summary prototype, nên verdict READY WITH CONDITIONS.

C5.2 passive preparation/read phases chỉ dùng detached input dưới Store lock;
mọi new await cần guard/canonical/resource rechecks. Không di chuyển live guard
closure vào thread. Final exact-byte check còn trên loop cho tới có ownership
khác tương đương; worker read trước đó không làm external-change detection CAS.

C5.3 worker replace: cần reservation bao phủ **mọi** relevant workflow/turn reset,
target invalidation, finding finalization và operator mutation, từ final guard
qua replace completion; Store ownership thêm canonical/CWE serialization. Lock
order proposal workflow reservation → Store lock → worker, không reverse. Phải
kiểm reentrancy ConfirmFindingTool gọi export và all call sites trước dùng.
Agent synchronous target/reset APIs không tự await mutation_lock. Thêm exporter
lock riêng hoặc check bookkeeping revision không đủ. Under current hard stops,
chưa được sửa các owners đó; **BLOCKED**, không chọn “stale nhưng admitted summary
vẫn publish” để bypass contract current-result. S8–S12 và stale-worker probe support.

## 8. Linearization/admission points và revoke/cancel semantics

| Boundary | Authority admission | Publication/effect point | Revoke/cancel policy |
|---|---|---|---|
| Current C2 | start = dispatch; final revalidation là last checked authority, không FS-atomic point | mkdir có effect trước content open/truncate; write tại chỗ có nhiều effects | Revoke trước guard rejected; sau completed write không rollback; không có declared worker lease |
| Proposed C2 | controller admits ready bound operation, before first mutation including mkdir | Existing file: first truncate/write; optional replacement: rename commit | Before admission abort ⇒ no mutation; after ⇒ bounded admitted work/drain only, subject to approved lease semantics |
| Proposed C3 read | controller approves ready bound source read | Actual read consumes authority, không thể undo đã đọc | Revoke before read admission blocks; after read admission semantics phải explicit như C2; stale controller adoption rejected |
| Proposed C3 storage | private storage transaction on detached sanitized bytes | successful no-clobber final-name publication | Cancel prepublish removes owned temp; postpublish complete unregistered proof may remain |
| C4 | accepted-result/evidence contract at caller; no FileWrite receipt in store | complete canonical write/reuse vs workflow persisted mark là hai facts | Cancel drain retains historical report, no caller/state snapshot commit; stale finalization rejected |
| C5 staged | controller current-result guard + checks without new pre-replace await | `os.replace` = derivative namespace commit | Pre-replace cancellation/staleness rejects; post-replace fsync/cancel not rollback |
| C5 worker replace | proposed universal workflow/store reservation before dispatch | actual worker replace while reservation held | No stale mutation during reserved commit; owner release only after join; unproven, BLOCKED |

Admission, syscall start, namespace publication và durability completion là bốn
điểm khác nhau. Fake permission success, YOLO và session trust không substitute
operation admission. New turns/resume không được reuse permit; no tickets in
durable memory/session artifacts. TTL đã consumed không tự biến thành running
TTL. Chỉ gọi finalization thành công sau existing evidence/assessment guards.

## 9. Deterministic reproduction và kết quả

Hai modules: `tests/security/test_persistence_handoff_audit.py` (35 old cases,
rerun), `tests/security/test_persistence_deep_audit.py` (7 additional cases).
Fixture dùng fresh `/tmp`, synthetic bytes, fake operator; network connect/DNS
fail closed kể cả swallowed violation. Thread holds có five-second bound và
finally release/join; nested cancel uses Events with bounded wait, không timing
ngẫu nhiên. Một số old cooperation assertions dùng short sleeps cho negative
lock observations; ordering nguy hiểm được anchor bằng Events/hooks, không bằng
“hy vọng race xảy ra”. Tests không patch production files.

| Case / initial state | Controlled interleaving | Expected safe / actual / oracle |
|---|---|---|
| Receipt prepared, no output | revoke → start | Reject; actual rejects, output absent. Old before-start test. |
| Valid active write, parent exists | mkdir hook revoke → final guard | Reject content write; actual rejects. Parent creation effects không rollback. |
| Valid active proposed worker held | final guard → revoke/abort/revision → release | No stale unadmitted work; naive writer still writes. DESIGN ONLY. |
| Output absent + outside canary | last guard → write_text hook symlink → actual open | Scope-bound use required; actual outside overwritten. PRODUCTION path-control prerequisite. |
| Approved source + inside/outside bytes | scope/source gate → read_bytes hook swap → publish/adopt | No outside read; actual snapshot outside, metadata adopted; later managed gate rejects. New full-policy test. |
| Source size 5 | stat → read hook replace with cap+1 bytes → hash | One snapshot length/hash bound; actual size=5/hash oversized bytes. New capture-growth test. |
| Source bytes AAAABBBB, read FD | read 4 → same-inode overwrite CCCCDDDD → read rest | FD identity alone not snapshot; actual AAAADDDD. DESIGN ONLY counterexample to B alone. |
| Complete proof source | fdopen writes prefix then raises | No partial final, retry success; actual prefix final + collision retry. Old production test. |
| Same digest worker held after final create | second capture attempts same final | Complete bytes/wait; naive worker sees collision on incomplete file. DESIGN ONLY. |
| Finding read worker held | cancel twice or mutate result → release | Join + lock until done; no persisted mark, one report. C4 candidate passes. |
| Finding canonical already written | parser error → retry | Canonical retained/idempotent; candidate passes. |
| C5 private preparation held | clear persisted state or change canonical → release | Final guard rejects/old derivative intact/temp gone. Production passes. |
| C5 preparation complete, hypothetical replace held | final guard → clear workflow → release replace | No stale derivative; naive commit still publishes. DESIGN ONLY. |
| C5 commit failure injection | replace fails, or replace succeeds then fsync fails → retry | Old derivative precommit; visible new derivative postcommit; canonical retained in both. Production passes. |
| Pending nested sensitive review of .env | signal.set or task.cancel → late ALLOW_ONCE | No write/receipt leak; new tests pass both variants. |
| Active receipt consumed at fake time 0 | clock beyond expires → revalidate → revoke → revalidate | Still active after dispatch TTL; invalid after revoke. New test passes. |
| Two receipts prepared for absent same dest | first production write completes → start second | Second stale resource rejects, first bytes remain. New test passes; not proof thread/cross-process serialization. |
| Held C4 candidate read, mounted TUI | heartbeat + actual Esc during synthetic 400ms I/O | 37.7ms heartbeat, 1.7ms Esc, 22 ticks, I/O off loop; unchanged oracle PASS. |

Existing C2 lifecycle tests supplement deny/expiry/frozen args/closed owner/nested
file replacement. New nested test is actual cancellation; do not conflate it
with closed-parent review rejection. Old C2 cancel-drain queued writer shows
joining alone does not implement pre-admission cancellation.

Measurements current production, same original 120ms thresholds:

| Boundary | Heartbeat gap ms | Esc delivery ms | Operation ms | Outcome |
|---|---:|---:|---:|---|
| FileWrite | 422.8 | 362.8 | 401.4 | strict XFAIL |
| Evidence snapshot | 425.6 | 370.5 | 404.9 | strict XFAIL |
| Finding post-read | 411.3 | 360.9 | 420.3 | strict XFAIL |
| Summary directory fsync | 408.4 | 353.7 | 417.3 | strict XFAIL |

Controls heartbeat 31.5–44.2ms, Esc 1.1–1.6ms; responsive oracle passes. Synthetic
holds prove loop blocking, not natural WSL latency or live freeze root cause.

## 10. Checkpoint implementation plan

Mỗi checkpoint là patch riêng. Không triển khai trong audit này.

| Checkpoint / kind | Minimal files proposed | Test-first + acceptance | Rollback boundary / stop |
|---|---|---|---|
| P1 C4 responsiveness | `src/findings/store.py`; focused finding/store tests; responsiveness marker only after proof | Capture before lock; write+canonical parse worker; cancellation/read-failure/dedup/stale evidence/current-result; mounted original oracle | Revert only post-read handoff, preserve reports/schema. Stop on duplicate or lock early-release; no error-precedence refactor. |
| P2 C5.1 responsiveness | `src/findings/store.py`; summary and audit regressions | Pinned directory fd; held fsync repeat-cancel/error/cleanup, canonical intact, mounted fsync oracle | Return durability call to controller; never rollback committed derivative/canonical. Stop if pinned directory ownership unproved. |
| P3 C3.1 source correctness | `src/workflow/evidence.py`; local resource adapter if needed; evidence tests | Bounded FD read; length/hash from same redacted bytes; swap/hardlink/source mutation/alias/redaction | Keep schema/location/provenance; old unsafe path-read fallback forbidden. Stop if platform/root binding unsupported. |
| P4 C3.2 publication correctness | `src/workflow/evidence.py`; publication helper + focused tests | Private temp, no-clobber complete publish; write/flush/fsync/close faults, collisions/retry, temp cleanup/crash-recovery protocol, managed nlink=1 | No migration/delete of valid existing proofs; failed new temp isolated. Stop on partial final visibility or retry poisoning. |
| P5 C3.3 responsiveness | evidence APIs + `src/tools/workflow/workflow_tool.py`; evidence/workflow tests | Explicit read admission, detached worker, new-await controller guards, cache owner, cancellation/drain + oracle | Retain correctness P3/P4 if threading reverted. Stop if ticket needs unapproved policy semantics or false evidence adoption. |
| P6 C2.1 admission/resource correctness | `src/tools/execution/file.py`; resource adapter; execution-policy design/tests | Approve mutation admission semantics before code; all pre-admission revoke/deny/cancel cases zero mutation; bound inode/name actual use | Policy/registry gates remain. Any needed `execution.py` guard contract change is separate authorized scope, not part of audit. Stop if ownership/root/strict revoke unresolved. |
| P7 C2.2 responsiveness | FileWrite + adapter; file/policy/worker tests | Ready handshake, one-operation permit, destination lock, drain, overwrite order/queue cancellation, all blocking phases + oracle | Keep resource correctness when offload reverted. Stop on worker live policy access/stale mutation. |
| P8 C5.2 passive responsiveness | Store lookup/preparation helpers + summary tests | Detached lookup/read output; final guard/canonical bytes detect every new-await state change | Keep controller publication; stop if any external-change detection lost. |
| P9 C5.3 commit responsiveness | Store + all reservation owners including finding/Agent/UI/workflow APIs as required | Explicit scope expansion first; universal mutator coverage, turn/target reset, no lock inversion, worker replace pinned handles | Keep staged fsync/prep improvements; stop until every mutator participates and stale replace impossible. |

Default priority P1 → P2 → P3/P4 → P5 → P6/P7 → P8/P9. C3 ordinary failure/retry
correctness can run independently before P1 if evidence availability is urgent.
If path-controlling attacker is established, prioritize containment fixes P3/P6;
do not deploy throughput gains that increase their race surface.

## 11. Acceptance tests, verification performed và stop conditions

Offline commands executed (no full suite):

```bash
PYTHONDONTWRITEBYTECODE=1 venv-linux/bin/python -m pytest -q -s --tb=short \
  -p no:cacheprovider tests/security/test_persistence_handoff_audit.py
# 35 passed in 8.27s (observations, including unsafe outcomes)

PYTHONDONTWRITEBYTECODE=1 venv-linux/bin/python -m pytest -q -s --tb=short \
  -p no:cacheprovider tests/security/test_persistence_deep_audit.py
# 7 passed in 3.28s (observations)

task_deep_scratch=$(mktemp -d /tmp/kagent-deep-regression.XXXXXX)
TMPDIR="$task_deep_scratch" PYTHONDONTWRITEBYTECODE=1 venv-linux/bin/python -m pytest \
  -q --tb=short -p no:cacheprovider -p tests.scenarios.offline_checkpoint \
  --basetemp="$task_deep_scratch" \
  tests/tools/test_file.py tests/security/test_evidence_reads.py \
  tests/data/test_findings_store.py tests/data/test_finding_summary_store.py \
  tests/tools/test_finding.py tests/security/test_execution_policy.py \
  tests/security/test_c2_review_lifecycle.py \
  -k 'not native and not process_and_mcp and not capture_credentials and not exact_approval and not private and not shell'
# 190 passed, 33 deselected in 20.52s

PYTHONDONTWRITEBYTECODE=1 venv-linux/bin/python -m pytest -q -s --tb=short \
  -p no:cacheprovider tests/ui/test_persistence_responsiveness.py -k 'not session_save'
# 5 passed, 2 deselected, 4 xfailed in 26.51s

venv-linux/bin/pyright src/tools/execution/file.py src/workflow/evidence.py \
  src/findings/store.py tests/security/test_persistence_handoff_audit.py \
  tests/security/test_persistence_deep_audit.py
```

Responsibility filter intentionally excludes native-network/process-related
tests, including some existing mocked cases; no claim of whole policy suite
coverage. C1 session group intentionally excluded. Legacy fixtures use shared
TMPDIR/basetemp containment per previous audit; guard not weakened.

Pyright: **0 errors, 0 warnings, 0 informations**; available-version notice
ignored, không install. `git diff --check` và explicit no-index whitespace
checks cho hai new files không có whitespace diagnostics. Tracked `git diff`
trống, gồm production, old probes và mounted oracle; new probe diff đã review.
Final worktree chỉ có hai untracked additions: báo cáo này và
`tests/security/test_persistence_deep_audit.py`. Không chạy full suite, C1,
native Windows, crash/power-loss, live model/Burp/external network.

Additional implementation acceptance matrix, **not yet passed**:

- Every phase before/after permission review, worker-ready, admission, open,
  truncate/create, publish, fsync, adoption: controlled Event/hook schedule.
- Fake-clock review/dispatch expiry; active TTL semantics; deny/revoke/YOLO toggle,
  owner close, nested task/signal cancellation; spent/replayed ticket rejected.
- Root/component/leaf symlink, regular file rename, hardlink/device, protected path,
  absent name collision, parent reparent; feature-unavailable platforms fail closed.
- Evidence size cap+1, empty/growth/truncate/same-inode mutation; redacted stored
  byte identity; binary behavior explicit; fingerprint/filename/id/readback agree.
- Temp open/fdopen/short-write/flush/fsync/chmod/close/link/replace/directory-sync
  errors; exact owner cleanup; retry same data and true conflicting bytes.
- Cancel before queue, ready, admit, during read/write, prepublish, postpublish;
  repeated cancel, worker fails during drain, second writer waits; no orphan.
- Finding historical canonical wins retry; parser fault/cancel/stale result or
  evidence never produce false persisted state. Complete-return vs global
  publication scope explicitly tested, not conflated.
- Summary stale result/assessment/canonical/target/turn/reset at every await;
  concurrency with save/CWE/export; lock order and no stale replace.
- Resume/checkpoint tests appropriate to changed callers; no receipt/read-approval
  serialization or new durable authorization; canonical success independent
  of derivative failure.
- Existing mounted heartbeat/Esc at original thresholds for each newly moved
  syscall; cancelled operation completion may wait for drain while UI schedules.

Stop implementation when required capability absent, live mutable authority
crosses worker boundary, old guards must be removed, all-mutator reservation not
proved, deterministic race still violates scope/identity, publication can poison
retry, or responsiveness improvement is measured by weakening oracle. Do not
try to remove every XFAIL through one refactor. Blocking syscalls cannot be
force-killed safely by asyncio; no artificial hard-timeout lock release.

## 12. Residual risks và unsupported assumptions

No native Windows, external-process adversary, power-loss or /mnt/d filesystem
conformance run. No POSIX primitive assumed portable, no guessed model/metadata,
no remote exploit claim. Directory pinning requires declared namespace trust;
source fstat stability is insufficient for adversarial point-in-time snapshot.
Current binary proof fallback may contain secrets; current in-place FileWrite
may leave partial content; current FindingStore is not a global atomic publisher.
Those are explicit limits, not effects fixed by threading.

Readback integrity does not establish semantic truth of a proof; existing
assessment/provenance/accepted_result gates stay authoritative. Complete orphan
proofs/reports after cancellation are different from orphan **workers**; retention
is part of retry semantics, cleanup must not erase a competing valid artifact.
Directory fsync failure after publication needs honest durability outcome, not
fictional rollback. Render/hash/redaction CPU may hold GIL; offload I/O does not
prove zero CPU stalls. Guard resolve/stat/canonical final read/replace remaining
on loop need separate timing tests even if sampled fsync oracle passes.

No separate reviewer/sub-agent was used. All design readiness is bounded by the
source/test evidence above; proposed new admission/no-clobber/reservation mechanisms
remain unimplemented and require test-first proof before deployment.

## 13. Final readiness verdict

**C4 READY; C5 staged fsync READY WITH CONDITIONS; C2/C3 full worker handoff and
C5 worker replace BLOCKED.** Security correctness checkpoints can proceed as
independent designs after implementation approval; no C2–C5 patch was installed.
This audit ends at solution design. It does not authorize production changes.
