# C4 cleanup + C3 correctness checkpoint

**Verdict: C4 PASS; C3 PARTIAL / BLOCKED.** Giữ phần bounded read và
captured-value consistency đã kiểm chứng. Không triển khai source-binding
adapter, publisher mới, C3 worker, C2 hoặc C5.

## A — C4 final cleanup

- Giữ bản vá có trước trong `src/findings/store.py`: freeze writer scalars trước
  lock; write/reuse/read/parse trong một joined worker; copy Finding trên loop.
  Shared project lock giữ xuyên worker drain; không đổi error precedence.
- Giữ 9 regression C4: thread ownership, queued cancellation, frozen inputs,
  read/parse error + retry, stale result/evidence, repeated cancel, worker error.
  Bỏ dependency vào trace framework; dùng Events và kiểm tra state/lock trực tiếp.
- Loại hai utility chỉ phục vụ điều tra: `tests/ui/persistence_diagnostics.py`
  và `tests/ui/test_persistence_diagnostics.py`. Gỡ trace wrappers/print khỏi
  C4 regression. Production không có debug hook mới.
- Giữ mounted responsiveness oracle, ngưỡng heartbeat/Esc 120 ms, tick/integrity
  assertions và các báo cáo/trace cũ. Các command trong báo cáo điều tra cũ mô tả
  revision trước cleanup; dùng command kiểm thử dưới đây cho patch hiện tại.

Entry gate sau cleanup: **12 passed, 8 deselected**; Pyright sạch;
`git diff --check` sạch. Held C4 post-read: operation 407.8 ms, heartbeat
27.4 ms, Esc 1.3 ms, I/O ngoài UI thread. Không duplicate, false persisted mark
hoặc thay đổi cancellation/error precedence trong các schedule đã kiểm thử.

## B — phần C3 đã sửa

| Lỗi / invariant | Sửa trong production | Acceptance evidence |
|---|---|---|
| Read toàn file trước cap | Unbuffered reads với tổng budget `MAX_EVIDENCE_BYTES + 1`; hỗ trợ short reads | Empty/cap/cap+1; growth vượt cap; short-read tổng byte budget; configurable cap |
| Size từ stat cũ, digest từ bytes mới | Size/hash/ID từ cùng captured bytes; fstat trước/sau cùng descriptor, từ chối thay đổi phát hiện được | Growth, truncation, same-inode overwrite, hash/size/ID formula |
| Snapshot recapture adopt bytes khác dưới filename cũ | Metadata từ redacted snapshot value; verification chỉ compare, không adopt giá trị khác | Không gọi recapture để tạo metadata; changed destination ⇒ integrity conflict |
| Guard của canonical readback | Tách guard cũ khỏi metadata construction, giữ resolve/containment/sensitive/is_file checks trước verification | Post-write ancestor ngoài project bị từ chối; sensitive leaf substitution bị từ chối trước read |
| Redaction, binary, retry | Giữ `apply_evidence`, binary fallback, source provenance, ID formula và incumbent conflict outcome | UTF-8 secret redaction; opaque binary unchanged; valid reuse; conflicting bytes không overwrite |
| I/O failure/adoption | Owned source handle đóng qua context manager; failed/detected-mutated capture không publish metadata | Read/fstat fault; workflow không add evidence; stable retry thành công |

Snapshot vẫn chấp nhận captured value không rỗng trong cap khi regular virtual
source có stat size không biểu diễn byte count. Cap/metadata dùng actual bytes;
fstat là consistency detection, không phải bằng chứng snapshot tại một thời điểm.
Schema, artifact locations, modes, source provenance, source associations và
validation/finding contracts không đổi. Captures phát hiện mutation hoặc stored
value mismatch nay bị từ chối thay vì trả artifact không nhất quán.

Source/verification vẫn synchronous. Không thêm await, worker, admission lease,
authorization cache hoặc platform-specific fallback. Cache checksum nhạy cảm
giữ schema/bound 1024 và không cấp quyền đọc.

## B — phần bị BLOCKED

**B1 source binding đầy đủ: BLOCKED.** Reader kiểm tra actual FD là regular file
và đọc có giới hạn; scope vẫn là pathname checks hiện tại. Real Registry +
ExecutionPolicy probes tái hiện leaf/ancestor swap trước open: outside synthetic
bytes vẫn có thể được snapshot/adopt. Đây là lỗi còn tồn tại, không phải PASS
cho source security. Một POSIX root/parent FD không chứng minh continued namespace
membership: parent có thể reparent ra ngoài root. Chưa có ownership contract hoặc
adapter đáp ứng invariant đó; không chọn assumption “root/ancestors trusted” ngầm.

**B3 complete publication/retry recovery: BLOCKED.** Giữ publisher cũ; chưa chữa
partial authoritative filename hoặc retry bị poisoned sau write failure. Proposed
hardlink publication có no-clobber trong schedule được thử, nhưng crash giữa
link/unlink để `nlink=2`, bị guard `ambiguous-hardlink` từ chối. Chưa có recovery
owner phân biệt abandoned temp với active invocation. Unconditional path cleanup
cũng có thể xóa resource của actor khác sau name substitution. Không đưa candidate
publisher đó vào production, không dùng `os.replace` như no-clobber, không thêm
flush/fsync/durability contract mới khi publication ownership còn thiếu.

Same-inode adversarial mutation không được giải quyết chỉ bằng FD identity/fstat.
External edits sau verification, namespace mutation và cross-process ownership
vẫn nằm ngoài guarantee của phần B2. Không kết luận reachability từ HTTP target.

## Verification và test classification

- Test-first B2 baseline: **16 failed, 7 passed**. Đây là acceptance failures
  của code cũ, không phải XFAIL mới.
- Review bắt thiếu sót ở bản nháp B2: **2 post-read guard tests failed**. Đã giữ
  lại các guard cũ trong `_checked_capture_path`; final regression bao gồm cả hai.
- Final trách nhiệm store/workflow/permission/assessment/session/checkpoint/UI/CWE:
  **582 passed**, không skip/fail/XFAIL. Chạy với `tests.scenarios.offline_checkpoint`,
  TMPDIR và basetemp trong cùng owned `/tmp` container.
- C3/C4 audit modules: full run trước refinement cuối **42 passed**; C3 subset
  final **12 passed, 30 deselected**. Observation PASS có thể tái hiện unsafe outcome. Các case
  size-growth và filename/value mismatch đã đổi sang `PRODUCTION_ACCEPTANCE`;
  hooks được chuyển tới actual bounded-read path, không giảm oracle.
- Mounted full run: **8 passed, 3 xfailed**; targeted final C4 + C3 oracle được
  chạy lại sau guard repair: **13 passed, 1 xfailed, 6 deselected**. C3 vẫn strict responsiveness XFAIL. Fault injection
  chuyển từ `Path.read_bytes` sang production bounded reader; delay/thresholds
  và integrity assertions giữ nguyên.
- Native `/tmp` blocker/design probes PASS với nghĩa “tái hiện blocker”.
  WSL mixed run: **46 passed, 2 failed** ở hai **DESIGN-ONLY** namespace/cleanup
  assumptions; không phải acceptance failures của patch B2. Không sửa oracle để
  biến hai failure này thành PASS.
- Final WSL bounded-value/permission acceptance: **46 passed**, không skip/fail.
  Pyright trên các Python files thuộc patch: **0 errors, 0 warnings, 0 informations**.
  `git diff --check` sạch; diff và worktree status đã kiểm tra. Full repository
  suite không chạy; version notice của Pyright chỉ là thông tin.
- Native Windows, power loss, mọi filesystem race và live LLM/Burp/HTTP không chạy.
  Production write/flush/fsync/close publication transaction acceptance chưa đạt
  vì B3 chưa có publisher/ownership contract được chấp nhận.

WSL `/mnt/d` không có cùng namespace visibility với `/tmp`: rooted open sau
directory reparent trả ENOENT; retired filename chưa visible trong lúc FD mở,
visible lại sau close. Probe độc lập không dùng fixture guard xác nhận khác biệt.
Hai design failure củng cố yêu cầu filesystem conformance trước B1/B3 implementation;
không chứng minh file bị mất vĩnh viễn hoặc một remote exploit.

Verification setup được ghi rõ: một broad run đầu có capability probe bị skip
vì fixture wrap `os.open`; capability snapshot nay lấy trước fixture. Focused
guarded rerun không skip. WSL run đầu chưa chạy test do pytest FD capture/TMPDIR/
basetemp trên drvfs; rerun dùng `-s`, giữ containment. Không cài dependencies.

## Files và boundary của handoff

- Retain: `src/findings/store.py` — C4 patch có trước, không có production edit
  mới trong checkpoint A.
- Edit: `src/workflow/evidence.py` — bounded captured value, stable metadata,
  canonical verification giữ guard cũ; publisher/permission/workflow state không
  được refactor.
- Edit: `tests/data/test_finding_postread_async.py`,
  `tests/ui/test_persistence_responsiveness.py`,
  `tests/security/test_evidence_reads.py`,
  `tests/security/test_persistence_handoff_audit.py`,
  `tests/security/test_persistence_deep_audit.py` — relevant C3/C4 regression/hooks.
- Add: `tests/security/test_evidence_correctness.py`,
  `tests/security/test_evidence_correctness_blockers.py`, báo cáo này.
- Remove: hai investigation-only utility nêu tại checkpoint A. Không xóa report,
  trace hoặc untracked artifacts khác; C2 feasibility work được giữ nguyên.

Để gỡ B1/B3 cần quyết định/review namespace ownership, platform binding và
complete-publication recovery contract trước implementation. Không tự chuyển
sang responsiveness/C5. Task dừng tại C4 PASS và C3 correctness partial.
