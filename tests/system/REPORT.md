# System/E2E validation

## Follow-up 2026-10-17: measurement accuracy và các mục còn mở

**Quy ước verdict cuối theo yêu cầu mới:** hai system scenario whole-target/direct
không fail chỉ vì heartbeat trên 120 ms. Vẫn đo/lưu raw gap và warning trên 120 ms;
verdict functional/lifecycle riêng chỉ pass sau workflow/ownership/persistence,
input phục hồi thật, idle busy/timer/modal và owned cleanup. Hang/watchdog,
cancel không settle, orphan hoặc UI không phục hồi vẫn fail. Các dedicated
responsiveness test giữ nguyên threshold và recovery oracle.
Rà soát matrix system cũng bỏ các numeric latency gate tương tự ở route/cancel;
vẫn giữ signal Esc thực sự được set, timeout chờ settle, idle/receipt/orphan
assertions. Dedicated tests trong UI/runtime/integration không đổi oracle.

Đã sửa nhiễu đo của harness và hai narrowing assertion UI; không đổi production
trong follow-up. **B vẫn timing/intermittent chưa đóng root cause.** CPU/heartbeat
cao của A còn là diagnostic chưa giải thích hết, không phải system acceptance
failure. Không skip/xfail. Hai fix HTTP/MCP trước đó được giữ nguyên.

**A — tái hiện và tách instrumentation.** Baseline mới: whole-target **1.002 ms**,
direct **586 ms**, functional/state/persistence/cleanup đều qua trước assertion.
Minimal reproducer chỉ đưa playbook SQLi thật **61.616 ký tự** vào
`TraceRecorder.record()`, không chạy Agent/network: **538 ms** với cProfile;
đo cặp không profiler **649 ms inline / 0,035 ms capture deferred**. Công việc
redact tương đương **583 ms** chạy sau cửa sổ đo, không bị bỏ. Phần lớn CPU
trong `_redact_json_fields` và regex khi harness redact lại JSON đã serialize.
Đây là **harness measurement contamination đã xác nhận**, không phải chứng minh
toàn bộ độ trễ đến từ harness.

Fix giới hạn ở helper: system runner snapshot event ngay tại callback, vẫn gọi
`InvariantOracle.boundary` tại transition cũ; chỉ defer JSON/redaction riêng của
trace đến sau measured turn, trước outcomes/export. Production sanitizer/store
không đổi. Export lỗi thì không ghi raw. Default của legacy scenario giữ inline.
Ba regression kiểm tra event copy/checkpoint ordering, export giống legacy và
fail-closed, cùng positive control cố ý block callback **160 ms** vẫn bị heartbeat
120 ms phát hiện. Không trừ thời gian GC/instrumentation khỏi heartbeat.

Ablation trước fix: bỏ riêng trace redaction còn **269/159 ms**; bỏ thêm oracle/
trace trong diagnostic probe còn **153/114 ms**. Hai mode bỏ oracle chỉ dùng
chẩn đoán, không tính là correctness pass. Sau fix, lượt không probe còn
**208/162 ms**, cả hai vẫn fail. Probe có observer/sampling có overhead rõ rệt;
stack cho thấy CPU trong runtime sanitizer, request/session deepcopy, artifact
verification và Textual layout/render. Chưa tách được một blocking production
path nhỏ, ổn định và duy nhất để sửa an toàn; **residual heartbeat diagnostic unresolved**.
Không quy kết scanner, fsync hoặc scheduler là root cause khi chưa có bằng chứng.
Rerun trong matrix trước đổi verdict (không probe): **181/153 ms**, permission key
handler **22/65 ms**, chỉ fail hard heartbeat assertion cũ; mọi functional/state/
cleanup oracle pass. Đây là thời gian handler trực tiếp, không phải physical-key
latency. Kết quả rerun với verdict mới được ghi riêng, không đổi nhãn run cũ.

Tách span ở whole-target có sampling (chỉ dùng định vị; observer làm tăng CPU):

| Lớp | Max span |
| --- | ---: |
| Harness record/checkpoint (bao gồm oracle) | 19,7 ms sync |
| Fake model | 0,28 ms async wall |
| HTTP / workflow / finding | 271 / 83 / 2,4 ms async wall |
| Session save | 589 ms async wall, bao gồm awaits |
| fsync thật | 0,17 ms ở worker |
| Runtime `safe_tool_text` | 129 ms sync |
| UI dispatch / recompute view | 112 / 102 ms sync |

Các span lồng nhau, không cộng tổng; async wall không phải thời gian block loop.
Đo riêng event-loop heartbeat, handler và callback CPU/wall, lấy GC timeline và
stack samples; không tắt production checks. Không cô lập tải IDE/shared host,
không can thiệp tiến trình người dùng; yếu tố môi trường chưa được loại trừ.

**B — timing/intermittent tái hiện.** Chạy tổng **80 vòng file_write**, không
thay implementation hoặc oracle; 78 pass, 2 fail giữa các cấu hình đo khác nhau:

| Lượt | Pass/fail | Heartbeat gap | Esc | Recovery ticks |
| --- | --- | --- | --- | --- |
| Isolated, observer không sampling | 20/0 | 23,4–59,7 ms | 0,82–5,32 ms | 3–5 |
| Nhóm logging/streaming/persistence, observer | 19/1 | 25,4–217,8 ms | 0,98–3,39 ms | 2–5 |
| Cùng nhóm với stack sampling | 19/1 | 22,9–83,3 ms | 0,96–2,30 ms | 1–5 |
| Source cuối, **không observer/sampling** | 20/0 | 22,7–102,5 ms | 0,83–3,33 ms | 3–5 |

Failure gap 218 ms: callback `to_thread` khoảng **166 ms CPU/wall**, worker-start
delay khoảng **155 ms**, không task tồn dư; chưa chứng minh thread-pool saturation
hoặc filesystem là nguyên nhân. Failure recovery: gap **81,9 ms**, Esc **1,02 ms**,
chỉ 1 tick; GC **54,5 ms** trong render/recovery window tương quan với thiếu tick.
Hai failure ở vị trí khác nhau, chưa có reproducer ổn định của production bug;
**giữ B mở dưới phân loại timing/intermittent**. I/O ở worker trong cả 80 vòng.
Chỉ chuyển in metrics ra trước recovery assertion và thêm timestamp/tick timeline
để failure không làm mất chứng từ; không thêm chờ hoặc thay số tick yêu cầu.

**C — đã sửa:** lưu `await_args` vào biến rồi assert khác `None` trước `.args`
ở đúng hai UI test. Hai file UI + ba harness regression: **50 pass**.
Broad trước đổi verdict: **398 pass, 2 fail**, 400 case/11 phút 19 giây. Hai failure
chỉ là hard heartbeat assertion cũ; HTTP/MCP ownership, dedicated responsiveness
và các functional/lifecycle case khác pass. Không gọi run đó là full green.
Rerun đầu với verdict mới: **55 pass** (`final-verdict.xml`), gồm các system case
liên quan và 13 dedicated responsiveness case. Whole-target gap **280 ms** có
warning, direct **98,7 ms** không warning; cả hai có `ui_recovered=true` và
`functional_lifecycle_verdict=passed` sau drain. Nhãn warning và verdict độc lập.
Pyright toàn repo trên source cuối: **625 file, 0 error, 0 warning**,
82,5 giây; chứng từ `pyright-verified.json`. Hai lỗi UI đã đóng. Các lỗi narrowing
tạm thời trong probe mới cũng đã sửa và kiểm tra riêng trước lượt toàn repo này.
Kết quả test source cuối sau rà soát matrix system được ghi tiếp bên dưới.

Hai system scenario trên source cuối: **functional/lifecycle đều pass**, kể cả
real-key recovery và drain. Heartbeat raw **185,5 ms whole-target / 154,7 ms
direct**, cả hai `heartbeat_warning=true`; không dùng để quyết định pass/fail.
Permission key-handler max **84,7/11,9 ms** là metric riêng. Không suy ra rằng
production đã đạt budget 120 ms từ verdict system này.

Chứng từ follow-up: [/tmp/kagent-system-followup-txoC5k](/tmp/kagent-system-followup-txoC5k).
`baseline.xml`, `deferred.xml`, các `probe*.xml/log` và `probe.json` giữ before/
after/ablation/callback/GC/stack spans. `persistence-summary.json` giữ toàn bộ 80
measurement; `file-final.log` giữ timestamp/ticks của lượt không observer.
Lệnh chạy probe và ý nghĩa async wall spans nằm trong [README.md](README.md).
Không chạy lại full suite trong follow-up; kết quả full ở
phần lịch sử dưới đây **không phải full green trên source cuối**.

## Lượt System/E2E trước follow-up

Bổ sung harness dùng HTTP loopback thật, Agent/registry/permission/stores thật và
Textual headless thật. Tái sử dụng helper/oracle hiện có; model deterministic chỉ
phát tool call và đọc feedback, không ghi trực tiếp workflow state. Chi tiết cách
chạy và mapping A–J: [README.md](README.md), [offline_matrix.txt](offline_matrix.txt).

Lab disposable bind `127.0.0.1:0`, readiness probe và connection-task cleanup.
Có public/hidden route, form/OpenAPI, reflection, giả lập SQLi bằng so sánh literal,
fake auth/access control, redirect, error/retry, response giữ ở header/body.
Không có SQL engine, dữ liệu thật, extraction hoặc tác động phá hoại.

Có **10 happy-path case** độc lập: whole-target HTTP; whole-target với ffuf thật;
direct validation; thiếu quyền rồi approve; resume attempt bị gián đoạn;
redirect/auth; transient retry; capture/replay; nguồn proof khác và dedup;
1.000 history message với streaming rồi hoàn tất validation.
Ngoài ra có direct-route matrix, timeout, deny/retry, revoke/scope trong network
await, callback modal cũ, reset/resume/clear target khi model pending, Esc/reset
khi HTTP pending, MCP success/timeout/Esc và lỗi provider/model giả lập.
Các responsibility test hiện có bổ sung scanner lifecycle/retention/manifest-last,
MCP queue/overlapping close, persistence drain và UI selection/follow-tail.

Hai lỗi correctness/lifecycle đã tái hiện và sửa:

| Lỗi | Severity, trigger và root cause | Fix và regression |
| --- | --- | --- |
| HTTP ghi observation sau khi quyền/scope/owner hết hiệu lực | **Medium**. Giữ response rồi đổi target, revoke grant hoặc deny session. Adapter kiểm tra trước send nhưng vẫn capture observation hoàn chỉnh sau await; cờ `trusted_http=False` chỉ thay cách giữ/redact body, không chặn publication. Chưa chứng minh bypass finding gate. | Revalidate owner/generation, target/scope/epoch, HTTP permission revision và execution receipt sau headers và sau body, trước context/evidence publication. Vẫn release reservation/response và giữ terminal bookkeeping. API standalone không có evidence store vẫn trả traffic lịch sử đã redaction; cookie/context giữ generation guard riêng. Regression: `test_scope_change_during_real_network_wait_cannot_publish_old_observations`, 6 ca header/body × 3 thay đổi, cộng test `test_old_revision_response_cannot_repopulate_reset_context` giữ nguyên. |
| MCP timeout/cancel có thể drain vô hạn | **High về availability/lifecycle**. RPC timeout qua Agent/TUI: owner có cancellation do timeout nội bộ rồi quay lại chờ queue; caller tưởng `task.cancelling()` nghĩa là đã yêu cầu owner dừng nên chỉ join. | Theo dõi riêng yêu cầu cancel của owner và trạng thái đang teardown; gửi cancel đúng một lần, không ngắt ngang teardown khi close/cancel chồng nhau. Minimal reproducer: `test_caller_cancel_stops_owner_with_unconsumed_internal_cancellation`; integration: `test_mcp_rpc_lifecycle_through_agent_ui[timeout]`. Queue, pending futures, owner task và UI busy/timer đều được kiểm tra terminal. |

Oracle kiểm tra phase/input/candidate linkage, source/attempt/session binding,
hash và quyền ghi immutable proof, đúng một finding/coverage row, chưa đủ evidence
thì không có finding/completion, session restore không mang quyền thực thi, không
stale observation/state credit, không pending receipt/task/child process sau drain,
UI quay về idle, modal/timer được dọn. Scanner kiểm tra normalized dataset và
manifest hash; trách nhiệm manifest-last/rollback/retention có regression riêng.

Responsiveness đo bằng heartbeat 10 ms, Esc delivery, ticks và per-delta counters.
Watchdog tổng 60 giây/kịch bản tách biệt với oracle 120 ms. Full run có instrument
đo heartbeat gap khoảng **615 ms whole-target / 580 ms direct TUI**; strict
oracle thất bại dù các state transition và cleanup hoàn tất. Giữ nguyên assertion;
chưa tách overhead oracle khỏi runtime, không tối ưu performance-only và không
quy kết đây là nguyên nhân của một lần freeze thực tế.

Repeatability đã chạy **20 runtime/store độc lập**, 20/20 hoàn tất ở cả lượt riêng
và full run, không pending task, connection, checkpoint tạm hoặc state lẫn session theo các assertion của
harness. Full repeat loop ghi heartbeat gap **444–2.028 ms**, nên không khẳng định
responsiveness đạt chuẩn từ 20 lượt pass chức năng. Đây không phải soak test
hoặc bằng chứng bug-free. Esc tại key handler đo khoảng **0,02 ms** cho MCP,
**0,03 ms** cho HTTP; HTTP cancellation settle khoảng **18 ms**. Đây không phải
latency từ bàn phím vật lý. Streaming có **0** lần recompute semantic/read proof
ngay trong delta callback; test hoàn tất workflow với 1.000 history message.

Kết quả kiểm chứng, không cộng các lượt overlap thành tổng test duy nhất:

| Lượt | Pass | Fail | Skip | Xfail |
| --- | ---: | ---: | ---: | ---: |
| Full suite, 8.119 case, 24 phút 46 giây | 8.103 | 4 | 12 | 0 |
| HTTP/ownership/assessment/context sau sửa tương thích cuối | 307 | 0 | 0 | 0 |
| Whole-target retry, capture/replay, streaming và file-write rerun trên source cuối | 4 | 0 | 0 | 0 |

Trong full run: Agent **828 pass**; integration **669 pass/1 fail**; system
**47 pass/2 fail**; UI **1.229 pass/1 fail**; security **1.700 pass/1 skip**;
state **308 pass**; data **254 pass**; runtime **225 pass**; LLM **359 pass**.
MCP/scanner/evidence/session/provider/config/cancellation responsibility tests
đều nằm trong run này. Full suite chưa chạy lại toàn bộ sau bản sửa tương thích
HTTP cuối; nhóm 307 và 4 case được chạy sau bản sửa đó.

Phân loại 4 failure của full run:

- **Regression do bản sửa HTTP**, đã sửa: chặn cả API standalone không có
  observation store. Giữ nguyên test cũ; thu hẹp publication guard đúng đường
  có evidence store. Nhóm 307 pass xác nhận đồng thời compatibility và stale
  publication prevention.
- **Hai strict responsiveness oracle mới còn fail**: 615/580 ms như trên;
  finding/completion/resume và cleanup đã qua trước assertion latency. Không
  đổi threshold hoặc thêm xfail.
- **Timing/intermittent ở test có sẵn** `file_write`: full đo gap **201,5 ms**, chỉ
  1 recovery tick so với yêu cầu 2, I/O chạy ngoài UI thread. Hai rerun pass;
  lượt cuối đo gap **22,8 ms**, Esc **1,06 ms**, 5 recovery ticks. Chưa xác định
  nguyên nhân spike; không sửa implementation/test đó để làm suite xanh.

12 skip: 9 Java fixture thiếu cache WAR/Tomcat offline, 1 existing-lab opt-in,
1 live-model characterization có sẵn, 1 live system test mới. Giữ nguyên ignore
`tests/integration/test_kagent_burp.py` trong `pytest.ini`; không chạy Burp live.

Pyright toàn repo: **623 file, 2 error, 0 warning**, cả hai trong các thay đổi UI
ngoài phần sửa: `tests/ui/test_removed_manual_commands.py:35` và
`tests/ui/test_skill_entrypoint.py:92` (`await_args` có thể là `None`). Không sửa
các tệp đó. Phần owned đã kiểm tra riêng 17 file sạch; xem JSON kiểm tra cuối.

Chứng từ ở [/tmp/kagent-system-e2e-aM2qqG](/tmp/kagent-system-e2e-aM2qqG):
[full log](/tmp/kagent-system-e2e-aM2qqG/full.log),
[full XML](/tmp/kagent-system-e2e-aM2qqG/full.xml),
[307 regression XML](/tmp/kagent-system-e2e-aM2qqG/http-final.xml),
[source cuối/4 case](/tmp/kagent-system-e2e-aM2qqG/last-system.log),
[group counts](/tmp/kagent-system-e2e-aM2qqG/verification-summary.json),
`system-scenarios/` chứa artifacts/state/trace đã capture của các system case.

Giới hạn: đây là shared runtime factory + headless TUI, chưa phải CLI bootstrap
trong terminal vật lý hoặc chứng minh khả năng lập kế hoạch tự do của model.
LLM thật **chưa chạy**. Mode opt-in dùng provider/profile đã lưu nằm ở
`tests/live/test_system_local.py`, mặc định skip. Nếu bật, model-policy refusal
và model-incomplete được ghi riêng; wire/hash/state vẫn là oracle độc lập.

Không gọi external target/provider thật, không dùng internet, không cài package,
không commit/push. Các thay đổi slash/UI xuất hiện đồng thời ngoài phần sửa này
được giữ nguyên; không sửa chúng để làm suite xanh.

Bàn giao: `git diff --check` sạch; đã đọc diff/status; staging rỗng. Các tiến trình
pytest, pyright và scanner thuộc lượt kiểm chứng này đã kết thúc.
