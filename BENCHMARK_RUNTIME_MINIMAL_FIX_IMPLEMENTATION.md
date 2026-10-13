# KAgent — Minimal fixes sau Independent Review

Ngày: **14/10/2026, Asia/Saigon**. Repository: `D:\DOANTOTNGHIEP\kagent`.
Baseline working tree: HEAD `b1466dc1e07d502d3ca75a1ed7a6bab08341f35c` cùng bản sửa runtime đã review.

**READY cho vòng nghiệm thu tiếp theo trong phạm vi D1, D2 và đồng bộ evidence-repair tests.** Hai lỗi đã được tái hiện trước sửa và regression tests PASS sau sửa. Broader verification không xác nhận regression mới. Đây không phải tuyên bố READY vô điều kiện cho Official 40 hoặc toàn repository; schema/context budget và provider retry failures vẫn tồn tại.

## 1. Các tệp sửa trong lượt này

| Tệp | Thay đổi và lý do |
|---|---|
| `src/agent/agent.py` | D1: HTTP readback progress lấy stable `response_hash` từ observation controller sau kiểm tra `retained_hash`; bỏ timing khỏi HTTP novelty identity. D2: outbound guard fail-closed khi successful reader mất source metadata, kiểm tra lại header/source/range/body khi resume. |
| `src/session/store.py` | Đưa `read_http_observation` vào hai HTTP paths hiện hữu: exact-content serialization và source-metadata hydration. |
| `tests/security/test_http_readback_lifecycle.py` — mới | 22 test instances cho integrated Direct loop, pagination/content novelty, retired Skill page reread, real Session Store, quyền/provenance sau resume, internal secret và no-new-HTTP. |
| `tests/security/test_observation_grounding.py` | Hai closure fixtures dùng initial + hai repairs; giữ cleanup/no-new-probes/unresolved assertions, bổ sung kiểm tra immutable proof bytes và parents. |
| `tests/scenarios/test_recovery.py` | Scenario budget-closure thực hiện đủ ba rejected submissions; kiểm tra immutable state trên cả ba boundaries. Nhánh successful repair giữ nguyên. |
| `tests/skills/test_validation_grounding_contract.py` | Hai SQLi/XSS guidance assertions chuyển phrase budget cũ “one repair” sang contract hiện hành “two repair submissions”. Giữ các grounding/evidence/semantic assertions khác. |

Tệp báo cáo này là artifact bàn giao mới. Không sửa hai implementation/review reports cũ hoặc independent review. Không đổi `kagent-changes.diff`, vốn là snapshot diff trước lượt sửa này.

Các thay đổi hợp lệ từ lượt trước được giữ nguyên. Hash manifest verification trước cho thấy trong 7 source + 3 regression files của lượt trước, **chỉ `src/agent/agent.py` thay đổi thêm**; sáu source còn lại và cả ba test files đó giữ nguyên byte content. Session Store và ba test files cũ được sửa đúng phạm vi mới. Đã đối chiếu Agent với source snapshot trước sửa để kiểm tra delta cục bộ.

## 2. D1 — Direct anti-stall

**Trước sửa:** tracker dùng HTTP reader header `retained_hash` làm progress identity. Hash này bind cả observation ID/metadata, nên cùng response qua capture mới có range identity mới. Chuỗi HTTP → readback lặp lại reset no-progress tới hết 24 iterations. Timing jitter cũng tạo HTTP exploration novelty dù response body không đổi.

**Sau sửa:**

- `retained_hash` tiếp tục kiểm tra capture integrity, không thay hay hạ evidence gate.
- Tracker tra observation theo header ID và yêu cầu retained hash khớp. Progress identity dùng `item.response_hash`, ổn định theo retained body bytes.
- Request args, observation ID và elapsed time không tạo content progress. HTTP response novelty và controller diagnostics vẫn dùng exploration allowance hiện hữu.
- Ranges chưa đọc của cùng nội dung vẫn là reader progress; overlapping/EOF/reread không reset vô hạn. Một response body khác vẫn có identity khác.
- Giữ `MAX_CONSECUTIVE_NO_PROGRESS=4`, exploration cap 8 và verification repeat allowance. Không thêm tracking subsystem hay output/schema field.

Integrated regression chạy Agent + production Registry/ExecutionPolicy, model giả và MockTransport: HTTP args thay đổi nhưng response giống nhau; Agent phải dừng `workflow_stalled` trước 24 tool iterations, giữ goal `in_progress`, attempts/evidence và không tạo negative/confirmed result hoặc finding giả.

Positive tests kiểm tra pagination, genuinely different retained content, bounded exploration cho HTTP responses khác nhau và retire → reread Skill page → accepted not-confirmed result. Reread không làm dừng nhầm validation hợp lệ; history vẫn giữ original pages.

## 3. D2 — HTTP readback session lifecycle

**Trước sửa:** saver đưa reader content qua generic redactor, làm thay cookie/JWT/text lab đã được HTTP analysis admit. Loader whitelist loại source refs của reader. Outbound guard bỏ qua message không refs, nên revoke/retest sau load không loại historical body.

**Sau sửa:**

- Dùng lại exact-content save exception và HTTP source-ref hydration hiện hữu cho reader. Generic redaction của các nội dung khác không đổi.
- Body hợp lệ, Unicode và target cookie/JWT giữ nguyên qua real Store.save/Store.load; source refs giữ nguyên. Runtime stamp/execution rights vẫn không được serialize.
- Outbound guard gọi lại reader rights validation: scope, session, epoch, current objective/attempt/candidate/binding, integrity, capability và revocation. Không tự cấp permission hay reassign source owner.
- Successful reader thiếu metadata hợp lệ bị omit fail-closed, kể cả legacy/damaged saved message. Error message không chứa HTTP body vẫn giữ diagnostic để Agent sửa lỗi hợp lệ.
- Header observation phải khớp source refs; retained hash, range types/bounds, source length và exact body slice phải khớp observation hiện tại. Historical body bị sửa hoặc metadata nguồn không hợp lệ không đi vào LLM context.

Real Session Store regressions dùng một fresh Agent controller với completed current attempt và existing fixture policy. Active execution attempts vẫn bị hydration đánh dấu interrupted theo contract cũ; tests không khôi phục execution rights hoặc mint resume authority. Những trường hợp invalid sau resume gồm HTTP/tool revoke, scope removal, session mismatch, epoch change, explicit retest, candidate/attempt change, integrity fault, source unavailable, missing/malformed metadata, header-source mismatch, body tampering và newly known internal secret.

Known internal-secret source-level blocking giữ nguyên, kể cả tiny reads có thể ghép secret. Không triển khai selective mixed-secret handling, không blanket redact target cookies/JWT và không thay workflow/evidence acceptance. Readback/resume verification không phát sinh HTTP mới.

## 4. Đồng bộ đúng 5 failing tests cũ

Đã đối chiếu `src/workflow/evidence_recovery.py`, `EvidenceSubmissionError.repair_hint`, hai playbooks SQLi/XSS và `test_evidence_recovery_contract.py` trước sửa:

- 1 initial submission + tối đa 2 repair submissions = tối đa 3 rejected submissions.
- Repair-turn bound vẫn 6 cho các bước write/register/submit riêng biệt.
- Exhaustion đóng honest `insufficient-evidence`, giữ mutation/cleanup, không salvage invalid sources/parents và không recapture HTTP chỉ để sửa manifest.

**Không sửa runtime retry constants, repair controller hoặc playbooks.** Hai grounding closure fixtures và một scenario closure fixture nay dùng đủ ba submissions. Hai loaded-guidance tests kiểm tra đúng phrase two-repair hiện có.

Các checks không bị làm yếu: no-new-HTTP, immutable proof/parents, không có finding giả, cleanup pending và mutation obligations, exactly one closure và unresolved attempt vẫn được giữ. Scenario kiểm tra state ổn định trên cả ba rejection boundaries. Tests thành công ở repair boundary, hết budget, persistence và continuation của controller hiện hữu đều nằm trong broader run.

## 5. Verification

Các runs dùng WSL Ubuntu và `venv-linux`, `--import-mode=importlib -p no:cacheprovider`, `PYTHONDONTWRITEBYTECODE=1`; bỏ bốn opt-in live/reset vars. HTTP fixtures dùng MockTransport và models là deterministic doubles. Không có live target/provider traffic.

| Kiểm tra | Kết quả |
|---|---|
| Regression trước source fix — 20 instances đầu của tệp mới | **18 FAIL, 2 PASS**, 22,95 giây. D1 fail vì `max_steps` thay vì `workflow_stalled`; D2 fail vì redaction/mất metadata và stale body không bị omit; timing novelty cũng fail. Hai positive pagination/retired-page cases PASS. |
| Focused sau source fix và đồng bộ 5 nodes | **39 PASS**, 34,43 giây: lifecycle, observation grounding, guidance, hai scenario repair/closure branches. |
| Broader Direct/Whole-target/permissions/evidence/persistence/scenario safety | **467 PASS**, 281,03 giây. |
| Final new regressions sau bổ sung positive/error tests và typing assertion | **22 PASS**, 16,32 giây. |
| Pyright trên bản cuối | **0 errors, 0 warnings, 0 informations**. Launcher có thông báo version update; không phải source diagnostic. |
| `git diff --check` | PASS. |
| Remaining baseline checks: schema budget + provider retry snapshot | **4 FAIL, 2 PASS**, 18,46 giây; không có failing node mới so với baseline log. |

Lượt Pyright đầu phát hiện một Optional-origin typing error trong test mới; đã sửa bằng explicit non-None assertion và chạy lại Pyright. Đây không phải unresolved source error.

Broader paths:

```text
tests/security/test_http_readback_lifecycle.py
tests/agent/test_bounded_validation_regressions.py
tests/agent/test_skill_context_policy.py
tests/security/test_http_observation_reader.py
tests/security/test_cleanup_actionability.py
tests/security/test_execution_policy.py
tests/security/test_agent_assessment.py
tests/security/test_evidence_recovery_contract.py
tests/security/test_observation_grounding.py
tests/security/test_session_authorization.py
tests/tools/test_http_context.py
tests/state/test_session_store.py
tests/state/test_session_persistence_async.py
tests/integration/test_requested_goal_lifecycle.py
tests/integration/test_requested_goal_review_regressions.py
tests/integration/test_whole_target_workflow.py
tests/integration/test_phase2_whole_target_reliability.py
tests/scenarios/test_safety.py
tests/scenarios/test_recovery.py
tests/skills/test_validation_grounding_contract.py
```

Logs lưu trong WSL `/tmp`:

```text
kagent-minimal-fix-before.log
kagent-minimal-fix-focused.log
kagent-minimal-fix-broader.log
kagent-minimal-fix-final-regressions.log
kagent-minimal-fix-pyright.log
kagent-minimal-fix-baseline-check.log
```

**Không chạy full suite trong lượt này.** Broader selection bao phủ các boundaries thay đổi, cả success/denial và fault scenarios đã ổn định; không có failure mới cần mở rộng tới toàn suite. Không suy ra một full-suite pass/fail count mới từ các focused runs hoặc cộng các pass counts có overlap.

## 6. Những vấn đề còn tồn tại

| Vấn đề | Mức độ / ảnh hưởng | Disposition |
|---|---|---|
| Hai schema-budget nodes | Medium: fixture vẫn đo **30.163 >28.000 characters**, ảnh hưởng context headroom. | Failures tái hiện, nằm trong baseline; không sửa hoặc tăng budget. Actual benchmark prompt/headroom vẫn cần nghiệm thu riêng. |
| Provider retry projection `[anthropic]` và `[gemini]` | Medium: mocked retry bodies khác nhau khi action projection thay đổi. | Failures tái hiện và khớp baseline; cần xử lý/xác minh trước khi dựa vào retry semantics của các backends này. |
| Whole-body known internal-secret withholding | Trade-off: có thể mất benign evidence nếu cùng body có internal secret. | Giữ guard theo yêu cầu; không triển khai selective handling. |
| HTTP destructive/write intent và SQLI-2/XSS semantic confirmation | Deferred contracts: scope/receipt không tự chứng minh action effects hoặc class-specific proof. | Không thay contract/semantic requirements. Cần evidence criteria/review riêng khi nghiệm thu thực nghiệm. |
| UI width và browser snapshot-layout failures trong full log trước | Low / environment-specific, không nằm trong boundaries sửa lần này. | Không sửa, không rerun; không tuyên bố chúng PASS hoặc vô hại. |

Bốn failing node IDs vừa kiểm tra trùng chính xác baseline; `new failing IDs = []`. Broader 467 tests không fail. Điều đó chứng minh các cơ chế được kiểm tra đã ổn định, không thay thế kiểm chứng tất cả behaviors của repository.

## 7. Kết luận và giới hạn

**D1: FIXED. D2: FIXED. Năm stale tests: SYNCHRONIZED, contract không bị nới. READY cho vòng nghiệm thu tiếp theo của ba hạng mục này.**

Giữ nguyên threshold 4, exploration cap, steps, timeouts, HTTP quota và toàn bộ known-secret/evidence guards. Không sửa schema/context budget, dataset, manifest, evaluator, runner protocol, kết quả cũ, write/destructive authority hoặc SQLi/XSS semantic confirmation. Không refactor, reset lab, live benchmark, provider call, commit hoặc push.

Chưa chạy Official 40. Trước khi tuyên bố READY cho Official40 không điều kiện, vẫn phải disposition schema headroom, backend retry và các tiêu chí evidence/authority đã ghi trong independent review. Không mở rộng implementation ngoài ba hạng mục được giao.
