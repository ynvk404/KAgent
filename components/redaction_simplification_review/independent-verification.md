# KAgent — Independent Verification: Lab Fidelity

**Kết luận: ACCEPTED WITH LIMITATIONS.** Không phát hiện regression P0/P1/P2 do implementation trong phạm vi đã kiểm chứng. Các invariant chính về fidelity, admission, hash/evidence, secrets và persistence đạt kiểm chứng offline. Suite toàn bộ vẫn không xanh: đã đối chiếu trực tiếp đúng 51 failures và 13 fixture errors với baseline, không chỉ tin phân loại trong handoff. Kết luận này không chứng nhận toàn repository hoặc hiệu quả pentest trên target thật.

Ngày: **2026-10-13, Asia/Saigon**. Repository thực tế: `/mnt/d/DOANTOTNGHIEP/kagent`. Review chỉ đọc production/tests/configuration; artifact duy nhất thêm vào repository là báo cáo này. Không commit/push/install/reset/restore; không sửa baseline hoặc các audit artifacts trước đó.

## 1. Phạm vi, tiêu chí và baseline độc lập

Đã đọc `AGENTS.md`, `audit-design.md`, `implementation-handoff.md`, toàn diff tracked, hai test files mới và implementation/tests trên các đường trực tiếp bị ảnh hưởng. Tiêu chí là policy cuối trong handoff và README: **bounded raw lab HTTP được phép vào LLM và private durable state**. Do đó yêu cầu safe-only persistence/version migration trong design ban đầu không còn là tiêu chí áp dụng. Header/request guards, actual internal credentials và finding eligibility vẫn phải giữ.

Baseline dùng để quy trách nhiệm là **HEAD `8fb8d9ecf56549473417776332665bcc35d95b60` cộng Browser/Burp patch trước implementation**, không phải HEAD thuần. Đã dựng bản riêng tại `/tmp/kagent-independent-baseline-49po3zoj` bằng `git archive HEAD`, áp dụng `/tmp/kagent-lab-fidelity-baseline-hjen8_nm/diff.patch`, và copy test passthrough vốn đã tồn tại. Không checkout/reset hoặc sửa repository gốc. Hash của test passthrough và các audit artifacts khớp manifest trước implementation. Bản baseline dùng cùng executable `venv-linux/bin/python`, nhưng import source từ bản riêng.

Đối chiếu AST xác nhận Native HTTP và Capture getter có `name`/`description`/`schema` giống baseline. `HTTPTool.validate_arguments` và `_prepare_with_diff` cũng không đổi. `registry.py`, `workflow/assessment.py`, `workflow/evidence.py`, Scenario 1 runtime, UI recovery tests và CWE test liên quan byte-identical với baseline. `mcp_server.py` và `redacted_view.py` giữ nguyên patch Browser/Burp ban đầu; getter chỉ thêm provenance vào contract đó.

**Sai lệch quy trình cần ghi rõ:** lần chạy regression ban đầu đã bao gồm `tests/integration/test_http_wire_replay.py` và các tests trong `tests/browser/test_server.py` dùng socket HTTP loopback/server fixture tự tạo. Điều này trái yêu cầu không chạy live HTTP theo nghĩa nghiêm ngặt, dù không truy cập target bên ngoài hay external LLM. Không tiếp tục kiểm thử qua socket; đã chạy lại các nhóm liên quan khi loại hai file này. Kết quả loopback không được tính vào bảng acceptance offline bên dưới. Sai lệch đã xảy ra, việc chạy lại không xóa nó.

## 2. Invariant đã xác minh độc lập

| Boundary | Bằng chứng thực thi và kiểm tra source | Kết quả |
|---|---|---|
| Native HTTP → Agent → FakeClient | Real registry/adapter với MockTransport; request LLM kế tiếp và private session chứa đúng `body.decode(errors='replace')`; Observation giữ bytes. Fixtures token red/sky, SQLi rows/count, IDOR owners, XSS/compound markers, CSRF/auth, public SHA256, Cookie-value collision, encoded payload, HTML, malformed JSON, Unicode và invalid UTF-8. | PASS trong producer/context bounds; không heuristic-mask body đã admit. |
| Scoped Capture → Agent → FakeClient | Getter thực, scoped runtime import, hai aliases `response_body`/`responseBody`, MIME-independent body; default/zero/max cap, metadata truncation và nguồn không bị mutate. Native/standalone MCP getter tests dùng mock lifecycle/IO. | PASS. Import là captured-string association, không authentication hoặc wire proof. |
| Trust admission | Canonical adapter type, policy/session/stamp, invocation/scope, source digest và runtime access được kiểm tra. Generic MCP RPC giả mạo qua real adapter bị sanitize. Probe riêng dùng shell/file/MCP/native tool name, `raw=true`, self-declared source/status và plain ToolOutput không tạo HTTP provenance. | PASS; tên tool/status/payload không nâng quyền. |
| Ownership, scope, revocation | Existing execution-policy tests; wrong owner/origin/session, revoked tool, changed capture method/body/time, capture bị xóa; recheck trước outbound. Probe resume loại missing source, foreign session, removed scope và newly managed secret. | PASS; không rerun HTTP hoặc cấp grant mới để hydrate context. |
| Source bytes/hash/ranges | Native `response_hash=SHA256(retained producer bytes)`; retained hash bằng `digest(source_row(item))`; redirect hop character ranges trỏ đúng decoded body. Excerpt byte ranges kiểm tra trên manifest/source bytes. Native caps 0/1/10/65536 giữ completeness/truncation đúng. | PASS; decoded body không được quảng cáo là original wire bytes. |
| Evidence, manifests, finding eligibility | Raw primary manifest/hex, terminal assessment, source/excerpt binding, immutable Evidence reads và integrity/TOCTOU regressions; confirmed-only reporting/finding gates. | PASS. Evidence text derivatives vẫn sanitize; việc raw body xuất hiện không tự tạo confirmed finding. |
| Historical state | Ngoài test legacy trong patch, đã tạo masked Observation bằng baseline thật, current load/persist giữ file byte-identical. Đã tạo confirmed workflow bằng baseline thật; current `WorkflowState.from_dict` giữ assessment binding, manifest, evidence refs, contract version và result ID. | PASS cho sealed records đã kiểm tra; không migration/reseal. |
| Actual internal secrets | Exact-value protection từ policy callback và active client key; Native body omission có marker non-exact, Capture omission giữ JSON valid và đồng bộ aliases. Probe key mới sau resume cũng chặn outbound. | PASS; raw Observation/body/response hash/retained hash không đổi. |
| Durable/private state | Repeated session saves/load và compaction giữ admitted content; source refs được lưu nhưng runtime stamp không được serialize. Observation temp mode được kiểm tra trước fsync, session/context final mode là 0600 trên Linux temp filesystem. | PASS trong môi trường test; hex không phải encryption. |
| Compaction/cache/display | Controller kiểm tra access/secrets trước format snapshots/compaction. Raw admitted results không vào sanitized result cache; probe riêng kiểm tra cache đã được khởi tạo, pending/references rỗng. Events dùng source/status metadata. Generic output redaction, terminal controls và debug guards giữ tests. | PASS; summaries vẫn lossy/model-authored. |
| Replay và regressions liên quan | Cookie jar origin/identity/revision, captured replay, execution/permission/scope, `related_requests`, cancellation/save/session/cache, memory description và reports. | PASS trong các nhóm responsibility đã chạy; không audit lại toàn transport/provider/UI. |

Probe riêng còn xác nhận **character cap khác byte cap**: Capture body `😀 × 20000`, getter cap 65536 giữ string 20000 characters; imported Observation chỉ giữ 65536 UTF-8 bytes, hash của bytes đó và `complete=false`. Không dùng hash bounded import để tuyên bố đã hash toàn getter body hoặc original traffic. Trường excerpt-truncated mô tả getter excerpt, không thay thế Observation completeness.

## 3. Patch scope và sức mạnh tests

Không thấy runtime class/framework mới, CLI flag, configuration mode hoặc Observation/Evidence schema version/migration. Các trường bổ sung nằm trên `ToolOutput`, `Message` và existing policy/source details; public tool schemas của implementation không đổi so với baseline Browser/Burp. API-key callback đọc Config/runtime hiện hành và client key; không đưa key vào source metadata hoặc persisted provider profile.

Các thay đổi assertions về response credentials/public checksum và receipt prose phù hợp policy mới: thay vì đòi body bị che, tests kiểm tra body exact, hashes, private persistence và request/header/display protection riêng. Assertions về ownership, permissions, completeness, integrity, source association và finding eligibility không bị bỏ. Các helper chuyển từ fixed prose label sang parse envelope thực tế. Memory-description regression bổ sung bảo vệ intake/filename/index.

Không thấy nới schema budget, provider retry expectations, Scenario 1 inputs/permissions, UI recovery expectations hoặc CWE fixture để làm PASS. Browser server test dùng in-memory Handler đã có trong baseline; không phải thay đổi của implementation này. Các tests mới đủ mạnh cho những cases đã assert, nhưng không chứng minh mọi secret encoding, mọi malicious Python plugin hoặc mọi provider transaction đều an toàn.

## 4. Verification record

Mọi lệnh acceptance dưới đây dùng executable `venv-linux/bin/python`, `PYTHONDONTWRITEBYTECODE=1`, `-p no:cacheprovider --import-mode=importlib`; flags live characterization/container tắt. Các nhóm có thể overlap; không cộng thành số unique tests. Không chạy lại full suite.

| Lần chạy độc lập | Kết quả | Log |
|---|---|---|
| Focused fidelity/redaction/admission/assessment/capture | 426 passed | `/tmp/kagent-independent-focused.txt` |
| Evidence/session/compaction/permission/replay/report/memory, loại socket tests | 609 passed, 7 skipped | `/tmp/kagent-independent-regressions-offline.txt` |
| HTTP/context/grants/lifecycle/offloading/recovery, loại socket tests | 241 passed | `/tmp/kagent-independent-boundaries-offline.txt` |
| Probe riêng ngoài repository | 15 passed | `/tmp/kagent-independent-probes.txt` |
| Current schema/provider/UI/CWE responsibility groups | 164 passed, 7 failed | `/tmp/kagent-independent-limitations.txt` |
| Current toàn bộ Scenario 1 nodes đã lỗi trong full log | 44 failed, 13 errors | `/tmp/kagent-independent-scenario1-failures.txt` |
| Baseline đúng toàn bộ 64 nodes đã lỗi trong full log | 51 failed, 13 errors | `/tmp/kagent-independent-baseline-failures.txt` |
| Configured Pyright | 543 files, 0 errors, 0 warnings | `/tmp/kagent-independent-pyright.json` |
| Default collect-only | 7006 collected, 1 import-file-mismatch error | `/tmp/kagent-independent-default-collection.txt` |

Hai lượt regression ban đầu có loopback fixture: 610 passed/7 skipped và 247 passed; chỉ ghi để minh bạch lịch sử, không dùng để gọi toàn bộ phiên là offline-only. Hai lỗi khởi tạo harness ngoài repo (thiếu `asyncio_mode=auto` khi chạy `/tmp` không chỉ định config, và resolve symlink interpreter làm mất virtualenv) đã được sửa bằng invocation đúng; không phải project failures, không sửa config hoặc cài package.

Lệnh focused có thể chạy lại:

```bash
PYTHONDONTWRITEBYTECODE=1 KAGENT_RUN_LIVE_TOOL_CHARACTERIZATION=0 \
KAGENT_S1_EXISTING_CONTAINER='' venv-linux/bin/python -m pytest \
  -p no:cacheprovider --import-mode=importlib -q \
  tests/security/test_http_body_fidelity.py tests/browser/test_response_passthrough.py \
  tests/security/test_redact.py tests/security/test_observation_grounding.py \
  tests/security/test_captured_http_replay.py tests/security/test_agent_assessment.py \
  tests/agent/test_output_pipeline.py tests/tools/test_browser_capture.py \
  tests/integration/test_burp_offline_audit.py tests/integration/test_burp_selection.py \
  tests/integration/test_candidate_validation_recovery.py
venv-linux/bin/pyright --outputjson
git diff --check
```

Probe riêng: `PYTHONDONTWRITEBYTECODE=1 venv-linux/bin/python -m pytest -c pytest.ini -p no:cacheprovider --import-mode=importlib -q /tmp/test_kagent_independent_probes.py`. File này chỉ nằm trong `/tmp`; không thêm/sửa tests của repository.

Các nhóm regression offline đã chạy với cùng options/flags của lệnh focused:

```text
tests/security/test_execution_policy.py tests/security/test_evidence_reads.py
tests/security/test_evidence_correctness.py tests/security/test_evidence_correctness_blockers.py
tests/security/test_related_request_evidence.py tests/security/test_session_authorization.py
tests/state tests/agent/test_post_compaction.py tests/agent/test_resume_after_compaction.py
tests/runtime/test_session_debug.py tests/tools/test_http_replay.py
tests/scenarios/test_related_requests_independent.py tests/report tests/data/test_memory_store.py
```

```text
tests/tools/test_http.py tests/tools/test_http_context.py tests/security/test_http_grants.py
tests/security/test_http_invocation_lifecycle.py tests/agent/test_tool_result_offloading.py
tests/browser/test_browser_mcp_server.py tests/scenarios/test_recovery.py
```

## 5. Đối chiếu 51 failures và 13 errors

Đã trích **nguyên node IDs, kể cả parameters chứa spaces**, từ full log trong handoff và chạy chúng trên baseline riêng. Sau đó so tập node IDs của baseline với hai lượt current. **Cả ba tập bằng nhau, đúng 64 nodes.** Điều này chứng minh các lỗi được báo cáo tồn tại trước implementation; không chứng minh mọi test còn lại của full suite hiện tại đã chạy độc lập.

| Nhóm | Full log/current | Baseline độc lập | Root cause và phân loại |
|---|---|---|---|
| Scenario 1 | 44 failures + 13 fixture errors | Cùng 44 + 13 | `request_fixture` luôn có `body=None` khi không có form body; native validator yêu cầu string nếu field tồn tại. Fail trước MockTransport, dispatch count=0; không có terminal result khiến finding fixture `latest is not None` fail. **Baseline functional/test-harness incompatibility**, không phải dependency/environment errors. |
| Schema budgets | 2 failures | Cùng 2; 29590 characters | Cap 28000 đã bị vượt trước implementation. Public tool schema AST không đổi. **Baseline schema-budget failure**. |
| Provider retries | Anthropic/Gemini: 2 failures | Cùng 2 | Retry re-encodes mutated request tools thay vì giữ encoded projection snapshot. Provider/action-view sources không đổi. **Baseline transport contract failure**. |
| UI recovery | 2 failures | Cùng 2 | Recovered entry hiển thị workflow summary với details `Recovered after 1 failed attempt`, test đòi error cũ trong `.text`. **Baseline UI/test contract mismatch**. |
| CWE enrichment | 1 failure | Cùng 1 | Test-local `prepare(tool,args)` không nhận existing keyword arguments `reviewing`/`signal`; enrichment bắt TypeError và prepared list rỗng. **Baseline fixture signature mismatch**. |

Reproduction nhỏ, giữ nguyên assertions:

```bash
PYTHONDONTWRITEBYTECODE=1 venv-linux/bin/python -m pytest \
  -p no:cacheprovider --import-mode=importlib -q --tb=short \
  tests/benchmarks/test_scenario1_data_contracts.py::test_transport_dispatch_success_failure_and_retry \
  tests/benchmarks/test_scenario1_findings.py::test_finding_export_redacts_links_and_preserves_sources \
  tests/integration/test_tool_schema_budget.py \
  tests/integration/test_hybrid_schema_budget.py \
  tests/llm/test_workflow_action_projection.py::test_transport_retry_keeps_encoded_projection_snapshot \
  tests/ui/test_candidate_recovery_contract.py::test_corrected_candidate_retry_recovers_owned_issue_once \
  tests/cwe/test_enrichment.py::test_evidence_receipt_uses_existing_readonly_workflow_action
```

Để kiểm tra cả tập lỗi, node list đã lưu tại `/tmp/kagent-independent-failed-nodes.json`. Đừng split node IDs theo whitespace vì parameters có spaces. Baseline reproduction dùng cùng list, cwd/PYTHONPATH trỏ baseline riêng và executable virtualenv tuyệt đối **không resolve symlink thành system Python**. Baseline patch/hash inputs và test outputs hiện có trong `/tmp`; không được xem là artifacts lưu bền.

**Collection/environment:** default pytest import mode tái hiện một collection error do hai files cùng basename `test_related_requests_independent.py` ở `tests/scenarios/` và `tests/tools/`. Đây là collision module import có sẵn, khác 13 Scenario 1 fixture errors. Không xóa caches/đổi filenames/config; dùng importlib mode cho các runs. Không phát hiện dependency/environment failure chưa giải quyết trong acceptance runs.

## 6. Vấn đề và các giới hạn còn lại

**P0/P1 do patch:** không phát hiện. **P2 do patch:** không phát hiện trong các đường đã kiểm tra. Năm nhóm baseline failures ở mục 5 là các follow-up **P2 engineering**, không là vulnerability findings về target. Reproductions cụ thể đã nêu; chúng vẫn ngăn dùng full-suite green hoặc Scenario 1 benchmark làm bằng chứng release hiện tại.

Chưa đủ bằng chứng để kết luận về:

- ACL/privacy thực tế của raw artifacts trên Windows/DrvFS, backups hoặc production filesystem; tests mode 0600 chạy ở Linux temporary storage. Không có encryption guarantee.
- Universal outgoing-secret firewall: chỉ actual full managed values trong admitted HTTP context được kiểm tra. Model/user-authored output, transformed/encoded secrets, summaries và mọi arbitrary text không nằm trong guarantee này. Raw private Observation/manifests có thể chứa reflected internal key theo policy được chấp nhận; outbound omission không xóa raw proof.
- Provider/profile switches end-to-end: đã kiểm tra callback/runtime wiring và active-client-key/new-key probes; không mở rộng thành audit transaction toàn bộ providers hoặc gọi external API.
- Real browser execution/XSS exploit, authentic original capture actor, original wire bytes, compression/charset coverage toàn diện hoặc hiệu quả trên live lab. FakeClient chứng minh dữ liệu nhận được, không chứng minh reasoning của external model.
- Full suite hiện tại ngoài các responsibility groups và 64 lỗi: không chạy lại 7008 tests. Các skips giữ nguyên; không hạ expected behavior để thay chúng bằng PASS.
- Adversarial sửa private session/source files hoặc compromised Python plugin/process. Saved source IDs là provenance để đọc context, không cryptographic proof cho transcript content hoặc grant thực thi.

Không có thay đổi bắt buộc để unblock patch trong phạm vi này; trạng thái **không phải BLOCKED**. Nếu yêu cầu tiếp theo là full-suite green, minimum follow-ups riêng là: omission/chuẩn hóa `body` absent trong benchmark request builder; giảm schema thực tế trong budget hiện có; giữ encoded snapshot qua provider retry; xác định đúng UI recovery contract rồi sửa đúng phía; cho CWE test wrapper forward existing keyword arguments; xử lý collection basename collision. Không sửa các vấn đề này trong phiên audit.

## 7. Handoff integrity

Đã lưu SHA256 inventory của 703 tracked/untracked files trước verification vào `/tmp/kagent-independent-start-hashes.json`. Đối chiếu cuối phiên: tất cả còn byte-identical; audit-design/probes/results cũ khớp thêm manifest trước implementation. Artifact mới duy nhất là báo cáo này. Final `git diff --check` PASS; đã inspect diff/status, và báo cáo không có trailing whitespace. Không stage, commit hoặc push. Dừng ở handoff này, chờ quyết định tiếp theo.
