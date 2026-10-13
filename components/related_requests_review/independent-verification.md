# Independent verification — Related Requests B + A + C

**BLOCKED đối với acceptance bảo mật/integration đầy đủ.** Contract của bản vá
`related_requests` và các scenario A–F được kiểm chứng offline; không phát hiện
regression mới của bản vá. Tuy nhiên, regression có sẵn tái hiện việc
`record_evidence` nhận bytes ngoài execution-policy root sau một pathname race.
Vì vậy không thể xác nhận vô điều kiện invariant bắt buộc về Evidence source
admissibility. Immutable snapshot bảo toàn bytes đã nhận không khắc phục việc
nhận nguồn không được phép. Cần chuyển blocker này về implementation riêng;
phiên QA không sửa production.

Hai lỗi retry Anthropic/Gemini vẫn tồn tại và suite rộng hơn không xanh. Chúng
không làm mất bằng chứng đã có cho duplicate rejection, Candidate-only,
supplementary associations hoặc delivery của error trong request không bị sửa.
Không dùng tổng số tests PASS làm tiêu chuẩn READY.

## Patch identity và quyền sở hữu

- HEAD trước/sau: `29c4f92f91d61e7a669af34d0d3d18e05f8767db`.
- Repository thực tế: `/mnt/d/DOANTOTNGHIEP/kagent`.
- Đã đọc `AGENTS.md`, handoff, manifest, patch, commands, verification results
  và agent-visible example. **23/23 SHA-256** trong manifest khớp khi bắt đầu;
  kiểm tra cuối phiên được ghi trong `independent-final-integrity.json`.
- Tracked diff ban đầu gồm đúng ba production files của Phiên 1:
  `src/agent/action_guidance.py`, `src/tools/workflow/workflow_tool.py`,
  `src/workflow/assessment.py`. Staged diff rỗng. Ba test modules Phiên 1 và
  thư mục handoff đã untracked từ đầu; đó không phải thay đổi do phiên QA tạo.
- QA chỉ thêm `tests/tools/test_related_requests_independent.py`,
  `tests/scenarios/test_related_requests_independent.py` và artifacts mang tên
  `independent-*` trong thư mục này. Không sửa test/harness có sẵn, source,
  Skills, schema, guidance, permissions, provider hoặc config.
- Source/test/artifact hashes Phiên 1 và tracked diff được giữ nguyên. Không
  reset/clean/restore, stage, commit, push hoặc cài dependency.

Chi tiết nhận diện: [initial integrity](independent-integrity.json),
[final integrity](independent-final-integrity.json),
[commands/results](independent-results.json).

## Checkpoints đã chạy

Các pytest runs dùng `venv-linux`; scenario runs dùng guard fail-closed hiện có.
Các nhóm ngoài `tests/scenarios/` cài plugin
`tests.scenarios.offline_checkpoint`, chặn network/DNS/process thật và đặt
durable stores trong scratch. Các nhóm có overlap; không cộng số invocation
thành số acceptance độc lập.

| Checkpoint | Kết quả | Log |
| --- | --- | --- |
| 106 acceptance tests Phiên 1, chạy lại độc lập | 106 PASS | [focused](independent-focused.log) |
| Independent contract: body/payload/identity fields | 3 PASS | [contract](independent-contract-accepted.log) |
| Independent scenario extensions B–F | 8 PASS | [scenarios](independent-scenarios-accepted.log) |
| E mở rộng: cleanup denial sau fresh resume | 1 PASS, rerun của case E | [cleanup](independent-cleanup.log) |
| Existing scenario A và safety/recovery | 35 PASS | [existing scenarios](independent-existing-scenarios.log) |
| Existing guarded integration responsibility manifest | 406 PASS | [integration](independent-integration.log) |
| 910-test handoff group + 73 HTTP/private-host/lifecycle tests | 981 PASS, 2 FAIL | [broader](independent-broader.log) |
| Configured full Pyright | 0 errors/warnings/informations | [Pyright](independent-pyright-final.log) |
| Pyright sau assertion cleanup cuối cùng, cả hai QA files | 0 errors/warnings/informations | [changed tests](independent-pyright-changed-tests.log) |

Existing 910-test subset có đúng 908 PASS / 2 FAIL như handoff; 73 tests thêm
đều PASS. Không có skip/xfail mới. Thông báo có phiên bản Pyright mới không
phải type warning; không cập nhật công cụ.

Không chạy full repository suite: collection hiện có cả real socket/wire replay,
worker/process và BenchmarkJava groups, trong khi chỉ responsibility manifest
đã có isolation được kiểm chứng. Không gọi paid/live LLM, live HTTP/Burp,
BenchmarkJava hoặc thay đổi live/external skip semantics để tạo một full-suite
PASS giả. Đây là giới hạn coverage, không phải kết luận các nhóm chưa chạy lỗi.

## Scenario matrix — expected và actual

Mọi scenario Agent dưới đây dùng production Agent, Planner, real Skill Registry,
Tool Dispatch, WorkflowState, HTTP observation capture, Evidence và Session.
Finding tham gia bằng persistence thật hoặc rejection thật khi được nêu.
Model và HTTP target/transport là scripted external boundaries. Không mock
Workflow/Evidence/Finding methods hoặc dựng terminal state để chứng minh thành công.

| Scenario/case | Production path và scripted boundary | Expected → actual | Status |
| --- | --- | --- | --- |
| A — existing direct SQLi | User objective → skill/load + payload resource → production registration → Candidate-only start → native HTTP capture → proof/result/finding → save/fresh resume. MockTransport mô phỏng filter. | Baseline, quote signal, hai TRUE/FALSE pairs; 6 sends, confirmed result, immutable proof, một finding và coverage row → đúng. | PASS |
| B — HTML-body XSS | Real XSS routing/start, 2 HTTP observations, Evidence/Result/Finding và fresh resume; synthetic ordinary HTML body, intact harmless title marker, không CSP/inert wrapper. | Deterministic HTTP exploitability, không tuyên bố browser execution; confirmed/finding → đúng. Không SQLi-pair contract. | PASS |
| B — plaintext negative | Cùng XSS production path; synthetic text/plain phản chiếu literal marker/script. | not-confirmed, no finding; cố gọi confirm_finding bị tool_exception → đúng. Chỉ là negative cho API/context đã thử. | PASS |
| B — truncated HTML | Native `max_response_bytes=3`, actual incomplete/truncated observation, registered immutable partial proof. | Terminal submission bị evidence-admissibility rejection; insufficient-evidence, no manifest/finding, workflow_blocked; 1 send → đúng. | PASS |
| C — Burp-assisted SQLi | Scripted bridge data → **CaptureStore.ingest** → production one-turn selection/context admission → Candidate baseline/source binding → 6 explicit native HTTP probes → proof/result/finding/session resume. | Selection không tự tạo observation/proof; terminal manifest toàn native-http, đúng session; synthetic Authorization secret không vào saved session → đúng. | PASS |
| D — small whole-target | Real recon → enumeration → input analysis phase artifacts/dispositions; một canonical observed input, SQLi và SSTI Candidates registered qua dispatch, hai validator starts. Scripted landing/OpenAPI/filter. | SQLi confirmed + persisted finding; SSTI insufficient-evidence; cả hai requested goals theo đúng trạng thái, phase handoff giữ nguyên, final workflow_blocked → đúng, 12 sends. | PASS |
| E — supplementary readback | POST `/filter` Candidate + required GET `/filter/123`; actual native capture/proof/result/finding. Fixture chỉ render response, không lưu trạng thái ứng dụng. | Thiếu readback: reject terminal atomically. Bổ sung readback và **new immutable proof**: confirmed, 7 manifest sources, một finding; association retained on fresh resume → đúng. | PASS |
| E — cleanup authority | **Fresh resumed Registry/HTTP permission path**, không phải một Agent cleanup turn. Operator DENY cho DELETE `/filter/123`, phase impact; no grants inherited. | Một exact high-impact/no-session-cache review, refusal, zero additional sends, Workflow không đổi → đúng. | PASS |
| F — grounded repair | Scripted LLM submits duplicate baseline/trigger POST cùng URL, nhận actual tool feedback, sửa thành Candidate-only, rồi production SQLi flow. | Error code/indices/hint; no attempt/revision change/HTTP on rejection; one fresh correctly owned attempt, 6 sends, confirmed/finding → đúng. | PASS |
| F — repeated rejection | Scripted LLM lặp duplicate 3 lần, sau đó production unstarted unresolved closure. | Không attempt/HTTP/proof/finding; insufficient-evidence, workflow_blocked → đúng. Không giả định association-specific retry counter. | PASS |

Trace mới có metadata/state transitions thực: [scenario summary](independent-scenario-summary.json)
và `independent-traces/`. Evidence/finding/session files thật được assert trong
temporary stores; không đưa fixture stores vào dữ liệu cá nhân/project thật.

Scope của D là một endpoint với hai hypotheses. Service discovery được ghi
not-applicable cho single numeric origin; hidden-content discovery và browser
capture được ghi skipped có lý do. Không tuyên bố full crawl hay universal absence.
C không mở socket ingest server và không kiểm chứng raw-request credential replay;
external bridge dừng ở data boundary, production ingestion/selection/binding vẫn chạy.

## Contract, Agent-visible behavior và lifecycle

- Real registry/validator routing cho SQLi, XSS, IDOR/access-control, CSRF, SSRF,
  SSTI: Candidate-only, `[]`, single legacy primary và supplementary đều admitted
  khi current prerequisites đủ. Shared contract tests không tạo exploit cho mọi lớp.
- Normalized method + resolved/redacted URL là association key. Different
  role/required, identical rows, relative/absolute, dot-path, lowercase method và
  secret-redaction collisions đều reject; original indices được giữ. Distinct
  method/path/query hợp lệ. Không auto-drop/merge hoặc sửa arguments.
- Body/payload/identity không phải fields được admission cho association: ba
  independent tests chứng minh `invalid_args` xảy ra trước duplicate classification,
  không silently bỏ fields hoặc tạo identity mới. Payload/principal differences
  trong actual POST HTTP observations vẫn được hỗ trợ bởi tests Phiên 1.
- Rejection trước attempt commit: `assessment.py:189`; atomicity bao gồm attempts,
  active owner, candidate status và committed revision. Explicit changed active
  declarations cần close/retest; omission giữ supplementary obligations hiện hành.
- Schema và Action Guidance giữ Candidate-only recommendation, Available /
  Recommended / Excluded và lifecycle text. Error envelope tại
  `workflow_tool.py:864` mang stable code, indices và hint không chứa URL/secret.
  Hint cấm invented URLs/merge/HTTP repair và chỉ cho Candidate-only khi không mất
  required supplementary obligation.
- Existing actual next-ChatRequest tests chứng minh status=error,
  error_kind=workflow_state, code/indices/hint ở streaming và non-streaming.
  Retention/session/elision không biến rejection thành successful receipt.
  Full compaction giữ canonical queued/no-attempt state; historical envelope có
  thể được tóm tắt, không hứa giữ nguyên text vĩnh viễn.
- Session load giữ declarations và historical proof/results nhưng interrupt active
  execution ownership. Fresh runtime không kế thừa positive HTTP grants, receipts,
  observations hoặc Generic trusted contexts. Explicit retest dùng fresh sources;
  malformed historical duplicate results không đủ Finding eligibility.
- Generic Candidate-only/proposal không bỏ qua trusted-context admission; CLI
  không có binder sẽ honest unresolved. No fake successful Generic production path.

## Security invariants và giới hạn chứng minh

Scope, private-host gate, session/epoch/candidate/attempt/objective/target binding,
source hash/provenance và Finding eligibility paths không bị bản vá sửa. Existing
responsibility tests kiểm tra wrong/stale references, missing/invalid/unfinished
sources, immutable proof tampering, denied/cancelled operations và rollback/checkpoint.
Existing scenario tests còn thực thi actual Agent cancellation/recovery tại HTTP
boundary, save/load interruption và pending requested goals. Negative fault tests
được phân loại là component/fault-injection coverage, không được gọi thành offline
Agent E2E nếu chúng trực tiếp sửa fixture state.

Confirmed Finding chỉ được persist sau accepted confirmed result, usable primary
sources, integrity-checked proof và coverage. New positive scenarios assert actual
files và ledger; negative/unresolved scenarios assert no persisted Finding.
Imported Burp captures không tự trở thành native validation proof. Current contract
có thể admit explicit **imported-capture** với source-reported completeness/current
ownership; existing tests giữ nhãn import và không gán receipt/native transport hash.

Association roles không cấp execution authority. Fresh-resume cleanup denial chứng
minh không kế thừa quyền từ association/result. Tuy nhiên autonomous exact-origin
lab grants hiện có bao phủ mọi endpoint/method/payload (`grants.py:834`): không thể
tuyên bố runtime luôn hỏi cleanup riêng khi một broad grant đã bao phủ request.
Separate cleanup intent vẫn là yêu cầu playbook/operator; phiên này không thêm
cleanup classifier hay policy mới.

**Invariant source-path authorization dưới adversarial namespace mutation vẫn
BLOCKED**, dù downstream snapshots/hash/ownership checks trong fixtures ổn định pass.

## Defects và minimal reproduction

### IV-01 — pre-existing evidence source namespace race — HIGH, acceptance blocker

- Production: `src/workflow/evidence.py:137`, `src/workflow/evidence.py:224`.
  Path resolve/check và pathname open tách rời; fstat consistency kiểm tra resource
  đã mở, không chứng minh resource đó vẫn thuộc authorized source namespace.
- Existing executable reproduction:
  `tests/security/test_evidence_correctness_blockers.py:24`, variants `leaf` và
  `ancestor`. Cả hai **PASS trong broader run nghĩa là counterexample tái hiện**.
- Repro: tạo policy root `lab`, safe `lab/parent/proof.txt` và synthetic outside
  sibling. Sau scope check, ngay tại filesystem open boundary thay leaf bằng symlink
  hoặc đổi ancestor thành symlink. Gọi actual Registry → workflow record_evidence.
  Actual response `ok=true`; immutable artifact chứa `synthetic outside`.
- Observed impact: source ngoài policy root được adopt làm proof. Không chứng minh
  remote exploit, arbitrary secrets bị lộ, RCE hoặc terminal Finding từ repro này.
  Preconditions gồm actor có quyền đổi source namespace trong đúng race window.
- Đây là code/test đã có ở HEAD và không đổi bởi B+A+C. Không mở audit/framework
  mới hoặc sửa lại design probes đã được xác minh.
- Phạm vi implementation tối thiểu cần bàn giao: xác định source namespace policy,
  bind approved source với resource thực tế được đọc, reject leaf/ancestor swaps
  trước artifact/state adoption, và regression cho no-commit rejection. Không mặc
  định rooted descriptor một mình giải quyết ancestor relocation; existing design
  counterexamples vẫn phải được tôn trọng. QA không đề xuất lại kiến trúc publishing.

### IV-02 — pre-existing provider retry snapshot — MEDIUM, preserved limitation

- Repro sẵn có: `tests/llm/test_workflow_action_projection.py:54`,
  `test_transport_retry_keeps_encoded_projection_snapshot[anthropic]` và `[gemini]`.
- First scripted 503 đổi `ChatRequest.tools` direct → whole_target; retry encoded
  bodies khác nhau. Production encode nằm trong từng attempt tại
  `anthropic.py:73` và `gemini.py:138`.
- Actual broader outcome: đúng hai FAIL này, như baseline. Không fix/skip/weaken.
  Frozen projected tools dưới concurrent/callback mutation chưa được bảo đảm;
  unchanged-request schema/error delivery đã pass riêng cho cả bốn encoders.
  Không suy ra một permission bypass từ failure này.

Không có production regression mới chưa giải thích của `related_requests`.
Ba design-only filesystem counterexamples khác trong blocker module là thử nghiệm
thiết kế, không phải ba production defects mới.

## Các giới hạn còn lại

- Observation-role ledger: association declaration không phải ledger cho baseline /
  TRUE / FALSE / trigger observations. Không thêm observation-role controller.
- Request identity: key không thêm body, identity hoặc authorization headers;
  redaction collisions bị reject, không phân biệt bằng secret. Host/default-port /
  fragment/general semantic URL identity không được audit lại.
- Retry bounds: F chứng minh correction và honest stop khi repeated errors. Không
  có association-specific enforced retry bound; existing outer iteration/stall /
  malformed-call limits và skill one-correction guidance vẫn là giới hạn hiện hành.
- SQLi semantic verifier: A/C/F dùng baseline + hai real captured TRUE/FALSE pairs
  phù hợp playbook. Runtime kiểm tra admissibility/bindings, không độc lập xác minh
  mọi technique/boolean semantics; không cho HTTP 200/token echo làm universal proof.
- HTML/plaintext redaction/completeness: small controlled HTML/text fixtures giữ
  bytes đúng và complete; cap=3 native truncation bị từ chối đúng. Không chứng minh
  mọi HTML structure/secret/multibyte/oversized response được giữ đầy đủ. Không sửa
  Redaction hoặc `Observation.complete`, không suy diễn browser execution.
- Live LLM adherence, provider/network behavior thực, Burp socket bridge và operator
  UX không được kiểm chứng. Scripted outcomes không chứng minh LLM thực luôn hiểu
  repair hint hoặc không tạo query giả.

Draft test failures còn giữ trong development logs: diagnostic từ preflight validator,
canonical XSS class alias, actual `tool_exception` classification, đúng tên
`max_response_bytes`, primary-versus-final expected outcome, và literal requested-goal
keyword SSTI. Chỉ sửa assumptions của tests mới, giữ nguyên behavioral assertions
và mọi existing tests/production. Accepted checkpoints/JUnit phân biệt rõ với drafts.

## Live retest checklist cho operator

1. Chỉ dùng exact authorized local/private origin; xác nhận target/permissions và
   các source-path trust assumptions trước chạy. Xử lý IV-01 trong implementation
   nếu cần acceptance bảo mật đầy đủ; live retest không thay thế việc sửa blocker.
2. Direct SQLi: Candidate registration → Candidate-only start; capture baseline và
   hai repeatable TRUE/FALSE pairs; proof/result/finding rồi save/fresh resume.
3. XSS: một context marker và một harmless context-specific marker; kiểm tra media,
   encoding/CSP/completeness. Browser-dependent/partial evidence phải unresolved.
4. Selected Burp request: đúng baseline/source/Candidate binding; phân biệt imported
   capture với native validation sources; kiểm tra saved session không chứa secrets.
5. POST primary + GET readback: missing required readback phải reject; bổ sung actual
   readback và new proof. Cleanup chỉ với đúng operator intent/current authority.
6. Duplicate feedback: không attempt/HTTP trước corrected arguments; không invented
   URL/query. Lặp lỗi phải dừng với outstanding work được ghi nhận, không success.
7. Whole-target: discovery handoff và ít nhất một unresolved branch; một Finding
   không được hoàn tất nhánh/goal còn lại. Kiểm tra cancellation/resume mất grants.

Phiên independent verification kết thúc tại báo cáo này. Chờ operator xử lý
implementation blocker và thực hiện live retest; không tự chạy live target/model.
