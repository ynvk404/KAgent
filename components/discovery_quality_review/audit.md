# KAgent — Independent Audit: Recon & Web Enumeration Quality

Ngày: 13/10/2026. Phạm vi: source hiện tại trong worktree; audit offline, không sửa production/tests/Skills.

## 1. Kết luận

**NOT READY cho tuyên bố kiểm thử web tổng quát không điều kiện trong phạm vi năng lực hiện có.** Có hai P1 tái hiện được: URL root-relative bị resolve khác nhau giữa HTTP và workflow trên target có subpath; content discovery bỏ phần hit vượt 100 mà không giữ nguồn để truy xuất lại. Đây là lỗi hành vi trong năng lực đã cung cấp, không phải yêu cầu xây crawler mới.

**READY WITH LIMITATIONS cho thực nghiệm đồ án có giới hạn được công bố**, với target base ở origin root hoặc mọi request dùng absolute URL đã resolve đúng, discovery chia batch nhỏ để không vượt trần kết quả, và báo cáo trung thực các phần chưa khám phá. Handoff canonical và các gate validation có nền tảng tốt, đã được kiểm chứng offline. Không có P0 được xác nhận trong phạm vi audit; điều này không phải chứng nhận an toàn toàn repository.

Recon đủ làm baseline ít nhiễu cho một web origin. Enumeration là một quy trình khám phá hữu hạn do LLM điều khiển, dùng native HTTP, shell có giới hạn, capture và optional semantic path discovery. Nó chưa phải một discovery engine tự động có parser/crawler/browser traversal tổng quát. Không có bằng chứng cần hard-code Juice Shop; cũng không có bằng chứng rằng LLM sẽ thu thập đủ surface trên mọi ứng dụng.

## 2. Phương pháp và giới hạn bằng chứng

Đã đọc `AGENTS.md`, ba playbook recon/enumeration/input-analysis, planner, agent dispatch/stall, native HTTP/request builder/context, discovery adapters, workflow state/tool/context resolver, capture store/scope view, session/compaction và tests trực tiếp liên quan. Wiring thực tế nằm ở `src/cli/runtime.py:736` (HTTP), `:738` (content), `:745` (service), `:806` (capture tools), được dùng bởi CLI; không suy luận khả năng chỉ từ SKILL.md.

Worktree trước audit có thay đổi tại:

- `skills/cross-site-scripting/SKILL.md`, `skills/web-input-analysis/SKILL.md`;
- `src/agent/agent.py`, `src/tools/workflow/workflow_tool.py`;
- `tests/security/test_evidence_recovery_contract.py`;
- untracked `tests/integration/test_phase2_whole_target_reliability.py`.

Các kết luận về distinct XSS hypotheses và continuation/recovery áp dụng cho **worktree đang có**, không khẳng định đã có trong HEAD. Không thay đổi các tệp này.

Đã chạy đúng nhóm focused sau bằng Python của `venv-linux`:

```sh
venv-linux/bin/python -m pytest -q \
  tests/skills/test_recon.py \
  tests/skills/test_web_enumeration.py \
  tests/skills/test_web_input_analysis.py \
  tests/tools/test_discovery_tools.py \
  tests/tools/test_http_context.py \
  tests/tools/test_request_builder.py \
  tests/state/test_workflow_state.py \
  tests/security/test_phase_coverage_attestation.py \
  tests/security/test_captured_http_replay.py \
  tests/integration/test_whole_target_workflow.py \
  tests/integration/test_structured_handoff_hardening.py \
  tests/integration/test_phase2a_handoff.py \
  tests/integration/test_phase2_whole_target_reliability.py
```

**498 passed in 62.88s.** Các tests dùng fixtures/mocks/scripted client; không chạy external LLM, live target, benchmark hoặc full suite. Không chạy pyright vì không đổi Python. Hai probes bổ sung chạy in-memory qua production helpers/adapter, không network và không tạo thêm tệp test.

Tests skill chủ yếu kiểm tra frontmatter/nội dung hợp đồng; pass của chúng không chứng minh parsing HTML/OpenAPI/JS hay chất lượng chiến lược thực tế. Integration tests chứng minh state transition và replay trên fixtures, không đo recall endpoint hay hiệu quả LLM.

## 3. Đánh giá Recon

### Năng lực thực có

- Target giữ base URL/name/revision (`src/target/target.py:17`); engagement scope là scheme/host/effective-port, không phải toàn private network (`src/engagement/state.py:46`, `:74`). HTTP gọi scope check trước chuẩn bị request và redirect (`src/tools/http/http_tool.py:194`, `:453`, `:712`). Private-host gate chỉ dùng declared-origin cache khi origin khớp (`src/tools/http/private_host.py:40`, `:92`). **NO CHANGE**.
- Native HTTP cho status, final URL, response headers, bounded body, effective request preview và observation metadata (`src/tools/http/http_tool.py:560`, `:580`, `:619`). Reachability không đồng nghĩa root phải trả HTML 200: runtime attests sau response, kể cả HTTP error (`:662`); playbook xử lý root JSON 401/404 và unknown architecture (`skills/recon/SKILL.md:236`, `:254`). **NO CHANGE**.
- Service discovery thật sự được đăng ký, có native TCP và optional nmap theo capability/profile/coverage. Chỉ active host/effective port, vetted numeric address, bounded timeout; origin suggestions không tự cấp scope (`src/tools/discovery/service.py:325`, `:382`, `:438`, `:627`, `:717`). Đây là xác minh service của URL, không phải quét mọi port/host. **LIMITATION hợp lý**.
- Redirect default không follow; tối đa 5, per-hop checks, dừng cross-origin, explicit-cookie thiếu provenance và captured redirect (`src/tools/http/http_tool.py:103`, `:437`, `:441`, `:453`). SSO/HTTP→HTTPS có thể tạo điểm dừng cần operator scope; không nên coi là unreachable. **NO CHANGE**.
- Architecture/intermediary/fingerprint là quan sát và suy luận của LLM từ traffic. Không có classifier framework/WAF tổng quát trong recon runtime. Playbook giữ uncertainty và nguồn (`skills/recon/SKILL.md:254`). **LIMITATION**, không phải fingerprint được engine xác nhận.
- CT/passive apex discovery là hướng dẫn shell trong playbook, điều kiện broader authorized scope, không phải native subdomain engine (`skills/recon/SKILL.md:99`). Shell không có cùng URL resolver/private-origin gate của native HTTP; registry/worker permissions vẫn tồn tại. Không được dùng capability hoặc prompt ví dụ làm authorization. **LIMITATION/P2 về tính nhất quán nguồn**, chưa thấy đường bypass P0 được chứng minh.

### Chất lượng và tránh lặp

Planner chọn phase từ canonical completion, không tự chọn bộ request cố định theo app (`src/agent/decision_planner.py:331`). LLM chọn nguồn và hướng tiếp theo theo phản hồi. Recon summary là artifact để enumeration tái dùng; workflow chỉ giữ completion/coverage và refs, không có typed technology/architecture/robots observation catalog. Vì vậy đọc lại summary là dependency thật, không có auto-hydration toàn bộ recon facts vào inventory.

Coverage core do HTTP attests lần đầu; request lặp không tạo thêm semantic progress chỉ nhờ observation ID mới (`src/tools/http/http_tool.py:662`). Stall tracker phân biệt structured facts với novel exploration, chống URL cache-buster/byte escalation (`src/agent/agent.py:711`, `:761`; `tests/integration/test_whole_target_workflow.py:423`). Điều này giảm lặp nhưng không deduplicate mọi request trước dispatch; không có frontier/visited URL database cho recon.

## 4. Ma trận kiến trúc và request surface

“Có một phần” nghĩa là có phương tiện thu thập/biểu diễn nhưng cần LLM hoặc capture/operator và không chứng minh completeness.

| Nhóm | Thu thập thực tế | Handoff/replay | Đánh giá |
|---|---|---|---|
| HTML/SSR, links/forms | Native HTTP giữ bounded HTML; LLM/shell đọc anchors, action, hidden/type/enctype. Native navigation parser chỉ attests có reference | Method/location/media/sample/source có schema; không tự tạo input từ HTML | Có một phần; phù hợp site nhỏ, form tĩnh |
| SPA với JS | Shell/bundle prefix và LLM phân biệt client route/network call; path discovery lọc wildcard shell | Canonical input nếu model record; capture hỗ trợ baseline thật | Có một phần; không tự chạy UI và lazy chunks |
| REST JSON/form có OpenAPI | HTTP lấy doc, LLM/shell giải thích paths/operations/schema/security | JSON/form identities tách biệt; sample/template có giới hạn; captured mutation giữ bytes ngoài field | Khả dụng có điều kiện; không có OpenAPI importer tự động |
| API không docs | Response/link/call-site clues, bounded GET path guesses | Model phải suy luận có nguồn và record từng input | Coverage thấp hơn; không có recursive API response explorer |
| Authentication/session | Native cookie + Authorization context theo identity/origin; browser/Burp ingest tùy tích hợp | Captured credentials có review riêng; refs bền, secrets/runtime availability không bền | Có một phần; login/OTP/SSO/accounts/refresh không tự giải quyết tổng quát |
| Dynamic path IDs | Grouping theo ≥2 observed paths là playbook; capture index giữ concrete URL | Path replay có exact old segment; không tự phát minh ID hay template | Có một phần; route shape/grouping cần model |
| Query, duplicate keys | URL/capture quan sát key; record query input | Replay chọn occurrence, giữ keys/encoding khác | Hỗ trợ khi baseline phù hợp |
| Header/cookie inputs | Có thể record location, đọc request headers từ capture | Manual native headers được phép; captured replay từ chối mutation header/cookie | Biểu diễn có; mutation tự động chỉ một phần |
| Nested JSON/arrays | Capture endpoint summary chỉ top-level keys; full body/baseline còn nguồn sâu | JSON Pointer/dotted path + array scalar replay | Có một phần; không có recursive input extraction |
| Multipart | Form metadata/capture; runtime không tự phân tích thành inventory đầy đủ | Text part mutation giữ boundary/binary siblings; file byte mutation bị từ chối | Text part có; binary upload payload là limitation |
| XML/raw/complex body | Manual observation/sample/raw capture | XML named exact value hoặc unique raw value; comments/CDATA/ambiguous selectors từ chối | Hỗ trợ giới hạn, không parser/mutator tổng quát |
| GraphQL | Playbook giới hạn introspection check, HTTP có thể gửi JSON | Input/sample có thể record; không đi toàn schema/type graph | LIMITATION có chủ đích |
| Multi-origin/front-end + API/SSO | Mỗi origin cần scope riêng | Whole-target inventory/candidate bound active objective origin | Không tự mở rộng một objective tới toàn topology |

Nguồn: `skills/web-enumeration/SKILL.md:89`, `:175`, `:225`, `:275`, `:321`; `src/tools/http/request_builder.py:151`, `:169`, `:269`, `:330`; `src/browser/store.py:550`, `:603`; `src/tools/http/context.py:12`. Ví dụ regex trong skill chỉ minh họa double-quoted attributes và `/api|rest` strings; không phải runtime parser đảm bảo mọi HTML hay call-site. Đừng đánh giá các ví dụ đó thành capability tổng quát.

## 5. Luồng dữ liệu và handoff ưu tiên

```text
Target + Engagement + Permissions
  → Planner chọn recon → load_skill cung cấp playbook
  → HTTP/service/shell → observations runtime + summary.md + coverage
  → Planner chọn enumeration → nguồn HTML/metadata/doc/JS/capture/path
  → LLM gọi record_input từng input → AttackSurfaceInput + inventory.md
  → Input analysis: get_input + context/probe có giới hạn
  → record_candidate(input_id) → Candidate + reverse link + goal link
  → start_validation → canonical candidate + transient validation_context
  → HTTP manual hoặc captured baseline → evidence → result → finding gate
```

### Dữ liệu bền và dữ liệu không bền

| Dữ liệu | WorkflowState/session canonical | Nơi khác / giới hạn |
|---|---|---|
| Origin/objective/phase coverage/completion | Có | Phase artifacts chỉ là path + operational existence checks |
| Endpoint/method/parameter/location/input_type | AttackSurfaceInput | `record_input` chỉ cho whole-target |
| Content type/sample body | Có; sample ≤4.000 ký tự, redacted | List sample ≤500; `get_input` lấy full canonical sample |
| Baseline/auth/source reference | Có | Ref không phải credential hoặc bảo đảm replay |
| Arbitrary required headers | Không có dedicated field trên input/candidate | Có trong live capture hoặc effective redacted request preview; LLM/artifact nếu chưa capture |
| Full original request bytes/session cookies | Không | CaptureStore/HTTPContextStore runtime-only, bounded và permission-gated |
| Response/baseline content | Không nhúng vào input/candidate | ObservationStore/capture/proof refs; không tự chuyển thành replay baseline |
| Architecture/route_type/reachability/required/hidden/form action association | Không có typed field trên input | Summary/inventory/prose/context do model tạo |
| Candidate class/test_case/signals/priority/template/links | Có | Template là sanitized skeleton, không mặc nhiên executable |
| Validation context availability/conflicts | Không | Derived lúc retrieval/start, loại khỏi retained transcript/session/compaction |

Nguồn: `src/workflow/state.py:224`, `:491`, `:2045`; `src/tools/workflow/workflow_tool.py:661`, `:681`, `:1883`; `src/workflow/validation_context.py:1`, `:149`, `:274`; `src/session/store.py:438`, `:521`; `src/agent/compaction.py:126`.

### Những gì đã bảo toàn đúng — NO CHANGE

1. **Inventory → Candidate không làm mất geometry khi có input_id.** Tool kế thừa method/endpoint/parameter/location/media/baseline/auth/source; marker-free sample không tự thành mutation template (`src/tools/workflow/workflow_tool.py:510`, `:586`). `tests/integration/test_whole_target_workflow.py:235` kiểm tra round-trip request shape; `tests/integration/test_phase2a_handoff.py:74` kiểm tra sample/template tách biệt.
2. **Link phải compatible và mutation thất bại là atomic.** Origin/objective/method/endpoint/query/location/media/auth/baseline conflicts bị từ chối, kiểm tra prospective enrichment trước commit (`src/workflow/state.py:1097`, `:1433`, `:1526`). Tests `test_f3_failed_create_or_duplicate_is_atomic`, `test_f3_canonical_add_and_link_cannot_bypass_compatibility` trong `tests/integration/test_structured_handoff_hardening.py:282`, `:296` đã pass.
3. **Distinct media/auth/baseline/test_case có identity riêng.** JSON vs form không đè nhau; charset/boundary không tự thành identity mới; legacy refs/IDs giữ links (`src/workflow/state.py:185`, `:455`). Tests hardening `:174`, `:198`, `:234` và state tests `:428`, `:467` đã pass. DOM/stored/API hypothesis có thể tách bằng test_case nhưng phải có evidence, không dựa tên input.
4. **Baseline runtime-bound không alias ID sau restart.** Capture ref chứa generation/signature, clear/fresh store cần recapture (`src/browser/store.py:300`, `:313`). `tests/integration/test_structured_handoff_hardening.py:69` và `:157` đã pass. Native HTTP observation_id không phải capture baseline_request_ref; không được dùng thay thế.
5. **Auth bảo toàn an toàn trong cùng runtime.** Identity + exact origin, cookie path/secure/expiry, target/engagement/permission reset clear context (`src/tools/http/context.py:20`, `:48`, `:64`). Tests `tests/tools/test_http_context.py:19`, `:35`, `:45`, `:65` pass. Captured credential replay dùng gate riêng, không pha native identity, không follow redirect (`tests/security/test_captured_http_replay.py:100`, `:140`, `:165`, `:305`). Session lưu refs, không khôi phục live credential.
6. **Ambiguous/foreign handoff không tự chọn baseline.** Resolver withholding conflicts/unknowns, exact lookup có ownership và bound, availability không tạo quyền (`src/workflow/validation_context.py:149`, `:274`). Tests Phase2A `:170`, `:193`, `:208`, `:370`, `:390`, `:407` pass.
7. **Finding gate cần proof/result.** Không biến inventory/candidate thành confirmed; latest result và registered evidence/finding persistence quyết định (`src/workflow/state.py:1971`, `:1985`; `tests/state/test_workflow_state.py:1129`, `:1149`). Không audit sâu từng vulnerability validator trong báo cáo này.

### Các lỗ hổng chất lượng còn lại trong handoff

- **P2 — Request headers/context chưa canonical đầy đủ khi không có capture.** Input/Candidate chỉ có body skeleton/media/refs; `X-Tenant`, `Accept` version, CSRF header, nonce hoặc fields bắt buộc khác không được auto-hydrate từ source_ref. Source_ref là string, không phải typed observation FK được kiểm chứng ở registration. Không thể tuyên bố mọi candidate có request tái tạo được. Đây là hạn chế representation; có manual HTTP headers và capture replay để đáp ứng case đã biết, nên không gán P1 cho mọi header thiếu. Minimal đề xuất: ghi rõ required non-secret context trong inventory và bind baseline thật trước validation cần exact replay; không lưu raw credentials.
- **P2 — Một request shape với nhiều payload mẫu/provenance chưa có multi-variant input slot.** Sample/source không nằm trong fingerprint; same geometry/media/auth/baseline nhưng sample/source xung đột sẽ trả error thay vì đè (`src/workflow/state.py:455`, `:1433`). An toàn hơn silent merge nhưng hai schema branches/nested sibling inputs hoặc hai form với cùng URL có thể cần baseline refs khác. Candidate có test_case, input không có tương đương. Giữ variant ở inventory, dùng parameter path/baseline đúng khi đã có; chưa chứng minh candidate hợp lệ bị xóa. Tests state `:208`, `:320`, `:373` chỉ xác nhận conflict/anchor semantics, không chứng minh model tự recover variant.
- **LIMITATION — Structured inputs không được tự tạo từ traffic/docs.** HTTP navigation parser (`src/tools/http/http_tool.py:40`) chỉ kiểm tra reference cho coverage; content tool chỉ trả paths; capture endpoint index chỉ query/top-level body names (`src/browser/store.py:550`, `:603`). LLM phải đọc nguồn, gọi workflow và giữ provenance. Input chưa record chỉ nằm ở context/artifact, dễ bị bỏ qua khi compaction. Không có assertion inventory.md đầy đủ/khớp toàn source observations.
- **LIMITATION — Resume không phải authenticated replay continuation tự động.** Refs bền, live context/capture không bền. Resolver báo stale/unavailable và cần recapture/operator login. Đây là lựa chọn an toàn, không bug mất session secret.

## 6. P0/P1 cần xử lý

### F1 — P1: HTTP root-relative URL trên target có subpath khác canonical handoff

**Root cause:** `src/tools/http/http_tool.py:715` nối `target.base_url().rstrip('/') + raw` cho mọi path không absolute. Trong khi input/candidate geometry và context resolver dùng origin + URL join (`src/workflow/state.py:1541`; `src/workflow/validation_context.py:121`), discovery common resolve `/...` từ origin (`src/tools/discovery/common.py:42`).

**Probe offline:** Target `https://target.test/app/`; record input GET `/search?q=safe`, link Candidate, resolve validation context, rồi gọi `HTTPTool.prepare` với cùng path:

```text
canonical_url     = https://target.test/search?q=safe
native_request_url= https://target.test/app/search?q=safe
discovery_base('/search') = https://target.test/search
```

Không có request network. Probe dùng production state/link/context/prepare; method/location còn nguyên nhưng URL đi tới route khác. Scope vẫn cùng origin nên không xếp P0. Có thể gây 404 sai, missed input, false negative nếu validator/probe dùng endpoint path thay absolute URL; còn captured replay hoặc absolute context URL tránh được.

**Sửa tối thiểu đề xuất, chưa triển khai:** thống nhất root-relative `/...` theo active origin và phân biệt path-relative với base URL. Giữ backward compatibility cho relative path nếu đó là API contract; focused regression target `/app/`, root-relative path/query và absolute URL, kiểm tra prepare URL trùng canonical geometry. Không đổi scope/permission.

**Trước thực nghiệm:** sửa nếu cho phép target subpath. Workaround có thể review: origin-root target hoặc absolute same-origin URLs được resolve từ nguồn/page URL. 498 tests pass không bao phủ inconsistency này.

### F2 — P1: content discovery bỏ hit vượt 100 trong một invocation hợp lệ

**Root cause:** Cho phép 500 paths/1.000 requests (`src/tools/discovery/content.py:41`, `:101`, `:118`) nhưng `_result` chỉ xuất `discovered[:MAX_RESULT_ITEMS]` và `rejected[:MAX_RESULT_ITEMS]`, trần 100 (`:829`, `:851`). Không có retained result store/cursor/artifact cho phần dư. Local observations mất khi `run` return. `make_result` ghi `performed` trước khi kết quả bị cắt, không biến result truncation thành incomplete-source reason (`:208`).

**Probe offline qua production `ContentDiscoveryTool.run`:** native mode, 105 unique paths, `max_requests=107`; mock `_probe` trả 105 distinct verified hits và 2 baselines, mock private gate/client/sleep để không network/wait. Phần budget/filter/result/coverage thực thi production:

```json
{"completed_requests":107,"scanned_paths":105,"returned_hits":100,
 "truncated":true,"coverage":{"status":"performed","reason":null},
 "retained_inputs":0,"result_has_cursor":false}
```

Flag truncation có cảnh báo, nên không gọi silent falsification; tuy nhiên các hit 101–105 không thể retrieve từ invocation đã chạy. Không có tự động record endpoint/input; model phải scan lại để biết phần dư. `performed` attests có execution, không chứng minh complete retained inventory.

**Sửa tối thiểu đề xuất, chưa triển khai:** giữ toàn compact structured results của invocation trong bounded artifact/retrievable result, trả ref và count khi preview vượt 100. Hoặc chia execution/results thành batches trong giới hạn sẵn có; không tăng request/response budgets, không xây crawler. Focused regression >100 verified hits phải truy xuất được phần dư và coverage reason không bị hiểu thành inventory đầy đủ.

**Trước thực nghiệm:** sửa nếu đánh giá một invocation có >100 hits. Workaround nhỏ: ≤100 requested paths mỗi lần (ffuf vẫn tính verification vào budget), account truncation và không claim full inventory từ invocation truncated.

## 7. P2 và limitations có thể chấp nhận cho đồ án

| Mã | Loại | Nguyên nhân / ảnh hưởng | Cách trình bày hoặc thay đổi tối thiểu |
|---|---|---|---|
| Q1 | P2 | Anti-stall chỉ cho 8 novel-exploration iterations/phase nếu chưa có structured fact; 4 no-progress iterations có thể dừng source-rich app trước khi model kịp record | Record input incremental; report stalled/incomplete. Không nâng budget chỉ để né thiếu handoff |
| Q2 | P2 | Wildcard signature dùng bounded 16 KiB normalized prefix/status/media/redirect; không phân biệt mọi dynamic page hoặc shell khác ở suffix | Hit là clue; giữ body_truncated và corroborate nguồn/call-site. Không coi hit là endpoint/backend proof |
| Q3 | P2 | Coverage dimensions xác nhận pass/method source, không measuring per-route/input completeness; artifact gate kiểm tra canonical nonempty file | Công bố bounded coverage và omissions, không dùng completed như “đã kiểm tra toàn web” |
| Q4 | P2 | Recon summary/route type/auth state/provenance detail chủ yếu Markdown; duplicate requests/route grouping không có canonical frontier | Dùng source_ref nhất quán và tái dùng summary; không cần crawler mới cho giai đoạn đồ án |
| Q5 | LIMITATION | GET-only content discovery không nhận auth_context_ref/headers; riêng client dùng User-Agent, không native identity jar | Authenticated enumeration dùng scoped HTTP/capture đã có; path sweep chỉ đại diện unauthenticated view |
| Q6 | LIMITATION | Một cấp link-following, không recursive sitemap index, OpenAPI $ref resolver, JS AST/deobfuscation hoặc API response graph walker native | Ghi rõ nguồn đã đọc và unresolved docs/bundle depth; không đánh giá recall tổng quát từ fixtures đơn giản |
| Q7 | LIMITATION | Browser-like HTTP profile chỉ UA/Accept + same-origin snapshot; không JS runtime/DOM interaction | Capture/operator hoặc optional authorized browser adapter; thiếu browser phải giữ browser-required |
| Q8 | LIMITATION | Capture summary không recursive nested fields/header/cookie extraction; bounded stores evict records | Full selected baseline để replay; ghi recapture requirement; không coi endpoint index là full input inventory |

Nguồn Q1: `src/agent/agent.py:154`, `:711`, `:761`, `:4479`. Q2: `src/tools/discovery/content.py:43`, `:606`, `:673`, `:709`. Q3: `src/tools/workflow/workflow_tool.py:1522`, `:1598`, `:1640`; `src/tools/http/http_tool.py:662`. Q5: `src/tools/discovery/content.py:101`, `:308`. Q7: `src/tools/http/http_tool.py:195`. Q8: `src/browser/store.py:15`, `:313`, `:550`, `:603`, `:669`.

Chưa chứng minh Q1–Q8 gây missing cụ thể trên live app; đây là execution-path constraints và rủi ro coverage, không nâng tự động thành P1. Tests wildcard/ffuf/budget/cancellation trong `tests/tools/test_discovery_tools.py:289`, `:379`, `:411`, `:544` pass xác nhận adapter bounded, không xác nhận classifier không false positive/negative ở mọi app.

## 8. Vai trò LLM và khả năng thích ứng

Planner kiểm soát thứ tự ưu tiên và canonical obligations, còn skill hướng dẫn chiến lược. LLM có thể đọc phản hồi mới, thay nguồn HTML → JS → docs/capture, gọi thêm bounded discovery và record input mới. Không thấy selector trong planner chạy riêng `/rest/products/search` hay đặc tính Juice Shop để mở discovery. Default paths (`src/tools/discovery/content.py:48`) là generic wordlist; ví dụ `/api` và `/rest` trong skill không phải runtime network-route whitelist.

Tool availability không chỉ do một skill: agent cho phép no-permission tools, các active skills có allowed-tools theo union; native/capture reads và registry permissions vẫn quyết định việc thực thi (`src/agent/agent.py:1595`, `:1626`; `src/tools/common/registry.py:187`). Không nên nói browser capture hoàn toàn không dùng được vì không ghi trong allowed-tools enumeration: capture reads `requires_permission=False` (`src/tools/common/browser_capture.py:70`), còn browser automation tùy adapter/context khác.

Playbook input analysis yêu cầu evidence cho input consumption/controllability, phân biệt HTML/DOM sink với JSON reflection và route name; classes được resolve từ loaded skill metadata (`skills/web-input-analysis/SKILL.md:94`, `:133`; `src/tools/workflow/workflow_tool.py:598`). Đây là generalizable triage contract, nhưng semantic signal vẫn do LLM đánh giá. Runtime bảo vệ proof integrity/ownership/completeness và route validator, không chứng minh ý nghĩa SQLi/XSS chỉ từ việc record candidate.

Model có thể finish sớm nếu tất cả dimensions được account (kể cả observed/skipped có lý do), artifact nonempty và known inputs đã triage; không có oracle cho undiscovered endpoints. Ngược lại source lớn/bundle truncated, auth chưa có, missing browser hoặc repeated guessing có thể tiêu hết exploratory allowance. Tests `tests/security/test_phase_coverage_attestation.py:84`, `:160`, `:174`, `:216` xác nhận không tự claim performed nhưng cho phép completed bounded pass có observed coverage. Điều này phù hợp thiết kế nếu kết luận giữ đúng giới hạn.

## 9. Sẵn sàng riêng cho Whole-target Kịch bản 3

Không tìm thấy định nghĩa “Kịch bản 3” độc lập trong Markdown/Python của repo. Trong báo cáo này dùng nghĩa user chỉ định: **một request whole-target chạy recon → enumeration → input analysis → candidates → validation và tổng hợp các nghĩa vụ của active origin**. Không suy đoán thêm dataset, target hoặc chỉ tiêu benchmark.

**Trạng thái: READY WITH LIMITATIONS cho offline/controlled experiment nhỏ; NOT READY để dùng Kịch bản 3 làm bằng chứng độ phủ web tổng quát.**

- Runtime phase order, pending/blocked inputs, candidate/result/evidence/finding obligations có tests production fixture. `tests/integration/test_whole_target_workflow.py:74` kiểm tra pipeline complete; `:326` blocked input; `:370` incremental enumeration không advance phase.
- Worktree reliability tests `tests/integration/test_phase2_whole_target_reliability.py:51`, `:73`, `:193`, `:287`, `:335` chứng minh early validation không bỏ discovery, independent result không close obligations khác, distinct XSS sibling giữ unresolved và continuation fail-closed. Không suy diễn chúng là live discovery benchmark.
- Late inputs có thể được record và pending inputs kéo planner về input analysis (`src/agent/decision_planner.py:396`); không tự reopen completed discovery phase. Inventory changes invalidate no-candidate review (`src/workflow/state.py:1423`). Do đó một pass completed không có nghĩa surface cố định vĩnh viễn; cũng không có scheduler tự quay lại crawl khi thấy mọi new URL.
- Cần prerequisite thực nghiệm: scope active origin rõ; nguồn/capture và auth thật nếu scenario yêu cầu; tránh hoặc sửa F1/F2; mỗi discovered input phải có disposition đúng; unresolved browser/auth/doc/truncation phải hiện trong inventory và kết quả. “No candidate” không được tính “tested negative”.
- Nên đánh giá tách nhóm: HTML form nhỏ; documented JSON/form API; SPA với nguồn JS/capture; authenticated app với hai identity được cung cấp. Ghi số input quan sát/record/triage/validate và limitations theo từng nhóm. Một Juice Shop run tốt không thay thế bằng chứng các nhóm còn lại. Báo cáo này **không chạy** các live cases đó.

## 10. Handoff audit

Ưu tiên sửa tối thiểu **F1, F2** hoặc giới hạn rõ case thực nghiệm tránh trigger, rồi kiểm chứng lại riêng các regression tương ứng. Có thể chấp nhận Q1–Q8 ở giai đoạn đồ án nếu mô tả hệ thống là agent khám phá có giới hạn, evidence-driven, hỗ trợ HTTP/capture và báo cáo coverage chưa đầy đủ; không gọi nó crawler/browser pentester tổng quát.

Đã kiểm tra `git diff --check` và whitespace của báo cáo mới, không có lỗi; đã đọc diff của các thay đổi có sẵn và kiểm tra `git status --short`, chỉ bổ sung thư mục báo cáo so với trạng thái đầu audit.

Không triển khai bản sửa, không thay đổi Phase 1/2, workflow/gates/budgets, không commit/push/reset/cleanup. Artifact duy nhất thêm bởi audit là báo cáo này. Full suite, external model, live target và benchmark không được chạy. Kết quả 498 focused tests chứng minh contracts đã nêu; hai probes chỉ chứng minh F1/F2, không đánh giá tỷ lệ phát hiện lỗ hổng ngoài thực tế.
