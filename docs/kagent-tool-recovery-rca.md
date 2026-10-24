# KAgent — Tool Contract & Operation Recovery RCA

Ngày audit: 23/10/2026 theo ngày của phiên làm việc. **AUDIT + DESIGN ONLY**. Không triển khai bản vá, chạy pentest, gọi LLM/provider, thay đổi quyền hoặc sửa dữ liệu thực nghiệm.

## 1. Executive conclusion

**Quyết định hiện tại: hướng 4 — chưa freeze/chạy lan-09, vì đã tái hiện một blocker về tính đúng đắn của recovery presentation.** Blocker mới không phải hai lần gọi Workflow sai arguments trong kịch bản 1. Đó là khả năng một success không phải retry của thao tác lỗi làm TUI ghi “Recovered” và loại lỗi quan trọng khỏi số unresolved.

- **Hai runtime rejections A/B là đúng.** A dùng observation ID thay cho selected-capture retrieval ID; B đưa field của record_attempt_state vào record_result. Session chứng minh các lần sửa sau được chấp nhận. Giữ nguyên nghiệm thu SQLi evidence, Intelligence và Finding của kịch bản 1; không audit lại các phần đó.
- **Contract có khiếm khuyết đã chứng minh.** Workflow dùng một flat schema cho 18 actions. Action allowlist đã được sinh thành mô tả từ ACTION_INPUTS, nhưng không ràng buộc cấu trúc theo action. Cả arguments sai và đúng của A/B đều pass JSON Schema hiện tại. source_ref thiếu phân biệt theo context; attempt_id còn có mô tả trái với allowlist.
- **False unresolved của A có nguyên nhân rõ.** Canonical proposal không xây được khi selected-source guard từ chối, nên failure dùng raw-argument identity; retry có canonical binding lại dùng một identity khác. B dùng cùng Candidate/Attempt/result position nên được ghép.
- **False recovery đã tái hiện offline.** Với HTTP error_kind=network, request B khác body nhưng cùng method/endpoint có thể recover lỗi A; B thậm chí đã được dispatch trước khi A lỗi. Với record_evidence, owner key bỏ evidence_path và observation_ids, nên success B có thể recover permission/persistence failure của proof A. Đây là kết quả chạy reducer/runtime_facts thật với sự kiện giả lập, không phải bằng chứng một run lịch sử đã mất evidence hoặc vượt quyền.
- **Phương án thoát gate nhỏ nhất:** contract-first A cộng bản sửa recovery theo loại lỗi, owner, resource và quan hệ retry; giữ mọi runtime rejection. Không tách tool, không bật oneOf/strict chưa được chứng minh, không mở lại SQLi development. Chỉ freeze sau khi các ca false recovery trở thành negative regressions và các ca A/B vẫn đúng.

Phân biệt phạm vi: lỗi presentation không tự sửa WorkflowState, không làm một result không hợp lệ thành accepted, không cấp quyền. Tuy vậy, yêu cầu gate của audit coi **false recovery che lỗi quan trọng** là BLOCKER; không được đổi nó thành NON-BLOCKING chỉ vì nằm ở TUI. Nếu chỉ xét A/B thì chưa có lý do hoãn lan-09.

## 2. Evidence & source references

### 2.1. Baseline và giới hạn bằng chứng

Đã đọc [nghiệm thu kịch bản 1](scenario1-final-acceptance.md), [RCA lan-08](lan-08-audit.md), [nghiệm thu lan-08](lan-08-acceptance.md), [tool history lan-08](lan-08-tool-history.md), và đối chiếu lịch sử lan-06/07 khi liên quan contract. Chưa có docs/kagent-tool-recovery-rca.md trước audit.

Source được audit là **worktree hiện tại**, HEAD a8b673414e161bd38694d304434de665b74f8441, có thay đổi chưa commit từ trước. Không coi HEAD là bản code đã chạy thí nghiệm. Đặc biệt các sửa lan-08 về source descriptions, context retention và banner đã có sẵn. Không có archive đầy đủ từng outbound provider request/schema của phiên kịch bản 1; vì vậy “schema hiện tại cho phép” là kiểm chứng hiện tại, không phải tuyên bố đã thu được nguyên schema trên wire của run lịch sử.

Nguồn lịch sử đọc trực tiếp:

| Nguồn | Định vị | Điều xác nhận trong audit này |
|---|---|---|
| Kịch bản 1 | /home/khainguyen/.kagent/sessions/3c0efc1d-d87d-40f1-8aaa-a38b4303e7cd.json | 38 messages; 18 tool calls; args, error và receipt của A/B |
| lan-06 | experiments/scenario3/runs/lan-06/profile-home/.kagent/sessions/7262ac7a-9da0-4871-8f9c-00031c3b2832.json | Sai coverage_phase; discovery observation không có validation ownership; source-path mismatch |
| lan-07 | experiments/scenario3/runs/lan-07/profile-home/.kagent/sessions/fbf1ddcd-78cf-4c94-b6e8-13d5e84b08e1.json | complete_skill bị chặn do input pending/blocked; file_edit ngoài allowed-tools của skill đang active |
| lan-08 | experiments/scenario3/runs/lan-08/profile-home/.kagent/sessions/135686eb-ee21-4663-b266-c9e22827d7c5.json | Sai discovery ID; obs_ làm replay baseline; ba observation IDs không tồn tại trong lần đăng ký proof đầu |

Chỉ trích opaque IDs, field names và lỗi cần cho RCA; không sao chép token, password, response body hoặc traffic đầy đủ. Banner lịch sử của kịch bản 1 được kế thừa từ báo cáo nghiệm thu/transcript mà báo cáo đó đối chiếu; session JSON không serialize nguyên AppState để replay chính xác banner.

### 2.2. Lịch sử A/B đã đối chiếu lại

Chỉ số messages bắt đầu từ 0:

| Ca | Call → result | Sai/đúng | Thay đổi ở retry |
|---|---|---|---|
| A | 9 → 10; call_00_iSJQU0mJbw94brSfhZP68489 | source_ref=obs_4f86b6218a9d4d2c9c892330496f1f19; selected retrieval ID là burp:burp-23f8b54efef80eed | 11 → 12 bỏ source_ref, baseline_request_ref, signals; giữ request geometry; runtime điền canonical source/baseline |
| B | 31 → 32; call_00_M7dXDdAN0ppQJe0YWmO99190 | record_result có mutation_state và effect_basis | 33 → 34 bỏ hai field, thêm notes; **mọi field chung còn lại bằng nhau** |

A trả “selected capture Candidate binding is ambiguous or mismatched”; B trả “record_result does not accept effect_basis, mutation_state; omit these arguments”, kèm Allowed fields. Không có bằng chứng lỗi A là endpoint sai; chính source_ref làm tập matches rỗng.

### 2.3. Đường đi từ instructions đến error

1. System prompt yêu cầu phase HTTP, không lặp invalid_args, thử một structured call trước batching: [system_prompt.py:70–73](../src/agent/system_prompt.py). Skill body được load theo allowed-tools; selection có guidance riêng: [selection.py:24–47](../src/browser/selection.py).
2. Registry đưa nguyên description/schema thành ToolSpec: [registry.py:141–157](../src/tools/common/registry.py). ActionView chỉ đổi enum/mô tả action theo objective, **không cắt các properties không dùng**: [action_view.py:24–45](../src/tools/workflow/action_view.py).
3. Adapter encode payload, không thực hiện action-dependent validation cho Workflow: OpenAI-compatible [openai.py:443–460](../src/llm/providers/openai.py), Anthropic [anthropic.py:216–224](../src/llm/providers/anthropic.py), Gemini [gemini.py:496–532](../src/llm/providers/gemini.py).
4. JSON arguments được parse, kiểm tra active skill và terminal blocker; selected-capture binding diễn ra **trước Registry dispatch**: [agent.py:6356–6444](../src/agent/agent.py).
5. Registry không có universal JSON Schema validator. Nó gọi validate_args khi tool cung cấp interface đó, rồi prepare/permission/dispatch. Action-aware permission gate và frozen args vẫn tồn tại: [registry.py:184–328](../src/tools/common/registry.py). Workflow tự kiểm tra action/fields trong _run: [workflow_tool.py:420–471](../src/tools/workflow/workflow_tool.py).
6. Workflow thực thi admission, nguồn evidence, ownership, epoch và persistence. Error/result trở thành ToolOutput/ToolResultEvent; raw selected-capture ValueError hiện rơi vào tool_exception, trong khi unsupported action field là invalid_args: [agent.py:491–514,6523–6539](../src/agent/agent.py), [workflow_tool.py:560–581](../src/tools/workflow/workflow_tool.py). Khác biệt taxonomy này quan trọng cho thiết kế recovery, không nên chữa bằng cách đổi mọi ValueError thành invalid_args.

## 3. Root causes — confirmed / likely / unknown

### RC-C1 — Confirmed: flat action contract cho phép structural superset

[workflow_tool.py:92–140](../src/tools/workflow/workflow_tool.py) có ACTION_REQUIRED và ACTION_INPUTS chính xác. Nhưng schema chỉ required=[action], còn mutation_state/effect_basis là properties cấp tool tại dòng 303–305. Hai field **không được định nghĩa riêng cho record_result**, cũng không có nhánh schema của record_result; chúng hiện diện vì cùng tool phải phục vụ record_attempt_state. Tất cả 18 action dùng chung properties.

Mô tả action tại dòng 348–353 đã liệt kê field hợp lệ, có dấu * cho required. Do đó không đúng nếu nói “LLM không được đưa bất kỳ contract theo action nào” hoặc đề xuất thêm lại allowlist vốn đã có. Điều thiếu là ràng buộc cấu trúc và hướng dẫn gần field, đặc biệt các tên dễ lẫn. _run từ chối field thừa tại dòng 433–441 trước dispatch action.

Đây là **mismatch biểu đạt đã chứng minh**, không phải JSON Schema nói chung không thể diễn đạt. oneOf/conditional có thể biểu đạt điều kiện tĩnh; tính portable của provider path hiện tại chưa được chứng minh cho những cấu trúc đó. Nó cũng không chứng minh model sẽ tuân thủ tuyệt đối một schema mới.

### RC-C2 — Confirmed: source_ref có contract theo context, mô tả chưa đủ

Ba định danh cùng xuất hiện cho một imported request, nhưng có vai trò khác:

| Định danh | Nhà phát hành/vai trò | Không được suy ra |
|---|---|---|
| burp:… / retrieval ID | CaptureStore; browser_capture_get.id; **selected record_candidate.source_ref** | Quyền HTTP, quyền replay hoặc positive validation |
| baseline:… | Resolver của captured request, gắn snapshot/binding; replay baseline | Có thể thay bằng obs_ hoặc tự tạo từ URL |
| obs_… | ObservationStore; imported-capture có metadata capture_id và analysis_session; nguồn observation/evidence trong đúng ownership | Retrieval ID của selection hoặc quyền biến imported capture thành native probe |

[browser_capture.py:237–259](../src/tools/common/browser_capture.py) thêm runtime_observation_id khi đọc qua trusted scoped bridge. [observations.py:272–304](../src/permission/runtime/observations.py) sinh imported observation, giữ source_details.capture_id, bridge_source, import_id và analysis_session. Đây là hai record cho hai nhiệm vụ, không phải duplicate ID cần hợp nhất.

Schema source_ref tại [workflow_tool.py:371–375](../src/tools/workflow/workflow_tool.py) nói “Observation provenance… An obs_ ID is not replay authority”; baseline description còn nói dùng source_ref cho matching HTTP observation. Điều này **đúng với đường observation provenance**, nơi _validate_input_http_source xác minh method/origin/path/session/epoch (dòng 1005–1069). Nhưng khi đang có selected capture, [agent.py:2643–2650](../src/agent/agent.py) yêu cầu source_ref bằng selected.retrieval_id. Schema chưa giải thích ngoại lệ/ngữ cảnh này.

Selection guidance yêu cầu “carry its exact source_ref” nhưng selection metadata xuất key **id**, không có key source_ref ([selection.py:34–35,73–75](../src/browser/selection.py)). browser_capture_get lại trả thêm runtime_observation_id. Đây là điểm nhập nhằng interface có căn cứ; không thể suy luận chắc chắn model đã nhìn riêng câu nào khi quyết định.

**Canonical auto-binding đã có:** nếu đúng origin, method/path, source/baseline assertion không mâu thuẫn và chỉ có **một** selected request khớp, _selected_capture_workflow_args điền baseline và source (dòng 2636–2663). Nó không auto-accept obs_ sai; explicit mismatch vẫn bị từ chối. Có thể hướng dẫn model bỏ các optional refs ngay từ đầu **chỉ khi selection duy nhất không mơ hồ**, hoặc copy đúng retrieval ID. Không được tổng quát hóa thành “bỏ provenance khi bị từ chối”; Whole-target input binding phải giữ input_id/source_ref của input đã kiểm chứng.

Không cần resolver obs_→burp: cho execution. Nếu dùng quan hệ hai ID để hỗ trợ correlation UI, chỉ được dùng trusted metadata hiện tại và selection còn nguyên signature/baseline; không dùng nó để chấp nhận call sai. Selection.validate kiểm tra target/scope/permission revision, policy stamp, request signature và baseline tại [selection.py:119–134](../src/browser/selection.py).

### RC-C3 — Confirmed: một mô tả trái allowlist; không có chỉ dẫn SQLi gọi sai B

attempt_id description nói **“record_result only”** ([workflow_tool.py:366](../src/tools/workflow/workflow_tool.py)), nhưng ACTION_INPUTS.record_attempt_state chứa attempt_id (dòng 130) và _record_attempt_state kiểm tra equality với active attempt (1506–1513). Cần sửa mô tả từ nguồn action metadata; không bỏ assertion runtime.

SQLi hiện hướng dẫn rõ mutation_state/effect_basis thuộc record_attempt_state và chỉ mutation_performed/cleanup được truyền ở record_result: [sql-injection/SKILL.md:112–123](../skills/sql-injection/SKILL.md). **Không tìm thấy ví dụ SQLi/system prompt trực tiếp yêu cầu call B sai.** XSS có câu rộng hơn “Explicit mutation/cleanup fields remain accepted on record_result” sau đoạn record_attempt_state ([cross-site-scripting/SKILL.md:82–92](../skills/cross-site-scripting/SKILL.md)); đây là wording dễ hiểu quá rộng, chưa phải ví dụ explicit mutation_state trên record_result. Không quy B của SQLi cho XSS text.

### RC-R1 — Confirmed: strict canonical identity không tồn tại ở failure A

runtime_facts gọi chính selected binding rồi candidate_proposal để tạo operation_owner. Khi binding ném lỗi, proposal=None; fallback dùng metadata từ raw args. Retry A hợp lệ lại có canonical owner. Offline replay phần tính key trả owner availability **False → True**. Xóa source/baseline không chỉ thay recovery hash: nó đổi **hệ tạo operation key**. Vì _recover_issues còn cần operation bằng nhau, chỉ bỏ source_ref khỏi raw hash không giải quyết gốc.

B có existing Candidate, đúng Attempt và result_position. runtime_facts dùng owner hiện hữu cho cả hai calls; hai key bằng nhau dù mutation_state/effect_basis bị bỏ. [outcomes.py:315–360](../src/ui/core/outcomes.py).

### RC-R2 — Confirmed: identity thay thế không giữ resource intent/quan hệ retry

HTTP network recovery bỏ recovery hash; owner của mọi Workflow action có existing Candidate lại chủ yếu là Candidate/Attempt/position/force. Không lưu “call này sửa failure nào”, không kiểm tra success được dispatch sau failure, và record_evidence không đưa proof resource vào owner. Các trường hợp chạy được mô tả ở §5/§9. Đây là nguyên nhân blocker mới.

### RC-R3 — Confirmed: loại lỗi bị gộp quá rộng

PresentedIssue chỉ lưu category, mất error_kind có cấu trúc. _recover_issues chấp nhận failure, denial, export, network, pending. policy_block/scope_denied/timeout/tool_exception thường thành failure; denial và pending có thể tự đổi thành recovered khi key khớp. Không có predicate riêng cho permission reauthorization, unknown execution effects hoặc persistence transaction. Cancellation được giữ category riêng và không auto-recover; đừng sửa mất tính chất đó.

### RC-R4 — Confirmed: banner tách workflow/history chưa đồng đều

Bản sửa lan-08 đã tách lịch sử unmatched error khỏi authoritative work **cho workflow_completed có completion_supported**. Nhánh final_response vẫn dùng residual bao gồm unresolved operation, rồi ghi “work remains” ngay cả khi không có workflow residual. Điều này giải thích banner Direct A mà không phủ định bản sửa Whole-target sẵn có. [state.py:743–821](../src/ui/core/state.py).

**Likely:** overload source_ref và thiếu field-local action descriptions làm tăng xác suất A/B; nhiều optional fields trong Whole-target làm tăng cơ hội chọn sai tổ hợp. **Unknown:** xác suất sau patch, exact historical outbound schema, đã có false recovery nghiêm trọng trong run nào, quan hệ nhân quả với chất lượng SQLi oracle. Không dùng giả thuyết cuối để quy lan-08 thiếu oracle cho schema.

## 4. Cross-tool contract mismatch matrix

Ký hiệu: **S** = schema/description mismatch tĩnh; **C** = điều kiện context/ownership hợp lệ, không thể quyết định chỉ từ schema tĩnh; **M** = quyết định/ID của model, không chứng minh mismatch. “Hợp lệ” dưới đây chỉ về shape; khi ghi rõ điều kiện thì vẫn cần target/owner/prerequisites thật. D/W = Direct và Whole-target. Không bỏ các runtime guards để làm schema-valid thành runtime-valid.

| Tool/action, field | Schema LLM nhận → runtime kiểm tra; ví dụ sai → đúng | Source cụ thể | Ảnh hưởng |
|---|---|---|---|
| workflow, toàn bộ actions | **S:** chỉ action required, mọi fields chung optional, không additionalProperties:false. {action:record_result, mutation_state:unknown,…} pass schema nhưng bị allowlist reject; bỏ field không thuộc action, giữ đủ fields bắt buộc | workflow_tool.py:92–140,197–343,433–452 | D/W, tất cả phase; retry/chi phí, không acceptance bypass |
| record_candidate.source_ref khi selected | **S+C:** string “observation provenance” so với exact retrieval ID. obs_… sai; burp:… đúng selection, hoặc omit refs nếu match duy nhất | workflow_tool.py:371–375; agent.py:2617–2663 | Burp-specific ở A, D/W nếu có selection; provenance guard đúng |
| record_candidate(input_id, geometry) | **C:** string refs không chứng minh ownership. Input ở /products + endpoint /product bị reject; dùng get_input và inherit đúng geometry/source | workflow_tool.py:624–693,710–748,1005–1069 | W chủ yếu; lan-06 có lỗi; không được bỏ input_id để “sửa” |
| record_input.baseline_request_ref | **C, description đã rõ:** obs_ không phải resolver baseline. Bỏ baseline khi thực sự không có capture; có thể giữ obs_ đúng request trong source_ref | workflow_tool.py:371–372,971–1003 | D có action projection hạn chế, W dùng trực tiếp; lan-08 gặp; không chứng minh bug runtime |
| start_validation.force/attempt_id/endpoint | **S:** fields tồn tại cấp tool nhưng action không cho. {action:start_validation,candidate_id:C,force:true} → bỏ force; primary-only có context đầy đủ chỉ cần candidate_id | workflow_tool.py:129,360–365,390,433–441 | D/W SQLi/XSS; không tự gán attempt hoặc reset budget |
| start_validation.related_requests | **C + cross-item constraint:** schema có maxItems=16 và enum; không bảo đảm unique normalized method+resolved/redacted URL. Cùng GET /search làm baseline và control → reject; primary-only omit redundant association nếu không mất nghĩa vụ supplementary | workflow_tool.py:211–217,378–388; assessment.py:49–91 | D/W; lỗi contract association, không bằng chứng mất response; giữ role/readback/cleanup obligations |
| start_validation admission | **C:** candidate_id đúng vẫn fail nếu chưa load validator/current prerequisites, wrong scope, exhausted attempt. Đúng: hoàn thành prerequisite hoặc resume chính owned active attempt | workflow_tool.py:1112–1166,1226–1278 | W thêm Recon→Enumeration→Analysis; D không bị áp gate W; không coi là schema bug |
| record_attempt_state.attempt_id | **S description:** nói record_result only nhưng allowlist/runtime chấp nhận ID active làm equality assertion | workflow_tool.py:130,366,1506–1513 | D/W; có thể gây omit/dư field không cần thiết; không mở quyền assign attempt |
| record_attempt_state.effect_basis | **S bounds:** schema string không min/max; runtime nonblank và ≤2000. Chuỗi 2001 ký tự → reject; cơ sở ngắn có thật + đúng sources → admissible | workflow_tool.py:303–305,1516–1542 | D/W SQLi/XSS; overhead. State/effect consistency, independent readback là **C**, không thể thay bằng regex |
| record_evidence.observation_ids | **S bounds:** array strings không maxItems/uniqueItems; references yêu cầu ≤32, distinct, nonblank, không surrounding whitespace. [obs_A,obs_A] → reject; exact unique owned IDs → admissible | workflow_tool.py:275,1472–1479; assessment.py:18,34–39 | D/W; giữ source ownership và immutable parent map; chỉnh schema được, không đoán IDs |
| record_evidence.evidence_path | **C:** string path không chứng minh file tồn tại/project containment/permission/integrity. Viết proof trước, đăng ký path trong project ngoài findings; file không tồn tại/sai candidate bị reject | workflow_tool.py:368,1416–1499 | D/W; lỗi missing prerequisite có hint tốt; không tạo file thay model trong handler |
| record_result.evidence_refs/assessment | **S:** evidence_refs thiếu maxItems=16/uniqueItems, observation_ids thiếu maxItems=32/uniqueItems; assessment là object rất rộng. **C:** ev_ phải thuộc Candidate; obs_ phải thuộc Attempt, evidence usable, assessment sealed; {} không tự đủ cho terminal result | workflow_tool.py:218,296–301,1604–1605,1643–1705; assessment.py:34–39 | D/W; retry hoặc honest unresolved, không nới terminal acceptance |
| confirm_finding | **S nhỏ:** title/url/impact strings cho chuỗi rỗng, runtime bắt nonempty. **C:** Candidate ID phải có latest accepted confirmed evidence; URL/method/parameter/class khớp; impact/severity v2 lấy từ accepted assessment | finding.py:129–206,239–254,278–365 | D/W; preserved correctness, không call Finding trước accepted result |
| http raw/replay modes | **S:** chỉ phase required; {phase:recon} pass schema nhưng thiếu url/candidate_id. Replay có candidate_id+url/body/headers pass schema nhưng runtime reject. Đúng: raw phase+url hoặc phase+candidate_id với replay mutation fields | http_tool.py:88–118,141–158,273–294 | D/W toàn bộ lifecycle; guards trước send, không silent retarget |
| http evidence_mode/browser profile | **S static dependencies:** cap=0 + default body pass schema nhưng reject; dùng positive cap cho content evidence hoặc explicit metadata-only. browser-like cần context+captured user-agent; **C:** cùng-origin snapshot tồn tại | http_tool.py:105–115,164–169,197–213 | D/W; không tăng cap vô hạn, không fabricate UA/auth |
| browser_capture_get | **C:** id và optional baseline so với current scoped capture, ID reuse/signature. Sai id → đúng retrieval ID xuất bởi list/selection; obs_ không phải argument thay thế | browser_capture.py:202–259; selection.py:119–134 | Capture-specific; không thấy action-union defect ở tool này |
| read_http_observation | **S:** observation_id chỉ string, runtime đòi obs_ +32 hex. tr_… pass schema nhưng reject; đúng obs_… mới qua shape. **C:** validation owner/attempt/epoch còn hợp lệ, discovery không được tạo attempt chỉ để đọc | tool_result.py:145–150,168–203 | D/W; lan-06 là ownership, không phải sai regex; IDs không cấp read rights |
| read_discovery_source / read_tool_result | ds_+64hex và tr_+32hex đã có pattern. Chuyển prefix obs_→ds_ hoặc truyền obs_ cho tr_ là **M/C**, không tự động là schema mismatch. read_tool_result ranges có clamp downstream nên thiếu minimum không đủ để kết luận runtime reject | tool_result.py:35–63,300–305; session/tool_results.py:372–375 | W discovery và D/W retrieval; không chạy lại HTTP để sửa reader |
| read_payloads / read_skill_file | **S conditional required:** action=read thiếu file/path pass schema; runtime reject. start_char>0 không source_ref cũng pass, nhưng lỗi continuation. Đúng: first page với file/path rồi copy sf_ + next offset đúng reader | payloads.py:39–79,128–157; skill_file.py:41–81,135; paths.py:128–147 | D/W SQLi/XSS; paging identity khác tr_/obs_. line limit được clamp là compatibility, không coi là rejection mismatch |
| coverage mark/list/untested/summary/clear | **S:** mark thiếu endpoint/param/vuln_class pass schema. **C:** production policy cấm model mark established coverage, cả shape đúng vẫn reject; phải sync qua accepted Workflow result. clear có action permission riêng | coverage.py:55–155,172–218 | D/W; projection không phải evidence. Không “sửa” bằng cho phép model mark |
| content_discovery | **S bounds:** paths items chỉ string; empty, >200 chars, traversal/delimiters sai bị reject. {paths:[api/items]} hợp shape/path; {paths:[../x]} không. Extensions có syntax runtime; **C:** base cùng active origin | content.py:108–119,408–453; discovery/common.py:81–110 | W Recon/Enumeration và D khi allowed; không broadening origin |
| service_discovery | Array/port/time bounds đã có schema; chỉ active target effective port là **C**, đã mô tả. ports=[port ngoài target] không phải lỗi enum thiếu tĩnh | service.py:58–89,370–409; discovery/common.py:187–201 | Không coi private address bất kỳ là authorized; không chạy TCP trong audit |
| ask_user, file/shell/web/search | **S nhỏ:** nhiều string required vẫn cho empty; ví dụ questions:[{question:""}], file_read path="", shell command="", web_fetch url="" → runtime reject. Không có action-specific union ở nhóm này; permissions/sensitive paths/skill allowlists là **C** | ask.py:67–118,144–169; file.py:194–223; shell.py:85–110; web.py:216–239 | D/W, overhead; không đổi approval thành intent hoặc durable authorization |

Các nhóm đã kiểm kê thêm: permission status và capture status/list/snapshot/clear/Burp task/issues là các tool riêng; command plugins dùng schema cấu hình nhưng executor đã nghỉ, không được fallback host; MCP schema từ server/capability nên không thể khẳng định parity cho server tùy ý chưa kết nối. load_skill, file_write/edit, glob/grep có required/type hoặc filesystem/loaded-skill constraints, không phát hiện thêm nguyên nhân giống B cần mở một nhánh sửa trước lan-09. Các trường unknown được ignore ở một số tool không được đồng nhất với action allowlist rejection của Workflow.

Lưu ý kiểu số: JSON Schema integer chấp nhận số nguyên về giá trị như 1.0, trong khi một số validators HTTP/readers dùng Python int chính xác; coverage positive_integer cố ý chấp nhận 1.0. Đây là góc compatibility nhỏ, chưa thấy trong lịch sử A/B; không mở rộng bản vá bằng một refactor validation toàn hệ thống.

## 5. Recovery identity and correlation analysis

### 5.1. Matching hiện tại

| Lớp | Key/điều kiện thực tế |
|---|---|
| Invocation delivery | call ID + tool name + Invocation(id,scope); unknown/retired/resolved result bị loại. Invocation xác nhận event thuộc dispatch nào, **không chỉ ra retry của call nào** |
| Runtime scope | SHA-256(origin, target revision, engagement revision, HTTP permission epoch, policy session ID, objective ID, workflow generation): [scope.py:11–20](../src/agent/scope.py) |
| call_metadata identity — HTTP | method; endpoint=(scheme,hostname,port,path); **tên** query params; parameter; candidate_id/attempt_id do args cung cấp; auth headers/query/userinfo/auth_context_ref. **Không body, giá trị query thường, non-auth headers, phase hoặc implicit active Candidate/Attempt** |
| call_metadata — workflow/confirm_finding | action,candidate_id,result_id,attempt_id,skill_name,phase,target,endpoint,method,parameter,input_id,goal_id,artifact_ref,force |
| recovery_identity mặc định | SHA-256 toàn bộ args; riêng Workflow record_result dùng identity ở trên |
| Canonical override — record_candidate | hash(scope, action, candidate_binding(proposal), input_id). Không có nếu proposal fail. candidate_binding bỏ status/priority/signals/source_skill/deferred_reason, giữ context/provenance/hypothesis |
| Canonical override — Workflow existing Candidate | hash(scope,action,candidate_binding,active attempt,result position,force). record_result có thêm lựa chọn owner theo explicit valid attempt/latest. Các action khác không đưa evidence_path, sources, effect_basis hoặc explicit attempt assertion vào key |
| Issue | hash(operation,category,error text/root), count và recovery_identity; operation=tool name + identity. Không giữ structured error kind/failed call ID/retry relation trong PresentedIssue |
| Recover | operation bằng nhau; category thuộc failure/denial/export/network/pending; recovery hash bằng nhau **hoặc category=network**. Một success có thể recover nhiều issue cùng key |

Nguồn: [admission.py:20–103,121–146](../src/ui/core/admission.py), [outcomes.py:315–394](../src/ui/core/outcomes.py), [state.py:410–443,563–633](../src/ui/core/state.py), [assessment.py:26–31](../src/workflow/assessment.py).

Success chỉ được xét khi status success/observation, không err và không non-diagnostic/non-incomplete issue. Workflow còn đòi receipt.ok=true; record_candidate/start_validation/record_result đòi facts.accepted_call, có đối chiếu runtime state. **record_evidence/record_attempt_state/sync_coverage không có accepted_call predicate tương tự.** confirm_finding có runtime-state check cho milestone nhưng generic recovery path không dùng milestone ấy làm điều kiện. Không suy từ một HTTP 200/401/500 ra validated finding; đó vẫn là observation.

### 5.2. False unresolved và false recovery

- A: provenance failure làm canonical owner không tồn tại, retry có owner; còn unresolved dù Candidate đã tạo đúng. record_input, file_edit, reader offset hoặc argument repairs khác cũng có thể đổi full-args hash. Không nên ghép chúng bằng tool name.
- B: fields sai không thuộc business owner; cùng Candidate/Attempt/position, accepted result receipt giúp ghép đúng. Phải giữ ca này.
- HTTP network: cùng POST /form, body mode=A thất bại; mode=B thành observation → **recovered=true dù recovery hashes khác**. Các giá trị query thường khác cũng bị bỏ khỏi operation identity. Raw HTTP không truyền candidate_id có thể đi qua những implicit Candidates/Attempts khác nhau cùng endpoint trong cùng objective mà key không biết.
- Workflow evidence: cùng Candidate/Attempt, proof-A+parents-A thất bại; proof-B+parents-B thành công → cùng owner, **recovered=true**. Simulation permission_denied và tool exception/persistence failure đều tái hiện; không chứng nhận rằng proof B thực sự giải quyết nghĩa vụ của proof A.
- Quan hệ thời gian: dispatch A; dispatch B; A fail; B success vẫn recover A. B được đề xuất trước failure nên không thể được coi là corrected retry chỉ từ thứ tự result arrival. System prompt khuyên mutation tuần tự không thay thế bảo đảm correlation.
- Same exact args: timeout, permission_denied, policy_block, scope_denied và permission_timeout đều được recover bởi success cùng key trong simulation. Có trường hợp một retry hợp lệ thực sự xử lý được lỗi, nhưng UI không giữ đủ điều kiện để phân biệt. Cấm suy “success sau đó” thành approval mới hay certainty về dispatch trước.
- Cancellation: category cancelled không nằm trong recover set; đã kiểm tra vẫn unrecovered. Tuy nhiên nó cũng không nằm trong unresolved operation count cuối; terminal cancellation label/history là kênh riêng. Không được diễn giải số unresolved=0 là chưa từng cancel.
- Runtime/session checkpoint ErrorEvent có operation=runtime và không có matching tool success thông thường; không có bằng chứng mọi persistence error đều bị che. Rủi ro đã tái hiện ở **tool-level** publication/registration errors bị group theo resource không đủ chi tiết.

Negative guards còn đúng: khác endpoint không recover; target/objective/epoch/generation đổi làm old invocation stale/retired; sibling Candidate có binding khác được tách ở canonical Workflow path. Các tests hiện có cũng bao phủ nhiều guard này, nhưng chưa bao phủ changed-resource success cùng owner và pre-failure sibling success.

### 5.3. Lịch sử, banner và vòng đời

_recover_issues giữ issue.text/count trong bộ nhớ, nhưng thay transcript row bằng nhãn và “Recovered after N failed attempts”; chi tiết lỗi gốc không còn trong row mới. Với false recovery, banner unresolved giảm và người dùng khó thấy lỗi cũ. Không được xóa issue để chữa triệu chứng.

_finish_outcome phân biệt facts.pending/incomplete/goals/blockers, unresolved operation, pending permission và export. Historical recovered errors không làm workflow còn việc. Whole-target workflow_completed + đủ completion facts có nhãn riêng “operation error without a matched retry”; final_response còn nhầm residual UI với work remains (§3).

call_history và issues đều bounded 256. Evicted call results fail closed; đó là bảo vệ tốt. Eviction issues ở state.py:425 có thể làm count không còn là tổng lịch sử của một turn rất dài; chưa thấy bằng chứng run A/B/lan-08 chạm mức này. Không thêm ledger vô hạn; cần giữ semantics “latest local UI snapshot”, và nếu sau này dùng số đếm làm audit authority thì cần overflow indication/retained aggregate riêng.

Compaction event không xóa issue/call ledger trong cùng AppState ([state.py:695–702](../src/ui/core/state.py)); simulation đã xác nhận. Turn mới/clear/scope change reset issue view và retire calls (295–310,336–401). Session lưu messages/workflow/engagement, **không lưu PresentedIssue/TurnDetails/Invocation retry ledger** ([state.py:83–84](../src/ui/core/state.py), [store.py:594–601](../src/session/store.py)). resume_saved bỏ selection, reset permission context và restore Workflow ([agent.py:2385–2431](../src/agent/agent.py)). Không được phục dựng một recovery assertion từ text đã compact/resume hoặc gọi history là live authorization.

## 6. Whole-target / lan-09 impact assessment

| Phạm vi | Khả năng phát sinh | Kết luận |
|---|---|---|
| Recon/Enumeration | phase coverage fields; HTTP raw/profile/cap; discovery vs validation readers; paths/ports/resource bounds | Shared contract; lan-06/08 có bằng chứng. Runtime reject bảo vệ đúng; retry làm tốn budget |
| Input Analysis | record_input source/baseline; record_candidate input_id/geometry; schema required/optional | Shared provenance + schema. Không drop input/source để đạt green receipt |
| SQLi/XSS validation | start attempt, related requests, effect bookkeeping, evidence/result | Cùng Workflow contract; không áp SQLi oracle lên XSS. XSS readback/browser requirements và cleanup riêng phải giữ |
| Nhiều Candidates/endpoint | existing Candidate owner tách sibling bindings; raw HTTP cùng endpoint không tự chứa implicit owner; evidence B cùng candidate có thể clear lỗi A | False-recovery risk tăng khi nhiều công việc liên tiếp; không cần Burp để gặp |
| Finding | ID/accepted result/evidence/severity giữ gate; publication/export có error riêng | Không thấy accepted Finding sai do A/B. Phải xác nhận đúng persisted fingerprint khi recover lỗi Finding/export |
| Permission/admission/limits | denial, policy/scope, queue/resource pending, timeout, evidence recovery budget | Không tất cả là invalid_args. Không tự retry/reset allowance để hết warning; unknown effects vẫn unknown |
| Compaction/resume | handles/context và local UI lifetime khác durable Workflow | Trong turn giữ identity; resume không mang quyền hay retry relation. Mất UI history không chứng minh workflow đã hết blockers |

Phân nhóm cần giữ khi phân tích số liệu lan-09:

1. **Burp-specific:** retrieval ID vs imported obs_ dưới selected context, selection signature và canonical baseline. A không tự áp vào mọi raw HTTP candidate.
2. **Workflow shared-contract:** flat action fields, missing action requirements, attempt/evidence namespaces và resource ownership. B áp dụng SQLi/XSS và các validator khác dùng Workflow.
3. **UI shared-recovery:** coarse HTTP network key, overly broad existing-Candidate owner, thiếu retry edge/category predicates và Direct banner. Áp dụng cả run không Burp.

Lịch sử chỉ chứng minh lỗi đúng lớp: lan-06 messages 53→54 sai coverage_phase; 75→76/77 reader ownership; 82→84/86 source path. lan-07 97→98 phase incomplete và 107→108 active-skill denial. lan-08 37→38 sai ds_, 62→63 obs_ baseline, 134→135 unavailable evidence refs. Không lấy các error này làm bằng chứng tất cả đều do schema. Đặc biệt **lan-08 thiếu SQLi oracle không có quan hệ nhân quả đã chứng minh với tool schema/recovery**; giữ nguyên kết luận nghiệm thu cũ và không sửa kết quả lịch sử.

Schema patch thay những gì model nhìn thấy nên **có thể thay tool/argument selection, số bước và chi phí**. Cần đóng băng một baseline mới có version/diff/schema hash trước lan-09, không mô tả đó là lặp lại cùng input model tuyệt đối. Recovery patch được thiết kế chỉ presentation: không đổi Workflow engine, result seal, evidence, coverage, permissions hoặc messages đưa model; nếu triển khai làm đổi những thành phần đó thì đã vượt thiết kế tối thiểu này.

## 7. Minimal fix alternatives and recommended design

### 7.1. So sánh A/B/C

| Phương án | Lợi ích | Chi phí/rủi ro/giới hạn | Quyết định |
|---|---|---|---|
| **A. Contract-first minimal patch** | Giữ tên tool; tận dụng ACTION_INPUTS/ACTION_REQUIRED; thêm action membership ngay ở field dễ nhầm; sửa description sai; ID vocabulary/context rõ; expose bounds đã có | Không biến flat schema thành structural union; model vẫn có thể gọi sai. Descriptions dài có token cost và thay model behavior | **Chọn**; đủ sửa nguyên nhân interface đã biết mà không đổi acceptance |
| **B. Action-discriminated schema** | Có thể chặn static combination/required fields ngay ở schema nếu provider thực sự enforce | Cần capability per adapter, normalization và error fallback; root oneOf/if/then/strict không được local tests hiện có chứng minh API support; nested refs bị Gemini normalization loại definitions/additionalProperties. Fixtures hiện chủ ý assert flat, không có strict | **DEFER** trước lan-09; không mặc định oneOf được hỗ trợ |
| **C. Split action tools** | Mỗi function có required/fields riêng; giảm nhập nhằng action | 18 tool identities, thay Registry/allowed-tools/permission routing, UI instrumentation, action guidance, token budget, fixtures, history aliases/replay; dễ mất compatibility; provenance context vẫn cần runtime | **DEFER**; A và recovery patch nhỏ hơn xử lý được các gốc đã biết |

Tương thích đã xác minh: normalize_tool_spec chỉ validate ToolSpec envelope, không rewrite union; OpenAI-compatible/Anthropic chuyển parameters/input_schema qua encoder; Gemini normalize_schema đổi string type sang uppercase và bỏ additionalProperties/$defs/definitions. Tests offline hiện assert một workflow flat tool cho cả non-stream/stream. **Đã chạy encoder tests, chưa thử server API oneOf/strict; không có cơ sở gọi B là tương thích thực tế trên mọi provider.** Không cần gọi provider để ra quyết định hoãn B.

A phải là sửa tại interface, không chỉ thêm prompt:

- Sinh field-local “used by / required for” từ ACTION_INPUTS/ACTION_REQUIRED; tránh duplicate table thủ công. Sửa attempt_id; gắn mutation_state/effect_basis rõ record_attempt_state-only. Giữ action-specific optionality; không required tất cả fields ở root.
- source_ref mô tả cả ordinary request observation provenance và selected-capture retrieval context; phân biệt obs_/retrieval/baseline/ev_/tr_/ds_/sf_. Selection metadata/guidance chỉ rõ id tương ứng source_ref cho Candidate. Không thêm alias execution hay tự đổi prefix.
- Thêm bounds/patterns chắc chắn phản ánh validators, ưu tiên observation_ids distinct/≤32, evidence_refs distinct/≤16, effect_basis nonblank/≤2000 và obs_ reader pattern. Không thêm regex global source_ref vì namespace phụ thuộc context; không global additionalProperties:false trước khi xem legacy record_input ownership fields đang supported nhưng không advertised.
- Error cho selected binding nên phân biệt wrong reference type, geometry mismatch, multiple matches và unavailable baseline, kèm cách copy canonical refs **không chứa traffic/secret**. Giữ reject. Không hướng dẫn chung “omit source_ref to bypass”; chỉ có single-selection unique case được omit, và cả guard cũ vẫn chạy.

### 7.2. Recovery patch riêng: logical identity + owner + retry edge

**Mục tiêu là chứng minh một failure cụ thể đã được sửa, không phải làm số unresolved bằng 0.** Tối thiểu giữ Invocation hiện có và bổ sung metadata trình bày bounded, không thêm arguments cho model, không viết durable authorization/history mới.

1. **Giữ hai khái niệm riêng.** Owner=(runtime scope, tool/action, Candidate binding, Attempt/result revision). Operation intent thêm resource identity thích hợp: input/discovery ID, exact proof source resource, result submission revision, hoặc effective HTTP request digest/owner nếu runtime đã cung cấp. Không lấy owner làm toàn bộ retry key cho mọi action. Không hash plaintext credential vào output/log; dùng opaque internal digest/token.
2. **Chỉ ghép retry sau một failure đủ điều kiện.** PendingCall/PresentedIssue giữ failed invocation ID, call/failure order và typed error kind/code; retry_of là liên kết nội bộ do controller/UI suy ra từ đúng một unmatched eligible failure. Retry phải được dispatch **sau** failure; cùng scope/owner/resource; không sibling đang chạy, không ambiguous multiple failures. Invocation ID không tự là retry ID. Không nhận retry_of từ LLM.
3. **Mặc định không tự resolve lỗi authority/effects/persistence.** permission_denied/pending/timeout/stale, policy_block, scope_denied, cancelled và unknown execution effects giữ nguyên lịch sử; một success khác chỉ ghi progress mới. Muốn resolve phải có riêng receipt xác nhận fresh approval/cùng action hoặc transaction reconciliation của cùng operation, không có thì unresolved. Loại bỏ ngoại lệ “network ignores recovery hash”. Network/timeout có thể xảy ra sau dispatch; không tự gửi lại HTTP vì UI đang unresolved.
4. **Corrected argument retry:** cho phép fields không quyết định identity thay đổi chỉ theo contract/action, ví dụ bỏ unsupported mutation_state/effect_basis khỏi record_result cùng owned attempt. Giữ accepted_call kiểm chứng real result; proof A→B, Candidate A→B, Attempt A→B hoặc auth/target đổi không đủ điều kiện. Ban đầu chỉ mở những action đã có acceptance predicate rõ; phần chưa có giữ unresolved thay vì broad recovery.
5. **A và canonical binding:** khi failed call không dựng proposal, không dùng geometry-only fallback chung. Với trusted selection còn nguyên, exact baseline hợp lệ và imported observation có source_details.capture_id đúng selected request, có thể tạo một **presentation-only intent token** từ canonical selection + request/input/hypothesis + current scope. Chỉ typed wrong-reference failure trước mutation được dùng token này. Retry vẫn phải qua _selected_capture_workflow_args nguyên trạng, rồi real Candidate receipt matching. Nếu thiếu current provenance, nhiều captures khớp, khác baseline/auth/input/test_case hoặc ref không chứng minh được association: giữ unresolved. Điều này dùng producer/selection interface, không hardcode chuỗi burp: hay sql-injection trong recovery matcher.
6. **Bảo toàn lịch sử.** Mark recovered_by=<invocation> trên issue, giữ original sanitized text/category/count và mở được chi tiết. Không reset error counter, không xóa issue theo tool name. Late/duplicate/retired events vẫn fail closed; 256-entry bound không được thành ledger vô hạn.
7. **Banner là projection độc lập.** Workflow residual chỉ từ facts; unmatched UI issue là một mục riêng cho cả Direct và Whole-target. Không đổi final_response thành “workflow completed” khi không có evidence completion; có thể ghi “Turn ended; workflow state has no pending work; N unmatched operation issues” khi facts đủ, vẫn hiện lỗi. Workflow incomplete không được sạch banner chỉ vì không có tool error.

Giới hạn tối thiểu: không cần sửa session schema hoặc carry retry edges qua resume trước lan-09. Recovery scope là current live turn; sau resume, reconstruct workflow obligations từ authoritative state, đánh dấu lịch sử là historical/unmatched thay vì đoán edge. Trong cùng turn, compaction không được xóa edge. Đây là bảo toàn persistence contract hiện có, không hứa durable UI audit ledger.

### 7.3. Bất biến, risk và rollback

**Trước → sau:** flat schema không nói đủ context → descriptions/bounds đồng bộ validators; runtime accepted set giữ nguyên. Broad owner/success matching → explicit eligible retry cùng owner/resource, temporal edge và verified receipt. Unknown/ambiguous giữ unresolved. B sửa arguments vẫn recover; A chỉ recover khi có trusted association, không tự hợp thức hóa ref sai.

**Tuyệt đối không nới:** Registry gate, exact origin/effective port và private-host cache, selection signature/baseline, observation ownership/session/epoch, input binding, Attempt budgets, evidence integrity/immutable parents, cleanup authorization, confirmed Finding prerequisites, secret handling và artifact paths. Không tự tạo source, đổi selection, reset/reopen attempt hoặc dùng recalled authorization.

Risk bản vá: quá chặt gây false unresolved; description dài tăng tokens; thay schema làm model đổi hành vi; canonical intent resolver dễ lặp logic hoặc vô tình nhận ambiguous owner; events cũ thiếu metadata. Default phải fail closed về **presentation correlation**, không fail open runtime. Dùng shared pure resolver/metadata thay copy validation vào TUI; event thiếu field vẫn hiển thị lỗi và không đoán recovered.

Rollback: tách contract và presentation change thành các diff nhỏ của lượt implementation sau; không migration state/artifacts, không rewrite historical logs. Nếu regression fail, bỏ phần correlation mới, giữ unmatched error hiện rõ; không rollback bằng khôi phục hành vi che lỗi rồi chạy lan-09. Bản báo cáo này không thực hiện checkout/reset/commit.

## 8. Proposed files/functions to change

Đây là danh sách **dự kiến**, chưa sửa:

| File/function | Thay đổi có giới hạn |
|---|---|
| src/tools/workflow/workflow_tool.py — schema, ACTION_INPUTS/ACTION_REQUIRED | Sinh field-local action guidance, sửa attempt_id/source_ref/mutation descriptions; bounds từ constants chung. _run allowlists và validators giữ nguyên |
| src/tools/workflow/action_view.py — ActionView.project_tools | Dùng cùng renderer contract; nếu mô tả field dựa available actions thì update projection từ cùng metadata, không đổi admission |
| src/browser/selection.py — CAPTURE_GUIDANCE, SelectedCapture.metadata | Gọi tên retrieval ID và Candidate source_ref rõ, giữ payload shape compatibility; không thêm authorization |
| src/agent/agent.py — _selected_capture_workflow_args, _tool_call_event/_tool_result_event | Chỉ tách typed binding error/safe diagnostic và presentation metadata nếu cần A; resolver execution giữ rejection/unique-match hiện tại. Không blanket-convert ValueError |
| src/agent/events.py — Invocation/ToolCallEvent/ToolResultEvent | Optional internal correlation metadata khi owner/resource không thể lấy an toàn ở UI; backward-compatible defaults, không thêm model args |
| src/ui/core/admission.py — PendingCall, call_metadata, issue_category | Giữ error kind/resource/call order; không generic geometry-only network recovery; không đánh đồng runtime guard với argument repair |
| src/ui/core/outcomes.py — runtime_facts | Tách owner và operation intent; acceptance predicate theo action/resource; canonical A chỉ có trusted mapping; không mutate Workflow |
| src/ui/core/state.py — PresentedIssue, _present_issue, _recover_issues, _finish_outcome | Bounded retry edge, loại lỗi không được auto-clear, lịch sử đọc được, phân biệt residual cho cả modes |
| src/tools/common/tool_result.py — ReadHTTPObservation.schema | Bổ sung exact obs_ pattern đã có runtime; không đổi retrieval rights |
| tests/tools/test_workflow_argument_contract.py; tests/llm/test_workflow_action_projection.py | Contract parity/action projection/bounds; không khẳng định union API support từ mock encoder |
| tests/ui/test_candidate_recovery_contract.py; test_c4_workflow_recovery.py; test_lan08_audit.py | A/B + negative wrong-owner/resource/parallel/category cases; kiểm tra state bất biến |
| tests/agent/test_capture_selection.py; tests/integration/test_burp_selection.py; tests/security/test_captured_http_replay.py | Unique binding, ID mismatch và live context guards bằng fixtures offline |

Các mục small mismatch ở coverage/ask/files/discovery không cần kéo vào blocker patch nếu chưa có causal evidence/acceptance risk; ghi nhận làm backlog có giới hạn. XSS wording có thể sửa cụ thể mutation_performed trong lượt được phép sửa Skill, sau khi đọc đúng skill/tests; không cần thay SQLi playbook đã rõ. Không thêm sửa provider/config/session persistence vào phạm vi patch.

## 9. Regression matrix and actual offline results

### 9.1. Những gì thực sự đã chạy

Các Python checks chạy bằng venv-linux/bin/python -B (môi trường hiện có Python 3.14), không cài dependency. Dùng audit hook **cấm mọi file write/mkdir/remove/rename/chmod, subprocess, socket connect/bind/DNS** trong tiến trình kiểm tra; tắt bytecode, pytest cache và plugin autoload. Chỉ mutate objects mới trong RAM. Không gọi tool runtime mạng, không provider chat/mock chat; tests provider được chọn chỉ encode request.

| Check thực thi | Kết quả | Giới hạn |
|---|---|---|
| tests/tools/test_workflow_argument_contract.py + encoder-only cases của tests/llm/test_workflow_action_projection.py | **53 passed, 7 deselected, 0.38s** | Bao gồm 18 unsupported-action rejection cases và 32 mode/provider/stream encoder combinations; không phải full integration suite |
| JSON Schema Draft202012 trên 4 historical args A/B | **4/4 schema-valid**; B bad chạy WorkflowTool.run trả error/invalid_args, không mutate action state | Current worktree schema, không archived outbound wire |
| Selected binding source method chạy trong RAM, exact function AST từ agent.py | **7 cases:** wrong obs rejected; omitted refs unique accepted/canonical; exact retrieval accepted; wrong origin rejected; wrong path rejected; multiple omitted rejected; multiple exact accepted | Fake capture-store rows; không replay HTTP, không thay thế full selection.validate/signature integration test |
| Schema counterexamples bổ sung | **6/6 pass schema:** HTTP missing URL, replay conflict, zero body cap, tr_ ở obs reader, duplicate evidence refs, effect_basis 2001 chars | Runtime rejection của từng cái đối chiếu source; không claim đã run đủ downstream actions |
| Historical field diff | A bỏ baseline/source/signals; B bỏ mutation/effect và thêm notes; mọi common B fields identical | Không xuất traffic/secret |
| Identity reconstruction | A canonical owner absent→present; B equal owner khi giữ cùng synthetic current Candidate/Attempt | Tính key thật; không replay toàn bộ live AppState lịch sử |
| Reducer HTTP changed body + network error | **False recovery=true**, operation equal, recovery hash unequal | Events giả lập, không network error thật do audit tạo |
| Reducer evidence proof A→B | permission_denied và tool-level publication failure đều **recovered=true**; zero registered evidence trong fixture vẫn đủ cho generic success branch | Chứng minh receipt-validation/correlation behavior, không claim real persistence/evidence loss |
| Pre-dispatched sibling success | **recovered=true** dù B dispatch trước A fail | Chứng minh thiếu causal retry edge |
| Category probes | cancelled không recovered; timeout/permission_denied/policy_block/scope_denied/permission_timeout có recovered khi success cùng args/key | Không cấp approval hoặc gửi lại action thật |
| Negative endpoint + compaction | Different endpoint **không recovered**; CompactEvent **giữ issues** | Chưa là end-to-end resume test |

Lệnh pytest tương đương, trong audit-hook wrapper:

~~~text
venv-linux/bin/python -B -
pytest.main([
  '-q', '--capture=sys', '--assert=plain', '-p', 'asyncio',
  '-p', 'no:cacheprovider', '-p', 'no:logging',
  'tests/tools/test_workflow_argument_contract.py',
  'tests/llm/test_workflow_action_projection.py',
  '-k', 'not transport_retry and not retry_payload'
])
~~~

Hai lần thử đầu **bị guard chặn trước write**, không phải test failure sản phẩm: pytest FD capture muốn tạo tempfile; import toàn Agent kéo filelock có filesystem capability probe. Sau đó dùng capture=sys/assert=plain/no logging và compile duy nhất method AST nguyên source để chạy pure selected-binding check. Không tắt bảo vệ write để chạy tiếp. Custom checks là inline probes, không tạo test/script file và không được tính lẫn vào 53 tests.

Chưa chạy full pytest, pyright, HTTP/provider integration, end-to-end SQLi/XSS, persistence/cancellation filesystem tests hoặc full resume. Các test cần tmp_path/persisted fixtures được **đề xuất**, không gắn nhãn đã pass. Không sửa test để pass và không làm yếu live-skip semantics.

### 9.2. Regression bắt buộc cho bản vá sau

| # | Case và assertion cần có | Trạng thái audit hiện tại / nơi đặt test |
|---|---|---|
| 1 | Wrong action-specific fields bị reject tại action contract, trước action mutation; error không chứa values/secrets | Existing 18 rejection cases đã pass; thêm B và field-local/schema parity assertions |
| 2 | Correct args accepted; không thay accepted set hoặc mutate unrelated state | Legacy input test pass; historical A/B receipts đối chiếu. Cần thêm accepted schema examples theo action |
| 3 | Selected Burp source_ref=obs_ sai vẫn reject, không tự chuyển namespace cho execution | Pure resolver đã reject; thêm full agent selection fixture |
| 4 | Omitted refs với exact unique selection được canonical bind | Pure resolver pass; thêm receipt + Candidate provenance assertion |
| 5 | Multiple/mismatched/changed captures không auto-bind; wrong origin/path/auth/baseline không recover | Unique/multiple/origin/path đã probe; signature/epoch/auth integration chưa chạy |
| 6 | Invalid args → correction cùng logical operation → recovered đúng một failure; A/B, Direct/W; original error vẫn xem được | A/B key probes có kết quả; existing candidate tests đọc nhưng chưa chạy. B phải giữ; A chỉ trusted mapping |
| 7 | Wrong target/Candidate/Attempt/input/hypothesis/auth/resource không false recovery; implicit active HTTP owner đổi cũng không | Different endpoint probe pass; changed proof/network body hiện fail desired behavior; thêm parameterized matrix |
| 8 | Permission denial/pending/scope/policy không auto-clear bởi generic success; only separately verified resolution nếu có | Current category probes chứng minh thiếu gate; cần negative regressions, không mock quyền mới để hợp thức hóa |
| 9 | Persistence error/cancel/unknown effects không bị proof/file/result khác che; same transaction reconciliation phải explicit | Tool-level presentation repro; cancelled preserved. Filesystem publication/cancellation tests chưa chạy |
| 10 | Workflow complete + genuinely recovered errors không outstanding giả; unmatched history hiện riêng; D/W đều giữ findings count | Existing lan-08 tests đọc; chưa chạy do fixture writes. Thêm final_response case A |
| 11 | Workflow incomplete + no tool errors vẫn work remains: input pending, proof missing, coverage, cleanup, goal | Source đã kiểm tra; chạy test_lan08_audit/test_outcomes trong implementation stage |
| 12 | Whole-target SQLi và XSS Candidate→Attempt→Evidence→Result→Finding: giữ prerequisites, source ownership, XSS readback/browser, cleanup và confirmed gate | Không re-run pentest; dùng offline integration fixtures, cả positive/negative/unresolved |
| 13 | Same-turn compaction giữ retry edges; resume/new turn/epoch không ghép history cũ; persisted Workflow obligations không mất | CompactEvent probe pass; full resume/persistence chưa chạy |
| 14 | A fail/B already dispatched/B success không recover; duplicate/late/fake receipt không resolve | Pre-dispatch repro hiện fail desired behavior; thêm tests cho invocation chronology và accepted receipt |
| 15 | Ambiguous ≥2 matching failures/resources và ledger eviction fail closed; giữ bounded memory và báo limitation nếu cần | Static inspection, chưa stress-test; không yêu cầu refactor durable ledger trước lan-09 |

### 9.3. Kiểm tra không làm thay đổi dữ liệu

Ngay trước khi viết báo cáo, lập fingerprint read-only của 3.338 files thuộc src/skills/tests/docs/integrations, project .kagent/artifacts, runs lan-06/07/08, các file cấu hình dự án đã liệt kê và đúng session kịch bản 1; loại bytecode và báo cáo mới. Aggregate SHA-256: **7f4ac0a9e8af18be3f762df2c7ccf991eecb903de3ccbd48ccb902ad2632bb94**. Fingerprint này là mốc trước/sau **ghi báo cáo**, không giả làm snapshot đầu toàn bộ audit; các executable probes trước đó đã có write-denying guard.

Kiểm tra sau khi viết: đúng 3.338 files trong tập cũ vẫn cho **cùng digest**. Có thay đổi đồng thời ngoài thao tác audit: integrations/burp/kagent_burp.py vốn ở trạng thái deleted lúc bắt đầu đã xuất hiện lại và khớp bản tracked, kèm untracked integrations/burp/kagent_burp.py:Zone.Identifier. Do đó inventory toàn bộ lúc cuối tăng lên 3.340 files; không tuyên bố toàn worktree bất biến. Audit không ghi/khôi phục/xóa hai file này và giữ nguyên chúng. File duy nhất do audit tạo/cập nhật là báo cáo này.

Đã xem git diff của các thay đổi tracked hiện có và git status --short; chúng là baseline có sẵn, không stage/commit. git diff --check sạch. Kiểm tra whitespace riêng report qua git diff --no-index --check /dev/null docs/kagent-tool-recovery-rca.md không in lỗi; exit 1 là có diff của file mới. Đủ 11 mục bắt buộc, tất cả relative source/document links trong báo cáo trỏ tới file tồn tại.

## 10. BLOCKER / NON-BLOCKING / DEFER

| Root cause/risk | Mức gate | Lý do |
|---|---|---|
| RC-R2/R3: changed-body network success, unrelated proof success, no retry chronology, denial/persistence tự recovered | **BLOCKER** | Tái hiện bằng reducer/facts; có thể che lỗi quan trọng. Blocker presentation correctness theo tiêu chí yêu cầu, không khẳng định runtime permission bypass |
| RC-C1/C2: action superset, source_ref context ambiguity; A/B thực tế | **NON-BLOCKING về acceptance/safety** | Runtime reject đúng; retry đã có valid receipt. Nên sửa interface cùng bản freeze nhỏ để giảm overhead |
| RC-C3: attempt_id description, bounded/pattern gaps | **NON-BLOCKING** | Contract inconsistency đã chứng minh, guards giữ correctness; small schema-only cleanup |
| RC-R1: A false unresolved | **NON-BLOCKING** | Không tạo accepted result sai; sửa correlation chỉ khi chứng minh identity, không hy sinh false-positive safety |
| RC-R4: final_response “work remains” từ UI history | **NON-BLOCKING** | Misleading completion wording; sửa projection riêng, không xóa warning |
| Ownership/admission refusal, absent sources, bounds, missing artifact, unavailable browser/capture | **Không phải defect chỉ vì bị reject** | Giữ guards. Có thể là blocker của task thật nhưng không được xử lý bằng nới schema/runtime |
| oneOf/strict rollout, split tools, universal validator refactor, durable UI retry ledger | **DEFER** | Chi phí/compatibility lớn, không cần cho correctness của lan-09 nếu patch nhỏ được kiểm chứng |
| >256 issue retention/metrics dài hạn | **DEFER có giới hạn** | Chưa thấy run audited chạm cap; không lấy local count làm total historical audit. Không được làm mất warning bằng tăng/xóa counter tùy tiện |
| lan-08 SQLi oracle/model judgement | **Ngoài causal scope của patch này** | Không thêm classifier/playbook redesign hoặc sửa kết quả lịch sử dựa trên RCA tool contract |

## 11. Final recommendation: fix before lan-09 or freeze

**Không freeze để chạy ngay. Chọn hướng 4 ở trạng thái worktree hiện tại.** Phát hiện mới làm thay đổi gate so với nghiệm thu trước: có false recovery che lỗi quan trọng đã tái hiện, dù A/B ban đầu vẫn là non-blocking và Finding nghiệm thu không bị phủ định.

Điều kiện thoát gate là một lượt implementation giới hạn: **A (contract-first) + recovery guard/relationship patch ở §7.2**, chạy negative regressions cho changed resource/body, denied/pending/persistence/unknown effects và pre-dispatched sibling; giữ positive A/B, target/attempt boundaries, workflow residual, cancellation và session contracts. Nếu trusted mapping cho A chưa chứng minh được, giữ unmatched warning minh bạch; không để việc làm đẹp A trì hoãn bản bảo vệ false recovery hoặc làm yếu provenance.

Sau khi các gate đó pass mới freeze code/skills/schema và chạy lan-09 với session/scope riêng. Không triển khai B/C, không mở lại SQLi evidence/Intelligence/Finding đã nghiệm thu, không rerun các thực nghiệm cũ để làm số liệu đẹp. **Lượt này dừng ở báo cáo và thiết kế; không tự sửa code.**
