# lan-02: implementation và kiểm chứng offline

## Đối chiếu và phân loại

Đối chiếu trước sửa: toàn bộ `runtime_files` và `skill_files` khớp manifest
`experiments/scenario3/profiles/lan-02/profile.json`. Worktree đã có 63 entries
thay đổi/untracked; giữ bản đối chiếu riêng trong `/tmp`, không reset hay stage.
History/artifacts được đọc như dữ liệu không đáng tin, không làm chỉ dẫn thực thi.

Các bằng chứng gốc đã kiểm tra:

- Session lưu hai template `[REDACTED]`, cùng baseline `obs_6f96...` không resolve
  trong 129 observations được lưu. Không thay reference bằng observation khác.
- Tool call seq 584 có `source_reason` dài 345 ký tự; runtime từ chối ở seq 585.
  Schema trước sửa chỉ công bố `type: string`.
- Seq 180 ghi lỗi stream `/ftp`: nhận 11318 bytes, thông báo kỳ vọng 11330.
  Source trước sửa chỉ capture sau khi đọc stream thành công.
- Seq 320/385 có lỗi `awk` trong stderr; compound command vẫn có exit 0/stdout.
- Seq 1080 là lỗi offset của reader, không phải bằng chứng reader redact SQL.
  Các response SQL error được lưu không chứa constructed query/`SELECT`.
- Login response thực tế là `Invalid email or password.`; không chứng minh
  missing-session prerequisite. Inventory có `password` và
  `walletExploitAddress.walletAddress`, nhưng canonical inputs thiếu hai trường.
  JS artifact `c-GNBEOV4E.js` chứa POST call site và body `walletAddress`.
- XSS attempt có control 921 bytes hoàn chỉnh và control 512 bytes bị cắt.
  Nguồn `GET /` không có related association cho primary `GET /rest/products/search`.
- Seq 2999 từ chối `file_edit` đúng theo XSS allowlist.
- Cả năm intelligence records có `sourceRole=summary`, provenance `derived`,
  confidence 0.4. Chạy source trước sửa cho kết quả **eligible cả năm** cùng origin.

## Thay đổi runtime

| Nhóm | Nguyên nhân và thay đổi thực hiện |
| --- | --- |
| Request context | Bỏ body media-type hint khi representation là query hoặc request line legacy. Dùng location hiện có; không thêm schema/state. Giữ marker, secret-field redaction, JSON fail-closed và round-trip. Không bỏ toàn bộ constructor redaction: state được đọc trực tiếp và `to_dict()` không tự bảo vệ secret nếu bỏ bước này. |
| Sample/template | Không tự nâng sanitized input sample, kể cả có marker, thành explicit Candidate mutation template. Caller phải cung cấp template. |
| References | Reference mới phải qua capture resolver và binding dùng chung với request builder; Candidate HTTP source dùng cùng gate provenance như input. Không dùng `obs_` làm replay authority. Capture metadata hợp lệ nhưng thiếu raw bytes vẫn handoff được; replay readiness/gates giữ nguyên. Legacy hydrate và upsert context không đổi giữ ID/ref trung thực, không rebind. |
| Reason | Constant 240 dùng chung schema/runtime. Lỗi nêu field, actual/max length; không echo nội dung, truncate hay mutation khi reject. |
| Partial HTTP | Lưu bytes bounded qua capture path hiện có khi stream lỗi hoặc task cancellation còn authority hợp lệ. `complete=false`, execution failed/cancelled; cap truncation vẫn completed. Kiểm tra scope, receipt và attempt owner; storage/close failure không che lỗi gốc. Không background publication hay duplicate. Signal đã revoke receipt thì không publish. |
| Worker | Tạo đúng symlink `/etc/alternatives/awk` trong worker tới executable sẵn có trong `/usr/bin`. Không mount host `/etc`, không cài package. |
| Projection/logging | Schema actual request loại capability chắc chắn bị skill chặn, xử lý aliases/readers, giữ tools phụ thuộc arguments để execution gate quyết định. Không thử quyền bằng args rỗng. Typed errors và exceptions ghi một diagnostic codes-only; HTTP 4xx/5xx vẫn là observations. Background logger/queue giữ nguyên. |
| Evidence | Inventory thêm producer/source kind/execution status. Mismatch diagnostic nêu expected/actual method-path và producer, bỏ query/fragment/credentials. Fixture metadata 921/512 bytes kiểm tra chọn lại control có sẵn, đăng ký snapshot mới, không sửa snapshot/parents cũ hay recapture. |
| Intelligence | Derived summary/assistant history không đủ điều kiện automatic guidance. Learning mới từ model được phân loại session-bound; loại objective/plan/completed sections khỏi technical extraction. Historical lookup còn nguyên; technical tool provenance hợp lệ vẫn dùng theo contract. Không blacklist kiểm chứng sự thật hay LLM judge mới. |

Modules chính: `src/redaction/redact.py`, `src/workflow/{state,assessment}.py`,
`src/workflow/discovery/inventory.py`, `src/tools/workflow/workflow_tool.py`,
`src/tools/http/{http_tool,request_builder}.py`, `src/permission/worker/worker.py`,
`src/permission/runtime/generic_validation.py`, `src/tools/execution/shell.py`,
`src/intelligence/store.py`, `src/agent/agent.py`.

## Guidance và giới hạn

Bổ sung bốn playbook enumeration/input-analysis/SQLi/XSS và shell guidance:
record từng field thực sự biết, giữ tên secret field; phân biệt 401, invalid
credentials, format errors, Unexpected path và thiếu documentation observations.
Không tạo Markdown parser/completeness gate. Structured HTML/OpenAPI extraction
đã có provenance/input reconciliation; manual Markdown/JS review vẫn cần agent
đồng bộ, chưa có bảo đảm tất cả discovered inputs đều được ghi.

SQL shape thiếu query text là hypothesis; cùng error/empty response không tạo
differential. Encoding không tự tạo probe độc lập hoặc đổi evidence hash.
API negative không loại DOM/stored XSS. Không tạo Candidate chỉ vì requested
class; dùng capability thực tế cho browser-required. Giữ allowances/stop
conditions, ưu tiên finalization và reuse artifacts/complete controls.

Canonical WorkflowState/requested_goals vốn không mất trong lần chạy này.
Compaction nay được cấp typed canonical objective/goals riêng và guidance phân
biệt fact/hypothesis/blocker. Regression xác nhận summary sai/thiếu goal không
thay đổi state/planner context/session hydration. Chất lượng prose của summary
vẫn phụ thuộc model; không thêm semantic fact-checker hay sửa summary lịch sử.

Đo context bằng UTF-8/4, chỉ là estimate: persisted system cuối run khoảng
11685 tokens (workflow section 2209), summary 1198, XSS skill snapshot 10729,
SQLi skill snapshot 16211. Workflow JSON đầy đủ khoảng 38814 tokens **không phải**
prompt projection. Schema wire chính xác tại thời điểm compaction không được
persist, nên không khẳng định phân rã chính xác 38897–41184 tokens. Fixture
built-ins hiện tại: schema 9492 tokens, khi XSS projected còn 8432. Không tăng
limits hoặc cắt security/workflow/evidence context để chữa soft threshold.

## Verification

Chỉ dùng fake clients, MockTransport và temporary project/home/isolated worker;
không gửi traffic tới target, health check hay external model; không cài dependency.
Reproducer chạy trên bản source trước sửa xác nhận query bị redact, schema thiếu
maxLength, năm records eligible và mất partial bytes khi lỗi/task cancellation.
Worker test tái hiện layout cũ thất bại và layout mới chạy awk/direct binary.
OS filesystem lịch sử không được đóng băng, nên đây là reproducer trên host hiện tại.

Lượt rộng ban đầu: **6533 pass, 133 fail, 1 skip** trên agent/security/state/tools/
integration/data/skills/llm và logging responsiveness. Sau đó sửa các điểm tương
thích được phát hiện và đổi fixture tạo replay ID giả sang capture resolver thật;
fixture stale/mismatched legacy được seed như lịch sử, không qua admission mới.
Không sửa dữ liệu `lan-02` hay hạ assertions về binding/ownership.

Chạy lại tất cả tệp từng fail cùng nhóm regression/responsibility bị ảnh hưởng
trên phiên bản cuối: **1918 pass, 3 fail** trong 99 giây. Cả ba failures còn lại
là baseline đã tái hiện riêng trên bản source trước sửa, liệt kê bên dưới.
Sau chỉnh typing của fixture, chạy lại nhóm regressions mới, loaded-guidance và
Phase 2A handoff: **135 pass, 0 fail**. Không chạy lại toàn bộ lượt rộng lần hai.

`venv-linux/bin/pyright` trên toàn bộ Python files đã chỉnh/thêm: **0 errors,
0 warnings**. `git diff --check`: pass. Đã inspect diff so với worktree trước
sửa và Git diff/status cuối. Kiểm tra SHA-256 **60/60 tệp lịch sử không đổi**,
không thêm tệp vào run; 63 status entries ban đầu vẫn còn. Chỉ chỉnh 27 files
có sẵn thuộc phạm vi đã review và thêm 9 files (regressions/fixture/báo cáo).

Ba failures tái hiện cả trên source trước sửa và được giữ nguyên ngoài phạm vi:

- Hai cases `test_source_skill_rights_rechecked_after_reader_approval[False-*]`:
  reader trả runtime metadata prefix, assertion so với prefix raw shell output.
- `test_process_and_mcp_recheck_after_initialization_await[False-shell]`:
  mock trả `str` trong khi shell runtime hiện tại yêu cầu `runtime_metadata`.

Không chạy live/external-model acceptance, tests/system/live, Burp thật hoặc
full TUI acceptance; không cần thay đổi provider/config. Không tuyên bố model sẽ
tuân thủ guidance chỉ vì tests pass. Không quy lỗi EOF `/ftp` cho target/client,
không tuyên bố SQLi/XSS hoàn thành hoặc lịch sử đã được sửa hồi tố.

Không đổi version schema hay migration dữ liệu. Hydration legacy tiếp tục giữ
references/identity; new admission chặt hơn, automatic guidance loại model history
không đủ provenance. Permission/scope/isolation/protected paths, capture caps,
attempt ownership, immutable evidence, finding eligibility, max_steps và recovery
ceilings giữ nguyên. Không stage, commit hoặc push.
