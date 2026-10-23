# CWE enrichment cho Finding

## Luồng đã truy vết trước khi chỉnh sửa

- Validator/agent assessment tạo ValidationResult confirmed, có evidence refs,
  assessment binding, result/attempt IDs. `accepted_result` xác minh nguồn và
  binding; không có enrichment nào được dùng để tạo hay xác nhận kết quả này.
- `src/vulnerability/taxonomy.py` định nghĩa immutable class-level mappings.
  `src/findings/classification.py:classify` chỉ chiếu taxonomy này.
- `ConfirmFindingTool.run` kiểm tra eligibility, accepted assessment và evidence,
  lấy severity/impact từ assessment, tạo Finding và `Store.save` persist một lần.
  Mapping có sẵn được lưu `verified-local`, revision 1. Các class rộng chủ ý
  không có primary CWE; không suy ra missing/incorrect authorization từ IDOR.
- `src/findings/store.py` giữ canonical Markdown, idempotent theo candidate,
  đọc lại snapshot đã lưu khi Continue/retry. `promote_classification` chỉ cho
  phép mapping rỗng, dùng digest/revision guards và atomic replace. Classified
  report không được ghi đè. Export summary dùng chung lock này.
- Compact Markdown dùng `src/findings/presentation.py`; PDF đọc persisted
  Finding qua `src/report/builder.py`; receipt/notifier nằm ở ConfirmFindingTool.
  Trước đợt bổ sung, local catalog helper chưa có caller production.

## Automatic enrichment

Sau persist và mark_finding_persisted, confirm_finding thử enrichment khi CWE
rỗng. Enrichment nhận persisted context guard đã có, không tạo Finding hay thay
đổi eligibility/validation/severity/evidence. Sau await, confirm_finding kiểm
tra lại assessment, session/snapshot và evidence bằng contract đọc hiện có.

Search dùng tên canonical class của cơ chế đã confirmed, không dùng toàn bộ
traffic, URL hay credentials. Chỉ chọn nếu normalized catalog name trùng chính
xác cơ chế này, có duy nhất một match và search không bị giới hạn. Sau đó get
exact ID và kiểm tra lại identity, Weakness Base/Variant, Stable/Usable, Allowed,
metadata đầy đủ, không deprecated/obsolete/truncated. Rank hoặc một search hit
đơn lẻ không chứng minh cơ chế. Không thêm NLP/LLM/semantic validator.

Đây là mapping dựa trên cơ chế Candidate đã được accepted confirmation, cùng
mức tin cậy class identity đang dùng cho taxonomy; không đánh giá lại nội dung
lỗ hổng. Class rộng như access-control/authentication, ambiguous match,
Allowed-with-Review hoặc catalog unavailable luôn unresolved. Lý do được lưu
trong annotation. Thành công dùng promotion rỗng hiện có, provenance chứa
reviewer automatic, selection rule, confirmed mechanism, corpus SHA-256,
source signature, reason và evidence refs. Không thay mapping có sẵn.

## Manual review

`/cwe <candidate_id>` là lệnh operator; không phải tool cho model. Chỉ chạy khi
idle và có Finding đã persist còn khớp accepted assessment. Operator giữ mapping
phù hợp hoặc nêu lý do không phù hợp, search mechanism, chọn exact CWE-N và ghi
rationale chứa ít nhất một owned Evidence ref. Metadata là reference data, được
hiển thị plain/scrollable; không có default chọn kết quả đầu. Allowed-with-Review
cần explicit review; unsupported/incomplete metadata không được gắn tự động.
Không đủ căn cứ thì chọn 0 và ghi lý do unresolved. Cancel không thay báo cáo.

Mapping rỗng dùng promotion đã có. Mapping đã gắn giữ nguyên trong `Finding.cwe`
và classification revision/provenance gốc; thay thế đề xuất được lưu trong
optional `classification_review` metadata cùng original CWE, confirmation binding,
evidence refs, corpus/source signature và lý do. `effective_cwe` chỉ phục vụ
presentation: annotation resolved hiển thị CWE reviewed; unresolved hiển thị
unresolved, kèm original mapping. Không dùng field này làm finding eligibility.
Manual unresolved không bị automatic override trong lần confirm/Continue sau.

## Persistence, permissions và tương thích

Annotation và promotion dùng chung full mutation lock/CAS, temporary preparation,
cancellation drain, final guards, atomic commit và snapshot publication. Chỉ
classification header rows thay đổi; các byte khác của canonical report được
giữ nguyên. Promotion sau manual unresolved xóa annotation cũ để không hiển thị
trạng thái lỗi thời. Concurrent writes không ghi đè nhau khi digest đã đổi.

Local Catalog đọc manifest/XML đã pin, không import code từ deployment, không
MCP/Worker/subprocess/network. Giữ config key cwe_mcp_deployment_path và file-tool
control-plane protections. Enrichment controller chỉ dùng evidence availability
check có sẵn; không cấp receipt giả hoặc đọc protected evidence chưa được xác
minh. Thay đổi session/context, revocation, evidence hoặc source làm review hết
hiệu lực. File/artifact/history roots không đổi. Giới hạn host account sau bỏ
Worker vẫn áp dụng; đây không phải OS sandbox.

Report/store đọc optional review metadata, không suy ra provenance cho báo cáo
cũ và không tự migrate khi load. Session snapshot/fingerprint confirmation giữ
nguyên; Continue/retry lấy classification từ canonical report. Enrichment không
phát notifier Finding mới và không tăng số Findings.

## Kiểm chứng

Regression offline bao phủ mapping có sẵn, mapping thiếu/không phù hợp, exact
mechanism và không chọn first rank, broad/ambiguous/restricted metadata,
catalog unavailable, manual override precedence, protected/stale evidence,
session/context/revocation thay đổi, annotation CAS/cancellation và restore.
Kiểm tra cả Registry confirm_finding, /cwe, compact Markdown và PDF model.
Không gọi LLM/API/live target và không commit/push.

**Kiểm tra tiếp nối ngày 2026-10-23**

Khi tiếp nhận, automatic enrichment, local catalog, `/cwe`, promotion/annotation,
presentation và regression tests đều đã có trên đĩa, gồm cả các file untracked.
Không có phần triển khai CWE nào cần viết tiếp sau khi kiểm tra. Phần còn thiếu
được phát hiện là danh sách kỳ vọng của test thứ tự slash menu chưa có `/cwe`.
Đã bổ sung đúng vị trí trong `tests/ui/test_slash_items.py`, giữ nguyên assertion
thứ tự đầy đủ; không sửa production code hoặc nới contract để làm test xanh.

Các lần chạy dùng `venv-linux/bin/python -m pytest`, offline:

| Nhóm | Kết quả |
| --- | --- |
| `tests/cwe` | 188 passed |
| Finding Store, Registry, finalization, report và session persistence | 424 passed, 1 failure ngoài CWE |
| Taxonomy, WorkflowState, Continue/compaction/resume, CLI và UI | 387 passed, 1 failure menu CWE trước khi sửa |
| Chạy lại toàn bộ `tests/ui/test_slash_items.py` sau sửa | 14 passed |
| Agent assessment, assessment review và validation finalization | 138 passed |

Nhóm Store/Registry/report/session gồm `tests/tools/test_finding.py`,
`tests/tools/test_tools_registry.py`, `tests/security/test_finding_finalization.py`,
`tests/data/test_findings_store.py`, `tests/data/test_findings_http_request.py`,
`tests/data/test_finding_summary_store.py`, `tests/data/test_finding_presentation.py`,
`tests/data/test_finding_postread_async.py`, `tests/report`,
`tests/ui/test_report_handler.py`, `tests/state/test_session_store.py` và
`tests/state/test_session_persistence_async.py`.

Nhóm Continue/UI gồm `tests/data/test_vulnerability.py`,
`tests/state/test_workflow_state.py`, `tests/agent/test_validation_continuation.py`,
`tests/agent/test_resume_after_compaction.py`, `tests/runtime/test_cli_main.py`,
`tests/ui/test_slash_handler.py`, `tests/ui/test_slash_items.py`,
`tests/ui/test_outcomes.py`, `tests/ui/test_text_input_modal.py` và
`tests/ui/test_modal_cleanup.py`. Nhóm assessment gồm
`tests/security/test_agent_assessment.py`,
`tests/security/test_assessment_review_fixes.py` và
`tests/security/test_validation_finalization.py`.

Hai failure được phân loại riêng:

- Regression do bổ sung CWE: `test_menu_orders_help_first_then_related_commands`
  thiếu `/cwe` trong expected list. Đã sửa và kiểm tra lại 14/14 tests trong file.
- Failure có sẵn trong worktree khi tiếp nhận, ngoài CWE:
  `test_unprofiled_generic_tools_and_ordinary_http_keep_review[plugin]`
  (`tests/tools/test_tools_registry.py:219`) đòi một approval request, nhưng
  `CommandPluginTool.validate_args` của đợt runtime simplification đã chặn plugin
  trước bước approval vì isolated executor bị bỏ. Test không đi qua Finding/CWE.
  Giữ nguyên cả implementation và test; đây là baseline của worktree tiếp nhận,
  không phải khẳng định failure tồn tại ở commit HEAD.

Sau khi tính lần chạy lại menu, 1.138 test riêng biệt đã pass, còn 1 failure
baseline ngoài CWE. Không có skip trong các nhóm trên. AST parse cả 8 file Python
của `tests/cwe` thành công. Pyright toàn repository theo `pyrightconfig.json`,
dùng `venv-linux/bin/pyright --outputjson`, phân tích 654 files:
0 errors, 0 warnings, 0 information. `git diff --check` toàn worktree sạch.

Đã đối chiếu code và assertions giữ nguyên taxonomy, eligibility, evidence refs,
confirmation binding/result/attempt, severity/impact, workflow state và số lượng
Finding/report. Manual review precedence, unavailable/protected/stale evidence,
session/revocation, CAS/cancellation, compact Markdown, PDF model và Continue
được kiểm tra bằng các test trên. Không gọi LLM/API, không chạy target thật,
không cài package, không commit/push. Không chạy toàn bộ pytest suite hoặc kiểm
chứng catalog production bên ngoài; catalog trong test dùng fixture XML đã pin.

Đợt tiếp nối chỉ sửa test menu và bổ sung kết quả kiểm chứng vào tài liệu này.
Snapshot hash lúc tiếp nhận được dùng để kiểm tra rằng các file khác, gồm toàn
bộ thay đổi Worker/scanner/browser không liên quan, giữ nguyên nội dung.
