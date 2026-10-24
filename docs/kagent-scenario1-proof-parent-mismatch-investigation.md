# Scenario 1 / lan-09 — điều tra PROOF_PARENT_MISMATCH

Ngày điều tra: 2026-10-24. Checkout ban đầu sạch, HEAD `41dcbba076aa5cc36ab8af8f445c7e3bc9e1c2fa`.

**Verdict: PASS cho bản sửa feedback/contract. Validator đã từ chối đúng;
nguyên nhân trực tiếp là manifest do Agent tạo thiếu bốn parents.**
Kết quả thực nghiệm vẫn là `insufficient-evidence`; không đăng ký lại proof thật,
không tạo Evidence/Finding, không mở lại Attempt và không gửi request tới target.
Không khẳng định bản sửa sẽ làm model tự sửa thành công trong một lần chạy live.

## 1. Định danh và phạm vi đọc

- User gọi lần chạy này là Scenario 1. Dữ liệu khớp chính xác Candidate/Attempt
  nằm trong `experiments/scenario3/runs/lan-09`; giữ nguyên tên/thư mục thực nghiệm đó.
- Session: `21b62d4d-8a9a-4df5-aa9a-3115a89398e0`.
- Candidate: `cand_53af287d6a04f54924aa`.
- Attempt: `attempt_4e2c943c1f284c7bad61cf6a293abc3e`.
- Target: `http://juice.lab:8081`; input JSON `email`, `POST /rest/user/login`.
- Log chính: `experiments/scenario3/runs/lan-09/logs/session.jsonl`.
- Session: `experiments/scenario3/runs/lan-09/profile-home/.kagent/sessions/21b62d4d-8a9a-4df5-aa9a-3115a89398e0.json`.
- Ledger: `experiments/scenario3/runs/lan-09/project/.kagent/observations/21b62d4d-8a9a-4df5-aa9a-3115a89398e0.json`.
- Proof source: `experiments/scenario3/runs/lan-09/project/artifacts/sql-injection/juice.lab_8081/cand_53af287d6a04f54924aa-proof.md`.
- Snapshot: `experiments/scenario3/runs/lan-09/project/.kagent/evidence/ed5171f35635aa16d67eb2cf/8c89de8bb8bf58e62a86dfdeaea4bfcee32cd4c49a245b99c6b0cf20370264d5.proof`.
- Code đọc: `src/tools/workflow/workflow_tool.py`,
  `src/workflow/evidence/artifacts.py`, `errors.py`, `recovery.py`,
  observation persistence/source-integrity code và các tests thuộc trách nhiệm evidence.
- Playbook đọc: `skills/sql-injection/SKILL.md` và chính output `load_skill`
  được lưu trong session. Toàn bộ body Skill trước sửa có mặt trong output đã lưu;
  chẩn đoán không dựa trên giả định model chưa nhận được Skill.

Kho Windows `D:\DOANTOTNGHIEP\kagent` không tồn tại trong môi trường này.
Repo thực được xác minh tại `/home/khainguyen/kagent` trong Ubuntu WSL.
Không dùng bridge Burp hoặc credentials/provider APIs cho điều tra.
Không audit lại toàn hệ thống hoặc đánh giá lại SQLi semantics.

## 2. Artifact tại thời điểm submission

Log seq 308 (`2026-10-24T02:44:09.161407Z`) là lần `file_write` duy nhất.
Seq 309 báo ghi 5.330 bytes. Không có `file_edit`, `shell`, hoặc lần
`file_write` nào khác trong turn được lưu.

| Biểu diễn | Bytes | SHA-256 |
|---|---:|---|
| Source file còn lưu | 5330 | `93c003a9c4b603ac683dc27839a20c8ff4d6f7e4a45cb855938a69e9f4d12c13` |
| Nội dung file_write đã redacted trong log và saved message | 5349 | `8c89de8bb8bf58e62a86dfdeaea4bfcee32cd4c49a245b99c6b0cf20370264d5` |
| Immutable snapshot còn lưu | 5349 | `8c89de8bb8bf58e62a86dfdeaea4bfcee32cd4c49a245b99c6b0cf20370264d5` |

Đối chiếu từng byte: logged write = saved message write = immutable snapshot
= kết quả evidence-redaction của source còn lưu. Không có thao tác sửa source
được ghi nhận giữa hai submissions; chỉ có một content-addressed snapshot.
Do đó có thể tái dựng chính xác nội dung redacted mà validator kiểm tra ở cả
hai submissions. Raw tool-call content trước redaction không được log giữ riêng;
không coi saved message là bản raw 5.330 bytes. Hai lần rejection không tự log
snapshot hash riêng, nên kết luận cùng nội dung dựa trên chuỗi ghi file, snapshot
và byte comparisons này.

`_record_evidence` chụp snapshot **trước** khi kiểm tra proof parents. Vì thế file
`.proof` vẫn có thể tồn tại sau rejection, nhưng `workflow.evidence=[]` và
`evidence_sources={}`: không có Evidence được đăng ký, không có `ev_` được trả về.
Giữ nguyên snapshot đó; không xóa hoặc sửa nó để làm sạch thực nghiệm.

Proof có một `candidate_id` rõ ràng ở dòng 3. Dưới tiêu đề
`## Ledger (owned observations of this attempt)`, bảng dòng 43–52 chứa đúng
10 observation references. Không có observation reference nào khác trong proof.
Các dòng bảng đều là active claims theo contract Markdown hiện hữu;
nhãn “inconclusive” hoặc “syntax adjustment” không miễn parent binding.
Các dòng code fence/quote vẫn giữ đúng phạm vi loại trừ hiện hữu.

## 3. Từng submission và khai báo parents

### Submission 1: seq/log line 315

- UTC: `2026-10-24T02:44:14.905559Z`.
- Call ID: `call_00_xJQk39nKmphA41pjSob64826`.

```json
{
  "action": "record_evidence",
  "candidate_id": "cand_53af287d6a04f54924aa",
  "evidence_path": "artifacts/sql-injection/juice.lab_8081/cand_53af287d6a04f54924aa-proof.md",
  "observation_ids": [
    "obs_1a05ea9b6b9545918f2fcc209abba97f",
    "obs_32288d36e5a744fe8cdfbb86ae01838f",
    "obs_d8a1edb6111245ca8fed016bac710a42",
    "obs_8b16f43625ce402eac81b17858ef6b70",
    "obs_173ce5ba6d6b4441b4327f92aefdb30e",
    "obs_3be4ae49f65c42959b6d789b82e00cb6"
  ]
}
```

### Submission 2: seq/log line 343

- UTC: `2026-10-24T02:44:20.224414Z`.
- Call ID: `call_00_GX6nsHsiiNMSZRE2UCBM2239`.

```json
{
  "action": "record_evidence",
  "candidate_id": "cand_53af287d6a04f54924aa",
  "evidence_path": "artifacts/sql-injection/juice.lab_8081/cand_53af287d6a04f54924aa-proof.md",
  "observation_ids": [
    "obs_d8a1edb6111245ca8fed016bac710a42",
    "obs_8b16f43625ce402eac81b17858ef6b70",
    "obs_173ce5ba6d6b4441b4327f92aefdb30e",
    "obs_3be4ae49f65c42959b6d789b82e00cb6",
    "obs_32288d36e5a744fe8cdfbb86ae01838f",
    "obs_1a05ea9b6b9545918f2fcc209abba97f"
  ]
}
```

Hai lời gọi đều đúng action/field whitelist; không có `attempt_id` thừa trong
`record_evidence`. Sự khác nhau duy nhất là thứ tự sáu `observation_ids`.
Hai tập parents bằng nhau, không thêm hoặc bỏ ID nào.

| Dòng proof/snapshot | Vai trò theo artifact | Observation reference | HTTP | Body bytes | Có trong cả hai submissions? |
|---:|---|---|---:|---:|---|
| 43 | control | `obs_1a05ea9b6b9545918f2fcc209abba97f` | 401 | 26 | có |
| 44 | syntax probe | `obs_32288d36e5a744fe8cdfbb86ae01838f` | 500 | 1221 | có |
| 45 | syntax adjustment 1 TRUE | `obs_59404d6d0bff48ddb835a3dd5a0c5ca8` | 401 | 26 | **thiếu** |
| 46 | syntax adjustment 1 FALSE | `obs_1b73919376ff46cc8c2d281114ba4c9e` | 401 | 26 | **thiếu** |
| 47 | syntax adjustment 2 TRUE | `obs_51ded22904d14ed29e54a24e91ba3f32` | 401 | 26 | **thiếu** |
| 48 | syntax adjustment 2 FALSE | `obs_a5219f05e57a485193e08336c73eedf0` | 401 | 26 | **thiếu** |
| 49 | pair 1 TRUE | `obs_d8a1edb6111245ca8fed016bac710a42` | 200 | 799 | có |
| 50 | pair 1 FALSE | `obs_8b16f43625ce402eac81b17858ef6b70` | 401 | 26 | có |
| 51 | pair 2 TRUE | `obs_173ce5ba6d6b4441b4327f92aefdb30e` | 200 | 799 | có |
| 52 | pair 2 FALSE | `obs_3be4ae49f65c42959b6d789b82e00cb6` | 401 | 26 | có |

Mismatch chính xác nằm ở `record_evidence.observation_ids`: thiếu references
được bảng proof khai báo tại dòng **45, 46, 47, 48**. Đây là bốn responses 401/26
bytes của các thử nghiệm chưa tạo differential. Bốn IDs không giả, không sai
namespace, không thuộc Attempt khác, không truncated; chúng bị bỏ khỏi arguments.

Ledger có 11 observations: 10 native captures thuộc Attempt và một imported
Burp capture `obs_26237379b24647ebb2c4d3b47770bf0d` không thuộc Attempt.
Imported capture không xuất hiện trong proof hoặc hai parent manifests;
không cần và không được tự nhận capture đó làm primary parent.

Kiểm tra cả 10 native sources: Candidate, Attempt, session, objective và
candidate_binding đều khớp; retained source hash khớp tính toán lại;
execution status `completed`, complete `true`, truncated `false`.
Hai positive captures có HTTP 200/799 bytes và token-field marker; hai negative
captures có 401/26 bytes. Chỉ kiểm tra dữ liệu đã lưu; không decode/replay token,
không biến các kiểm tra này thành một ValidationResult mới.

## 4. Vì sao self-correction thất bại

Log và saved session chứng minh có **hai submissions tổng cộng: initial + một
retry**, không phải initial + hai repair submissions. Các dòng TUI lặp lại không
phải bằng chứng có thêm tool call. Persisted recovery counter cũng là `rejections=2`.

| Log seq | UTC | Hành động thực tế |
|---:|---|---|
| 308–309 | 02:44:09–02:44:12 | Ghi proof duy nhất |
| 315–316 | 02:44:14 | record_evidence đầu: thiếu 4 parents, bị từ chối |
| 336–337 | 02:44:18 | record_attempt_state thành công: ghi effects, dùng hai IDs của pair 1 |
| 343–344 | 02:44:20 | record_evidence retry: cùng file, cùng tập 6 IDs, lại bị từ chối |
| 377–378 | 02:44:25 | record_result insufficient-evidence được chấp nhận |

Ở saved message 34 (index bắt đầu từ 0), Agent nói:
“The primary parent isn't declared. Adding an explicit primary request association.”
Nhưng tool call thực tế là `record_attempt_state`, với `mutation_state`,
`effect_basis`, `cleanup_state`, `cleanup_status`, `mutation_performed` và
`observation_ids` của pair 1 TRUE/FALSE. Action này chỉ ghi effects của Attempt;
không viết source proof, không thay `evidence_sources`, không khai báo parents
cho một EvidenceArtifact. Lần retry chỉ đổi thứ tự sáu IDs.

Agent đã hiểu sai “primary parent” thành request/effects association. Nó không
đối chiếu tập references trong artifact với manifest. Phát ngôn “adding” không
được hỗ trợ bởi một thao tác thêm proof parent thật.

Closure có result `result_938736c59cbe42509e5c68a7da9ef719`,
`evidence_refs=[]`, outcome `insufficient-evidence`; không đủ điều kiện Finding.
Persisted recovery: `rejections=2`, `repair_turns=0`, `paused=true`, `closed=true`.
Runtime ceiling vẫn là initial + tối đa hai retries (`MAX_EVIDENCE_REJECTIONS=3`),
terminal repair turn ceiling là 6. Skill/preface đã hướng dẫn retry tối đa một
lần trong trường hợp này. Không có bằng chứng runtime đã tiêu hết ba rejection
slots; không quy failure này cho recovery-budget defect hoặc Anti-stall.
Không đổi budget/closure behavior.

## 5. Phân loại root cause

| Lớp | Kết luận | Bằng chứng |
|---|---|---|
| Agent artifact + arguments | Nguyên nhân trực tiếp | Proof giữ 10 rows; manifest chỉ có 6 parents; retry không thêm IDs hoặc sửa file |
| SQLi Skill | Khoảng hở hướng dẫn, không phải chỉ thị tạo proof sai | Có yêu cầu giữ ledger/adverse evidence và ít nhất 4 distinct pair sources, nhưng chưa nói rõ mọi explicit ID trong bảng đều cần parent |
| Tool contract | Khoảng hở mô tả | observation_ids mô tả ownership/request và capture quality; chưa chỉ rõ reference trong bảng/historical rows cũng là parent claim |
| Error feedback | Khoảng hở chẩn đoán | PROOF_PARENT_MISMATCH chỉ báo chung; không trả missing IDs hoặc line numbers; hint chung không phân biệt effects với proof parents |
| Validator | **Không xác nhận defect** | Phép kiểm active references minus declared parents phát hiện đúng bốn IDs; cả bản trước và sau đều reject cùng manifest |
| Ownership/integrity/scope/permission | Không phải nguồn rejection này | Sáu declared sources qua resolve_sources; bốn thiếu cũng có ownership/hash/capture hợp lệ trong ledger |

Skill không bảo Agent bỏ bốn rows khỏi parents. Không có bằng chứng provider
làm mất arguments, tool tự thay parents hoặc runtime không ghi artifact.
Không mở rộng kết luận sang chất lượng SQLi reasoning, permissions hay model
reliability toàn hệ thống.

## 6. Sửa ở lớp nhỏ nhất

1. `src/workflow/evidence/artifacts.py`: giữ nguyên phạm vi/parser và điều kiện
   rejection; thêm thu thập 1-based physical line numbers cho references bị thiếu.
2. `src/workflow/evidence/errors.py`: giữ nguyên code/repair_kind, thêm diagnostics
   bounded chỉ chứa canonical `obs_` + 32 hex và line numbers. Tối đa 16 IDs,
   8 dòng/ID; trả total count và truncation flag. Không echo proof text, payload,
   đường dẫn, credentials hoặc ID tùy ý. Chẩn đoán không xác nhận source tồn tại,
   ownership hoặc admissibility. Hint nêu rõ effects và proof parents khác nhau,
   đảo thứ tự cùng tập IDs không sửa được mismatch.
3. `src/tools/workflow/workflow_tool.py`: chỉ làm rõ description của observation_ids;
   every explicit candidate-proof ID trong fields/headings/table phải có parent.
   Không thêm action/field, không tự điền parents hoặc tự retry.
4. `skills/sql-injection/SKILL.md`: giải thích inconclusive-history rows, map diagnostics
   về ledger thật, giữ adverse evidence, sửa đúng artifact/manifest theo lỗi thực;
   không dùng record_attempt_state để khai báo proof parents hoặc gửi HTTP để sửa.
5. `tests/security/test_proof_parent_feedback.py`: sáu regression cases.

Không sửa observation store, evidence publication, parent immutability,
resolve_sources, terminal admissibility, result/finding eligibility, scope,
permission, recovery limits hoặc Anti-stall thresholds. Không tự accept Evidence
và không tự bỏ adverse rows để hợp thức hóa một proof.

Feedback mới trên **chính bytes proof đã lưu và chính arguments cũ**, chỉ gọi
pure reference checker, không gọi workflow registration:

```json
{
  "code": "PROOF_PARENT_MISMATCH",
  "repair_kind": "manifest",
  "missing_primary_parent_count": 4,
  "missing_primary_parents": [
    {
      "observation_id": "obs_59404d6d0bff48ddb835a3dd5a0c5ca8",
      "proof_line_numbers": [
        45
      ]
    },
    {
      "observation_id": "obs_1b73919376ff46cc8c2d281114ba4c9e",
      "proof_line_numbers": [
        46
      ]
    },
    {
      "observation_id": "obs_51ded22904d14ed29e54a24e91ba3f32",
      "proof_line_numbers": [
        47
      ]
    },
    {
      "observation_id": "obs_a5219f05e57a485193e08336c73eedf0",
      "proof_line_numbers": [
        48
      ]
    }
  ],
  "missing_primary_parents_truncated": false
}
```

Cả parser trước sửa và parser sau sửa vẫn reject hai manifests 6 parents.
Một counterfactual parser-only khai báo đầy đủ 10 references đã có sẽ qua parent
check ở cả hai bản. Điều đó chứng minh đây là manifest mismatch có thể sửa bằng
dữ liệu hiện hữu, **không chứng minh** một terminal assessment hay Finding sẽ
được chấp nhận. Không đăng ký counterfactual vào session/project thật.

## 7. Deterministic offline regression và validation

Tests chạy trong disposable checkout `/tmp/kagent-proof-parent-rr19zo_l/checkout`.
HTTP fixtures dùng MockTransport; guard chặn network ngoài fixture và cấm ghi
vào original experiment/artifact/session stores. Live opt-in không được bật.
Pyright dùng trực tiếp bundled local Node entry point với network-denying
preloader; không dùng Python wrapper có kiểm tra package metadata qua mạng.
Không cài package, không gọi model hoặc target.

| Kiểm tra | Kết quả |
|---|---|
| New regressions trước production patch | 4 failed, 2 passed; lỗi thiếu diagnostics và rule mô tả được tái hiện |
| Targeted manifest/parser/loaded Skill set | 48 passed |
| Evidence/security responsibility set, final source | 323 passed in 63.10s |
| Workflow/Skill/provider schema contracts + new regression, final source | 293 passed in 16.53s |
| Pyright toàn src/tests/benchmarks, final source | 0 errors, 0 warnings, 0 informations |
| Diff/whitespace | git diff --check và new-file whitespace checks sạch |
| Historical preservation | 3.123/3.125 file giữ nguyên bytes; 2 log/context files được runtime đang mở cập nhật (chi tiết bên dưới) |

Sáu cases mới bao phủ:

- Ten-row ledger / six-parent submission bị reject với đúng 4 IDs/dòng;
  effects declaration và permutation không sửa được lỗi. Caller chủ động khai báo
  đủ 10 nguồn fixture đã sở hữu thì đăng ký thành công, không thêm HTTP, không
  tự tạo result/finding, không đổi proof.
- Well-shaped nhưng absent source vẫn bị PRIMARY_REFERENCE_UNAVAILABLE.
- Source thuộc Attempt khác vẫn bị SOURCE_OWNERSHIP_MISMATCH; không adopt/rebind.
- Diagnostic bị giới hạn số ID/dòng và không lộ text chứa credential fixture.
- Inconclusive table row vẫn cần parent; quote/fence/other-Candidate scope giữ nguyên.
- Nội dung load_skill thật và schema thật nêu rõ contract cần sửa.

Nhóm evidence/security chạy các modules: agent_assessment, assessment_review_fixes,
observation_grounding, evidence_correctness, evidence_correctness_blockers,
evidence_reads, evidence_recovery_contract, evidence_source_binding,
evidence_atomic_publication, related_request_evidence, lan02_evidence_controls,
sqli_evidence_guidance, trial1_evidence_guidance, cli_evidence_repair,
validation_finalization, finding_finalization, proof_parent_feedback,
phase1_evidence_contracts, bounded_validation_regressions.
Các tests hiện hữu tiếp tục kiểm ownership, integrity, immutable parent association,
publication/source races, permissioned reads, terminal evidence/finding gates,
bounded retries và honest unresolved closure. Không sửa hoặc bỏ assertion cũ.

Nhóm contract chạy Workflow actions/arguments, schema interop và encoders
OpenAI-compatible/DeepSeek/Anthropic/Gemini, action projection, Skill grounding.
Các nhóm có overlap; không cộng các lượt pass thành một số tests duy nhất.
Không chạy lại full repository suite vì thay đổi giới hạn ở proof diagnostics và
contract; không thực hiện live retest hoặc đo model success rate.

Logs/audit reproduction ở `/tmp/kagent-proof-parent-rr19zo_l`:
`reconstruction.json`, `reconstruct.py`, `logged-proof-redacted.md`,
`red-before.txt`, `targeted.txt`, `evidence-security-final.txt`,
`contracts-final.txt`, `pyright-final.txt`, historical/source manifests.
Không phụ thuộc các file temp để đọc kết luận/root-cause trong báo cáo này.

## 8. Bảo toàn và verdict cuối

Đã hash trước/sau 3.125 files trong `.kagent`, `artifacts`, `experiments` và
personal session storage. Không có file bị thiếu hoặc file mới trong các cây
được bảo vệ. 3.123 files giữ nguyên hash/size, gồm toàn bộ source proof,
immutable snapshot, observation ledger và saved session của lần chạy này.
Không có historical artifact nào bị thao tác ghi từ công việc điều tra/tests.

Có thay đổi đồng thời ở **hai file**: `lan-09/logs/session.jsonl` và context
snapshot `lan-09/profile-home/.kagent/context/21b62d4d-8a9a-4df5-aa9a-3115a89398e0.md`.
Đã xác minh Python process PID 41522 còn hoạt động với CWD là `lan-09/project`.
Log được append các `context_snapshot` events lúc 02:49:17, 02:54:18 và 02:59:18
UTC (seq 388–390), phù hợp với runtime lan-09 còn mở. Không có tool-call mới.
Đây không phải bytes do tests ghi: toàn bộ verification dùng guard cấm ghi vào
original experiment storage. Không dừng runtime hoặc khôi phục đè các thay đổi.

Prefix 273.016 bytes của log lúc bắt đầu điều tra vẫn khớp nguyên SHA-256
`8bf3a6a066d74ab78a1ffb48c8484f18239b802f3b46b488f2d9a85880b165da`.
Đã giữ bản sao prefix xác minh này trong audit temp để việc tái dựng hai
submissions không phụ thuộc log tiếp tục append. Không thể tuyên bố tất cả
3.125 hashes bất biến vì hai file live nói trên; các chứng cứ liên quan trực tiếp
đến proof/parents vẫn nguyên vẹn.

Source/tests/skills kiểm tra không có drift ngoài đúng các files sửa; bytes
của năm files source/Skill/test thay đổi khớp disposable checkout được kiểm thử.
Các báo cáo cũ giữ nguyên. Git HEAD không đổi, không stage/commit/push,
không thay cấu hình, không reset/checkout/clean/stash và không cài package.

**Verdict: Agent tạo manifest không khớp proof; validator rejection đúng.
Khoảng hở feedback/Skill/tool description đã được sửa với regression offline.
Thực nghiệm vẫn insufficient-evidence và chưa được đánh giá lại.**
