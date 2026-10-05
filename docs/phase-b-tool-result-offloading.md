# Phase B — selective hybrid tool-result offloading

Bàn giao implementation và đo offline trên current tree. Chỉ Phase B; chưa stage, commit hoặc push. Dữ liệu đo đầy đủ: [phase-b-tool-result-offloading-measurements.json](phase-b-tool-result-offloading-measurements.json).

## 1. Phase A Prerequisite Verification

Worktree ban đầu sạch, Phase A tại commit `4c4bb630b4db90f4db5b1e4bf99d45b3c4bf7a62`. Đã đọc AGENTS.md, implementation và tests trước khi sửa. Không tìm thấy handoff Phase A riêng trong repository; dùng current source, commit và regression tests làm căn cứ, không giả định đã đọc một tài liệu không có sẵn.

Prerequisite chạy trước implementation:

```bash
venv-linux/bin/python -m pytest -q tests/agent/test_output_pipeline.py tests/agent/test_sanitizer.py tests/agent/test_tool_outcomes.py tests/agent/test_post_compaction.py tests/agent/test_resume_after_compaction.py
```

**78 passed**. Xác nhận cả năm contract: structured compaction boundary, marker spoof resistance, repeated-pressure rebound, live redaction và outcome metadata preservation. Phase B reuse output-bounds và sanitizer hiện có; không gộp sửa lỗi Phase A còn thiếu.

## 2. Final Data Flow

```text
tool execution / adapter caps
  ├─ existing observations / authoritative evidence branch
  └─ adapter-returned result + transient execution provenance
       → existing Phase A sanitization
       → full sanitized live UI event
       → pressure-aware retention admission
           ├─ inline sanitized result + existing Phase A guard
           └─ fully published scoped sanitized artifact
                → distributed preview + opaque reference in history/session
                → structured continuation catalog across compaction/resume
                → Registry + current rights + fresh permission + integrity
                → bounded character-range reread
```

Raw execution results vẫn phục vụ runtime như trước. UI event nhận full sanitized adapter-returned output trước khi history bị thay bằng preview. UI payload không được cộng lần hai vào LLM context. Result artifact không phải proof, authorization hoặc authoritative evidence.

## 3. Admission Policy

Whitelist theo **exact adapter class**, không dựa vào tên tool do plugin/model tự đặt: `ShellTool`/`BashTool`, `FileReadTool`/alias, `HTTPTool` chỉ `phase=recon` và không `candidate_id`, `WebFetchTool`, `WebSearchTool`.

Chỉ successful/observation adaptive results có trusted sanitized original và snapshot provenance/generation từ execution hiện tại được xét. Không backfill old history, không suy diễn original từ preview. Snapshot được chụp trước dispatch và đối chiếu sau execution để tránh gán lại output cho target/source mới.

Preserve-class, errors/cancellations, workflow/validation/evidence/finding/review/permission/goal/coverage receipts, playbooks/load_skill/ask_user và unknown adapters giữ inline. File reads của `.kagent`, finding directories, generic-validation artifacts và registered evidence paths/source paths cũng bị loại. Grep/search/glob và MCP/plugins chưa đủ trusted per-result provenance contract nên không được offload.

Admission dùng actual working-message estimate gồm provider continuation/tool calls và active tool schemas. Reuse threshold, safety ratio/minimum 128 tokens, floor 2,000 chars, proportional allocation và distributed windows của Phase A. Không dùng cutoff KiB. Preview phải tiết kiệm hơn envelope/schema cost. Large output dưới threshold giữ inline; medium output trong context gần limit có thể admit. Storage refusal hoặc exception quay về sanitized inline và Phase A bounds, giữ tool success.

## 4. Result Store

```text
<project>/.kagent/tool-results/<SHA256(session_id)>/
  .lock
  tr_<controller UUID hex>.result
```

Mỗi `.result` là controller JSON header, newline và full sanitized UTF-8 adapter-returned payload. Header bind project canonical-path hash, session hash, target generation, descriptor và minimum source provenance. Payload có SHA-256, byte length và Unicode character length; provenance có hash riêng. Source locator chỉ ở private header, không đưa vào LLM reference/index. Không dùng EvidenceArtifact.

Store reject malformed IDs trước filesystem access; không nhận pathname từ model. Project inode và storage directories được pin; mở từng component bằng no-follow directory descriptors. Tool-results/session directories mode `0700`; files/lock `0600`, regular, đúng owner, link count 1. Existing `.kagent` phải đúng owner và không writable bởi group/others; không đổi permission của nó.

RLock + flock trên held session-directory inode serialize writers, kể cả nhiều store instances/processes. `.lock` vẫn được kiểm tra owner/mode/nlink và binding, nhưng không còn là serialization domain có thể bị tách bằng pathname replacement. Exclusive temp creation, complete write/flush/fsync, atomic no-replace publication và directory fsync xảy ra trước khi ref được trả ra. Temp link được xóa trước publication transaction trả về. Transaction synchronous và bounded, không có background writer tiếp tục publish sau cancellation/fallback. Collision không overwrite. Commit kiểm tra lại mọi canonical directory edge từ `/` qua project/.kagent/tool-results/session, cùng lock binding, trước link, sau link/unlink/fsync và trước return; failure rollback chỉ inode của transaction qua held descriptors. Reads kiểm tra private file, binding, hash/length và inode/size/mtime/ctime stability. Header provenance dùng unbuffered delimiter-exact reads tối đa 8,192 bytes, không prefetch payload trước sensitive gate; oversized header không được publish.

Caps: **1 MiB/result gồm header**, **16 MiB/session**, **32 results/session** để bound continuation metadata. Refusal deterministic; không tự evict live/saved refs. Artifact sống qua turns/save/resume/compaction. `cleanup(live_refs, saved_refs, stale_before)` chỉ là explicit controller maintenance, trong đúng scoped store; caller phải cung cấp reachability đầy đủ. Không tự chạy khi quota đầy/resume, không xóa authoritative evidence. Stale temp/orphan không thuộc live/saved sets mới được xóa.

## 5. Reread Contract

`read_tool_result(result_ref, start_char, max_chars)` chỉ nhận opaque ref và integers. Reader resolve ref trong current session catalog, project và target generation; đọc bounded provenance header trước sensitive approval, kiểm tra full payload sau gates.

Đi qua Registry prepare/start execution receipts hiện có. Current source adapter phải còn đúng identity; policy từng tồn tại không được biến mất; check revoked source capabilities, project/path restrictions, shell adapter/resource profile, current network origin scope. Active skill phải cho phép original source capability; generic-validation boundary vẫn được kiểm tra trước. Không biến derivative reader thành capability mở generic filesystem.

Fresh read approval có `no_session_cache=True`; sensitive file derivatives còn đi qua existing sensitive-path gate. Exact-range cache key chỉ coalesce cùng Registry invocation, không làm durable/session authorization. Existing runtime yolo semantics giữ nguyên. Owning Agent source capability được check trước Registry approval, sau range approval và sau sensitive-source review. Permissioned shell bị block nếu skill không còn cho phép; non-permissioned FileReadTool vẫn theo existing active-skill semantics. Scope/provenance/current rights được check lại sau permission suspension.

Offsets là **Python Unicode characters**, không phải UTF-8 bytes. Start clamp vào `[0,total_length]`; max clamp vào `[0,2000]`. JSON response tổng cộng tối đa 2,000 chars kể cả escaping/envelope nên content thực tế có thể ngắn hơn. Trả `actual_start`, `actual_end`, `total_length`, `next_offset`, `completeness`, ref/hash, `offset_unit` và `adapter_truncated`. `complete` nghĩa returned end tới EOF của retained payload, không khẳng định adapter đã giữ tất cả upstream bytes.

Reader preserve bounded structured receipt, không recursive offload, không hydrate full output vào history, không rerun original action. Missing/corrupt/unauthorized trả safe retrieval error; preview vẫn dùng được, unseen region phải được báo là chưa đọc.

## 6. Persistence / Compaction

Message thêm optional internal `tool_result_refs` và `tool_result_scope`; existing session schema/persistence/redaction giữ nguyên. Tool message chỉ giữ preview/ref sau admit; system message giữ bounded catalog tối đa 32 descriptors. Internal fields không encode trực tiếp lên provider wire.

Descriptor enum type checks reject arbitrary malformed JSON safely; mixed valid/invalid optional descriptors preserve valid catalog entries, preview/messages and workflow during actual resume. Old sessions thiếu fields vẫn load. Resume restore preview/catalog với đúng project/target/generation, không đọc payload artifact. Missing/corrupt artifact không ngăn preview resume; chỉ reread thất bại. Reset/target revision change rotate generation; đổi target đi rồi quay lại cũng không tái cấp quyền cho old refs. Nếu generation đổi ngay trong turn, guard giữ old preview nguyên trạng kể cả original còn ở transient cache; không rebound bằng ref đã unavailable.

Compaction chuyển offloaded tool content thành compact reference envelope, không nested preview, không hydrate artifact. Tool-call pairing/outcome và provider-private continuation được giữ bởi Phase A structured transform. Catalog attach vào controller-owned system Message độc lập prose summary; prompt index chỉ tool name/ref/length và hướng dẫn retrieval. Không redesign structured handoff.

## 7. Files / Functions Changed

| File | Thay đổi |
| --- | --- |
| `src/agent/agent.py` | `ToolCallResult.__init__` transient execution snapshot; `Agent.__init__` controller-scoped reader; `is_tool_allowed`; `reset`, `resume_saved`, `save`; `rebuild_system_prompt`, `build_system_prompt_with_memory`; `run` pending lifecycle; `guard_working_context`; `run_parsed_tool_call`, `record_tool_result`; `apply_compaction_summary`; `ensure_system_prompt`; `bounded_history_for_compaction`. |
| `src/tools/common/registry.py`, `src/cli/runtime.py` | Live scoped reader view; shared adapter identity/late registration; CLI uses the owning view. |
| `src/agent/tool_results.py` | `PendingResult`, `source_provenance`, `shell_profile`, `reference_header`, `retained_preview`; `ResultRetention` scope/restore/attach/continuation/remember/admit/lookup/current-source validation. |
| `src/session/tool_results.py` | `ResultReference` validation, `ToolResultStore` scoped write/provenance/resolve/cleanup, strict ID and Unicode range helpers. |
| `src/tools/common/tool_result.py` | `ReadToolResult` schema/permission hints/argument and rights validation/gated bounded range execution. |
| `src/llm/core/types.py` | Optional Message reference/scope metadata. |
| `src/session/store.py` | `_message_from_dict`, `Store.save`: additive optional descriptor serialization/validation. |
| `src/permission/runtime/execution.py` | `ExecutionPolicy.validate`: register dedicated reader adapter and call its source-rights validation; existing generic gate runs first. |
| `tests/agent/test_tool_result_offloading.py` | Admission, UI/history separation, redaction, gates, persistence/compaction, execution provenance, concurrency, semantic exclusions/failure regressions. |
| `tests/state/test_tool_result_store.py` | Store isolation/integrity/filesystem/ranges/quota/concurrency/publication/cancellation/cleanup regressions. |
| `tests/ui/test_offloaded_transcript.py` | Actual reducer + app Ctrl-K/O/F behavior with full sanitized tool event. |
| `benchmarks/internal/tool_result_offloading.py` | Real runtime offline Phase A/B comparison with request encoding, persistence/resume and gated reread. |
| `docs/phase-b-tool-result-offloading.md` | This 15-section handoff. |
| `docs/phase-b-tool-result-offloading-measurements.json` | Complete measured output from current implementation. |

## 8. Security Review

No artifact/raw source path in LLM reference/index; no pathname argument, arbitrary read or generic `.kagent` opening. Session/project/target generation isolation and current rights được check; old approval không là durable authorization. Registry có live controller-scoped view cho reader: mỗi Agent giữ reader riêng; source adapters và late registrations vẫn shared với cùng object identity. Agent không có session store không inherit reader của Agent khác. CLI dùng Agent view cho known-tools validation; Registry permission prepare/start/receipt implementation giữ nguyên. Dedicated execution-policy branch thêm reader enforcement, không bypass existing gates.

Sensitive provenance được giữ private, hash-bound và revalidated. Existing sanitizer xử lý secret/injection cases trước UI/store; sanitizer failure không ghi raw payload. Unknown MCP/plugin/search sources bị exclude thay vì suy đoán quyền. Ref không satisfy evidence gate hoặc finding eligibility. Existing workflow/evidence/finding formats không sửa; missing token artifact không invalidate independent valid proof.

Review này gồm code inspection và offline adversarial/regression tests, không phải filesystem security guarantee trên mọi platform. Unsupported POSIX/storage primitives fail closed cho optimization; inline remains available.

## 9. Failure Semantics

| Tình huống | Tested behavior |
| --- | --- |
| Write/disk/quota refusal | Sanitized inline, Phase A bounds, tool success nguyên trạng; không ref. Disk-full path được fault injection bằng write error, không lấp đầy ổ đĩa thật. |
| Sanitizer fails | Existing safe representation-unavailable result; không raw artifact/secret event. |
| Partial write/cancellation/fsync/publication failure | Không ref escape; safe temp/publication cleanup; incomplete result không resolve. Cancellation checkpoint faults được inject trong bounded transaction. |
| Artifact published, session save fails | Existing save failure propagates; không rollback external action; possible orphan được explicit cleanup xử lý. |
| Saved artifact missing/corrupt | Preview resume được; reader unavailable/integrity error; không fallback path hoặc rerun. |
| Ref/binding/hash/length/provenance mismatch | Reject, không use content. |
| Current source denied/revoked/changed | Reread blocked, không reuse old authorization. |
| Missing token artifact / valid proof | Existing proof vẫn resolvable. Missing authoritative proof vẫn theo existing workflow gates. |

## 10. Tests

Historical Phase B implementation/audit counts are preserved in the audit report. They are not verification of this fix tree.

This fix session reproduced the 8 original audit failures before editing. Final audit regressions: **68 passed** in 22.00s, no skips/warnings. Phase A + Phase B selection: **188 passed** in 26.20s, no skips/warnings. Agent/state/Registry/file/CLI/security responsibilities: **1,462 passed, 1 skipped** in 162.36s, no warnings; this selection collected before the unrelated token-accounting audit appeared.

Full suite on the final code/test tree, including all audit regressions and the unrelated newly added `tests/agent/test_token_accounting_audit.py`: **3,971 passed, 1 skipped, 2 warnings** in 344.29s. Both warnings are existing malformed custom-provider configuration sanitation warnings; none was suppressed. The current final pyright command analyzes **375 files**, with **1 error, 0 warnings**, solely in that new file's `DynamicTool` fixture (missing `Tool.run` and `Tool.requires_permission`). The earlier 374-file check passed with 0 errors/warnings. No confirmed Phase B regression is skipped/excluded/xfail. The unrelated file remains unchanged because the requested scope explicitly preserves unrelated worktree changes; no approval to edit it was received. The proposed minimal fixture patch is at `/tmp/kagent-token-accounting-fixture-fix.patch`.

Offline benchmark completed on the final Phase B implementation: all non-latency fields in 12 cases match the previous measurements; JSON and local timing table were updated only from actual output. No external model API calls or dependency installation. Physical disk exhaustion, crash/kill recovery, combined rollback-cleanup failure and cross-platform filesystem stress were not run.

Exact executed selections and current verification state are recorded in section G of `docs/phase-b-tool-result-offloading-audit.md`.

```bash
venv-linux/bin/python -m pytest -q
venv-linux/bin/pyright --outputjson
venv-linux/bin/python -m benchmarks.internal.tool_result_offloading
git diff --check
git status --short
```

## 11. Before / After Measurements

Thực thi `Agent.run`, actual `FileReadTool`, current Phase A guard, session-save, compaction và resume; scripted offline client chỉ thay model response. Baseline tắt Phase B store/admission và reader schema, giữ current Phase A implementation. Không dùng simulation cũ. Request snapshot deepcopy trước history mutation; wire bytes lấy qua existing OpenAI request encoder, không gửi request.

Default threshold 16,000 approximate tokens; relaxed case 64,000. Fixture thêm synthetic Authorization header và distributed canaries. Core inventory: glob/grep/file/shell/http/web_fetch/web_search/load_skill/permissions_status/workflow, cộng reader ở Phase B. Những tool ngoài file_read chỉ đóng góp schemas trong benchmark, không bị execute. Payload sizes là fixture nominal sizes; adapter/sanitized lengths thực tế ghi riêng.

A = Phase A baseline, B = Phase B. Mọi cặp số là **A → B**. Chars là Unicode character counts; bytes là logical file/request bytes. Request tokens là approximate estimate, không phải billed tokens. Multiple/sequential lists là từng result/request theo thứ tự.


| Case | Adapter chars | Sanitized chars | Immediate result chars A → B | Immediate request tokens A → B |
| --- | --- | --- | --- | --- |
| 4KiB | 4155 | 4139 | 4139 → 4139 | 3586 → 3740 |
| 10KiB | 10299 | 10283 | 10283 → 10283 | 5122 → 5276 |
| 40KiB | 41019 | 41003 | 41003 → 41003 | 12802 → 12956 |
| 100KiB | 102459 | 102443 | 52511 → 51895 | 15680 → 15680 |
| multiple_3x40KiB | 41019/41019/41019 | 41003/41003/41003 | 17447/17447/17447 → 17976/17976/15768 | 15680 → 15681 |
| sequential_3x40KiB | 41019/41019/41019 | 41003/41003/41003 | 41003/26185/41003 → 41003/20133/41003 | 12806/15681/12961 → 12960/15680/13190 |
| core_inventory_40KiB | 41019 | 41003 | 41003 → 41003 | 14895 → 15050 |
| near_limit_10KiB | 10299 | 10283 | 3191 → 3191 | 15680 → 15680 |
| core_inventory_100KiB | 102459 | 102443 | 44143 → 43523 | 15680 → 15680 |
| relaxed_100KiB | 102459 | 102443 | 102443 → 102443 | 28165 → 28319 |
| quota_fallback_100KiB | 102459 | 102443 | 52499 → 51883 | 15680 → 15680 |
| write_fallback_100KiB | 102459 | 102443 | 52499 → 51883 | 15680 → 15680 |

| Case | Pre-turn trigger tokens | Next request tokens | Resume request tokens | Compactions / input chars A → B |
| --- | --- | --- | --- | --- |
| 4KiB | 3194 → 3348 | 3598 → 3752 | 3609 → 3763 | 0 / 0 → 0 / 0 |
| 10KiB | 4730 → 4884 | 5134 → 5288 | 5145 → 5299 | 0 / 0 → 0 / 0 |
| 40KiB | 12410 → 12564 | 12814 → 12968 | 12825 → 12979 | 0 / 0 → 0 / 0 |
| 100KiB | 27771 → 15364 | 2690 → 15768 | 2701 → 15779 | 1 / 22731 → 0 / 17.838 |
| multiple_3x40KiB | 32955 → 15401 | 2690 → 15805 | 2701 → 15816 | 1 / 22731 → 0 / 16.991 |
| sequential_3x40KiB | 12461 → 12690 | 12973 → 13202 | 12984 → 13213 | 1 / 22730 → 1 / 14.784 |
| core_inventory_40KiB | 14503 → 14658 | 14907 → 15062 | 14918 → 15073 | 0 / 0 → 0 / 0 |
| near_limit_10KiB | 17061 → 15363 | 2690 → 15767 | 2701 → 15778 | 1 / 22731 → 0 / 12.516 |
| core_inventory_100KiB | 29863 → 15364 | 4779 → 15768 | 4790 → 15779 | 1 / 22731 → 0 / 14.565 |
| relaxed_100KiB | 27773 → 27927 | 28177 → 28331 | 28188 → 28342 | 0 / 0 → 0 / 0 |
| quota_fallback_100KiB | 27774 → 27928 | 2690 → 2844 | 2701 → 2855 | 1 / 22731 → 1 / 22731 |
| write_fallback_100KiB | 27774 → 27928 | 2690 → 2844 | 2701 → 2855 | 1 / 22731 → 1 / 22731 |

| Case | Immediate request wire bytes | Next request wire bytes | Resume request wire bytes |
| --- | --- | --- | --- |
| 4KiB | 14875 → 15492 | 15000 → 15617 | 15117 → 15734 |
| 10KiB | 21020 → 21637 | 21145 → 21762 | 21262 → 21879 |
| 40KiB | 51740 → 52357 | 51865 → 52482 | 51982 → 52599 |
| 100KiB | 63257 → 63298 | 11173 → 63728 | 11290 → 63845 |
| multiple_3x40KiB | 63651 → 63767 | 11173 → 64346 | 11290 → 64463 |
| sequential_3x40KiB | 51753/63577/52496 → 52370/63618/53417 | 52621 → 53542 | 52738 → 53659 |
| core_inventory_40KiB | 60115 → 60732 | 60240 → 60857 | 60357 → 60974 |
| near_limit_10KiB | 63330 → 63371 | 11173 → 63800 | 11290 → 63917 |
| core_inventory_100KiB | 63264 → 63301 | 19533 → 63731 | 19650 → 63848 |
| relaxed_100KiB | 113189 → 113806 | 113314 → 113931 | 113431 → 114048 |
| quota_fallback_100KiB | 63260 → 63261 | 11173 → 11790 | 11290 → 11907 |
| write_fallback_100KiB | 63260 → 63261 | 11173 → 11790 | 11290 → 11907 |

| Case | Session JSON bytes | Artifact bytes A → B | Total disk bytes | Ref metadata / envelope chars B |
| --- | --- | --- | --- | --- |
| 4KiB | 12849 → 13079 | 0 → 0 | 12849 → 13079 | 0 / 0 |
| 10KiB | 18994 → 19224 | 0 → 0 | 18994 → 19224 | 0 / 0 |
| 40KiB | 49714 → 49944 | 0 → 0 | 49714 → 49944 | 0 / 0 |
| 100KiB | 111155 → 62013 | 0 → 103250 | 111155 → 165263 | 425 / 616 |
| multiple_3x40KiB | 132621 → 65034 | 0 → 125454 | 132621 → 190488 | 1269 / 1842 |
| sequential_3x40KiB | 50715 → 51696 | 0 → 41820 | 51144 → 93945 | 423 / 614 |
| core_inventory_40KiB | 49729 → 49959 | 0 → 0 | 49729 → 49959 | 0 / 0 |
| near_limit_10KiB | 68724 → 62418 | 0 → 11098 | 68724 → 73516 | 423 / 614 |
| core_inventory_100KiB | 111170 → 53656 | 0 → 103265 | 111170 → 156921 | 425 / 616 |
| relaxed_100KiB | 111163 → 111393 | 0 → 0 | 111163 → 111393 | 0 / 0 |
| quota_fallback_100KiB | 111170 → 111400 | 0 → 0 | 111170 → 111400 | 0 / 0 |
| write_fallback_100KiB | 111170 → 111400 | 0 → 0 | 111170 → 111400 | 0 / 0 |

Disk snapshot lấy **trước next-turn compaction**: session + result artifacts + existing context snapshots; không gồm synthetic source fixtures, filesystem allocation blocks hoặc lock inode. Sequential case gồm 429 bytes existing context snapshot mỗi bên; các case khác chưa có snapshot tại thời điểm đo. Session bytes sau compaction không được dùng để thay thế snapshot này.


| Case | Phase A guard dropped chars | Phase B guard dropped chars | Residual tokens A → B | B reread chars / tokens / local ms |
| --- | --- | --- | --- | --- |
| 4KiB | 0 | 0 | 0 → 0 | — |
| 10KiB | 0 | 0 | 0 → 0 | — |
| 40KiB | 0 | 0 | 0 → 0 | — |
| 100KiB | 49932 | 0 | 0 → 0 | 456 / 114 / 17.838 |
| multiple_3x40KiB | 70668 | 22564 | 0 → 1 | 455 / 113 / 16.991 |
| sequential_3x40KiB | 29636 | 15128 | 1 → 0 | 455 / 113 / 14.784 |
| core_inventory_40KiB | 0 | 0 | 0 → 0 | — |
| near_limit_10KiB | 7092 | 0 | 0 → 0 | 452 / 113 / 12.516 |
| core_inventory_100KiB | 58300 | 0 | 0 → 0 | 456 / 114 / 14.565 |
| relaxed_100KiB | 0 | 0 | 0 → 0 | — |
| quota_fallback_100KiB | 49944 | 50560 | 0 → 0 | — |
| write_fallback_100KiB | 49944 | 50560 | 0 → 0 | — |

Guard dropped counts chỉ đếm Phase A guard events, không đếm ký tự mà admission đã thay bằng preview. Vì vậy 0 ở B không có nghĩa không giảm context. Residual 1 token trong multiple B và sequential A là accounting/rounding pressure được báo rõ, không bị giấu.


Reader schema overhead: **615 chars, ~153 tokens** theo floor estimate của schema riêng; actual request delta ở small-inline cases là ~154 tokens. Ref metadata khoảng 423–425 chars/result, envelope 614–616 chars/result, ngoài optional session scope/catalog. Một reread yêu cầu 128 content chars dùng **1 additional tool call**, 92 argument chars và 452–456 reply chars (~113–114 reply tokens). Latency trong bảng là local offline runtime/approval-fixture elapsed, không gồm real operator/model/network delay.


Head/middle/tail canaries sống trong **mọi result**, kể cả multiple/sequential. Mọi offloaded preview đã bỏ gap canary; mỗi case có artifact đọc lại gap thành công qua actual gated reader. JSON lưu per-result fidelity, reductions, residuals và full request-size observations.


**Diễn giải:** 4/10/40 KiB và relaxed 100 KiB không offload; near-limit 10 KiB được admit. 100 KiB giảm pre-turn estimate từ 27,771 xuống 15,364 và session JSON từ 111,155 xuống 62,013 bytes; tránh một compaction nhưng total disk tăng từ 111,155 lên 165,263 bytes. Immediate Phase A request vốn đã được guard bound, nên B không luôn tạo request nhỏ hơn: wire bytes ca này tăng nhẹ 63,257 → 63,298. Next request A đã compact nên chỉ 2,690 tokens; B giữ preview không compact nên 15,768 tokens. Không dùng sự khác nhau này để tuyên bố mọi request hoặc tổng disk đều giảm. Sequential vẫn compact một lần ở cả hai bên và chỉ result còn trusted original tại pressure point được offload; không backfill result cũ. Quota/write refusal giữ artifact bytes = 0 và existing fallback/compaction behavior.


## 12. Remaining Limitations

- Full artifact chỉ là sanitized adapter-returned output. Existing shell/file/HTTP/MCP caps và captured/evidence branches là authority; không phục hồi upstream bytes adapter đã bỏ.
- Approximate token accounting không thay tokenizer của provider. Safety margin/floor inherited; không bảo đảm mọi request dưới hard provider limit nếu semantic/nonreducible context quá lớn.
- Preview vẫn có omitted regions. Reread thêm tool call, bounded response và fresh approval; local latency không bao gồm người duyệt hoặc model/network latency. Hash verification đọc capped payload vào transient runtime memory, không hydrate LLM history.
- Total disk có thể tăng rõ vì giữ artifact lẫn preview. Quotas có thể từ chối result mới sau 32 publications; không auto-GC hoặc session-deletion integration. Explicit cleanup cần full live/saved reachability, không nên gọi với incomplete sets.
- Filesystem mutation tests require same-UID access to private storage. Directory flock prevents `.lock` replacement splitting the writer domain; commit checks reject the tested directory/ancestor replacement timings. These checks are observations, not an atomic namespace lease: hostile same-UID mutation after the last check or arbitrary direct writes can still invalidate retention. Model tools cannot infer rights to protected `.kagent` from these tests.
- POSIX no-follow/flock/no-replace semantics cần filesystem hỗ trợ; không benchmark Windows/remote filesystems. Bounded synchronous fsync có thể block event loop ngắn; đổi sang background I/O cần cancellation-safe transaction riêng.
- Grep/search/glob/MCP/plugins/unknown classes deliberately unsupported. Các nguồn này cần trusted source-specific contracts trước khi admit.
- Không backfill old turns khi original đã hết runtime lifetime. Sequential fixture vẫn compaction một lần; không hứa offloading loại bỏ mọi compaction.
- Live UI giữ full sanitized event và Ctrl-K/O/F; không thêm transcript replay full output sau restart.
- Tests include threaded and spawned-process overlap, count/byte quotas, link/unlink/directory-fsync binding replacement, and post-publication cancellation/rollback. Cleanup failure combined with hostile substitution, process-kill/crash recovery, physical disk-exhaustion and cross-platform stress remain unverified. Không gọi external model APIs.

## 13. ToolResult Normalization Follow-up

Existing adapters trả string hoặc structured outcomes khác nhau. Một số string adapters thể hiện caps bằng text marker thay vì structured `truncated` field; descriptor chỉ giữ metadata hiện có, không tự suy ra authoritative outcome từ marker. `ToolCallResult` chỉ thêm hai transient provenance fields phục vụ Phase B. Nếu muốn thống nhất adapter status/truncation/provenance contracts, làm ở follow-up riêng có responsibility tests; không implement broad normalization ở đây.

## 14. Scope Confirmation

**NO** planner changes; **NO** requested-goal semantic changes; **NO** workflow semantic changes; **NO** evidence/finding eligibility changes; **NO** broad ToolResult normalization; **NO** structured handoff redesign; **NO** external model API calls; **NO** stage/commit/push. Không thêm dependency, general artifact framework hoặc generic filesystem access. Dừng ở Phase B.

## 15. Verdict

**PARTIALLY FIXED — all six production fixes/regressions pass; final type check blocked outside scope.** Full suite: 3,971 passed, 1 skipped, 2 existing warnings. Pyright: 375 files, 1 error solely in the newly added unrelated token-accounting fixture. The file was preserved; FIXED AND VERIFIED is withheld until that final check passes. No required command was omitted. No Phase C, broad normalization, structured-handoff redesign, production token-accounting changes, installation, external model calls, staging, commits or pushes.
