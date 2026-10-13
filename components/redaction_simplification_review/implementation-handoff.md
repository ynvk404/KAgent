# Redaction simplification implementation handoff

Date: 2026-10-13 (Asia/Saigon). Baseline HEAD: `8fb8d9ecf56549473417776332665bcc35d95b60`, including the pre-existing Browser/Burp worktree patch.

**Operator's final policy:** “Giữ contract hiện tại, cho phép lưu raw trong lab.” This supersedes the original requirement to omit full bodies from durable state. There is one lab usage policy, no `--lab-fidelity` flag, no configuration mode, no new runtime/framework/class, and no Observation/Evidence schema version migration. Explicitly authorized lab usage is a documented operating constraint; private addresses, capture metadata and scope do not establish that a target is a lab.

## 1. Baseline and preservation

Read `AGENTS.md`, `audit-design.md`, `probe-results.json`, relevant producers/stores/tests, and the SQLi/XSS allowed-tool and completion contracts. Baseline diff and file hashes were saved outside the repository under `/tmp/kagent-lab-fidelity-baseline-hjen8_nm/`.

Existing changes in `src/browser/mcp_server.py`, `src/browser/redacted_view.py`, their browser tests, `tests/tools/test_browser_capture.py`, `tests/integration/test_burp_offline_audit.py`, and `tests/browser/test_response_passthrough.py` were preserved. Only `src/tools/common/browser_capture.py` received additional producer provenance on top of its existing patch; integration test additions preserve the original response-passthrough assertions. The audit artifacts remain unchanged. No reset/restore/clean/install/commit/push was performed.

The initially prepared additional abstraction and Observation/Evidence versioning were removed when the operator narrowed the implementation. Those files contain no leftover migration. `related_requests`, Evidence TOCTOU, `Observation.complete`, skills, planner, dispatch scheduling, permissions, scope and grants are unchanged.

## 2. Production and regression changes

Production:

- `src/tools/http/http_tool.py`: retain bounded native decoded response bytes/body text after genuine runtime execution; protect request previews and labelled headers separately; carry observation IDs/hashes and body character ranges through redirects.
- `src/tools/common/browser_capture.py`: retain the existing getter JSON/aliases/excerpt behavior and attach controller metadata only after scoped runtime access.
- `src/permission/runtime/observations.py`: internal `retain_body` admission at existing capture call sites; scoped import provenance; private temporary file creation before writing raw proof. Existing persistence location, final mode, hashes and lifecycle remain intact.
- `src/tools/common/outcome.py`, `src/llm/core/types.py`: small provenance fields on existing types. `ToolOutput` stays a string; `Message` stays the existing provider input type.
- `src/agent/agent.py`: verify canonical adapter, current execution/session/scope, source hash and access rights before admitting HTTP text. Presentation/debug events carry source metadata. Recheck source access and actual managed credentials before outbound and before formatting compaction/context snapshots.
- `src/session/store.py`, `src/agent/compaction.py`: preserve admitted HTTP content without rescanning it; retain normal protection for other content, arguments and provider-private state. Sessions save source IDs, never execution receipts/stamps or new grants.
- `src/agent/tool_results.py`: exclude admitted raw HTTP from the existing sanitized offloading cache. Existing context bounding and other cache capabilities remain.
- `src/permission/runtime/execution.py`, `src/cli/runtime.py`: supply actual provider/manual/custom-profile key slots and the Bridge credential to the existing controller's exact-value protection. The closure reads current configuration and does not mutate provider configuration.
- `src/redaction/redact.py`: parse valid JSON envelopes before recursive masking; remove unconditional public-digest inference while retaining labelled credential/password-hash rules and shared APIs.
- `src/memory/store.py`: redact explicit description before its filename/index/persistence use.
- `readme.md`: disclose lab-only usage, external LLM body transfer, raw private persistence, decoding/bounds and the internal-secret exception.

Tests: new `tests/security/test_http_body_fidelity.py`; focused updates in redaction, output pipeline, observation grounding, captured replay, agent assessment and memory tests. Burp/validation/scenario helpers parse controller metadata without asserting the old “redacted capture” prose label. Assertions for completeness, ownership, integrity, permissions and finding eligibility remain.

## 3. Actual trust admission

Native HTTP admission requires the exact canonical adapter, the same engagement/target binding, a current registry execution context, the invocation digest and current target/scope/epoch. HTTP authorization, private-host review, reservation and send precede body retention. No gate is replaced.

Capture admission requires the native getter bound to `ScopedCaptureStore` with the current execution policy and receipt. Its imported source is explicitly `imported-capture`, with original actor/receipt/wire hashes unknown. Import is not native execution or authentication proof.

The Agent verifies out-of-band `ToolOutput` source IDs/hashes, session and policy stamp against actual owned observations. Native body ranges must match the recorded bytes after the producer's decoding. Capture admission also checks the current capture's method, origin, timestamp and bounded body hash. Access/revocation is checked again before sending tagged HTTP messages.

Generic MCP content, `raw=true`, self-declared owner/origin/source kind, a tool name or `status=observation` cannot create this metadata. Standalone Capture MCP/Bridge keep their existing direct-client passthrough contract; a generic MCP result entering the Agent remains protected.

## 4. Content contracts and storage consent

No independent representation pipelines or new stores were introduced. Existing tool execution, history, Observation and workflow objects carry the data.

- Runtime: native bounded decoded **bytes** stay in `Observation.body`; native Agent content is the corresponding `decode(errors='replace')` string. Capture is the existing capped **string**, sliced according to the getter contract; import retains its bounded UTF-8 bytes. Neither is described as original wire traffic.
- Agent/LLM: approved HTTP body text remains exact within producer/context bounds unless an actual managed internal secret requires explicit omission. Authorization/Cookie request headers are not newly exposed.
- Durable: the operator approved raw bounded HTTP bodies in private observations/manifests/sessions/context archives. They may contain target credentials. Hex is serialization, not encryption. Other transcript fields, provider state, memory/intelligence, findings and report exports keep their existing guards/minimization.
- Presentation: admitted HTTP tool events expose source metadata and existing status/receipt fields rather than full traffic. Existing terminal/markup escaping remains. Display text is not validation evidence.

Temporary observation output now requests mode `0600` before its first write; final observation/session mode remains `0600`. Linux temporary-store regressions verify this. Storage paths and lifecycle are unchanged. Effective privacy still depends on the host filesystem/ACLs; these are not encrypted archives.

## 5. HTTP/Capture → Agent/LLM verification

Offline mocked native HTTP and real scoped getter calls feed the real Agent and its next `FakeClient` request. Fixtures cover red/sky tokens, SQLi TRUE/FALSE, IDOR owners, CSRF/auth tokens, Cookie-value collisions, public SHA256, credential-shaped target values, XSS/compound markers, encoded values, HTML, malformed JSON, Unicode and invalid UTF-8 native bytes.

Tests cover valid nested pretty/compact MCP envelopes, stable repeated saves/compaction, getter aliases, private persistence, zero/default/max caps, metadata-only mode, redirected hop bodies and source hashes. Wrong owner/origin/session, spoofed tool identity and revoked access withhold raw admission without changing the original execution outcome or rerunning HTTP.

## 6. Observation/Evidence integrity and resume

There is **no new version/schema** on Observation/Evidence, no historical rewrite and no migration/reseal. Existing `response_hash` hashes captured producer bytes; `retained_hash` hashes the existing source envelope including retained body. For newly admitted complete bounded native responses, body and response hash agree. Imported body hashes describe the bounded captured-string UTF-8 representation, not original wire bytes.

`source_row`, hex manifests, selected sources, byte excerpt checks, result seals and Finding bindings are unchanged. Raw bytes are stored **before** computing the existing retained envelope hash. They are not masked/omitted after sealing. The regression confirms a terminal assessment, raw parent manifest, private source resume and unchanged historical result seal.

Existing immutable Evidence snapshots remain durable derivatives governed by their existing reads, redaction, byte hash and content-addressed path. Public digests are no longer inferred to be secrets. No TOCTOU or binary-proof behavior was changed. Legacy masked observations stay masked and retain their hashes; they are not relabelled raw.

Resume restores actual retained source bytes when the corresponding observation or selected manifest exists. Missing/evicted source does not hydrate new raw proof from transcript/display text. Historical accepted findings keep their original result/evidence contracts and grant no new execution permission.

## 7. Internal credential boundary

Protection uses actual managed values: the active client's key, current/saved provider key slots and Bridge token. Values/callbacks are not copied to messages, profiles, transcripts or source metadata. Request previews protect these values before hex encoding. No target-body key-name/entropy/API-key-shape regex is used for admission.

If an actual full managed value occurs in an admitted outbound body, native output omits that body with an explicit non-exact marker; Capture output replaces both body aliases and adds `analysis_body_exact=false` while keeping JSON valid. Raw Observation bytes and hashes remain unchanged and remain the validation source.

This is not a global firewall for model/user-authored content or every possible secret encoding. Under the final raw persistence consent, a managed value reflected into the **raw target body** can also remain in private raw proof storage; outbound omission does not claim zero-secret-at-rest. Configuration secrets are not automatically inserted into that storage.

## 8. Compaction/cache/export behavior

Admitted HTTP content is excluded from repeated shared-redactor scans during session serialization and compaction formatting. Other content follows the existing safeguards. Controller compaction/context snapshots check access before converting tagged tool content into a formatted string. Context archives explicitly disclose that lab HTTP bodies may be raw.

Admitted raw HTTP is not placed in the sanitized tool-result cache. The existing context guard still bounds it; validation uses Observation/source manifests. Generic file/shell/research/MCP offloading and its permissions/owner/hash guards are unchanged.

Findings/reports and reusable memory/intelligence are not raw HTTP archives. Confirmed gates and export minimization remain; explicit memory description now shares the existing intake redactor. Shared redaction succeeding is not represented as proof that arbitrary content contains no secret.

## 9. Verification record

No live targets, external LLM or paid API were used. Fixtures use MockTransport/FakeClient, temporary stores and existing local synthetic harnesses. Opt-in live characterization/container flags were OFF; configured skips were preserved.

- Observation/Evidence checkpoint: **130 passed**.
- Session/compaction/cache/debug checkpoint before routing: **190 passed**.
- Initial activated focused responsibility group: **234 passed**.
- Extended response/trust/evidence tests before the final small additions: **72 passed**.
- Updated assessment/memory/response group: **161 passed**.
- Burp/Capture/independent candidate recovery group after semantic receipt parsing: **44 passed**.
- Combined acceptance plus offline scenarios: **418 passed** before the final private-temp/context-label tests.
- Broader initial run: **4447 passed, 18 failed, 1 skipped**. Thirteen failures were superseded masking/receipt-label expectations subsequently covered by passing focused/acceptance runs. The mounted responsiveness test passed independently; no threshold was changed. Four baseline limitations remain below.
- Final focused run after the private-temp, context-label and accessor-failure additions: **225 passed**.
- Final Pyright (configured `venv-linux`): **0 errors, 0 warnings**, 543 files.
- Full offline suite: **6923 passed, 51 failed, 13 errors, 18 skipped, 3 xfailed**, 2 existing config warnings; 7008 collected tests, 1185.87 seconds. Default import collection encountered two pre-existing same-basename test files; the runnable full command uses `--import-mode=importlib`, without deleting caches or changing pytest configuration. The last accessor-failure regression was subsequently included in the passing final focused run.
- `git diff --check`: passed; final diff/status and original-patch preservation were inspected.

Full command:

```bash
PYTHONDONTWRITEBYTECODE=1 \
KAGENT_RUN_LIVE_TOOL_CHARACTERIZATION=0 KAGENT_S1_EXISTING_CONTAINER='' \
venv-linux/bin/python -m pytest -p no:cacheprovider \
  --import-mode=importlib -q --tb=short
```

Baseline limitations reproduced without editing expectations or provider code:

1. `tests/integration/test_tool_schema_budget.py` and `test_hybrid_schema_budget.py`: existing default schema **29,590 characters**, cap **28,000**. Native/Capture public name/description/schema ASTs are identical to reconstructed HEAD + original worktree patch; this implementation adds no public tool schema fields.
2. Anthropic/Gemini cases of `tests/llm/test_workflow_action_projection.py::test_transport_retry_keeps_encoded_projection_snapshot`: retry observes changed projected tool schema. Both fail with original HEAD request/message classes; OpenAI-compatible/DeepSeek cases pass. Provider and action-projection source files are unchanged. Provider retry repair is explicitly excluded from this task.
3. Scenario 1 benchmark family: **44 failures + 13 fixture errors**. The unchanged benchmark runtime generates `body=None` in its designated baseline; the native HTTP adapter requires a string when `body` is present. Transport is never reached, causing missing terminal evidence/metrics/findings and cascading export/recovery failures. A minimal reproduction using the original HEAD validator also raises `body must be a string`; the validator and `_prepare_with_diff` ASTs and benchmark runtime are identical to baseline. No benchmark fix or input/permission weakening was made.
4. Two `tests/ui/test_candidate_recovery_contract.py` expectations require the old error text in the recovered transcript entry; the unchanged reducer renders a recovery summary instead. Both failures reproduce with the original HEAD `Agent._tool_result_event`. The recovery assertions otherwise pass; no UI expectation was changed.
5. `tests/cwe/test_enrichment.py::test_evidence_receipt_uses_existing_readonly_workflow_action`: its test-local `prepare(tool, args)` monkeypatch cannot accept the existing registry's `reviewing`/`signal` keyword arguments. The diagnostic is `CWE enrichment: TypeError`. Registry, CWE enrichment and the production `prepare` method are unchanged. No assertion or fixture was weakened.

Thus the final full suite remains non-green. The 51 failures consist of 44 benchmark failures, the four schema/provider failures and the three UI/CWE failures above; fixture errors are all in the same benchmark finding family. The mounted responsiveness oracle that failed during the earlier concurrent broader/typecheck run passes independently and in the final full run.

Temporary run logs: `/tmp/kagent-lab-fidelity-{acceptance,broader,full,baseline-limitations,capture-final,final-focused}.txt`; Pyright JSON: `/tmp/kagent-lab-fidelity-pyright.json`.

## 10. Limitations and independent verification checklist

The final policy intentionally allows credential-bearing lab bodies to external LLMs and private raw archives. It does not automatically recognize labs, encrypt archives, authenticate original Capture actors or provide a universal outgoing-secret firewall. Historical masked data cannot be recovered. Compaction summaries remain lossy/model-authored; native invalid UTF-8 is decoded with replacement for LLM text while runtime bytes remain exact. Source eviction can withhold future tagged context; it does not reverse historical findings.

Independent verification should:

- Review the final operator consent and README; confirm there is no new redaction flag/mode/runtime class or Observation/Evidence version.
- Recheck actual production storage ACLs/modes, raw hex disclosure and retention limits, including temporary writes, private session/context files and source eviction/resume.
- Reproduce next-FakeClient native/Capture bodies, aliases, caps and byte/character distinctions; verify known internal-secret omission leaves source bytes/hash unchanged.
- Attempt generic MCP spoofing, wrong-owner/session/origin, changed/removed captures and revocation before outbound; verify execution gates and dispatch counts remain intact.
- Check raw primary hashes/ranges, sealed manifests, old masked evidence, historical confirmed finding eligibility, missing-source behavior and sanitized proof/report exports.
- Verify cache exclusion, terminal controls, snapshot credential guards, Cookie jar/captured replay, memory authorization exclusions and `related_requests` tests.
- Run the final recorded suite/typecheck commands and separately address the unchanged schema-budget/provider-retry failures without weakening their tests.

**IMPLEMENTATION COMPLETE WITH LIMITATIONS**

Production changes and focused acceptance are complete. Full-suite failures and raw storage/disclosure limitations are disclosed above. Stop here for the separately requested Independent Verification session; no independent review, live engagement, commit or publication was performed.
