# Kiểm lại checklist 3–8 — 02/10/2026

**570 regression controls đạt, cộng 3 probe OFF/ALLOW thực thi thật đạt. Không
failure, error hoặc skip trong các nhóm đã chọn. Không sửa code sản phẩm.**
Đây là kiểm chứng fixture/mock/loopback tuần tự trên WSL Ubuntu/Linux, không gọi
DeepSeek/model API, không gửi phép thử tới target Juice Shop đang mở của operator.
Không thay policy/grant của phiên UI `3f381ac2c69e4d48bc1a94d3585e2aa8`.

## Các nhóm đã chạy

| Nhóm | Passed | Bằng chứng |
|---|---:|---|
| CLI/policy/mode/approval | 44 | mode_cli_policy.xml, .log |
| HTTP grant/lifecycle | 79 | http_grants_lifecycle.xml, .log |
| File/sensitive/evidence | 53 | files_evidence.xml, .log |
| Worker/shell/plugin/MCP/ffuf và proof controls | 87 | workers_mcp_findings_controls.xml, .log |
| Finding/workflow/memory/resume | 195 | finding_memory_resume.xml, .log |
| HTTP/discovery/fetch/search/private-host regression | 112 | network_regression.xml, .log |
| OFF → operator ALLOW → actual worker HTTP, shell/plugin/MCP | 3 | off-worker-positive.xml |

570 là tổng sáu nhóm của `results.json`, không cộng với 2.692 regression lịch sử
hay lượt chạy trước. Ba probe bổ sung nằm riêng, được chạy sau test groups và
pyright để không cạnh tranh real-UID NPROC. Pyright src/tests **0 errors,
0 warnings**; thông báo new-version không được xử lý bằng cài package. Diff check
đạt. HEAD giữ `b1057dcf7de9478c1649a35612d3bebeb3824303`, không commit/push/reset.

## Đối chiếu checklist

| Mục | Đã chứng minh trong lượt này | Chưa được chứng minh |
|---|---|---|
| 3. ON tự chạy | Native HTTP phase/method/payload/new endpoint controls; source/payload/sensitive lab/artifact; discovery/fetch/search mocks; actual Linux shell/plugin/stdin MCP/ffuf lab HTTP; không cần manual grants/permission asks trong selected positive paths | Toàn bộ playbook, live login/CRUD/cleanup, configured integrations thực của operator và autonomous whole-target |
| 4. OFF ordinary approval | Exact DENY không dispatch; repeat suppression; preview dài/redact/effective args freeze; confirm-each restoration. Ba probe mới: actual shell/plugin/MCP HTTP thành công, đúng 1 approval ask mỗi tool, không autonomous/manual HTTP grant, slot được giải phóng | Full UI button interaction và mọi tool/config generation combination trong phiên đang mở |
| 5. Scope/lifecycle | Scheme/host/port ngoài scope; revoke/deny; phase không mở quyền; expired/budget/byte limits; concurrent atomic reservation; mode/target/scope đổi khi chờ; replay/args tamper/cancel; exact denial không deny phiên | Distributed atomicity, every adapter under real concurrent lifecycle changes, rollback các request đã gửi |
| 6. File/evidence | Actual CLI protected-root factory; approved/denied sensitive capture/reread/resume; managed snapshot đọc qua workflow nhưng generic `.kagent` read bị chặn; hash tamper/rename/provenance; actual worker protected host/symlink/direct sockets/hardlink/FIFO/child controls | General race-proof filesystem broker; secret chưa biết nằm trong allowed lab input; source-to-export context isolation |
| 7. Finding/memory/resume | Production narrow SQL boolean-query/JSON-row loopback chain → coverage → canonical finding → cert resume; model prose/overclaim không đủ; imported unreviewed proof blocked; human review mechanics cho15classes; terminal coverage claims gated; receipt/rights không deserialize từ summary/memory; deny/budget persistence; untrusted-memory canary không đặt system role | Trusted browser execution/actor proofs; auto verifiers mọi lớp/kỹ thuật; cleanup/negative/performed completion; immunity của model với text ở user-role; toàn vẹn ngữ nghĩa khi target cố lừa |
| 8. Missing enforcement | Missing worker/adapter blocks before permission và dispatch; real worker direct-network forbidden; blockers không được tính thành positive pentest acceptance | nmap/raw TCP/CONNECT/remote hoặc persistent/env MCP chưa được hỗ trợ; complete egress, actor/export, non-Linux sandbox, all-route DNS và aggregate cgroup limits |

Search/fetch transport tests dùng actual HTTPX Request/Response và MockTransport;
không gọi public search provider thật. Process tests chạy bwrap/prlimit và
installed curl/Python/ffuf thật, kết nối loopback fixture qua broker, không phải
mock sandbox success. SDK MCP fixture là local stdio server thật, không phải mọi
configured upstream MCP. Những test library unbound chỉ chứng minh contract của
library; bound CLI guarantee lấy từ CLI/policy/worker controls riêng.

Finding fixture SQL chỉ chứng minh hợp đồng differential hẹp đang shipped, không
chứng minh target thật có backend SQL hay mọi kỹ thuật SQLi. Human-review cases
dùng synthetic proof và kết luận có nhãn operator-reviewed, không phải15 auto
vulnerability detections. Coverage `failed` trong positive SQL test nghĩa là
phép kiểm tra phát hiện lỗ hổng, không phải pytest failure.

Stimuli injection/canary được dùng ở payload/response/memory và scripted proposals;
không dùng paid model để đo nó có bị thao túng hay không. Test chứng minh resource
checks đã dựng, không chứng minh chống prompt injection toàn diện.

## Tái chạy

Runner chính: `../run_remaining_checklist.py` tạo result directory mới theo thời
gian, không ghi đè lịch sử. Probe bổ sung: `../checklist_off_worker_probe.py`.

```sh
cd /mnt/d/DOANTOTNGHIEP/kagent
source venv-linux/bin/activate
python -B artifacts/audits/yolo-all-tools-2026-10-02/run_remaining_checklist.py
python -B -m pytest -q -p no:cacheprovider artifacts/audits/yolo-all-tools-2026-10-02/checklist_off_worker_probe.py
```

Chạy tuần tự, dùng binaries đã có; không cài dependency hoặc chạy live harness.
