# Rà soát worktree và đóng gói nghiệm thu

## Phạm vi kiểm kê

Kiểm kê ban đầu: **15.338 entries** gồm 716 tracked (hai file đã được xóa
trong thay đổi trước cleanup), 182 untracked và 14.440 ignored; tương ứng
15.336 file đang tồn tại. Đã đối chiếu worktree, index ban đầu rỗng, branch
`main`, lịch sử/refs/reflogs, các file binary/lớn và quy tắc ignore. Các script
kiểm kê và bản diff nguyên trạng được giữ ngoài repository trong thư mục tạm.

## Phân loại và xử lý

| Nhóm | Nội dung | Xử lý |
| --- | --- | --- |
| A — commit | Source, tests/regressions, hai skill recon/enumeration, benchmark Stage 2, báo cáo Stage 1/2/3 và Milestone C | Giữ nội dung đã nghiệm thu; stage từng đường dẫn cụ thể |
| A — evidence | Manifest freeze gốc, kết quả cuối, JUnit đầy đủ đã vệ sinh, log cuối, scripts và provenance | Đóng gói tại `verification-milestone-c/` |
| B — local | `venv-linux/`, `.kagent/`, `artifacts/`, IDE settings, cấu hình benchmark local, Python/test caches | Giữ nguyên, không commit |
| C — có thể tái tạo | Cache và outputs intermediate/duplicate | Không xóa; ưu tiên ignore để bảo toàn bằng chứng |
| D — ngoài phạm vi | `components/browser_mcp/LATENCY_CLI.md`, `scripts/browser_latency_protocol.mjs` | Giữ nguyên các exclusion local hiện có, không đưa vào commit |
| D — cần quyết định riêng | Loose Git object hỏng, không được refs/reflogs/index tham chiếu | Giữ nguyên, không sửa lịch sử hoặc xóa object |

`benchmarks/recon_stage2.py` là microbenchmark offline dùng dữ liệu giả lập,
đo insert/dedup/frontier và parse/admission HTML/OpenAPI. Nó không gửi HTTP
hay chạy agent/model. Vị trí trong `benchmarks/` phù hợp; implementation nằm
trong `src/workflow/` và các tool liên quan.

Không thực hiện bất kỳ thao tác xóa file nào. `.gitignore` bổ sung vùng raw
`docs/verification-stage3/`, output verification local và các cache/environment
Python thông dụng. **191 raw evidence files, 12.596.007 bytes**, được giữ
nguyên và có chỉ mục đường dẫn/kích thước/SHA-256. Cache nằm trong vùng này
không thuộc chỉ mục evidence. Bốn báo cáo nghiệm thu được chuẩn hóa đường dẫn
máy cá nhân và liên kết tới evidence có thể công bố hoặc chỉ mục archive local.

## An toàn dữ liệu

Đã quét candidate source/docs/evidence cho private keys, provider keys, JWT,
credential-bearing URLs, Authorization/Cookie literals và secret assignments;
kiểm tra riêng đường dẫn cá nhân trong documentation/artifacts. Các literal
được giữ trong tests là fixture tổng hợp để kiểm tra redaction, credentials
và negative cases; không phải credential lấy từ runtime/lab. Không đưa `.env`,
session/database, API config local hoặc virtualenv vào candidate commit.

JUnit công bố giữ đủ test cases/status/time/skips nhưng bỏ hostname và
diagnostic properties, thay 45 parameter IDs có dạng dữ liệu nhạy cảm bằng
nhãn hash. Các original logs/XML vẫn giữ local; `provenance.json` phân biệt
hash bản gốc với hash bản công bố. Không chỉnh sửa số lượng pass/fail/skip.
Đây là rà soát theo mẫu và ngữ cảnh source, không phải chứng minh tuyệt đối
rằng mọi nội dung lịch sử Git không có dữ liệu nhạy cảm.

## Bảo toàn verification

Cleanup chỉ chỉnh `.gitignore`, documentation và verification utilities dưới
`docs/`; không chỉnh production, tests, skills hay cấu hình runtime/test đã
freeze. Đối chiếu lại **715 files** với SHA-256:

`76168e98a362ef43f4636dc745fc356cfa57a425e59f89ec842b5b174bce653c`.

Manifest lịch sử bao gồm hai file ignored: cấu hình benchmark local và script
latency nói trên. Giữ nguyên manifest, không công bố hai file này. Bản clone
mới có thể đối chiếu **713 versioned source files** với hash gốc; không thể
tự nhận đã khớp aggregate 715 file nếu thiếu hai file local. Audit utility
báo rõ hai trường hợp. Xem [hướng dẫn và provenance](verification-milestone-c/README.md).

Do source/test/runtime config không đổi, sử dụng lại nghiệm thu cuối:
full **8.490 passed / 12 skipped**, targeted **1.296 passed**, integration
**6.729 passed / 1 skipped**, pyright **0 errors / 0 warnings**. Không chạy
lại các suite này trong cleanup. Kiểm tra bổ sung gồm AST các script mới,
references/imports liên quan file đã xóa, liên kết tài liệu, evidence hashes,
JUnit counts, source manifest, diff whitespace và staged content/tree.

## Tình trạng Git và giới hạn

Trước staging, đọc và kiểm SHA typed payload cho **7.095 reachable objects**
từ refs/reflogs: 308 commits, 2.855 trees, 3.932 blobs; không có hash sai hoặc
missing object trong tập này. Loose object
`bc465804755a4202b07b819565b3afb292e735fc` bị hỏng nhưng không nằm trong tập
reachable, index hay blob tương ứng nội dung worktree. Không có active hook
local được cài đặt. Giữ nguyên author/config, không push hoặc rewrite history.
Các thay đổi Stage 1/2/3 giao nhau nên được đóng gói thành một commit nhất quán.

**Full `git fsck` vẫn thất bại** do loose object trên. Kiểm tra reachable và
prospective commit tree không có nghĩa đã sửa repository corruption. Object
này cần một quyết định sửa chữa riêng; cleanup không tự xóa dữ liệu Git.

Timeout `stall` lịch sử vẫn **chưa xác định root cause**. Lượt full cuối pass
case đó trong 3,597 giây, không phải bằng chứng đã sửa lỗi timeout. M2 có
đồng bộ goal khi dựng Whole-target status; chưa chứng minh vi phạm contract
nên giữ nguyên production behavior. Không chạy Scenario 3 hoặc triển khai Stage 4.
