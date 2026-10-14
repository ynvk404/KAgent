# WSL KAgent migration report

Ngày bàn giao: 2026-10-14 (Asia/Saigon). **Migration hoàn tất; offline acceptance đạt.**
Source code, Fix A/B/C, permission/evidence/security gates và historical artifacts không được chỉnh sửa. Không chạy benchmark cases, provider/LLM thật, HTTP target, Docker reset, commit hoặc push.

## 1. Source, destination và filesystem

- Linux user: `khainguyen`, UID/GID 1000; HOME `/home/khainguyen`.
- WSL distro: Ubuntu 26.04 LTS, WSL2; kernel `6.18.33.2-microsoft-standard-WSL2`.
- Source: `/mnt/d/DOANTOTNGHIEP/kagent`, filesystem `9p`, mount `/mnt/d`, device `D:\`.
- IDE path `/mnt/d/doantotnghiep/kagent` có cùng device/inode với source trên; đây là cùng repository.
- Destination: `/home/khainguyen/kagent`, filesystem `ext4`, device `/dev/sdd`, mount `/`. Thư mục thực, không phải symlink.
- Preflight còn khoảng 156 GB trên source filesystem và 931 GB trên Linux filesystem; đủ dung lượng, không xóa dữ liệu để giải phóng chỗ.
- Destination chưa tồn tại khi bắt đầu. Task tạo staging `/home/khainguyen/.kagent-stage-rl5sno4x` trên cùng filesystem Linux.

## 2. Git trước và sau

Branch `main`; HEAD `07346bcadcd63612214b0d5a076b210cb2ca9439` ở cả source và destination. Source có `git status --short` rỗng khi bắt đầu; không có staged/unstaged/untracked changes ngoài dữ liệu ignored đã inventory. Destination cũng sạch sau copy và verification, trước khi tạo báo cáo này.

`git ls-files --stage`, worktree diff và staged diff giống nhau. Sau cài đặt/kiểm tra trong Linux, 730 index entries cập nhật cached filesystem stat (ctime/mtime/device/inode). Parser index xác minh **mode, uid/gid, size, blob OID, flags, path và index extensions không đổi**. Khác biệt `.git/index` và directory mtime của `.git` được giải thích bằng cache filesystem này; không có thay đổi staged content.

Báo cáo này là file untracked mới duy nhất được thêm cho bàn giao; `venv-linux` và `kagent.egg-info` mới thuộc generated/ignored installation data. Không stage, commit hoặc push.

## 3. Dữ liệu sao chép và exclusions

Sao chép bằng `rsync -aH` với exclusions theo **đường dẫn cụ thể**, không dùng Git ignore làm bộ lọc. Bảo toàn source, `.git`, project `.kagent`, tests, skills, scripts, configuration, báo cáo, artifacts, benchmark manifests/results, ignored/untracked data hiện có và symlinks.

Inventory cuối dùng để promotion: **8,289 entries, 6,463 regular files, 60,185,699 logical bytes**. Project `.kagent`: 1,477 files, 28,919,773 bytes. Ba symlinks historical artifacts giữ nguyên relative targets và đều resolve được ở destination. Permissions, uid/gid, file/directory mtimes được bảo toàn khi copy; không normalize quyền nguồn.

Chỉ bỏ `venv-linux` và 71 cache directories (`__pycache__`, `.pytest_cache`, `.ruff_cache`) đã xác định. Không có bytecode standalone ngoài các cache directories trong inventory. Không loại trừ thêm runtime data, logs, reports hay artifacts.

Danh sách exclusions chính xác, tương đối với repository root:

```text
.pytest_cache
.ruff_cache
benchmarks/common/__pycache__
benchmarks/scenario1/core/__pycache__
benchmarks/scenario1/reporting/__pycache__
benchmarks/scenario1/reset/__pycache__
benchmarks/scenario1/__pycache__
benchmarks/__pycache__
components/browser_mcp/__pycache__
components/cwe_mcp/__pycache__
components/__pycache__
scripts/__pycache__
src/agent/__pycache__
src/browser/__pycache__
src/cli/__pycache__
src/config/__pycache__
src/coverage/__pycache__
src/engagement/__pycache__
src/findings/__pycache__
src/intelligence/__pycache__
src/llm/core/__pycache__
src/llm/providers/__pycache__
src/llm/runtime/__pycache__
src/llm/transport/__pycache__
src/llm/__pycache__
src/logger/__pycache__
src/memory/__pycache__
src/permission/network/__pycache__
src/permission/runtime/__pycache__
src/permission/worker/__pycache__
src/permission/__pycache__
src/redaction/__pycache__
src/report/__pycache__
src/session/__pycache__
src/skills/__pycache__
src/target/__pycache__
src/tools/common/__pycache__
src/tools/discovery/__pycache__
src/tools/execution/__pycache__
src/tools/http/__pycache__
src/tools/mcp/__pycache__
src/tools/skills/__pycache__
src/tools/workflow/__pycache__
src/tools/__pycache__
src/ui/bridges/__pycache__
src/ui/commands/__pycache__
src/ui/core/__pycache__
src/ui/render/__pycache__
src/ui/utils/__pycache__
src/ui/widgets/__pycache__
src/ui/__pycache__
src/vulnerability/__pycache__
src/workflow/__pycache__
src/__pycache__
tests/agent/__pycache__
tests/benchmarks/__pycache__
tests/browser/__pycache__
tests/cwe/__pycache__
tests/data/__pycache__
tests/helpers/__pycache__
tests/integration/__pycache__
tests/llm/__pycache__
tests/report/__pycache__
tests/runtime/__pycache__
tests/scenarios/__pycache__
tests/security/__pycache__
tests/skills/__pycache__
tests/state/__pycache__
tests/tools/__pycache__
tests/ui/__pycache__
tests/__pycache__
venv-linux
```

## 4. Integrity và consistency

Trước copy không phát hiện writable source file descriptors của tiến trình Linux. Inotify theo dõi các source directories được bảo toàn trong lúc copy và verification. Full inventories so sánh type, size, SHA-256, mode, uid/gid, mtimes và symlink target; không chỉ đối chiếu Git-tracked files.

Lần copy đầu đạt checksum/metadata nhưng phiên bị ngắt trước promotion. Khi tiếp tục, Codex tạo thêm một internal capture ref dưới `.git/refs/codex/turn-diffs/captures`; source code và `.kagent` không đổi. Task giữ staging, đồng bộ metadata Git bổ sung rồi chạy lại full integrity verification. Không chấp nhận snapshot cũ như thể source chưa đổi.

Final promotion check: **0 source differences, 0 staging differences, 0 write events** trong lượt copy/verify ổn định. Staging được đưa thành destination bằng `renameat2(RENAME_NOREPLACE)`; không ghi đè destination.

Full source checksum kiểm tra lại đạt sau promotion; watcher tiếp tục đến cuối verification với **0 events**. Task không sửa/xóa source. Final destination inventory xác nhận mọi preserved entry đạt, ngoài cached Git stat đã giải thích và root directory mtime do tạo venv/package metadata. Project `.kagent` và historical artifacts không đổi.

Records đầy đủ nằm trong private task directory `/home/khainguyen/.kagent-migration-u4e6qwv7` (mode 0700): `source-before.json`, `staging.json`, `copy-verification.json`, `source-final-verification.json`, `source-final-events.json`, `git-final-semantic-verification.json`, `final-integrity-results.json`. Records không chứa raw secret/evidence contents. Inventory không dùng inode/device/access time làm tiêu chí bằng nhau giữa hai filesystem; các thuộc tính này không được coi là nội dung dữ liệu.

## 5. Python environment và dependencies

Tạo mới bằng `/usr/bin/python3.14 -m venv /home/khainguyen/kagent/venv-linux`; Python **3.14.4**, tương thích và cùng version môi trường cũ. Base interpreter `/usr/bin/python3.14` và standard library `/usr/lib/python3.14` ở Linux filesystem.

Không có Python lockfile. Dùng `pyproject.toml` canonical manifest, extras `[dev,enhanced]`, cùng constraints lấy từ versions cũ để tránh tự nâng transitive dependencies. Install command:

```bash
venv-linux/bin/python -m pip install \
  -c /home/khainguyen/.kagent-migration-u4e6qwv7/source-environment-constraints.txt \
  -e '.[dev,enhanced]' pyright==1.1.411
```

Không copy venv và không dùng `pip install --upgrade`. Manifest yêu cầu `filelock==3.32.2`, trong khi venv cũ có 3.32.0; manifest pin được ưu tiên rõ ràng. `pypdf==6.19.0` được cài theo dev manifest. KAgent package metadata mới là 0.2.0 theo manifest (venv cũ còn metadata 0.1.0). Không khôi phục các package legacy ngoài dependency graph hiện tại chỉ vì chúng có trong venv cũ.

Pip 25.1.1; pytest 9.1.1; pytest-asyncio 1.4.0; Pyright 1.1.411; Textual 8.2.8. Package inventory: `original-packages.json`, `new-packages.json`; installation log trong private task directory.

`pip check` đạt. `python`, `pip`, `pytest`, `pyright`, `kagent` đều dùng `~/kagent/venv-linux`; console-script shebangs và editable project URL đã kiểm tra. Không có `/mnt/d` trong Python import paths của môi trường mới. Pyright update notice được giữ nguyên; không nâng version.

## 6. Activation và launchers

**File ngoài repo duy nhất chỉnh sửa: `/home/khainguyen/.bashrc`.** Backup nguyên bản với metadata trước khi sửa: `/home/khainguyen/.kagent-migration-u4e6qwv7/bashrc.before`; proposed/after copies được giữ cùng directory. `bash -n` đạt trước khi ghi file thật.

Chỉ thay khối auto-enter project/auto-activate venv: chuyển vào `$HOME/kagent`; tìm repo root từ CWD/parent markers rồi activate `venv-linux/bin/activate` tương đối với root. New shells loại bỏ inherited old KAgent venv/PATH ở cả hai alias source paths. Những literal source paths còn trong block chỉ dùng để loại bỏ old environment, không launch code/venv cũ.

Fresh interactive shell smoke từ HOME, native root và native `src/` đều đạt: CWD đúng, `sys.prefix` đúng, năm executable đúng native venv, PATH không còn old KAgent venv và CLI help chạy được.

Không sửa `.vscode/settings.json`/`launch.json`: chúng đã dùng `${workspaceFolder}`, native venv relative path và workspace CWD. Setup/test scripts cũng dùng repo-local venv; setup check đạt. VS Code machine default của một workspace `pentestagent` khác được giữ nguyên vì KAgent workspace settings đã override nó. Không có `KAGENT_PROJECT_ROOT` override cũ trong invocation được kiểm tra.

Terminals/IDE windows đang mở trước migration vẫn cần mở lại hoặc activate venv mới trong shell hiện tại; task không thay environment của tiến trình đang chạy khác.

## 7. Project và global data

`project_root()` xác định `/home/khainguyen/kagent` từ root và `src/`; `project_data_root()` là `/home/khainguyen/kagent/.kagent`. `user_data_root('/home/khainguyen')` vẫn là `/home/khainguyen/.kagent`.

Toàn bộ **639 global entries** được đối chiếu SHA-256/type/mode/uid/gid/mtime trước và sau: **0 differences**. Không xóa, di chuyển, ghi đè provider config, secrets, sessions hay personal intelligence. Offline test children dùng isolated HOME `/home/khainguyen/.kagent-migration-u4e6qwv7/offline-home`; đây chỉ là child environment, không đổi HOME của user/shell thực. Responsibility tests dùng existing offline store/path guards và task-owned basetemp/TMPDIR.

## 8. Offline verification

| Check | Kết quả cuối |
|---|---|
| `pip check` | PASS |
| Installed CLI và `python -m src.cli.main --help` | PASS |
| `scripts/setup.sh --check-only` | PASS |
| Benchmark import/help và real local smoke config `resolve_config` | PASS; không gọi runner/cases |
| Benchmark config override fixture | **1 PASS** |
| TUI mount/input/unmount harness | **4 PASS** |
| Six targeted Fix A/B/C responsibility files | **158 PASS**, 0 FAIL/SKIP |
| Additional final security group trong closure implementation document | **138 PASS**, 0 FAIL/SKIP |
| Repository-wide Pyright 1.1.411 | **0 errors, 0 warnings, 0 informations** |
| Shell activation smoke | **3 PASS** |
| `git diff --check` | PASS |

Targeted files chạy nguyên nhóm:

```text
tests/benchmarks/test_scenario1_closure.py
tests/benchmarks/test_scenario1_request_body.py
tests/benchmarks/test_scenario1_reliability.py
tests/security/test_http_observation_reader.py
tests/security/test_http_readback_lifecycle.py
tests/agent/test_bounded_validation_regressions.py
```

Additional security group: correctness/blockers, observation grounding, evidence recovery contract, execution policy và private host (six files trong command thứ hai của closure implementation document).

Harness-only issues được giữ trong logs: ban-all subprocess guard ban đầu chặn fixture Git metadata; một audit prototype cài quá sớm chặn pytest `/dev/null` sink và dir-fd cleanup của filelock import probe; environment checker ban đầu chọn generated egg-info thay vì installed dist-info. Không sửa production/tests để xử lý các lỗi này. Final targeted harness reuse existing `_offline_scenario`, chỉ permit exact `git -C <owned fixture> rev-parse HEAD` và `status --porcelain`; mọi subprocess khác, DNS/network, outside-scratch stores/writes vẫn bị chặn. Installed metadata check chọn đúng venv site-packages dist-info. Logs các lần đầu được giữ riêng; kết quả cuối ở `final-targeted-results.json` và `environment-smoke-result.json`.

## 9. TUI performance: natural và synthetic

`tests/ui/test_persistence_diagnostics.py` được tài liệu nhắc đến nhưng không có trong source snapshot; không tạo lại hay sửa source để bù. Task-only harness `/home/khainguyen/.kagent-migration-u4e6qwv7/natural_tui.py` reuse `_make_app`, real Textual key dispatch, real Session/Finding/FileWrite/Evidence/Summary stores và fixture helpers hiện có.

Hai phía chạy **tuần tự**, cùng Python/dependencies trong venv mới, import production code tương ứng từ source/destination (đã assert import path), 80×24 TUI, timer heartbeat 20 ms, ba lần cho mỗi boundary. Không overlap với regression/checksum workloads. Fixtures mới nằm ngoài source repo, trên `9p` và `ext4`; tất cả fixture directories đã được dọn đúng ownership. Không dùng project evidence/session thực.

Natural operation không có injected delays/held syscalls. Warmup/recovery waits nằm ngoài timed operation. Evidence workload: file proof 67,584 bytes, năm candidates, mỗi candidate capture + immutable snapshot + retry. Synchronous instrumentation đo nested wall-time spans trên UI thread; không cộng các spans để suy tổng blocking. Snapshot span bao gồm Python/CPU và filesystem work, không phải syscall-only attribution.

Trung vị ba samples, milliseconds, **source → destination**:

| Boundary | Operation | Heartbeat gap | Esc delivery | Max measured synchronous loop span |
|---|---:|---:|---:|---:|
| session | 36.06 → 15.21 | 28.86 → 27.50 | 2.28 → 7.89 | 2.78 → 0.03 |
| file_write | 35.30 → 1.37 | 57.80 → 23.79 | 43.42 → 10.39 | 5.99 → 0.32 |
| evidence | 2099.86 → 469.90 | 2121.54 → 491.79 | 2110.14 → 475.94 | 288.43 → 53.14 |
| finding | 45.62 → 9.83 | 26.32 → 23.12 | 2.69 → 1.41 | 0.00 → 0.00 |
| summary | 541.44 → 21.22 | 225.63 → 35.35 | 203.79 → 12.37 | 14.34 → 2.28 |

Natural evidence sample ranges (ms):

| Filesystem | Operation | Heartbeat gap | Esc delivery |
|---|---:|---:|---:|
| Windows 9p | 1982.84–2497.24 | 2011.45–2518.82 | 1990.29–2503.20 |
| Linux ext4 | 460.49–854.90 | 482.40–901.90 | 465.79–864.59 |

Source measured evidence snapshot stages là slowest synchronous stages; native evidence snapshots vẫn synchronous. Native evidence heartbeat ~492 ms và Esc ~476 ms cho batch này chứng minh **migration không loại bỏ mọi freeze**. Không áp long-operation tick oracle cho operations ngắn hơn timer tick; fast operations có thể xong trước Esc được queue. Samples nhỏ, thứ tự source-before-destination cố định và không có host I/O counters; đây là workload-specific observations, không chứng minh mọi workload/live session chắc chắn nhanh hơn.

Existing injected-delay `test_persistence_responsiveness.py`: **8 PASS, 3 XFAIL** (known synchronous boundaries), 0 unexpected failures. Các measurements này dùng artificial holds/async-wait controls và `/tmp` fixtures; **không dùng để kết luận Linux filesystem nhanh hơn**. Natural JSON/logs, bounded slow-span records và synthetic log ở private task directory.

## 10. Limitations, blockers và rollback

Không còn migration acceptance blocker. Không chạy full 2.559-test suite/full repo pytest, live providers, real benchmark cases, HTTP targets, Docker resets hoặc live TUI sessions. Benchmark dataset/WAR là external artifacts ngoài KAgent repo và giữ original paths; dataset vẫn ở Windows filesystem. Local benchmark config chỉ cấu hình smoke manifest, không tự thêm official selection hay đổi manifests.

Giữ task-owned private directory làm audit/rollback archive; không tự xóa các hồ sơ này. Không để lộ keys/tokens/cookies hay raw sensitive evidence trong báo cáo.

Rollback nếu cần: dừng tiến trình đang dùng repo mới, đóng workspace mới; source vẫn nguyên vẹn và có thể mở lại. Chỉ restore `.bashrc` backup nếu không có subsequent user edits cần merge:

```bash
cp --preserve=mode,timestamps \
  /home/khainguyen/.kagent-migration-u4e6qwv7/bashrc.before ~/.bashrc
cd /mnt/d/DOANTOTNGHIEP/kagent
source venv-linux/bin/activate
```

Không reset Git, xóa source, xóa `~/.kagent` hoặc xóa benchmark data. Giữ native copy để review; nếu muốn cách ly thì rename nó sang tên mới chưa tồn tại sau khi dừng processes, không overwrite destination khác.

## 11. Mở VS Code WSL và chạy KAgent

Trong WSL terminal:

```bash
cd ~/kagent
code .
source venv-linux/bin/activate
python -m pip check
kagent --help
# Khi muốn chạy phiên KAgent thật với cấu hình hiện có:
kagent
```

Chọn window Remote–WSL Ubuntu mới và interpreter `${workspaceFolder}/venv-linux/bin/python`; mở terminal mới. Existing terminal có thể activate lệnh trên trực tiếp. Với development/tests, đứng tại repo root và dùng `venv-linux/bin/python -m pytest ...`; Pyright dùng `venv-linux/bin/pyright`. Task không chạy lệnh `kagent` tương tác cuối cùng này trong offline verification.
