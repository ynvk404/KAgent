"""Check the committed evidence bundle without running a model or test suite."""
from pathlib import Path
import hashlib
import json
import xml.etree.ElementTree as ET


BUNDLE = Path(__file__).resolve().parent
ROOT = BUNDLE.parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_manifest():
    paths = []
    for name in ("src", "tests", "benchmarks", "skills", "scripts"):
        paths.extend(p for p in (ROOT / name).rglob("*") if p.is_file()
                     and "__pycache__" not in p.parts and ".pytest_cache" not in p.parts)
    paths.extend(ROOT / name for name in (
        "AGENTS.md", "pyproject.toml", "pytest.ini", "pyrightconfig.json", "requirements.txt"))
    rows = {str(p.relative_to(ROOT)): digest(p) for p in sorted(set(paths))}
    aggregate = hashlib.sha256("".join(f"{h}  {p}\n" for p, h in rows.items()).encode()).hexdigest()
    return {"files": rows, "count": len(rows), "aggregate": aggregate}


def main():
    freeze = json.loads((BUNDLE / "freeze.json").read_text())
    current = source_manifest()
    local_only = {
        "benchmarks/scenario1/config.local.toml",
        "scripts/browser_latency_protocol.mjs",
    }
    # The historical freeze includes two ignored local files. Never require their
    # publication or silently claim a fresh clone reproduces the full aggregate.
    assert set(current["files"]) - set(freeze["files"]) == set(), "Unexpected source files"
    missing = set(freeze["files"]) - set(current["files"])
    assert missing <= local_only, f"Missing versioned source: {sorted(missing)}"
    assert all(h == freeze["files"][p] for p, h in current["files"].items()), "Source differs from the verified freeze"
    versioned = {p: h for p, h in freeze["files"].items() if p not in local_only}
    assert len(versioned) == 713
    provenance = json.loads((BUNDLE / "provenance.json").read_text())
    assert provenance["source_freeze"] == freeze["aggregate"]
    for name, receipt in provenance["published"].items():
        path = BUNDLE / name
        assert path.is_file() and digest(path) == receipt["sha256"], name
    results = json.loads((BUNDLE / "results.json").read_text())
    assert results["source_aggregate"] == freeze["aggregate"]
    for name, record in results["runs"].items():
        assert record["exit_code"] == 0 and record["source_unchanged"], name
        assert record["source_before_aggregate"] == record["source_after_aggregate"] == freeze["aggregate"], name
        if name != "pyright":
            assert record["junit_valid"] and not record["junit"]["failures"] and not record["junit"]["errors"], name
    suites = ET.parse(BUNDLE / "full.junit.xml").getroot().findall("testsuite")
    counts = {key: sum(int(s.get(key, "0")) for s in suites)
              for key in ("tests", "failures", "errors", "skipped")}
    assert counts == results["runs"]["full"]["junit"]
    cases = [case for suite in suites for case in suite.findall("testcase")]
    assert len(cases) == counts["tests"]
    assert sum(case.find("skipped") is not None for case in cases) == counts["skipped"]
    assert not any(case.find("failure") is not None or case.find("error") is not None for case in cases)
    regressions = [case for case in cases if case.get("classname", "").endswith("test_target_request_intent")]
    assert len(regressions) == 51 and not any(case.find("skipped") is not None for case in regressions)
    print(json.dumps({"historical_source_files": freeze["count"], "historical_source_aggregate": freeze["aggregate"],
                      "versioned_source_files_checked": len(versioned),
                      "local_only_files_present": sorted(local_only - missing),
                      "full_local_freeze_matches": current == freeze,
                      "full_junit": counts, "quoted_url_regressions": len(regressions),
                      "evidence_hashes_match": True, "tests_rerun": False}, indent=2))


if __name__ == "__main__":
    main()
