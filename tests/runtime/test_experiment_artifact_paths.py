"""Actual disk writes through CLI-created stores in two isolated fixture trials.

This checks storage wiring only. Fixture Findings do not represent lab results
and no validation/confirmation authorization is inferred from this test.
"""
import json
from pathlib import Path

from scripts import experiment_profile as profile
from src.findings.store import Finding
from src.paths import project_root, project_artifact_root
from src.workflow.evidence import EvidenceArtifact
from tests.runtime.test_cli_exit_diagnostics import offline_cli
from tests.runtime.test_experiment_profile import layout, make_plan, original_bytes


async def test_cli_created_stores_write_artifacts_findings_and_evidence_per_trial(offline_cli, layout, monkeypatch, record_property):
    cli = offline_cli.cli
    first = make_plan(layout)
    second = profile.plan(layout[0], layout[1], layout[2], layout[3].with_name("run-2"), first["origin"])
    plans = [first, second]
    for value in plans:
        profile.apply(value)  # tmp_path fixtures only; no real --apply.
    originals = original_bytes(layout)
    paths = []

    for index, value in enumerate(plans, 1):
        run = Path(value["run"])
        project = run / "project"
        async def inspect(app):
            # Inspect instances actually constructed by runtime.main(), rather
            # than constructing a second store with test-selected directories.
            finding_tool = app.agent.tools.get("confirm_finding")
            workflow_tool = app.agent.tools.get("workflow")
            store = finding_tool.store
            assert project_root() == Path.cwd() == project
            assert store.project_dir == workflow_tool.evidence_root == project
            assert store.dir == project_artifact_root() / "findings"

            source = project_artifact_root() / "fixture" / "proof.md"
            source.parent.mkdir(parents=True)
            source.write_text(f"Offline fixture trial {index}; password=private-fixture-value")
            evidence = EvidenceArtifact.capture_immutable_snapshot(
                "fixture-candidate", str(source.relative_to(project)), workflow_tool.evidence_root)
            snapshot = project / evidence.path
            assert snapshot.is_file() and snapshot.is_relative_to(project / ".kagent/evidence")
            assert "private-fixture-value" not in snapshot.read_text()
            assert snapshot.stat().st_mode & 0o777 == 0o400

            finding = Finding(title="Offline path fixture", severity="info", url=value["origin"] + "/fixture",
                observed_impact="Synthetic storage test only.", potential_impact="No live target tested.",
                slug="offline-path-fixture", candidate_id="fixture-candidate", evidence_refs=[evidence.id])
            report = Path(await store.save(finding))
            assert report.is_file() and report.parent == project / "artifacts/findings"
            assert "Synthetic storage test only." in report.read_text()
            # Production retry semantics retain the existing canonical report.
            duplicate = Path(await store.save(finding))
            assert duplicate == report and duplicate.is_file()

            await app.agent.save()
            await app.agent.save_context_snapshot("offline artifact path fixture")
            assert app.agent.store.path.is_relative_to(run / "profile-home/.kagent/sessions")
            assert app.agent.store.context_snapshot_path().is_file()
            paths.append((report, snapshot, app.agent.store.path))

        monkeypatch.setattr(cli.KAgent, "run_async", inspect)
        with profile.bound_runtime(value), profile.patch.object(profile.sys, "argv", [
            "kagent", "--target", value["origin"], "--log", str(run / "logs/kagent.log"),
            "--debug-session-path", str(run / "logs/session.jsonl"),
        ]):
            assert await cli.main() == 0

    assert len(paths) == 2
    assert all(path.is_file() for trial in paths for path in trial)
    assert all(path.is_relative_to(Path(first["run"])) for path in paths[0])
    assert all(path.is_relative_to(Path(second["run"])) for path in paths[1])
    assert set(paths[0]).isdisjoint(paths[1])
    assert original_bytes(layout) == originals
    assert not (layout[0] / "artifacts/findings").exists()
    assert not (layout[0] / ".kagent/evidence").exists()
    assert not offline_cli.client.requests
    record_property("verified_artifact_paths", json.dumps([[str(path) for path in trial] for trial in paths]))
