The eight cases in `benchmarks/fixtures/lan22_accuracy.json` cover SQLi oracle
reasoning and the factual errors observed in lan-22. They contain bounded,
sanitized excerpts and a human review rubric. They preserve no credentials and
do not reconstruct missing target queries or request bytes.

The offline regression suite checks reference arithmetic, SQLite counterexamples,
HTTP request/response boundaries, delivered guidance, synthesis projections and
compaction/resume state. These checks use SQLite in memory, MockTransport and
FakeClient. They measure deterministic contracts, **not model reasoning quality**.

For a future explicitly requested model evaluation, give each case's context and
task without its rubric, then review the answer against each rubric item. Record
the exact build, skill hashes, model configuration and answer; compare unchanged
cases before/after guidance changes. Do not score the supplied reference answers
or scripted FakeClient responses as model successes. No provider evaluation or
live target is run by this dataset or its tests.
