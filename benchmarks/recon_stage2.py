"""Offline observations of bounded discovery costs; timings are not an SLA."""
from time import perf_counter
import json

from src.workflow.discovery import EndpointRecord, SourceRecord, ProvenanceRecord, discovery_page
from src.workflow.state import WorkflowObjective, WorkflowState


def measure():
    origin = 'http://fixture.test'
    state = WorkflowState(objective=WorkflowObjective('benchmark', 'whole_target', origin))
    batches = []
    for batch in range(4):
        source = SourceRecord('benchmark', origin, 'http', f'obs-{batch}', f'{batch:064x}')
        endpoints = tuple(EndpointRecord('benchmark', origin, f'/path/{batch * 250 + index}', 'GET')
                          for index in range(250))
        links = tuple(ProvenanceRecord(source.id, ep.id) for ep in endpoints)
        batches.append((source, endpoints, links))
    timings = {}
    for name in ('insert_1000_endpoints', 'dedup_1000_endpoints'):
        start = perf_counter()
        for batch in batches:
            state.admit_discovery(*batch)
        timings[name] = perf_counter() - start
    start = perf_counter()
    for index in range(100):
        state.admit_discovery(SourceRecord('benchmark', origin, 'http', f'new-{index}', f'{index:064x}'))
    timings['insert_100_sources'] = perf_counter() - start
    start = perf_counter()
    for source in tuple(state.discovery_sources.values()):
        state.update_discovery_source(source.id, generation=state.generation, disposition='processed')
    timings['update_104_sources'] = perf_counter() - start
    start = perf_counter()
    for _ in range(100): discovery_page(state, {'view': 'sources', 'limit': 25})
    timings['100_frontier_listings'] = perf_counter() - start
    from src.workflow.extraction import extract_html, apply_extraction
    document_url = origin + '/large.html'
    html = ('<form method="post">' + ''.join(f'<input name="field{index}">' for index in range(260))
            + '</form>' + ' ' * 50000).encode()
    start = perf_counter()
    extraction = extract_html(html, document_url)
    timings['bounded_large_html_parse'] = perf_counter() - start
    source = SourceRecord('benchmark', origin, 'http', 'obs-html', 'f' * 64, document_url,
                          retained_ref='obs-html', selected=True)
    state.admit_discovery(source)
    start = perf_counter()
    apply_extraction(state, source.id, extraction, generation=state.generation,
                      retained_ref='obs-html', retained_hash='f' * 64, document_url=document_url)
    timings['bounded_large_html_admission'] = perf_counter() - start
    from src.workflow.openapi import extract_openapi
    doc = {'openapi': '3.1.0', 'paths': {f'/api/{index}': {'post': {'requestBody': {'content': {
        'application/json': {'schema': {'properties': {f'q{i}': {'type': 'string'} for i in range(12)}}}}}}}
        for index in range(60)}}
    body = json.dumps(doc).encode()
    start = perf_counter()
    extracted = extract_openapi(body, origin + '/openapi.json')
    timings['bounded_large_openapi_parse'] = perf_counter() - start
    src = SourceRecord('benchmark', origin, 'http', 'obs-api', 'e' * 64, origin + '/openapi.json',
                        retained_ref='obs-api', selected=True)
    state.admit_discovery(src)
    assert src.document_url is not None
    start = perf_counter()
    apply_extraction(state, src.id, extracted, generation=state.generation,
                      retained_ref='obs-api', retained_hash='e' * 64, document_url=src.document_url)
    timings['bounded_large_openapi_admission'] = perf_counter() - start
    return timings


if __name__ == '__main__':
    print(json.dumps(measure(), indent=2))
