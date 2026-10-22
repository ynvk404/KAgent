"""Offline observations of bounded discovery costs; timings are not an SLA."""
from time import perf_counter
import json

from src.workflow.discovery.inventory import EndpointRecord, SourceRecord, ProvenanceRecord, discovery_page
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
    from src.workflow.discovery.attribution import record_attributed_input
    from src.workflow.state import AttackSurfaceInput
    source = SourceRecord('benchmark', origin, 'http', 'obs-document', 'f' * 64,
                          origin + '/openapi.json', retained_ref='obs-document')
    state.admit_discovery(source)
    # Synthetic caller-authored metadata, no parsing or LLM-quality measurement.
    declarations = [AttackSurfaceInput('benchmark', origin, method='POST', endpoint='/orders',
                    parameter=f'field{index}', location='json', content_type='application/json')
                    for index in range(32)]
    for operation in ('insert', 'dedup'):
        start = perf_counter()
        for item in declarations:
            assert item.parameter is not None
            record_attributed_input(state, item, {
                'discovery_source_id': source.id, 'retained_ref': source.retained_ref,
                'retained_hash': source.retained_hash,
                'document_location': '/components/schemas/Order/properties/' + item.parameter,
            }, generation=state.generation)
        timings[operation + '_32_manual_attributions'] = perf_counter() - start
    return timings


if __name__ == '__main__':
    print(json.dumps(measure(), indent=2))
