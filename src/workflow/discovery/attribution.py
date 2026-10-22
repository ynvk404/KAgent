"""Caller-declared document attribution, without reading or interpreting bytes.

The reserved ``manual:`` locator namespace distinguishes these declarations
from historical extractor locators without changing persisted IDs or schema.
Neither kind supplies request context, execution authority or test evidence.
"""
from __future__ import annotations

from copy import deepcopy
from typing import TYPE_CHECKING, Any

from .inventory import EndpointRecord, ProvenanceRecord, SourceRecord, exact

if TYPE_CHECKING:
    from ..state import AttackSurfaceInput, WorkflowState


def record_attributed_input(state: WorkflowState, item: AttackSurfaceInput, attribution: Any,
                            *, generation: str) -> tuple[AttackSurfaceInput, bool, ProvenanceRecord]:
    """Stage input and graph admission, then publish synchronously under the caller's lock.

    Bind exact admitted metadata, including historical references. Availability
    of bytes is deliberately not inferred from metadata; no reader is invoked.
    Any invalid attribution rejects the entire proposal, including enrichments.
    """
    keys = {'discovery_source_id', 'retained_ref', 'retained_hash', 'document_location'}
    if not isinstance(attribution, dict) or set(attribution) != keys:
        raise ValueError('source_attribution requires exact source ID, retained_ref, retained_hash and document_location')
    for key in keys:
        exact(attribution[key], maximum=233 if key == 'document_location' else 500)
    source = state.discovery_source(attribution['discovery_source_id'], generation=generation,
                                    retained_ref=attribution['retained_ref'])
    if (source.id != attribution['discovery_source_id'] or SourceRecord(**source.to_dict()) != source
            or source.retained_hash != attribution['retained_hash']
            or source.kind not in {'http', 'capture'} or source.document_url is None):
        raise ValueError('manual attribution requires exact admitted HTTP/capture document metadata and hash')
    if state.discovery_restore_invalid:
        raise ValueError('discovery restore integrity failed; attribution unavailable')
    trial = deepcopy(state)
    stored, created = trial.add_attack_surface_input(item)
    assert stored.endpoint is not None  # shared input admission requires an endpoint
    endpoint = EndpointRecord(stored.objective_id, stored.target_origin, stored.endpoint, stored.method)
    link = ProvenanceRecord(source.id, endpoint.id, stored.id,
                            'manual:' + attribution['document_location'], media_type=stored.content_type)
    trial.admit_discovery(source, (endpoint,), (link,))
    # Preserve historical object identities when unchanged and never replace
    # live ownership, locks, generation, phases or evidence stores.
    inputs = {key: state.attack_surface_inputs[key] if key in state.attack_surface_inputs
              and state.attack_surface_inputs[key] == row else row
              for key, row in trial.attack_surface_inputs.items()}
    if (state.attack_surface_inputs != inputs or state.endpoints != trial.endpoints
            or state.discovery_provenance != trial.discovery_provenance):
        state.attack_surface_inputs = inputs
        state.endpoints = trial.endpoints
        state.discovery_provenance = trial.discovery_provenance
        state._invalidate_inventory_reviews(None)
        state.mark_committed()
    return state.attack_surface_inputs[stored.id], created, link
