"""Tests for bounded finding-ingestion batches."""

import api_client


def test_finding_batches_respect_item_limit(monkeypatch):
    monkeypatch.setattr(api_client, "_MAX_FINDINGS_PER_BATCH", 2)

    batches = api_client._finding_batches([{"id": i} for i in range(5)])

    assert [len(batch) for batch in batches] == [2, 2, 1]


def test_finding_batches_respect_serialized_size_limit(monkeypatch):
    monkeypatch.setattr(api_client, "_MAX_FINDINGS_BATCH_BYTES", 60)

    batches = api_client._finding_batches([
        {"description": "a" * 30},
        {"description": "b" * 30},
    ])

    assert [len(batch) for batch in batches] == [1, 1]
