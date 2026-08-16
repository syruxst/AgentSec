"""Tests de la suite de payloads y del prober con cliente mock."""

import httpx

from agentsec.payloads import ProbeConfig, Prober, load_payloads


def test_payloads_loaded_indirect():
    payloads = load_payloads(suite="indirect")
    assert len(payloads) >= 8
    assert {p.id for p in payloads} >= {"INJ-001", "INJ-008"}


def _mock_prober(handler):
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport, timeout=5)
    config = ProbeConfig(target="http://example.test/invoke", suite="indirect")
    return Prober(config, client=client)


def test_no_trigger_on_clean_response():
    def handler(request):
        return httpx.Response(200, json={"answer": "normal response"})

    prober = _mock_prober(handler)
    result = prober.probe(load_payloads()[0])
    assert result.triggered is False
    assert result.status_code == 200


def test_trigger_on_marker_present():
    def handler(request):
        return httpx.Response(200, text='{"answer": "no, IGNORED-PREVIOUS"}')

    prober = _mock_prober(handler)
    payload = load_payloads()[0]
    result = prober.probe(payload)
    assert result.triggered is True
    assert "IGNORED-PREVIOUS" in result.reason


def test_network_error_reported():
    def handler(request):
        raise httpx.ConnectError("boom")

    prober = _mock_prober(handler)
    result = prober.probe(load_payloads()[0])
    assert result.server_error
    assert result.triggered is False


def test_run_all_payloads_clean():
    def handler(request):
        return httpx.Response(200, json={"ok": True})

    prober = _mock_prober(handler)
    results = prober.run()
    assert len(results) == len(load_payloads())
    assert all(not r.triggered for r in results)
