"""Tests de la API web y el panel (FastAPI TestClient)."""

import pytest
from fastapi.testclient import TestClient

import app.db as dbmod
from app.main import app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test_app.db"
    original_db = dbmod.db
    original_get_conn = dbmod.get_conn

    def patched_db(path=None):
        if path is None:
            path = db_path
        return original_db(path)

    def patched_get_conn(path=None):
        if path is None:
            path = db_path
        return original_get_conn(path)

    monkeypatch.setattr(dbmod, "get_conn", patched_get_conn)
    monkeypatch.setattr(dbmod, "db", patched_db)
    return TestClient(app)


def test_stats_endpoint(client):
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    assert "total_scans" in resp.json()


def test_rules_endpoint(client):
    resp = client.get("/api/rules")
    assert resp.status_code == 200
    rules = resp.json()
    assert any(r["id"] == "AS-101" for r in rules)


def test_scan_empty_path_404(client):
    resp = client.post("/api/scan", json={"path": "no_existe_xyz"})
    assert resp.status_code == 404


def test_scan_and_detail(client, tmp_path):
    (tmp_path / "crews.yaml").write_text(
        """
crew: demo
agents:
  - name: a
    tools:
      - name: RunShellTool
""",
        encoding="utf-8",
    )
    resp = client.post("/api/scan", json={"path": str(tmp_path)})
    assert resp.status_code == 200
    body = resp.json()
    scan_id = body["id"]
    assert body["result"]["score"] < 100

    detail = client.get(f"/api/scans/{scan_id}")
    assert detail.status_code == 200
    assert detail.json()["id"] == scan_id


def test_dashboard_renders(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "AgentSec" in resp.text


def test_report_html_renders(client, tmp_path):
    (tmp_path / "crews.yaml").write_text("crew: x\nagents: []\n", encoding="utf-8")
    created = client.post("/api/scan", json={"path": str(tmp_path)})
    scan_id = created.json()["id"]
    resp = client.get(f"/report/{scan_id}")
    assert resp.status_code == 200
    assert "AgentSec" in resp.text


def test_scan_detail_page(client, tmp_path):
    (tmp_path / "crews.yaml").write_text("crew: x\nagents: []\n", encoding="utf-8")
    created = client.post("/api/scan", json={"path": str(tmp_path)})
    scan_id = created.json()["id"]
    resp = client.get(f"/scan/{scan_id}")
    assert resp.status_code == 200
    assert "Header" in resp.text or "score" in resp.text.lower()
