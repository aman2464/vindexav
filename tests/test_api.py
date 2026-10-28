from pathlib import Path
from fastapi.testclient import TestClient
from server.main import app
from config import cfg

client = TestClient(app)


def test_api_status_endpoint():
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert "realtime_protection" in data
    assert "total_scans" in data


def test_api_scan_workflow(tmp_path: Path):
    test_file = tmp_path / "sample.txt"
    test_file.write_text("Benign file")

    response = client.post("/api/scan", json={
        "target_path": str(tmp_path),
        "scan_type": "custom"
    })
    assert response.status_code == 202
    data = response.json()
    scan_id = data["id"]

    # Poll status
    poll_res = client.get(f"/api/scan/{scan_id}")
    assert poll_res.status_code == 200


def test_api_directory_traversal_protection():
    # Attempting to scan or traverse into quarantine vault must yield 403 Forbidden
    response = client.post("/api/scan", json={
        "target_path": str(cfg.vault_dir),
        "scan_type": "custom"
    })
    assert response.status_code == 403