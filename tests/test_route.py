import os
import tempfile
import pytest
from app import app
import storage

@pytest.fixture
def client():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    app.config["TESTING"] = True
    storage.init_db(path)
    
    with app.test_client() as client:
        yield client

    if os.path.exists(path):
        os.remove(path)

def test_dashboard_route(client):
    response = client.get("/")
    assert response.status_code == 200

def test_api_stats(client):
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.get_json()
    assert "total_events" in data

def test_api_alerts(client):
    response = client.get("/api/alerts")
    assert response.status_code == 200
    assert isinstance(response.get_json(), list)

def test_simulation_routes(client):
    res_ps = client.post("/api/simulate/port_scan")
    assert res_ps.status_code == 200

    res_sf = client.post("/api/simulate/syn_flood")
    assert res_sf.status_code == 200

    res_clear = client.post("/api/clear_data")
    assert res_clear.status_code == 200