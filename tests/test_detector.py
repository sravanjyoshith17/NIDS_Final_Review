import os
import tempfile
import pytest
from detector import NIDSDetector

@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_severity_classification(temp_db):
    detector = NIDSDetector(db_path=temp_db)
    assert detector.classify_severity(5) == "Low"
    assert detector.classify_severity(10) == "Medium"
    assert detector.classify_severity(18) == "High"

def test_port_scan_simulation(temp_db):
    detector = NIDSDetector(db_path=temp_db)
    alert = detector.simulate_port_scan()
    assert alert is not None
    assert alert["src_ip"] == "192.168.1.105"
    assert "Port Scan" in alert["attack_type"]

def test_syn_flood_simulation(temp_db):
    detector = NIDSDetector(db_path=temp_db)
    alert = detector.simulate_syn_flood()
    assert alert is not None
    assert alert["src_ip"] == "10.0.0.45"
    assert "SYN Flood" in alert["attack_type"]