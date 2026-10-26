import os
import tempfile
import pytest
from storage import init_db, log_alert, get_all_alerts, get_statistics, get_suspicious_ips, clear_alerts_db

@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    init_db(path)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_storage_operations(temp_db):
    alert = {
        "timestamp": "2026-06-06 12:00:00",
        "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8",
        "attack_type": "Test Attack",
        "severity": "High",
        "status": "Active"
    }
    log_alert(temp_db, alert)
    
    alerts = get_all_alerts(temp_db)
    assert len(alerts) == 1
    assert alerts[0]["src_ip"] == "1.2.3.4"

    stats = get_statistics(temp_db)
    assert stats["total_events"] == 1
    assert stats["unique_ips"] == 1
    assert stats["high_severity"] == 1

    suspicious = get_suspicious_ips(temp_db)
    assert len(suspicious) == 1
    assert suspicious[0]["src_ip"] == "1.2.3.4"

    clear_alerts_db(temp_db)
    assert len(get_all_alerts(temp_db)) == 0