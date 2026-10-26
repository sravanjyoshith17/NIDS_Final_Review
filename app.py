import os
from flask import Flask, render_template, jsonify, request
from storage import init_db, get_all_alerts, get_statistics, get_suspicious_ips, clear_alerts_db
from detector import NIDSDetector
from packet_capture import start_capture, stop_capture, get_capture_status

app = Flask(__name__)
db_path = os.path.join("data", "nids.db")
detector = NIDSDetector(db_path=db_path)

os.makedirs("data", exist_ok=True)
init_db(db_path)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats", methods=["GET"])
def api_stats():
    stats = get_statistics(db_path)
    stats["capture_status"] = get_capture_status()
    return jsonify(stats)

@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    alerts = get_all_alerts(db_path)
    return jsonify(alerts)

@app.route("/api/suspicious_ips", methods=["GET"])
def api_suspicious():
    ips = get_suspicious_ips(db_path)
    return jsonify(ips)

@app.route("/api/simulate/port_scan", methods=["POST"])
def simulate_port_scan():
    alert = detector.simulate_port_scan()
    return jsonify({"status": "success", "message": "Port scan simulation executed.", "alert": alert})

@app.route("/api/simulate/syn_flood", methods=["POST"])
def simulate_syn_flood():
    alert = detector.simulate_syn_flood()
    return jsonify({"status": "success", "message": "SYN flood simulation executed.", "alert": alert})

@app.route("/api/simulate/normal_traffic", methods=["POST"])
def simulate_normal_traffic():
    detector.simulate_normal_traffic()
    return jsonify({"status": "success", "message": "Normal traffic simulated successfully."})

@app.route("/api/clear_data", methods=["POST"])
def clear_data():
    clear_alerts_db(db_path)
    detector.reset_state()
    return jsonify({"status": "success", "message": "Demo data cleared successfully."})

@app.route("/api/capture/start", methods=["POST"])
def capture_start():
    data = request.get_json() or {}
    interface = data.get("interface", None)
    success, msg = start_capture(db_path, interface=interface)
    return jsonify({"success": success, "message": msg})

@app.route("/api/capture/stop", methods=["POST"])
def capture_stop():
    success, msg = stop_capture()
    return jsonify({"success": success, "message": msg})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)