
import time
from datetime import datetime

from storage import log_alert, init_db


class NIDSDetector:
    def __init__(
        self,
        db_path="data/nids.db",
        port_scan_threshold=5,
        syn_flood_threshold=10,
        alert_cooldown=10
    ):
        self.db_path = db_path
        init_db(self.db_path)

        self.port_scan_threshold = port_scan_threshold
        self.syn_flood_threshold = syn_flood_threshold
        self.alert_cooldown = alert_cooldown

        self.port_track = {}
        self.syn_track = {}
        self.threat_scores = {}
        self.recent_alerts = {}

        # Simulation packets must not generate extra "Live" alerts.
        self._simulation_mode = False

    def reset_state(self):
        self.port_track.clear()
        self.syn_track.clear()
        self.threat_scores.clear()
        self.recent_alerts.clear()
        self._simulation_mode = False

    def classify_severity(self, score):
        if score >= 15:
            return "High"
        elif score >= 8:
            return "Medium"
        return "Low"

    def analyze_packet(self, packet_info):
        src_ip = packet_info.get("src_ip")
        dst_ip = packet_info.get("dst_ip")
        dst_port = packet_info.get("dst_port")
        flags = packet_info.get("flags", "")

        if not src_ip:
            return

        # Track destination ports for port-scan detection.
        if src_ip not in self.port_track:
            self.port_track[src_ip] = set()

        if dst_port is not None:
            self.port_track[src_ip].add(dst_port)

        if len(self.port_track[src_ip]) >= self.port_scan_threshold:
            if not self._simulation_mode:
                self._trigger_alert(
                    src_ip=src_ip,
                    dst_ip=dst_ip or "Multiple",
                    attack_type="Port Scan (Live)",
                    base_score=10,
                    status="Active"
                )

            # Start a fresh detection window.
            self.port_track[src_ip] = set()

        # Track TCP SYN packets without the ACK flag.
        if "S" in flags and "A" not in flags:
            self.syn_track[src_ip] = (
                self.syn_track.get(src_ip, 0) + 1
            )

            if self.syn_track[src_ip] >= self.syn_flood_threshold:
                if not self._simulation_mode:
                    self._trigger_alert(
                        src_ip=src_ip,
                        dst_ip=dst_ip or "Server",
                        attack_type="TCP SYN Flood (Live)",
                        base_score=15,
                        status="Active"
                    )

                # Start a fresh detection window.
                self.syn_track[src_ip] = 0

    def _trigger_alert(
        self,
        src_ip,
        dst_ip,
        attack_type,
        base_score,
        status="Active"
    ):
        # Cooldown applies separately to each source IP and attack type.
        key = (src_ip, attack_type)
        now = time.time()

        last_alert_time = self.recent_alerts.get(key)

        if (
            last_alert_time is not None
            and now - last_alert_time < self.alert_cooldown
        ):
            return None

        current_score = self.threat_scores.get(src_ip, 0) + base_score
        self.threat_scores[src_ip] = current_score

        severity = self.classify_severity(current_score)

        alert_data = {
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "attack_type": attack_type,
            "severity": severity,
            "status": status,
            "score": current_score
        }

        # Log first. Only start the cooldown after logging succeeds.
        log_alert(self.db_path, alert_data)
        self.recent_alerts[key] = time.time()

        return alert_data

    def _simulate_packets(self, packets):
        # Prevent simulated packets from generating "Live" alerts.
        self._simulation_mode = True

        try:
            for packet in packets:
                self.analyze_packet(packet)
        finally:
            self._simulation_mode = False

    def simulate_port_scan(self):
        src_ip = "192.168.1.105"
        dst_ip = "192.168.1.1"

        packets = [
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": port,
                "flags": "S",
                "protocol": "TCP"
            }
            for port in [21, 22, 23, 25, 80, 443, 8080]
        ]

        self._simulate_packets(packets)

        score = self.threat_scores.get(src_ip, 10)
        severity = self.classify_severity(score)

        alert = {
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "attack_type": "Port Scan (SIMULATED)",
            "severity": severity,
            "status": "Active"
        }

        # Preserve the existing simulation button behavior.
        log_alert(self.db_path, alert)
        return alert

    def simulate_syn_flood(self):
        src_ip = "10.0.0.45"
        dst_ip = "192.168.1.1"

        packets = [
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": 80,
                "flags": "S",
                "protocol": "TCP"
            }
            for _ in range(12)
        ]

        self._simulate_packets(packets)

        score = self.threat_scores.get(src_ip, 15)
        severity = self.classify_severity(score)

        alert = {
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "attack_type": "TCP SYN Flood (SIMULATED)",
            "severity": severity,
            "status": "Active"
        }

        # Preserve the existing simulation button behavior.
        log_alert(self.db_path, alert)
        return alert

    def simulate_normal_traffic(self):
        # No attack alert is generated for normal traffic.
        return {
            "status": "success",
            "message": "Normal traffic simulated successfully."
        }


def log_layer_alert(db_path, alert):
    log_alert(db_path, alert)
