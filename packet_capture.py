import threading

_capture_active = False
_capture_thread = None

def get_capture_status():
    global _capture_active
    return "Live (Capturing)" if _capture_active else "Simulated / Inactive"

def start_capture(db_path, interface=None):
    global _capture_active, _capture_thread
    if _capture_active:
        return True, "Live capture is already running."
    
    try:
        from scapy.all import sniff
        from detector import NIDSDetector
        detector = NIDSDetector(db_path=db_path)
    except ImportError:
        return False, "Scapy is not installed or available. Running in simulation mode."
    except Exception as e:
        return False, f"Failed to initialize capture: {str(e)}"

    _capture_active = True

    def packet_callback(pkt):
        if not _capture_active:
            return
        if pkt.haslayer('IP'):
            ip_layer = pkt['IP']
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto
            dst_port = None
            flags = ""

            if pkt.haslayer('TCP'):
                tcp_layer = pkt['TCP']
                dst_port = tcp_layer.dport
                flags = str(tcp_layer.flags)
            elif pkt.haslayer('UDP'):
                udp_layer = pkt['UDP']
                dst_port = udp_layer.dport

            detector.analyze_packet({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "flags": flags,
                "protocol": str(proto)
            })

    def run_sniff():
        try:
            kwargs = {"prn": packet_callback, "store": False}
            if interface:
                kwargs["iface"] = interface
            sniff(**kwargs)
        except Exception:
            global _capture_active
            _capture_active = False

    _capture_thread = threading.Thread(target=run_sniff, daemon=True)
    _capture_thread.start()
    return True, "Live packet capture started successfully."

def stop_capture():
    global _capture_active
    if not _capture_active:
        return False, "Live capture is not currently running."
    _capture_active = False
    return True, "Live packet capture stopped."