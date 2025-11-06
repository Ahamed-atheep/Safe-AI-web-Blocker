"""
Main packet interception and blocking logic
"""
import pydivert
from config import FILTER
from logger import log
from model_loader import ModelPredictor
from hosts_manager import HostsManager
from packet_parser import extract_host_from_http, extract_sni_from_tls

class NetworkInterceptor:
    def __init__(self):
        self.predictor = ModelPredictor()
        self.hosts_manager = HostsManager()

    def run(self):
        """Main interception loop"""
        log("Starting interceptor (requires Admin). Filter: " + FILTER)
        try:
            with pydivert.WinDivert(FILTER) as w:
                for pkt in w:
                    try:
                        hostname = None

                        # Parse HTTP payload for Host header (port 80)
                        if pkt.tcp and pkt.tcp.dst_port == 80 and pkt.tcp.payload:
                            host = extract_host_from_http(pkt.tcp.payload)
                            if host:
                                hostname = host

                        # Parse TLS ClientHello SNI for port 443
                        elif pkt.tcp and pkt.tcp.dst_port == 443 and pkt.tcp.payload:
                            sni = extract_sni_from_tls(pkt.tcp.payload)
                            if sni:
                                hostname = sni

                        # If we got a hostname, normalize & predict
                        if hostname:
                            h = self.predictor.safe_hostname(hostname)
                            pred = self.predictor.predict_hostname(h)
                            if pred is None:
                                # Unknown -> allow for now
                                w.send(pkt)
                                continue

                            if pred == 1:
                                # Harmful -> block
                                log(f"HARMFUL detected: {h} | Blocking and adding to hosts.")
                                self.hosts_manager.add_to_hosts(h)
                                # Drop packet (don't send it)
                                continue
                            else:
                                # Safe -> forward the packet
                                w.send(pkt)
                                continue

                        # If no hostname extracted, forward packet
                        w.send(pkt)

                    except Exception as inner_e:
                        log(f"Error processing packet: {inner_e}")
                        # On exception, forward packet to avoid breaking connectivity
                        try:
                            w.send(pkt)
                        except Exception:
                            pass
        except Exception as e:
            log(f"Failed to open WinDivert handle. Ensure driver installed and run as Administrator. Error: {e}")
