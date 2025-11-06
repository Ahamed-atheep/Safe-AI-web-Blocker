"""
Simple Blocker - Logging Only (No Blocking)
"""

import pydivert
import time
from model_loader import ModelPredictor
from packet_parser import extract_host_from_http, extract_sni_from_tls, is_valid_hostname

class SimpleClickLogger:
    def __init__(self):
        self.predictor = ModelPredictor()
        self.processed_domains = set()
        self.session_timeout = 15
        self.last_reset = time.time()

    def get_main_domain(self, hostname):
        """Extract main domain"""
        parts = hostname.lower().split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return hostname

    def should_log(self, hostname):
        """Only log unique main domains"""
        current_time = time.time()
        
        if current_time - self.last_reset > self.session_timeout:
            self.processed_domains.clear()
            self.last_reset = current_time
            print("🔄 Session reset - ready for new clicks")
        
        main_domain = self.get_main_domain(hostname)
        
        if main_domain in self.processed_domains:
            return False
        
        self.processed_domains.add(main_domain)
        return True

    def run(self):
        print("\n🎯 Simple Click Logger (NO BLOCKING)")
        print("=" * 50)
        print("✅ This will ONLY LOG URLs you click")
        print("❌ No websites will be blocked")
        print("🎯 Only shows main domains (ignores background resources)")
        print("Press Ctrl+C to stop\n")
        
        filter_rule = "outbound and tcp.PayloadLength > 0 and (tcp.DstPort == 80 or tcp.DstPort == 443)"
        
        try:
            with pydivert.WinDivert(filter_rule) as w:
                for packet in w:
                    try:
                        hostname = None
                        
                        if packet.tcp and packet.tcp.dst_port == 80 and packet.tcp.payload:
                            hostname = extract_host_from_http(packet.tcp.payload)
                        elif packet.tcp and packet.tcp.dst_port == 443 and packet.tcp.payload:
                            hostname = extract_sni_from_tls(packet.tcp.payload)
                        
                        if hostname and is_valid_hostname(hostname) and self.should_log(hostname):
                            h = self.predictor.safe_hostname(hostname)
                            pred = self.predictor.predict_hostname(h)
                            
                            if pred == 1:
                                print(f"🚫 WOULD BLOCK: {hostname} (harmful detected)")
                            else:
                                print(f"✅ WOULD ALLOW: {hostname} (safe)")
                        
                        # Always forward packets (no blocking)
                        w.send(packet)
                        
                    except Exception:
                        w.send(packet)
                        
        except KeyboardInterrupt:
            print(f"\n\n🛑 Simple Click Logger stopped.")
            print(f"📊 Total unique domains logged: {len(self.processed_domains)}")
        except Exception as e:
            print(f"\n❌ Failed to start logger: {e}")
            print("Make sure you're running as Administrator!")

def main():
    logger = SimpleClickLogger()
    logger.run()

if __name__ == "__main__":
    main()
