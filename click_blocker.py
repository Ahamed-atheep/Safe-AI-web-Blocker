"""
Enhanced Click-Based Blocker with All Features - FIXED
"""

import pydivert
import time
import threading
from model_loader import ModelPredictor
from hosts_manager import HostsManager
from logger import log
from packet_parser import extract_host_from_http, extract_sni_from_tls, is_valid_hostname

# Initialize feature flag OUTSIDE the class
HAS_ENHANCED_FEATURES = False

try:
    from false_positive_prevention import FalsePositivePrevention
    from confidence_analyzer import ConfidenceAnalyzer
    HAS_ENHANCED_FEATURES = True
    print("✅ Enhanced features imported successfully")
except ImportError as e:
    print(f"⚠️ Enhanced features not available: {e}")
    HAS_ENHANCED_FEATURES = False

class EnhancedClickBasedBlocker:
    def __init__(self):
        self.predictor = ModelPredictor()
        self.hosts_manager = HostsManager()
        
        try:
            from config import FILTER
            self.filter = FILTER
        except ImportError:
            self.filter = "outbound and tcp.PayloadLength > 0 and (tcp.DstPort == 80 or tcp.DstPort == 443)"
        
        self.processed_domains = set()
        self.session_timeout = 15
        self.last_reset = time.time()
        self.lock = threading.Lock()
        
        # Use instance variable for feature availability
        self.has_enhanced = HAS_ENHANCED_FEATURES
        
        # Initialize enhanced features if available
        if self.has_enhanced:
            try:
                self.fp_prevention = FalsePositivePrevention()
                self.confidence_analyzer = ConfidenceAnalyzer()
                log("✅ Enhanced features enabled: False positive prevention, confidence scoring")
            except Exception as e:
                log(f"Failed to initialize enhanced features: {e}")
                self.has_enhanced = False
                self.fp_prevention = None
                self.confidence_analyzer = None
        else:
            self.fp_prevention = None
            self.confidence_analyzer = None
            log("ℹ️ Basic mode: Enhanced features disabled")

    def get_main_domain(self, hostname):
        """Extract main domain"""
        if not hostname or len(hostname) < 3:
            return None
        
        parts = hostname.lower().split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return hostname

    def should_process(self, hostname):
        """Only process unique main domains per session"""
        current_time = time.time()
        
        with self.lock:
            # Reset session periodically
            if current_time - self.last_reset > self.session_timeout:
                self.processed_domains.clear()
                self.last_reset = current_time
                log("🔄 Session reset - ready for new clicks")
            
            main_domain = self.get_main_domain(hostname)
            if not main_domain:
                return False
            
            if main_domain in self.processed_domains:
                return False
            
            self.processed_domains.add(main_domain)
            return True

    def run(self):
        if self.has_enhanced:
            log("🛡️ Starting Enhanced Click-Based Blocker...")
            log("✅ Features: False positive prevention, confidence scoring, easy unblocking")
        else:
            log("🛡️ Starting Basic Click-Based Blocker...")
        
        try:
            with pydivert.WinDivert(self.filter) as w:
                for packet in w:
                    try:
                        hostname = None
                        
                        # Extract hostname from HTTP/HTTPS
                        if packet.tcp and packet.tcp.dst_port == 80 and packet.tcp.payload:
                            hostname = extract_host_from_http(packet.tcp.payload)
                        elif packet.tcp and packet.tcp.dst_port == 443 and packet.tcp.payload:
                            hostname = extract_sni_from_tls(packet.tcp.payload)
                        
                        # Process valid hostnames
                        if hostname and is_valid_hostname(hostname) and self.should_process(hostname):
                            h = self.predictor.safe_hostname(hostname)
                            
                            # Enhanced prediction with confidence
                            if self.has_enhanced and self.confidence_analyzer and self.fp_prevention:
                                pred, confidence = self.confidence_analyzer.predict_with_confidence(h)
                                should_block, reason = self.fp_prevention.should_block_safely(h, pred, confidence)
                                
                                # Log decision
                                self.fp_prevention.log_block_decision(h, should_block, reason, confidence)
                                
                                if should_block:
                                    log(f"🚫 BLOCKED: {h} | Confidence: {confidence:.2f} | Reason: {reason}")
                                    self.hosts_manager.add_to_hosts(h)
                                    
                                    # Notify if uncertain block
                                    if confidence < 0.9:
                                        print(f"""
⚠️ UNCERTAIN BLOCK: {h}
Confidence: {confidence:.2f} | Reason: {reason}

If this was a mistake, run: python unblock_manager.py {h}
                                        """)
                                    continue
                                else:
                                    log(f"✅ ALLOWED: {h} | Confidence: {confidence:.2f} | Reason: {reason}")
                            
                            else:
                                # Basic prediction (fallback)
                                pred = self.predictor.predict_hostname(h)
                                if pred == 1:
                                    log(f"🚫 BLOCKED: {h} (basic mode)")
                                    self.hosts_manager.add_to_hosts(h)
                                    continue
                                else:
                                    log(f"✅ ALLOWED: {h} (basic mode)")
                        
                        # Forward all packets
                        w.send(packet)
                        
                    except Exception as e:
                        w.send(packet)
                        
        except Exception as e:
            log(f"Failed to start enhanced blocker: {e}")
            print(f"Error: {e}")
            print("Make sure you're running as Administrator and WinDivert is installed.")

# Backward compatibility
ClickBasedBlocker = EnhancedClickBasedBlocker

def main():
    try:
        blocker = EnhancedClickBasedBlocker()
        blocker.run()
    except KeyboardInterrupt:
        log("Enhanced click-based blocker stopped by user.")

if __name__ == "__main__":
    main()
