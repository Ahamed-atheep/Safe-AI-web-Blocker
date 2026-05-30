"""
False Positive Prevention and Hybrid Heuristic Analysis System
"""

import json
import time
import os
import math
from collections import Counter

from logger import log
from whitelist_manager import WhitelistManager
from background_detector import BackgroundDetector

class FalsePositivePrevention:
    def __init__(self):
        try:
            from config import CONFIDENCE_THRESHOLD
            self.confidence_threshold = CONFIDENCE_THRESHOLD
        except ImportError:
            self.confidence_threshold = 0.85
        
        # Initialize sub-managers
        self.whitelist_manager = WhitelistManager()
        self.background_detector = BackgroundDetector()
        
        self.block_history = self.load_block_history()
        
        # High-risk phishing and brand hijacking keywords
        self.suspicious_keywords = [
            'secure', 'signin', 'login', 'verify', 'update', 
            'banking', 'account', 'support', 'billing', 'invoice', 
            'confirm', 'portal', 'webscr', 'paypal', 'netflix', 
            'microsoft', 'google', 'phishing', 'malicious', 'free-gift',
            'wallet', 'crypto', 'recovery'
        ]
    
    def load_block_history(self):
        """Load block history from local JSON log"""
        try:
            if os.path.exists('blocked_log.json'):
                with open('blocked_log.json', 'r', encoding='utf-8') as f:
                    return json.load(f)
            return []
        except Exception as e:
            log(f"Failed to load block history: {e}")
            return []

    def calculate_entropy(self, text):
        """Calculate Shannon entropy to identify randomly generated domains (DGA)"""
        if not text:
            return 0.0
        # Calculate character frequency probability
        freqs = Counter(text)
        total = len(text)
        entropy = -sum((count / total) * math.log2(count / total) for count in freqs.values())
        return entropy

    def get_heuristic_risk(self, hostname):
        """Analyze structural features of the domain and return a risk score (0.0 to 1.0) and reasons"""
        if not hostname:
            return 0.0, []

        hostname_lower = hostname.lower().strip()
        risk_score = 0.0
        reasons = []

        # 1. Look for suspicious keywords
        matched_keywords = []
        for keyword in self.suspicious_keywords:
            if keyword in hostname_lower:
                matched_keywords.append(keyword)
        
        if matched_keywords:
            # Scale score based on number of matched high-risk keywords
            increment = min(0.35 * len(matched_keywords), 0.70)
            risk_score += increment
            reasons.append(f"Suspicious subwords: {matched_keywords}")

        # 2. Shannon Entropy Analysis (DGA detection)
        # We analyze only the core second-level domain name (SLD) to avoid TLD/subdomain bias
        parts = hostname_lower.split('.')
        sld = parts[-2] if len(parts) >= 2 else hostname_lower
        entropy = self.calculate_entropy(sld)
        
        if entropy > 3.8:
            risk_score += 0.25
            reasons.append(f"High domain character entropy ({entropy:.2f})")
        elif entropy > 3.5:
            risk_score += 0.10
            reasons.append(f"Moderate domain character entropy ({entropy:.2f})")

        # 3. Structural Complexity Check
        # Deep subdomain paths are typical of phishing URLs (e.g. login.secure.update.domain.com)
        segment_count = len(parts)
        if segment_count >= 5:
            risk_score += 0.15
            reasons.append(f"High subdomain depth ({segment_count} segments)")
        elif segment_count >= 4:
            risk_score += 0.05
            reasons.append(f"Moderate subdomain depth ({segment_count} segments)")

        # 4. Hostname Length Check
        # Extremely long hostnames are often malicious cloaking attempts
        if len(hostname_lower) > 50:
            risk_score += 0.10
            reasons.append(f"Abnormal domain length ({len(hostname_lower)} chars)")

        return min(risk_score, 1.0), reasons

    def should_block_safely(self, hostname, ml_prediction, confidence=0.5):
        """Combined Hybrid blocking decision using Whitelists, Background Detector, and Heuristics"""
        
        # 1. Consult the Whitelist Manager
        is_white, white_reason = self.whitelist_manager.is_whitelisted(hostname)
        if is_white:
            return False, f"Allowed: {white_reason}"
        
        # 2. Consult the Background Detector
        is_bg, bg_reason = self.background_detector.is_background_resource(hostname)
        if is_bg:
            return False, f"Allowed background process: {bg_reason}"
        
        # Calculate heuristic risk score
        heuristic_score, heuristic_reasons = self.get_heuristic_risk(hostname)
        
        # 3. Hybrid decision matrix
        # ML predicts Harmful (1)
        if ml_prediction == 1:
            # High confidence block
            if confidence > self.confidence_threshold:
                return True, f"Blocked: High confidence harmful ({confidence:.2f})"
            
            # Medium confidence block (elevated if heuristic risk is present)
            elif confidence >= 0.70:
                return True, f"Blocked: Medium confidence harmful ({confidence:.2f})"
            
            # Low confidence block - block only if heuristics support it
            else:
                if heuristic_score >= 0.25:
                    reason_str = ", ".join(heuristic_reasons)
                    return True, f"Blocked: Low confidence harmful ({confidence:.2f}) elevated by heuristics [{reason_str}]"
                else:
                    return False, f"Allowed: Low confidence harmful ({confidence:.2f}) without validating heuristics"
                    
        # ML predicts Safe (0) but has high uncertainty
        else:
            # If the model thinks it's safe but the confidence is extremely low (e.g. ~50%)
            # and our heuristics strongly indicate a phishing domain, we override the ML
            if confidence < 0.60 and heuristic_score >= 0.40:
                reason_str = ", ".join(heuristic_reasons)
                return True, f"Blocked: ML claimed safe but heuristics strongly flagged harmful [{reason_str}]"
            
            # Explicit check: If it contains highly dangerous keywords and ML confidence in 'Safe' is not absolute (< 0.95)
            if confidence < 0.95 and any(kw in hostname.lower() for kw in ['phishing', 'malicious', 'free-gift']):
                return True, f"Blocked: Override for critical threat keyword in domain"

        return False, f"Allowed: Low risk domain ({confidence:.2f})"
    
    def log_block_decision(self, hostname, blocked, reason, confidence):
        """Log the blocking decision to the history file"""
        entry = {
            'hostname': hostname,
            'blocked': blocked,
            'reason': reason,
            'confidence': confidence,
            'timestamp': time.time()
        }
        
        self.block_history.append(entry)
        
        # Keep last 1000 history entries
        try:
            with open('blocked_log.json', 'w', encoding='utf-8') as f:
                json.dump(self.block_history[-1000:], f, indent=2)
        except Exception as e:
            log(f"Failed to save block history: {e}")
