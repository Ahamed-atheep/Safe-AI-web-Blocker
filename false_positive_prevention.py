"""
False Positive Prevention System
"""

import json
import time
import os
from logger import log

class FalsePositivePrevention:
    def __init__(self):
        try:
            from config import WHITELIST, BACKGROUND_PATTERNS, CONFIDENCE_THRESHOLD
            self.system_whitelist = WHITELIST
            self.background_patterns = BACKGROUND_PATTERNS
            self.confidence_threshold = CONFIDENCE_THRESHOLD
        except ImportError:
            self.system_whitelist = {"google.com", "microsoft.com", "youtube.com"}
            self.background_patterns = ["cdn", "static", "api"]
            self.confidence_threshold = 0.85
        
        self.user_whitelist = self.load_user_whitelist()
        self.block_history = self.load_block_history()
    
    def load_user_whitelist(self):
        """Load user-specific whitelist"""
        try:
            if os.path.exists('user_whitelist.txt'):
                with open('user_whitelist.txt', 'r') as f:
                    return set(line.strip().lower() for line in f if line.strip())
            return set()
        except Exception:
            return set()
    
    def load_block_history(self):
        """Load block history"""
        try:
            if os.path.exists('blocked_log.json'):
                with open('blocked_log.json', 'r') as f:
                    return json.load(f)
            return []
        except Exception:
            return []
    
    def is_whitelisted(self, hostname):
        """Check if domain is whitelisted"""
        hostname_lower = hostname.lower()
        
        # Check system whitelist
        if hostname_lower in self.system_whitelist:
            return True, "System whitelist"
        
        # Check user whitelist
        if hostname_lower in self.user_whitelist:
            return True, "User whitelist"
        
        # Check pattern matching (subdomains)
        for whitelisted in self.system_whitelist:
            if hostname_lower.endswith('.' + whitelisted):
                return True, f"Subdomain of {whitelisted}"
        
        return False, "Not whitelisted"
    
    def is_background_resource(self, hostname):
        """Detect background resources"""
        hostname_lower = hostname.lower()
        
        # Check patterns
        for pattern in self.background_patterns:
            if pattern in hostname_lower:
                return True, f"Background pattern: {pattern}"
        
        # Check for CDN-style subdomains
        parts = hostname.split('.')
        if len(parts) > 2:
            first_part = parts[0]
            if any(char.isdigit() for char in first_part) and len(first_part) > 5:
                return True, "CDN-style subdomain"
        
        return False, "Not background resource"
    
    def should_block_safely(self, hostname, ml_prediction, confidence=0.5):
        """Safe blocking decision with multiple checks"""
        
        # 1. Check whitelist first
        is_whitelisted, whitelist_reason = self.is_whitelisted(hostname)
        if is_whitelisted:
            return False, whitelist_reason
        
        # 2. Check if background resource
        is_background, bg_reason = self.is_background_resource(hostname)
        if is_background:
            return False, bg_reason
        
        # 3. Conservative ML-based decision
        if ml_prediction == 1:
            if confidence > 0.9:
                return True, f"Very high confidence harmful ({confidence:.2f})"
            elif confidence > self.confidence_threshold:
                return True, f"High confidence harmful ({confidence:.2f})"
            elif confidence > 0.7:
                return True, f"Medium confidence harmful ({confidence:.2f}) - Review recommended"
        
        return False, f"Low confidence or safe ({confidence:.2f})"
    
    def log_block_decision(self, hostname, blocked, reason, confidence):
        """Log blocking decisions"""
        entry = {
            'hostname': hostname,
            'blocked': blocked,
            'reason': reason,
            'confidence': confidence,
            'timestamp': time.time()
        }
        
        self.block_history.append(entry)
        
        # Save to file (keep last 1000 entries)
        try:
            with open('blocked_log.json', 'w') as f:
                json.dump(self.block_history[-1000:], f, indent=2)
        except Exception as e:
            log(f"Failed to save block history: {e}")
