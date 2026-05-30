"""
Background Traffic Context Detector for Safe-AI-web-Blocker
"""

from logger import log

class BackgroundDetector:
    def __init__(self):
        self.background_patterns = self._load_patterns()
        # Common Windows update and telemetry domains that are background processes
        self.known_telemetry_domains = {
            "events.data.microsoft.com",
            "telemetry.microsoft.com",
            "watson.telemetry.microsoft.com",
            "v10.events.data.microsoft.com",
            "settings-win.data.microsoft.com",
            "diagnostics.office.com",
            "self.events.data.microsoft.com",
            "delivery.mp.microsoft.com"
        }

    def _load_patterns(self):
        """Load background keyword patterns from config"""
        try:
            from config import BACKGROUND_PATTERNS
            return [pattern.lower().strip() for pattern in BACKGROUND_PATTERNS]
        except ImportError:
            # Secure default fallback patterns
            return [
                'cdn', 'static', 'assets', 'media', 'images',
                'fonts', 'videos', 'api', 'analytics',
                'telemetry', 'metrics', 'logging', 'tracking'
            ]

    def is_background_resource(self, hostname):
        """Analyze if the hostname corresponds to a background process or service"""
        if not hostname:
            return False, "Empty hostname"

        hostname_lower = hostname.lower().strip()

        # 1. Check known telemetry/update domains exactly
        if hostname_lower in self.known_telemetry_domains:
            return True, "Known Windows telemetry/utility domain"

        # 2. Check if it's a subdomain of a known telemetry domain
        for telemetry in self.known_telemetry_domains:
            if hostname_lower.endswith('.' + telemetry):
                return True, f"Subdomain of telemetry domain '{telemetry}'"

        # 3. Check for specific background keywords (e.g., telemetry, cdn, api)
        for pattern in self.background_patterns:
            if pattern in hostname_lower:
                return True, f"Matched background pattern: '{pattern}'"

        # 4. Check for numerical/highly-structured CDN subdomains
        # (e.g. static subdomains with long sequences of letters and numbers)
        parts = hostname_lower.split('.')
        if len(parts) > 2:
            first_part = parts[0]
            # If the first segment is long and contains a mix of digits and letters (e.g. rr3---sn-q4fl6nds)
            if len(first_part) > 8 and any(char.isdigit() for char in first_part) and '-' in first_part:
                return True, "CDN-style structured subdomain"

        return False, "Not flagged as background resource"
