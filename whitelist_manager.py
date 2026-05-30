"""
Whitelist Manager for Safe-AI-web-Blocker
"""

import os
from logger import log

class WhitelistManager:
    def __init__(self):
        self.user_whitelist_file = 'user_whitelist.txt'
        self.system_whitelist = self._load_system_whitelist()
        self.user_whitelist = self._load_user_whitelist()
        self.combined_whitelist = self.system_whitelist.union(self.user_whitelist)

    def _load_system_whitelist(self):
        """Load built-in whitelisted domains from config"""
        try:
            from config import WHITELIST
            return set(domain.lower().strip() for domain in WHITELIST)
        except ImportError:
            # Secure default fallback
            return {
                "localhost", "127.0.0.1", "google.com", "microsoft.com", 
                "live.com", "windows.com", "github.com", "youtube.com"
            }

    def _load_user_whitelist(self):
        """Load user whitelisted domains from file"""
        domains = set()
        if os.path.exists(self.user_whitelist_file):
            try:
                with open(self.user_whitelist_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line_cleaned = line.strip().lower()
                        if line_cleaned and not line_cleaned.startswith('#'):
                            domains.add(line_cleaned)
            except Exception as e:
                log(f"Error loading user whitelist: {e}")
        return domains

    def refresh(self):
        """Reload the whitelists from disk/config"""
        self.system_whitelist = self._load_system_whitelist()
        self.user_whitelist = self._load_user_whitelist()
        self.combined_whitelist = self.system_whitelist.union(self.user_whitelist)

    def is_whitelisted(self, hostname):
        """Check if hostname matches any whitelisted domain (exact or subdomain)"""
        if not hostname:
            return False, "Empty hostname"

        hostname_lower = hostname.lower().strip()
        
        # 1. Direct exact match
        if hostname_lower in self.combined_whitelist:
            return True, "Exact whitelist match"
        
        # 2. Subdomain wildcard match (e.g. sub.google.com matches google.com)
        for allowed in self.combined_whitelist:
            # Check if hostname ends with .allowed (e.g., mail.google.com ends with .google.com)
            if hostname_lower.endswith('.' + allowed):
                return True, f"Subdomain match of whitelisted '{allowed}'"

        return False, "Not whitelisted"

    def add_to_whitelist(self, hostname):
        """Add domain to user whitelist file"""
        if not hostname:
            return False

        hostname_cleaned = hostname.lower().strip()
        if not hostname_cleaned:
            return False

        if hostname_cleaned in self.user_whitelist:
            return True  # Already whitelisted

        try:
            # Open in append mode
            with open(self.user_whitelist_file, 'a', encoding='utf-8') as f:
                f.write(f"{hostname_cleaned}\n")
            
            self.user_whitelist.add(hostname_cleaned)
            self.combined_whitelist.add(hostname_cleaned)
            log(f"Added to user whitelist: {hostname_cleaned}")
            return True
        except Exception as e:
            log(f"Failed to add {hostname_cleaned} to whitelist: {e}")
            return False

    def remove_from_whitelist(self, hostname):
        """Remove domain from user whitelist file"""
        if not hostname:
            return False

        hostname_cleaned = hostname.lower().strip()
        if hostname_cleaned not in self.user_whitelist:
            return False

        try:
            self.user_whitelist.remove(hostname_cleaned)
            self.combined_whitelist = self.system_whitelist.union(self.user_whitelist)
            
            # Rewrite user_whitelist.txt excluding this domain
            lines_to_keep = []
            if os.path.exists(self.user_whitelist_file):
                with open(self.user_whitelist_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip().lower() != hostname_cleaned:
                            lines_to_keep.append(line)
            
            with open(self.user_whitelist_file, 'w', encoding='utf-8') as f:
                f.writelines(lines_to_keep)
                
            log(f"Removed from user whitelist: {hostname_cleaned}")
            return True
        except Exception as e:
            log(f"Failed to remove {hostname_cleaned} from whitelist: {e}")
            return False
