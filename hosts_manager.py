"""
Hosts File Manager for Blocking/Unblocking Domains
"""

import os
import subprocess
from logger import log

class HostsManager:
    def __init__(self):
        try:
            from config import HOSTS_FILE_PATH
            self.hosts_file = HOSTS_FILE_PATH
        except ImportError:
            self.hosts_file = r"C:\Windows\System32\drivers\etc\hosts"
        
        self.blocked_marker = "# AI Blocker - Blocked Domain"
    
    def add_to_hosts(self, hostname):
        """Add domain to hosts file for blocking"""
        try:
            # Read current hosts file
            with open(self.hosts_file, 'r') as f:
                content = f.read()
            
            # Check if already blocked
            if hostname in content:
                return False
            
            # Add blocking entry
            entry = f"127.0.0.1 {hostname} {self.blocked_marker}\n"
            
            # Append to hosts file
            with open(self.hosts_file, 'a') as f:
                f.write(entry)
            
            log(f"Hosts updated: {hostname} -> 127.0.0.1")
            return True
            
        except PermissionError:
            log(f"Permission denied: Cannot modify hosts file. Run as Administrator.")
            return False
        except Exception as e:
            log(f"Error updating hosts file: {e}")
            return False
    
    def remove_from_hosts(self, hostname):
        """Remove domain from hosts file"""
        try:
            # Read hosts file
            with open(self.hosts_file, 'r') as f:
                lines = f.readlines()
            
            # Filter out the blocked domain
            filtered_lines = []
            removed = False
            
            for line in lines:
                if hostname not in line or self.blocked_marker not in line:
                    filtered_lines.append(line)
                else:
                    removed = True
            
            if removed:
                # Write back to hosts file
                with open(self.hosts_file, 'w') as f:
                    f.writelines(filtered_lines)
                
                log(f"Removed from hosts: {hostname}")
                return True
            
            return False
            
        except Exception as e:
            log(f"Error removing from hosts: {e}")
            return False
    
    def get_blocked_domains(self):
        """Get list of currently blocked domains"""
        try:
            blocked_domains = []
            with open(self.hosts_file, 'r') as f:
                lines = f.readlines()
            
            for line in lines:
                if self.blocked_marker in line and line.strip():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        domain = parts[1]
                        blocked_domains.append(domain)
            
            return blocked_domains
            
        except Exception as e:
            log(f"Error reading hosts file: {e}")
            return []
    
    def flush_dns(self):
        """Flush DNS cache"""
        try:
            subprocess.run(['ipconfig', '/flushdns'], capture_output=True, check=True)
            log("DNS cache flushed")
            return True
        except Exception as e:
            log(f"Failed to flush DNS: {e}")
            return False
