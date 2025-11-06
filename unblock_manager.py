"""
Easy Unblock Manager
"""

import sys
import os
from hosts_manager import HostsManager
from logger import log

class UnblockManager:
    def __init__(self):
        self.hosts_manager = HostsManager()
    
    def unblock_domain(self, hostname):
        """Unblock a specific domain"""
        try:
            # Remove from hosts file
            success = self.hosts_manager.remove_from_hosts(hostname)
            
            if success:
                # Add to user whitelist
                with open('user_whitelist.txt', 'a') as f:
                    f.write(f"{hostname}\n")
                
                # Flush DNS
                self.hosts_manager.flush_dns()
                
                log(f"✅ Successfully unblocked: {hostname}")
                print(f"✅ Successfully unblocked: {hostname}")
                print("✅ DNS cache flushed. Domain should be accessible now.")
                return True
            else:
                print(f"⚠️ Domain {hostname} was not found in blocked list.")
                return False
                
        except Exception as e:
            log(f"❌ Failed to unblock {hostname}: {e}")
            print(f"❌ Failed to unblock {hostname}: {e}")
            return False
    
    def list_blocked_domains(self):
        """List currently blocked domains"""
        try:
            blocked_domains = self.hosts_manager.get_blocked_domains()
            if blocked_domains:
                print("\n📋 Currently Blocked Domains:")
                for i, domain in enumerate(blocked_domains, 1):
                    print(f"{i}. {domain}")
            else:
                print("✅ No domains currently blocked.")
            return blocked_domains
        except Exception as e:
            print(f"❌ Error listing blocked domains: {e}")
            return []
    
    def interactive_unblock(self):
        """Interactive unblocking interface"""
        print("🔓 Unblock Manager")
        print("=" * 30)
        
        blocked_domains = self.list_blocked_domains()
        
        if not blocked_domains:
            input("\nPress Enter to continue...")
            return
        
        try:
            choice = input("\nEnter domain name or number to unblock (or 'q' to quit): ").strip()
            
            if choice.lower() == 'q':
                return
            
            if choice.isdigit():
                index = int(choice) - 1
                if 0 <= index < len(blocked_domains):
                    domain = blocked_domains[index]
                    self.unblock_domain(domain)
                else:
                    print("❌ Invalid number")
            else:
                self.unblock_domain(choice)
                
        except KeyboardInterrupt:
            print("\n👋 Exiting...")

def main():
    manager = UnblockManager()
    
    if len(sys.argv) > 1:
        # Command line usage
        domain = sys.argv[1]
        manager.unblock_domain(domain)
    else:
        # Interactive mode
        manager.interactive_unblock()

if __name__ == "__main__":
    main()
