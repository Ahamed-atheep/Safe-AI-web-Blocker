"""
AI System Blocker - Enhanced Main Entry Point
"""

try:
    from logger import log
except ImportError:
    def log(msg): print(f"[LOG] {msg}")

import sys
import os

def show_menu():
    print("\n🛡️ AI System Web Blocker (Enhanced)")
    print("=" * 50)
    print("1. Full System Blocker (blocks all traffic)")
    print("2. Enhanced Click-Based Blocker (recommended)")
    print("3. Simple Blocker (logging only)")
    print("4. Test Model")
    print("5. Unblock Manager")
    print("6. View Block History")
    print("7. Exit")
    print("=" * 50)

def check_admin():
    """Check if running as administrator"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    log("Enhanced AI System Blocker launched.")
    
    # Check admin privileges
    if not check_admin():
        print("⚠️ Warning: Not running as Administrator")
        print("Some features may not work properly.")
        print("For best results, run as Administrator.\n")
    
    while True:
        show_menu()
        choice = input("Select option (1-7): ").strip()
        
        try:
            if choice == "1":
                try:
                    from interceptor import NetworkInterceptor
                    log("Starting Full System Blocker...")
                    interceptor = NetworkInterceptor()
                    interceptor.run()
                except ImportError as e:
                    log(f"Failed to import interceptor: {e}")
                    print("interceptor.py not found or has issues.")
                break
                
            elif choice == "2":
                try:
                    from click_blocker import EnhancedClickBasedBlocker
                    log("Starting Enhanced Click-Based Blocker...")
                    blocker = EnhancedClickBasedBlocker()
                    blocker.run()
                except ImportError as e:
                    log(f"Failed to import click_blocker: {e}")
                    print("click_blocker.py not found or has import issues.")
                    print("Check if all dependencies are installed.")
                break
                
            elif choice == "3":
                try:
                    from simple_blocker import SimpleClickLogger
                    log("Starting Simple Blocker...")
                    logger = SimpleClickLogger()
                    logger.run()
                except ImportError as e:
                    log(f"Failed to import simple_blocker: {e}")
                break
                
            elif choice == "4":
                try:
                    from test_model import test_existing_model
                    log("Running model test...")
                    test_existing_model()
                except ImportError as e:
                    log(f"Failed to import test_model: {e}")
                    print("test_model.py not found.")
                continue
                
            elif choice == "5":
                try:
                    from unblock_manager import UnblockManager
                    log("Opening Unblock Manager...")
                    manager = UnblockManager()
                    manager.interactive_unblock()
                except ImportError as e:
                    log(f"Failed to import unblock_manager: {e}")
                continue
                
            elif choice == "6":
                try:
                    if os.path.exists('blocked_log.json'):
                        import json
                        with open('blocked_log.json', 'r') as f:
                            history = json.load(f)
                        
                        print(f"\n📊 Block History (Last {len(history)} entries):")
                        print("-" * 60)
                        for entry in history[-10:]:  # Show last 10
                            status = "🚫 BLOCKED" if entry['blocked'] else "✅ ALLOWED"
                            confidence = entry.get('confidence', 'N/A')
                            print(f"{status}: {entry['hostname']} | Confidence: {confidence} | {entry['reason']}")
                    else:
                        print("📊 No block history found.")
                    
                    input("\nPress Enter to continue...")
                except Exception as e:
                    print(f"Error reading history: {e}")
                continue
                
            elif choice == "7":
                log("Exiting Enhanced AI System Blocker.")
                sys.exit(0)
                
            else:
                print("Invalid choice. Please select 1-7.")
                continue
                
        except KeyboardInterrupt:
            log("Stopped by user (KeyboardInterrupt).")
            break
        except Exception as e:
            log(f"Error: {e}")
            print(f"An error occurred: {e}")
            continue

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Critical error: {e}")
        input("Press Enter to exit...")
