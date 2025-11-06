"""
Test All Imports
"""

def test_imports():
    print("🧪 Testing all imports...")
    print("=" * 30)
    
    modules_to_test = [
        'config',
        'logger', 
        'hosts_manager',
        'model_loader',
        'packet_parser',
        'click_blocker',
        'simple_blocker',
        'false_positive_prevention',
        'confidence_analyzer',
        'unblock_manager'
    ]
    
    success_count = 0
    
    for module in modules_to_test:
        try:
            __import__(module)
            print(f"✅ {module}")
            success_count += 1
        except ImportError as e:
            print(f"❌ {module}: {e}")
        except Exception as e:
            print(f"⚠️ {module}: {e}")
    
    print(f"\n📊 Results: {success_count}/{len(modules_to_test)} modules imported successfully")
    
    if success_count == len(modules_to_test):
        print("🎉 All imports successful! Your project is ready to run.")
    else:
        print("⚠️ Some imports failed. Check the errors above.")

if __name__ == "__main__":
    test_imports()
