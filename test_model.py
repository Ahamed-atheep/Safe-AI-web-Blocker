"""
Model Testing Script
"""

import os
from model_loader import ModelPredictor
from logger import log

def test_existing_model():
    """Test the existing ML model"""
    print("🧪 Testing AI Model...")
    print("=" * 30)
    
    # Initialize predictor
    predictor = ModelPredictor()
    
    if not predictor.model or not predictor.vectorizer:
        print("❌ Model or vectorizer not loaded properly")
        return False
    
    # Test domains
    test_domains = [
        "google.com",
        "facebook.com", 
        "github.com",
        "malicious-site.com",
        "phishing-example.org",
        "youtube.com"
    ]
    
    print("Testing predictions:")
    print("-" * 40)
    
    for domain in test_domains:
        try:
            pred = predictor.predict_hostname(domain)
            
            # Get probability if available
            try:
                proba = predictor.predict_proba(domain)[0]
                confidence = max(proba)
                result = "HARMFUL" if pred == 1 else "SAFE"
                print(f"{domain:20} | {result:7} | Confidence: {confidence:.3f}")
            except:
                result = "HARMFUL" if pred == 1 else "SAFE"
                print(f"{domain:20} | {result:7}")
                
        except Exception as e:
            print(f"{domain:20} | ERROR: {e}")
    
    print("\n✅ Model test completed!")
    return True

if __name__ == "__main__":
    test_existing_model()
