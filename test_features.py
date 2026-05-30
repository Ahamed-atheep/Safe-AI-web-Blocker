"""
Automated Test Suite for Enhanced Whitelist, Background Detector, and Heuristics
"""

import sys
from whitelist_manager import WhitelistManager
from background_detector import BackgroundDetector
from false_positive_prevention import FalsePositivePrevention

def run_tests():
    print("=========================================")
    print("Running Safe-AI-web-Blocker Features Test")
    print("=========================================\n")

    # 1. Test Whitelist Manager
    print("--- 1. Testing Whitelist Manager ---")
    wm = WhitelistManager()
    
    whitelist_test_cases = [
        ("google.com", True, "Direct match google.com"),
        ("mail.google.com", True, "Subdomain match mail.google.com"),
        ("dev.live.com", True, "Subdomain match dev.live.com"),
        ("unknown-site.org", False, "Non-whitelisted domain"),
    ]
    
    wm_passed = 0
    for domain, expected, desc in whitelist_test_cases:
        res, reason = wm.is_whitelisted(domain)
        status = "PASS" if res == expected else "FAIL"
        print(f"[{status}] {domain:20} -> Expected: {expected}, Got: {res} ({reason})")
        if res == expected:
            wm_passed += 1

    # 2. Test Background Detector
    print("\n--- 2. Testing Background Detector ---")
    bd = BackgroundDetector()
    
    bg_test_cases = [
        ("events.data.microsoft.com", True, "Known telemetry domain"),
        ("watson.telemetry.microsoft.com", True, "Known telemetry subdomain"),
        ("static.azureedge.net", True, "Keyword match: 'static'"),
        ("rr3---sn-q4fl6nds.googlevideo.com", True, "Structured CDN subdomain"),
        ("google.com", False, "Normal user-accessed site"),
    ]
    
    bd_passed = 0
    for domain, expected, desc in bg_test_cases:
        res, reason = bd.is_background_resource(domain)
        status = "PASS" if res == expected else "FAIL"
        print(f"[{status}] {domain:35} -> Expected: {expected}, Got: {res} ({reason})")
        if res == expected:
            bd_passed += 1

    # 3. Test False Positive Prevention & Hybrid Heuristics
    print("\n--- 3. Testing Hybrid Heuristics & ML Overrides ---")
    fpp = FalsePositivePrevention()
    
    # We will test various ML prediction outputs combined with heuristics
    heur_test_cases = [
        # Domain, ML Pred, ML Confidence, Expected Block, Description
        ("github.com", 1, 0.50, False, "GitHub false positive allowed due to low confidence and low heuristics"),
        ("malicious-site.com", 1, 0.66, True, "Harmful domain blocked due to low confidence elevated by moderate heuristics"),
        ("phishing-example.org", 0, 0.90, True, "Phishing domain blocked via high-risk keyword override despite ML safe prediction"),
        ("secure-banking-login.com", 0, 0.55, True, "Login/banking domains blocked via heuristics override on low ML safe confidence"),
        ("google.com", 1, 0.95, False, "Safe whitelist match takes priority even if ML says harmful"),
    ]
    
    fpp_passed = 0
    for domain, ml_pred, ml_conf, expected_block, desc in heur_test_cases:
        should_block, reason = fpp.should_block_safely(domain, ml_pred, ml_conf)
        status = "PASS" if should_block == expected_block else "FAIL"
        print(f"[{status}] {domain:26} | ML: {ml_pred} (Conf: {ml_conf}) -> Blocked: {should_block} ({reason})")
        if should_block == expected_block:
            fpp_passed += 1

    # Print Summary
    print("\n=========================================")
    print("TEST SUITE SUMMARY")
    print(f"Whitelist Manager:      {wm_passed}/{len(whitelist_test_cases)} passed")
    print(f"Background Detector:    {bd_passed}/{len(bg_test_cases)} passed")
    print(f"Hybrid Heuristics FPP:  {fpp_passed}/{len(heur_test_cases)} passed")
    print("=========================================")

if __name__ == "__main__":
    run_tests()
