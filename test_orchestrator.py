#!/usr/bin/env python3
"""
Test script for the enhanced orchestrator with sample agent outputs.
"""

import asyncio
from orchestrator import orchestrate, generate_summary, OrchestrationConfig, OrchestrationResult

async def test_orchestrator():
    """Test orchestrator with various combinations of agent outputs."""
    
    print("Testing Enhanced Orchestrator")
    print("=" * 60)
    
    # Test cases with different risk scenarios
    test_cases = [
        {
            "name": "Low Risk - Legitimate Email",
            "content_out": {
                "score": 0.1,
                "highlights": [],
                "explain": "No significant phishing indicators detected"
            },
            "link_out": {
                "score": 0.0,
                "links": [
                    {"url": "https://microsoft.com", "domain": "microsoft.com", "score": 0.0, "reasons": []}
                ],
                "total_links": 1,
                "suspicious_count": 0,
                "details": "Analyzed 1 links. No suspicious link indicators found"
            },
            "behavior_out": {
                "score": 0.0,
                "reasons": [],
                "sender_history": {
                    "is_new_sender": False,
                    "message_count": 15,
                    "first_seen": "2024-01-15T10:30:00",
                    "last_seen": "2024-10-20T14:45:00"
                },
                "details": "No significant behavioral anomalies"
            }
        },
        {
            "name": "Medium Risk - Suspicious Content",
            "content_out": {
                "score": 0.7,
                "highlights": [
                    {"start": 10, "end": 16, "reason": "suspicious_keyword", "token": "urgent"},
                    {"start": 25, "end": 31, "reason": "suspicious_keyword", "token": "verify"}
                ],
                "explain": "High keyword suspicion (score: 0.60). Found suspicious keywords: urgent, verify. ML model shows moderate suspicion (0.75)"
            },
            "link_out": {
                "score": 0.3,
                "links": [
                    {"url": "https://bit.ly/verify123", "domain": "bit.ly", "score": 0.3, "reasons": ["Uses URL shortening service"]}
                ],
                "total_links": 1,
                "suspicious_count": 0,
                "details": "Analyzed 1 links. No highly suspicious links detected"
            },
            "behavior_out": {
                "score": 0.2,
                "reasons": ["Subject contains urgency indicators"],
                "sender_history": {
                    "is_new_sender": False,
                    "message_count": 2,
                    "first_seen": "2024-10-20T09:30:00",
                    "last_seen": "2024-10-21T10:15:00"
                },
                "details": "Minor behavioral inconsistencies detected. Sender has 2 previous messages"
            }
        },
        {
            "name": "High Risk - Phishing Attempt",
            "content_out": {
                "score": 0.9,
                "highlights": [
                    {"start": 0, "end": 6, "reason": "suspicious_keyword", "token": "URGENT"},
                    {"start": 15, "end": 21, "reason": "suspicious_keyword", "token": "verify"},
                    {"start": 35, "end": 43, "reason": "suspicious_keyword", "token": "password"}
                ],
                "explain": "High keyword suspicion (score: 0.80). Found suspicious keywords: urgent, verify, password. ML model predicts high phishing probability (0.95)"
            },
            "link_out": {
                "score": 0.9,
                "links": [
                    {
                        "url": "http://192.168.1.100/paypal-verify",
                        "domain": "192.168.1.100",
                        "score": 0.9,
                        "reasons": [
                            "Uses IP address instead of domain",
                            "Similar to trusted domain 'paypal.com' (possible typosquatting)"
                        ]
                    }
                ],
                "total_links": 1,
                "suspicious_count": 1,
                "details": "Analyzed 1 links. 1 suspicious links detected. 1 high-risk links found"
            },
            "behavior_out": {
                "score": 0.9,
                "reasons": [
                    "Sender has no prior message history (new sender)",
                    "Display name suggests 'paypal' but sender domain is 'suspicious-domain.com'",
                    "Reply-To local part 'noreply' differs from sender 'support'"
                ],
                "sender_history": {
                    "is_new_sender": True,
                    "message_count": 0
                },
                "details": "High behavioral suspicion detected. First message from this sender"
            }
        },
        {
            "name": "IP-Based Links Override",
            "content_out": {
                "score": 0.3,
                "highlights": [
                    {"start": 10, "end": 16, "reason": "suspicious_keyword", "token": "update"}
                ],
                "explain": "Moderate keyword suspicion detected"
            },
            "link_out": {
                "score": 0.85,
                "links": [
                    {
                        "url": "http://203.0.113.1/login",
                        "domain": "203.0.113.1",
                        "score": 0.85,
                        "reasons": ["Uses IP address instead of domain", "HTTP used for login page (insecure)"]
                    }
                ],
                "total_links": 1,
                "suspicious_count": 1,
                "details": "Analyzed 1 links. 1 suspicious links detected. IP-based URLs detected"
            },
            "behavior_out": {
                "score": 0.2,
                "reasons": ["Subject contains urgency indicators"],
                "sender_history": {"is_new_sender": False, "message_count": 5},
                "details": "Minor behavioral inconsistencies detected"
            }
        },
        {
            "name": "Custom Weights Test",
            "content_out": {
                "score": 0.8,
                "highlights": [{"start": 0, "end": 5, "reason": "suspicious_keyword", "token": "ALERT"}],
                "explain": "High content suspicion detected"
            },
            "link_out": {
                "score": 0.2,
                "links": [{"url": "https://google.com", "domain": "google.com", "score": 0.0, "reasons": []}],
                "total_links": 1,
                "suspicious_count": 0,
                "details": "Low link suspicion"
            },
            "behavior_out": {
                "score": 0.1,
                "reasons": [],
                "sender_history": {"is_new_sender": False, "message_count": 10},
                "details": "No behavioral anomalies"
            },
            "custom_config": OrchestrationConfig(content_weight=0.8, link_weight=0.1, behavior_weight=0.1)
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n🧪 Test {i}: {test_case['name']}")
        print("-" * 40)
        
        # Get configuration
        config = test_case.get('custom_config', None)
        if config:
            print(f"Custom weights: Content={config.content_weight}, Link={config.link_weight}, Behavior={config.behavior_weight}")
        else:
            print("Default weights: Content=0.5, Link=0.3, Behavior=0.2")
        
        # Show input scores
        content_score = test_case['content_out']['score']
        link_score = test_case['link_out']['score']
        behavior_score = test_case['behavior_out']['score']
        
        print(f"\n📊 Input Scores:")
        print(f"  Content:  {content_score:.2f}")
        print(f"  Link:     {link_score:.2f}")
        print(f"  Behavior: {behavior_score:.2f}")
        
        # Run orchestration
        result = await orchestrate(
            test_case['content_out'],
            test_case['link_out'], 
            test_case['behavior_out'],
            config
        )
        
        print(f"\n🎯 Orchestration Results:")
        print(f"  Final Score: {result.final_score:.3f}")
        print(f"  Action: {result.action.upper()}")
        print(f"  Confidence: {result.confidence:.3f}")
        
        print(f"\n📝 Summary:")
        print(f"  {result.summary}")
        
        print(f"\n🔍 Top Reasons:")
        for j, reason in enumerate(result.detailed_reasons[:3], 1):
            print(f"  {j}. {reason['text']} (priority: {reason['priority']:.2f})")
        
        # Show expected vs actual action
        expected_actions = {
            "Low Risk - Legitimate Email": "allow",
            "Medium Risk - Suspicious Content": "flag", 
            "High Risk - Phishing Attempt": "quarantine",
            "IP-Based Links Override": "quarantine",  # Should be escalated due to IP links
            "Custom Weights Test": "flag"  # High content weight should drive decision
        }
        
        expected = expected_actions.get(test_case['name'], "unknown")
        status = "✅" if result.action == expected else "❌"
        print(f"\n{status} Expected: {expected}, Got: {result.action}")
        
        print("=" * 60)

async def test_edge_cases():
    """Test edge cases and error conditions."""
    
    print("\n🧪 Testing Edge Cases")
    print("=" * 40)
    
    # Test with missing data
    print("\n1. Missing Data Test:")
    result = await orchestrate(
        {"score": 0.5},  # Missing explain and highlights
        {"score": 0.3},  # Missing links data
        {"score": 0.7}   # Missing reasons
    )
    print(f"  Score: {result.final_score:.2f}, Action: {result.action}")
    print(f"  Summary: {result.summary}")
    
    # Test with zero scores
    print("\n2. All Zero Scores Test:")
    result = await orchestrate(
        {"score": 0.0, "highlights": [], "explain": "Clean content"},
        {"score": 0.0, "links": [], "total_links": 0, "suspicious_count": 0, "details": "No links"},
        {"score": 0.0, "reasons": [], "sender_history": {"is_new_sender": False}, "details": "Normal behavior"}
    )
    print(f"  Score: {result.final_score:.2f}, Action: {result.action}")
    print(f"  Summary: {result.summary}")
    
    # Test with invalid weights
    print("\n3. Invalid Weights Test:")
    try:
        invalid_config = OrchestrationConfig(content_weight=0.6, link_weight=0.3, behavior_weight=0.2)
        print("  ❌ Should have failed validation")
    except ValueError as e:
        print(f"  ✅ Correctly caught validation error: {e}")
    
    # Test with extreme scores
    print("\n4. Extreme Scores Test:")
    result = await orchestrate(
        {"score": 1.0, "highlights": [{"token": "URGENT!!!", "reason": "extreme"}], "explain": "Maximum suspicion"},
        {"score": 1.0, "links": [{"score": 1.0, "reasons": ["Everything wrong"]}], "total_links": 1, "suspicious_count": 1, "details": "All links suspicious"},
        {"score": 1.0, "reasons": ["All red flags"], "sender_history": {"is_new_sender": True}, "details": "Maximum behavior suspicion"}
    )
    print(f"  Score: {result.final_score:.2f}, Action: {result.action}")
    print(f"  Confidence: {result.confidence:.2f}")

async def test_weight_sensitivity():
    """Test how different weights affect outcomes."""
    
    print("\n🧪 Testing Weight Sensitivity")
    print("=" * 40)
    
    # Sample agent outputs
    content_out = {"score": 0.8, "highlights": [], "explain": "High content risk"}
    link_out = {"score": 0.2, "links": [], "total_links": 0, "suspicious_count": 0, "details": "Low link risk"}
    behavior_out = {"score": 0.1, "reasons": [], "sender_history": {"is_new_sender": False}, "details": "Low behavior risk"}
    
    weight_configs = [
        ("Content Heavy", OrchestrationConfig(0.8, 0.1, 0.1)),
        ("Link Heavy", OrchestrationConfig(0.1, 0.8, 0.1)),
        ("Behavior Heavy", OrchestrationConfig(0.1, 0.1, 0.8)),
        ("Balanced", OrchestrationConfig(0.33, 0.33, 0.34)),
        ("Default", None)
    ]
    
    for name, config in weight_configs:
        result = await orchestrate(content_out, link_out, behavior_out, config)
        weights_str = f"{config.content_weight:.1f}/{config.link_weight:.1f}/{config.behavior_weight:.1f}" if config else "0.5/0.3/0.2"
        print(f"  {name} ({weights_str}): Score={result.final_score:.2f}, Action={result.action}")

async def main():
    """Run all orchestrator tests."""
    await test_orchestrator()
    await test_edge_cases()
    await test_weight_sensitivity()
    
    print("\n✅ All orchestrator tests completed!")

if __name__ == "__main__":
    asyncio.run(main())
