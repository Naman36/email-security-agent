#!/usr/bin/env python3
"""
Example usage of the enhanced orchestrator functions.

This demonstrates how to use the new orchestrate() function with configurable weights.
"""

import asyncio
from orchestrator import orchestrate, OrchestrationConfig

async def example_orchestration():
    """Example of using the new orchestration functions."""
    
    print("🎯 Enhanced Orchestrator Example")
    print("=" * 50)
    
    # Sample agent outputs (these would normally come from your agents)
    content_output = {
        "score": 0.75,
        "highlights": [
            {"start": 0, "end": 6, "reason": "suspicious_keyword", "token": "URGENT"},
            {"start": 15, "end": 21, "reason": "suspicious_keyword", "token": "verify"}
        ],
        "explain": "High keyword suspicion (score: 0.60). Found suspicious keywords: urgent, verify. ML model predicts high phishing probability (0.85)"
    }
    
    link_output = {
        "score": 0.6,
        "links": [
            {
                "url": "https://paypal-verify.suspicious.com",
                "domain": "paypal-verify.suspicious.com", 
                "score": 0.6,
                "reasons": [
                    "Similar to trusted domain 'paypal.com' (possible typosquatting)",
                    "Uses suspicious TLD: .suspicious"
                ]
            }
        ],
        "total_links": 1,
        "suspicious_count": 1,
        "details": "Analyzed 1 links. 1 suspicious links detected"
    }
    
    behavior_output = {
        "score": 0.7,
        "reasons": [
            "Sender has no prior message history (new sender)",
            "Display name suggests 'paypal' but sender domain is 'suspicious.com'"
        ],
        "sender_history": {
            "is_new_sender": True,
            "message_count": 0
        },
        "details": "High behavioral suspicion detected. First message from this sender"
    }
    
    print("📊 Agent Outputs:")
    print(f"  Content Score: {content_output['score']:.2f}")
    print(f"  Link Score: {link_output['score']:.2f}")
    print(f"  Behavior Score: {behavior_output['score']:.2f}")
    
    # Example 1: Default weights (content=0.5, link=0.3, behavior=0.2)
    print(f"\n🎯 Orchestration with Default Weights:")
    result1 = await orchestrate(content_output, link_output, behavior_output)
    
    print(f"  Final Score: {result1.final_score:.3f}")
    print(f"  Action: {result1.action.upper()}")
    print(f"  Confidence: {result1.confidence:.3f}")
    print(f"  Summary: {result1.summary}")
    
    # Example 2: Custom weights (emphasize behavior more)
    print(f"\n🎯 Orchestration with Custom Weights (Behavior-Heavy):")
    custom_config = OrchestrationConfig(
        content_weight=0.3,
        link_weight=0.2, 
        behavior_weight=0.5
    )
    
    result2 = await orchestrate(content_output, link_output, behavior_output, custom_config)
    
    print(f"  Final Score: {result2.final_score:.3f}")
    print(f"  Action: {result2.action.upper()}")
    print(f"  Confidence: {result2.confidence:.3f}")
    print(f"  Summary: {result2.summary}")
    
    # Example 3: Show detailed reasons
    print(f"\n🔍 Detailed Analysis (Top 3 Reasons):")
    for i, reason in enumerate(result1.detailed_reasons[:3], 1):
        print(f"  {i}. {reason['text']}")
        print(f"     Agent: {reason['agent']}, Priority: {reason['priority']:.3f}")
    
    # Example 4: Different action thresholds demo
    print(f"\n📋 Action Mapping:")
    print(f"  allow:      score < 0.4")
    print(f"  flag:       0.4 ≤ score < 0.7") 
    print(f"  quarantine: score ≥ 0.7")
    print(f"  + Override rules for high-risk indicators")

async def demonstrate_weight_impact():
    """Demonstrate how different weights affect the final decision."""
    
    print(f"\n🧪 Weight Impact Demonstration")
    print("=" * 50)
    
    # Scenario: High content risk, low link/behavior risk
    content_out = {
        "score": 0.9,
        "highlights": [{"token": "URGENT", "reason": "keyword"}],
        "explain": "Extremely suspicious content detected"
    }
    
    link_out = {
        "score": 0.1,
        "links": [{"url": "https://legitimate.com", "score": 0.0, "reasons": []}],
        "total_links": 1,
        "suspicious_count": 0,
        "details": "Clean links"
    }
    
    behavior_out = {
        "score": 0.1,
        "reasons": [],
        "sender_history": {"is_new_sender": False, "message_count": 20},
        "details": "Established sender, no anomalies"
    }
    
    weight_scenarios = [
        ("Content-Heavy", OrchestrationConfig(0.8, 0.1, 0.1)),
        ("Balanced", OrchestrationConfig(0.33, 0.33, 0.34)),
        ("Content-Light", OrchestrationConfig(0.2, 0.4, 0.4))
    ]
    
    print("Scenario: High content risk (0.9), low link/behavior risk (0.1)")
    print()
    
    for name, config in weight_scenarios:
        result = await orchestrate(content_out, link_out, behavior_out, config)
        weights = f"C:{config.content_weight}/L:{config.link_weight}/B:{config.behavior_weight}"
        print(f"  {name:15} ({weights}): Score={result.final_score:.2f} → {result.action.upper()}")

if __name__ == "__main__":
    asyncio.run(example_orchestration())
    asyncio.run(demonstrate_weight_impact())
