#!/usr/bin/env python3
"""
Test script for the enhanced content agent.
"""

import asyncio
from agents.content_agent import analyze_content

async def test_content_agent():
    """Test the enhanced content agent with sample emails."""
    
    # Test cases
    test_cases = [
        {
            "name": "Legitimate Email",
            "subject": "Weekly Team Meeting",
            "body": "Hi team, our weekly meeting is scheduled for tomorrow at 2 PM. Please bring your project updates."
        },
        {
            "name": "Phishing Email - PayPal",
            "subject": "URGENT: Your PayPal account will be suspended!",
            "body": "Dear customer, your PayPal account will be suspended unless you verify immediately by clicking here: http://paypal-verify.com/login. You have 24 hours to act!"
        },
        {
            "name": "Phishing Email - Lottery",
            "subject": "Congratulations! You've won $1,000,000!!!",
            "body": "You have won the international lottery! Click here to claim your prize: http://192.168.1.100/claim. Limited time offer expires today!"
        },
        {
            "name": "Suspicious Email - Credentials",
            "subject": "Security Alert",
            "body": "Your account has been compromised. Please confirm your username and password immediately to prevent suspension."
        }
    ]
    
    print("Testing Enhanced Content Agent")
    print("=" * 50)
    
    for test_case in test_cases:
        print(f"\n🧪 Test: {test_case['name']}")
        print(f"Subject: {test_case['subject']}")
        print(f"Body: {test_case['body'][:100]}...")
        
        # Analyze the content
        result = await analyze_content(test_case['body'], test_case['subject'])
        
        print(f"\n📊 Results:")
        print(f"  Score: {result['score']:.3f}")
        print(f"  Explanation: {result['explain']}")
        
        if result['highlights']:
            print(f"  Highlights ({len(result['highlights'])}):")
            for i, highlight in enumerate(result['highlights'], 1):
                print(f"    {i}. '{highlight['token']}' - {highlight['reason']}")
        else:
            print("  No highlights found")
        
        # Risk assessment
        if result['score'] >= 0.8:
            risk = "🔴 HIGH RISK"
        elif result['score'] >= 0.5:
            risk = "🟡 MEDIUM RISK"
        elif result['score'] >= 0.3:
            risk = "🟠 LOW RISK"
        else:
            risk = "🟢 SAFE"
        
        print(f"  Assessment: {risk}")
        print("-" * 50)

if __name__ == "__main__":
    asyncio.run(test_content_agent())
