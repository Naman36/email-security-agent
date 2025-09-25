#!/usr/bin/env python3
"""
Test script for the enhanced behavior agent.
"""

import asyncio
import os
from datetime import datetime, timedelta
from agents.behavior_agent import (
    analyze_behavior, 
    create_email_store, 
    EnhancedBehaviorAgent,
    SQLiteEmailStore
)

async def test_behavior_agent():
    """Test the enhanced behavior agent with various scenarios."""
    
    # Create test store
    store = create_email_store("sqlite", db_path="test_data/test_behavior.db")
    
    # Test cases
    test_cases = [
        {
            "name": "New Sender - Legitimate",
            "email": {
                "from": "john.doe@company.com",
                "subject": "Weekly Report",
                "headers": {
                    "Date": "Mon, 21 Oct 2024 10:30:00 +0000",
                    "Message-ID": "<12345@company.com>",
                },
                "body_text": "Here's this week's report."
            }
        },
        {
            "name": "New Sender - Suspicious Display Name",
            "email": {
                "from": "Amazon Support <noreply@suspicious-domain.com>",
                "subject": "Account Verification Required",
                "headers": {
                    "Date": "Mon, 21 Oct 2024 11:00:00 +0000",
                    "Reply-To": "different@another-domain.com"
                },
                "body_text": "Please verify your account immediately."
            }
        },
        {
            "name": "Reply-To Mismatch",
            "email": {
                "from": "support@paypal.com",
                "subject": "Account Update",
                "headers": {
                    "Date": "Mon, 21 Oct 2024 11:30:00 +0000",
                    "Reply-To": "noreply@different-domain.com",
                    "Message-ID": "<67890@paypal.com>"
                },
                "body_text": "Update your account information."
            }
        },
        {
            "name": "Display Name Spoofing",
            "email": {
                "from": "PayPal Security <security@fake-paypal.ru>",
                "subject": "Urgent Security Alert",
                "headers": {
                    "Date": "Mon, 21 Oct 2024 12:00:00 +0000",
                    "Message-ID": "<alert123@fake-paypal.ru>"
                },
                "body_text": "Your account has been compromised."
            }
        },
        {
            "name": "Established Sender - Pattern Change",
            "email": {
                "from": "john.doe@company.com",  # Same as first email
                "subject": "URGENT: Immediate Action Required!!!",
                "headers": {
                    "Date": "Mon, 21 Oct 2024 12:30:00 +0000",
                    "Reply-To": "different@untrusted.com",  # New reply-to
                    "X-Mailer": "BulkMailer Pro"
                },
                "body_text": "Click here immediately or your account will be suspended!"
            }
        },
        {
            "name": "Missing Headers",
            "email": {
                "from": "admin@bank.com",
                "subject": "Account Suspended",
                "headers": {
                    "Date": "Mon, 21 Oct 2024 03:00:00 +0000",  # Unusual hour
                    # Missing Message-ID
                },
                "body_text": "Your account has been suspended."
            }
        }
    ]
    
    print("Testing Enhanced Behavior Agent")
    print("=" * 60)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n🧪 Test {i}: {test_case['name']}")
        print(f"From: {test_case['email'].get('from', 'N/A')}")
        print(f"Subject: {test_case['email'].get('subject', 'N/A')}")
        
        # Analyze behavior
        result = await analyze_behavior(test_case['email'], store)
        
        print(f"\n📊 Results:")
        print(f"  Score: {result['score']:.3f}")
        print(f"  Details: {result['details']}")
        
        if result['reasons']:
            print(f"  Reasons:")
            for j, reason in enumerate(result['reasons'], 1):
                print(f"    {j}. {reason}")
        
        print(f"\n👤 Sender History:")
        history = result['sender_history']
        if history['is_new_sender']:
            print(f"  Status: New sender (no prior messages)")
        else:
            print(f"  Message Count: {history['message_count']}")
            print(f"  First Seen: {history['first_seen']}")
            print(f"  Last Seen: {history['last_seen']}")
            if history['display_names']:
                print(f"  Display Names: {', '.join(history['display_names'])}")
            if history['reply_to_addresses']:
                print(f"  Reply-To Addresses: {', '.join(history['reply_to_addresses'])}")
        
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
        print("-" * 60)
        
        # Small delay to ensure timestamp differences
        await asyncio.sleep(0.1)
    
    # Clean up
    await store.close()

async def test_storage_backends():
    """Test different storage backends."""
    print("\n🧪 Testing Storage Backends")
    print("=" * 40)
    
    # Test SQLite
    print("\n📁 Testing SQLite Storage:")
    sqlite_store = create_email_store("sqlite", db_path="test_data/sqlite_test.db")
    
    # Record some test data
    await sqlite_store.record_email(
        "test@example.com", 
        "Test User", 
        "reply@example.com", 
        datetime.now()
    )
    
    # Retrieve history
    history = await sqlite_store.get_sender_history("test@example.com")
    if history:
        print(f"  ✅ SQLite: Found {history.message_count} messages for test@example.com")
    else:
        print(f"  ❌ SQLite: No history found")
    
    await sqlite_store.close()
    
    # Test Redis (if available)
    print("\n📝 Testing Redis Storage:")
    try:
        redis_store = create_email_store("redis", redis_url="redis://localhost:6379")
        
        # Test connection
        await redis_store.record_email(
            "redis-test@example.com",
            "Redis Test User",
            "redis-reply@example.com",
            datetime.now()
        )
        
        history = await redis_store.get_sender_history("redis-test@example.com")
        if history:
            print(f"  ✅ Redis: Found {history.message_count} messages for redis-test@example.com")
        else:
            print(f"  ❌ Redis: No history found")
        
        await redis_store.close()
        
    except Exception as e:
        print(f"  ⚠️  Redis: Not available ({str(e)})")

async def test_display_name_extraction():
    """Test display name extraction."""
    print("\n🧪 Testing Display Name Extraction")
    print("=" * 40)
    
    agent = EnhancedBehaviorAgent()
    
    test_cases = [
        'John Doe <john.doe@example.com>',
        '"Amazon Support" <noreply@amazon.com>',
        'PayPal Security Team <security@paypal.com>',
        'simple@email.com',
        'User With Spaces <user@domain.com>',
        '"Quoted Name" <quoted@example.com>',
    ]
    
    for from_field in test_cases:
        display_name = agent._extract_display_name(from_field)
        print(f"  '{from_field}' → Display: '{display_name}'")

async def main():
    """Run all tests."""
    # Ensure test directory exists
    os.makedirs("test_data", exist_ok=True)
    
    await test_behavior_agent()
    await test_storage_backends()
    await test_display_name_extraction()
    
    print("\n✅ All tests completed!")

if __name__ == "__main__":
    asyncio.run(main())
