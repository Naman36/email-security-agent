#!/usr/bin/env python3
"""
Test script for the enhanced header agent.
"""

import asyncio
from agents.header_agent import analyze_headers, EnhancedHeaderAgent

async def test_header_agent():
    """Test the enhanced header agent with various header scenarios."""
    
    # Test cases
    test_cases = [
        {
            "name": "Normal Gmail Email",
            "headers": {
                "From": "John Doe <john.doe@gmail.com>",
                "To": "recipient@company.com",
                "Subject": "Weekly meeting notes",
                "Date": "Mon, 21 Oct 2024 10:30:00 +0000",
                "Message-ID": "<CABcdefgh12345@mail.gmail.com>",
                "Received": [
                    "from mail-yw1-f173.google.com (mail-yw1-f173.google.com [209.85.128.173]) by mx.company.com; Mon, 21 Oct 2024 10:30:05 +0000",
                    "by mail-yw1-f173.google.com with SMTP id abc123; Mon, 21 Oct 2024 10:30:03 +0000"
                ],
                "Authentication-Results": "mx.company.com; dkim=pass; spf=pass; dmarc=pass",
                "DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=20210112;"
            }
        },
        {
            "name": "Identity Mismatch - PayPal Spoofing",
            "headers": {
                "From": "PayPal Security <security@paypal.com>",
                "To": "user@example.com",
                "Subject": "Urgent: Account verification required",
                "Date": "Mon, 21 Oct 2024 11:00:00 +0000",
                "Message-ID": "<suspicious123@fake-paypal.ru>",
                "Received": [
                    "from suspicious-server.ru (unknown [192.168.1.100]) by mx.example.com; Mon, 21 Oct 2024 11:00:05 +0000",
                    "from bulk-mailer.sketchy.com by suspicious-server.ru; Mon, 21 Oct 2024 11:00:02 +0000"
                ],
                "Return-Path": "<noreply@fake-paypal.ru>",
                "Authentication-Results": "mx.example.com; dkim=fail; spf=fail; dmarc=fail",
                "X-Mailer": "BulkMailer Pro v2.1"
            }
        },
        {
            "name": "Excessive Routing Hops",
            "headers": {
                "From": "notifications@legitimate-service.com",
                "To": "user@example.com",
                "Subject": "Service notification",
                "Date": "Mon, 21 Oct 2024 12:00:00 +0000",
                "Message-ID": "<notification456@legitimate-service.com>",
                "Received": [
                    "from final-server.com by mx.example.com; Mon, 21 Oct 2024 12:00:15 +0000",
                    "from relay9.suspicious.tk by final-server.com; Mon, 21 Oct 2024 12:00:12 +0000",
                    "from relay8.bulk.ml by relay9.suspicious.tk; Mon, 21 Oct 2024 12:00:10 +0000",
                    "from relay7.spam.gq by relay8.bulk.ml; Mon, 21 Oct 2024 12:00:08 +0000",
                    "from relay6.mass.cf by relay7.spam.gq; Mon, 21 Oct 2024 12:00:06 +0000",
                    "from relay5.campaign.ga by relay6.mass.cf; Mon, 21 Oct 2024 12:00:04 +0000",
                    "from relay4.marketing.ru by relay5.campaign.ga; Mon, 21 Oct 2024 12:00:02 +0000",
                    "from relay3.bulk.cn by relay4.marketing.ru; Mon, 21 Oct 2024 12:00:00 +0000",
                    "from relay2.spam.cc by relay3.bulk.cn; Mon, 21 Oct 2024 11:59:58 +0000",
                    "from relay1.suspicious.pw by relay2.spam.cc; Mon, 21 Oct 2024 11:59:56 +0000",
                    "from origin.legitimate-service.com by relay1.suspicious.pw; Mon, 21 Oct 2024 11:59:54 +0000"
                ]
            }
        },
        {
            "name": "Authentication Failures",
            "headers": {
                "From": "Microsoft Security <security@microsoft.com>",
                "To": "user@company.com",
                "Subject": "Security alert for your account",
                "Date": "Mon, 21 Oct 2024 13:00:00 +0000",
                "Message-ID": "<security789@fake-microsoft.com>",
                "Received": [
                    "from sketchy-server.ru (unknown [10.0.0.1]) by mx.company.com; Mon, 21 Oct 2024 13:00:05 +0000"
                ],
                "Authentication-Results": "mx.company.com; spf=fail (domain does not exist); dkim=none; dmarc=fail",
                "Received-SPF": "fail (domain does not exist) client-ip=10.0.0.1; envelope-from=noreply@fake-microsoft.com"
            }
        },
        {
            "name": "Suspicious Timing and IPs",
            "headers": {
                "From": "Bank Alert <alerts@bank.com>",
                "To": "customer@example.com",
                "Subject": "Urgent: Account compromised",
                "Date": "Mon, 21 Oct 2024 03:30:00 +0000",  # Unusual hour
                "Message-ID": "<alert999@suspicious-bank.com>",
                "Received": [
                    "from server.suspicious.tk ([192.168.1.1]) by mx.example.com; Mon, 21 Oct 2024 03:30:05 +0000",
                    "from internal.local ([127.0.0.1]) by server.suspicious.tk; Mon, 21 Oct 2024 01:30:02 +0000"  # Out of order timestamp
                ],
                "X-Mailer": "Mass Email Blaster v3.0"
            }
        },
        {
            "name": "Missing Standard Headers",
            "headers": {
                "From": "admin@important-site.com",
                "Subject": "Account suspension notice",
                "Date": "Mon, 21 Oct 2024 14:00:00 +0000",
                # Missing To, Message-ID
                "Received": [
                    "from bulk-sender.com by mx.example.com; Mon, 21 Oct 2024 14:00:05 +0000"
                ],
                "X-Mailer": "BulkSender Professional"
            }
        },
        {
            "name": "Legitimate Corporate Email",
            "headers": {
                "From": "HR Department <hr@company.com>",
                "To": "employees@company.com",
                "Subject": "Important policy update",
                "Date": "Mon, 21 Oct 2024 15:00:00 +0000",
                "Message-ID": "<policy.update.2024@company.com>",
                "Received": [
                    "from mail.company.com (mail.company.com [203.0.113.45]) by mx.company.com; Mon, 21 Oct 2024 15:00:03 +0000",
                    "by mail.company.com with ESMTP id xyz789; Mon, 21 Oct 2024 15:00:01 +0000"
                ],
                "Authentication-Results": "mx.company.com; dkim=pass; spf=pass; dmarc=pass",
                "DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed; d=company.com; s=selector1;"
            }
        },
        {
            "name": "Display Name Spoofing - Amazon",
            "headers": {
                "From": "Amazon Customer Service <noreply@amazon-security.tk>",
                "To": "customer@example.com",
                "Subject": "Your order has been cancelled",
                "Date": "Mon, 21 Oct 2024 16:00:00 +0000",
                "Message-ID": "<order123@amazon-security.tk>",
                "Received": [
                    "from fake-amazon.tk (fake-amazon.tk [45.67.89.123]) by mx.example.com; Mon, 21 Oct 2024 16:00:05 +0000"
                ],
                "Return-Path": "<bounce@different-domain.ru>",
                "Authentication-Results": "mx.example.com; spf=softfail; dkim=none; dmarc=none"
            }
        }
    ]
    
    print("Testing Enhanced Header Agent")
    print("=" * 70)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n🧪 Test {i}: {test_case['name']}")
        
        # Show key header info
        from_header = test_case['headers'].get('From', 'N/A')
        subject = test_case['headers'].get('Subject', 'N/A')
        received_count = len(test_case['headers'].get('Received', []))
        
        print(f"From: {from_header}")
        print(f"Subject: {subject}")
        print(f"Routing Hops: {received_count}")
        
        # Analyze headers
        result = await analyze_headers(test_case['headers'])
        
        print(f"\n📊 Results:")
        print(f"  Score: {result['score']:.3f}")
        print(f"  Verdict: {result['verdict']}")
        print(f"  Details: {result['details']}")
        
        if result['reasons']:
            print(f"  Key Issues:")
            for j, reason in enumerate(result['reasons'], 1):
                print(f"    {j}. {reason}")
        
        # Show routing analysis if available
        routing = result.get('routing_analysis')
        if routing:
            print(f"\n🛣️  Routing Analysis:")
            print(f"  Total Hops: {routing.total_hops}")
            if routing.origin_server:
                print(f"  Origin Server: {routing.origin_server}")
            if routing.origin_ip:
                print(f"  Origin IP: {routing.origin_ip}")
            if routing.suspicious_hops:
                print(f"  Suspicious Servers: {', '.join(routing.suspicious_hops)}")
        
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
        print("-" * 70)

async def test_routing_path_parsing():
    """Test routing path parsing functionality."""
    print("\n🧪 Testing Routing Path Parsing")
    print("=" * 50)
    
    agent = EnhancedHeaderAgent()
    
    # Test complex Received headers
    test_headers = {
        "Received": [
            "from mail.google.com (mail.google.com [74.125.136.27]) by mx.example.com with ESMTPS id abc123 (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256); Mon, 21 Oct 2024 10:30:05 +0000",
            "by mail.google.com with SMTP id def456; Mon, 21 Oct 2024 10:30:03 +0000",
            "from user-laptop.local ([192.168.1.100]) by mail.google.com with ESMTPSA id ghi789; Mon, 21 Oct 2024 10:30:01 +0000"
        ]
    }
    
    routing = agent._parse_routing_path(test_headers)
    
    print(f"📈 Routing Path Analysis:")
    print(f"  Total Hops: {routing.total_hops}")
    print(f"  Origin Server: {routing.origin_server}")
    print(f"  Origin IP: {routing.origin_ip}")
    print(f"  Final Server: {routing.final_server}")
    
    print(f"\n🛤️  Hop Details:")
    for i, hop in enumerate(routing.route_hops, 1):
        print(f"    {i}. Server: {hop.server}")
        print(f"       IP: {hop.ip_address}")
        print(f"       Timestamp: {hop.timestamp}")

async def test_domain_extraction():
    """Test domain extraction functionality."""
    print("\n🧪 Testing Domain Extraction")
    print("=" * 40)
    
    agent = EnhancedHeaderAgent()
    
    test_cases = [
        "john.doe@gmail.com",
        "John Doe <john.doe@company.com>",
        '"Display Name" <user@domain.org>',
        "PayPal Security <security@paypal.com>",
        "noreply@suspicious-domain.tk",
        "invalid-email-format",
        ""
    ]
    
    for email in test_cases:
        domain = agent._extract_domain_from_email(email)
        print(f"  '{email}' → Domain: '{domain}'")

async def test_authentication_checks():
    """Test authentication header analysis."""
    print("\n🧪 Testing Authentication Analysis")
    print("=" * 45)
    
    agent = EnhancedHeaderAgent()
    
    test_cases = [
        {
            "name": "All Pass",
            "headers": {
                "Authentication-Results": "mx.example.com; dkim=pass; spf=pass; dmarc=pass",
                "DKIM-Signature": "v=1; a=rsa-sha256; d=domain.com; s=selector1;",
                "Received-SPF": "pass"
            }
        },
        {
            "name": "All Fail",
            "headers": {
                "Authentication-Results": "mx.example.com; dkim=fail; spf=fail; dmarc=fail",
                "Received-SPF": "fail (domain does not exist)"
            }
        },
        {
            "name": "Mixed Results",
            "headers": {
                "Authentication-Results": "mx.example.com; dkim=pass; spf=softfail; dmarc=none",
                "DKIM-Signature": "v=1; a=rsa-sha256; d=domain.com; s=selector1;"
            }
        },
        {
            "name": "No Authentication",
            "headers": {
                "From": "user@domain.com",
                "Subject": "Test"
            }
        }
    ]
    
    for test_case in test_cases:
        print(f"\n📋 Test: {test_case['name']}")
        
        auth_score, auth_reasons = agent._analyze_authentication_headers(test_case['headers'])
        
        print(f"  Score: {auth_score:.3f}")
        if auth_reasons:
            print(f"  Issues: {', '.join(auth_reasons)}")
        else:
            print(f"  Issues: None detected")

async def test_verdict_determination():
    """Test verdict determination logic."""
    print("\n🧪 Testing Verdict Determination")
    print("=" * 40)
    
    agent = EnhancedHeaderAgent()
    
    test_cases = [
        {
            "name": "Identity Mismatch",
            "score": 0.5,
            "identity_reasons": ["Sender domain 'paypal.com' doesn't match origin server 'suspicious.ru'"],
            "routing_reasons": []
        },
        {
            "name": "Suspicious Routing",
            "score": 0.6,
            "identity_reasons": [],
            "routing_reasons": ["Excessive routing hops: 12", "Suspicious routing servers: spam.tk"]
        },
        {
            "name": "Normal Email",
            "score": 0.2,
            "identity_reasons": [],
            "routing_reasons": []
        },
        {
            "name": "High Score Default",
            "score": 0.8,
            "identity_reasons": [],
            "routing_reasons": []
        }
    ]
    
    for test_case in test_cases:
        verdict = agent._determine_verdict(
            test_case['score'],
            test_case['identity_reasons'],
            test_case['routing_reasons']
        )
        print(f"  {test_case['name']} (score: {test_case['score']}) → Verdict: {verdict}")

async def main():
    """Run all tests."""
    await test_header_agent()
    await test_routing_path_parsing()
    await test_domain_extraction()
    await test_authentication_checks()
    await test_verdict_determination()
    
    print("\n✅ All header agent tests completed!")

if __name__ == "__main__":
    asyncio.run(main())
