#!/usr/bin/env python3
"""
Demo script for the new Header Agent functionality.
"""

import asyncio
from agents.header_agent import analyze_headers

async def demo_header_agent():
    """Demonstrate the Header Agent with example email headers."""
    
    print("🧪 Header Agent Demo")
    print("=" * 50)
    print("The Header Agent analyzes email headers for routing patterns and identity mismatches.")
    print("It returns verdicts: 'normal', 'identity mismatch', or 'suspicious routing'\n")
    
    # Test case 1: Normal legitimate email
    print("1️⃣  Normal Gmail Email")
    normal_headers = {
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
    
    result = await analyze_headers(normal_headers)
    print(f"   Score: {result['score']:.3f}")
    print(f"   Verdict: {result['verdict']}")
    print(f"   Details: {result['details']}")
    if result['reasons']:
        print(f"   Issues: {', '.join(result['reasons'])}")
    print()
    
    # Test case 2: Identity mismatch (PayPal spoofing)
    print("2️⃣  Identity Mismatch - PayPal Spoofing")
    spoofing_headers = {
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
        "Authentication-Results": "mx.example.com; dkim=fail; spf=fail; dmarc=fail"
    }
    
    result = await analyze_headers(spoofing_headers)
    print(f"   Score: {result['score']:.3f}")
    print(f"   Verdict: {result['verdict']}")
    print(f"   Details: {result['details']}")
    if result['reasons']:
        print(f"   Issues: {', '.join(result['reasons'])}")
    print()
    
    # Test case 3: Suspicious routing (too many hops)
    print("3️⃣  Suspicious Routing - Excessive Hops")
    routing_headers = {
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
    
    result = await analyze_headers(routing_headers)
    print(f"   Score: {result['score']:.3f}")
    print(f"   Verdict: {result['verdict']}")
    print(f"   Details: {result['details']}")
    if result['reasons']:
        print(f"   Issues: {', '.join(result['reasons'])}")
    
    # Show routing analysis
    routing_analysis = result.get('routing_analysis')
    if routing_analysis:
        print(f"   Routing Hops: {routing_analysis.total_hops}")
        if routing_analysis.suspicious_hops:
            print(f"   Suspicious Servers: {', '.join(routing_analysis.suspicious_hops[:3])}")
    print()
    
    print("🎯 Key Features of the Header Agent:")
    print("   • Analyzes email routing paths (like passport stamps)")
    print("   • Detects identity mismatches (e.g., PayPal email from suspicious domain)")
    print("   • Identifies suspicious routing patterns (too many hops)")
    print("   • Checks authentication headers (SPF, DKIM, DMARC)")
    print("   • Returns simple verdicts: normal, identity mismatch, suspicious routing")
    print("\n✅ Header Agent Demo Complete!")

if __name__ == "__main__":
    asyncio.run(demo_header_agent())
