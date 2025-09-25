#!/usr/bin/env python3
"""
Test script for the enhanced link agent.
"""

import asyncio
from agents.link_agent import analyze_links, EnhancedLinkAgent

async def test_link_agent():
    """Test the enhanced link agent with various URL types."""
    
    # Test cases with different types of suspicious URLs
    test_cases = [
        {
            "name": "Legitimate URLs",
            "links": [
                "https://www.google.com/search?q=test",
                "https://github.com/user/repo",
                "https://microsoft.com/office"
            ]
        },
        {
            "name": "IP Address URLs",
            "links": [
                "http://192.168.1.100/login",
                "https://10.0.0.1/verify",
                "http://203.0.113.1/secure"
            ]
        },
        {
            "name": "Typosquatting URLs", 
            "links": [
                "https://paypaI.com/login",  # I instead of l
                "https://microsft.com/verify",  # missing 'o'
                "https://googIe.com/secure",  # I instead of l
                "https://gmai1.com/inbox"  # 1 instead of l
            ]
        },
        {
            "name": "Suspicious Patterns",
            "links": [
                "https://secure-paypal-verify.tk/login",
                "http://bit.ly/urgent-verify", 
                "https://xn--e1afmkfd.xn--p1ai/test",  # Punycode
                "https://login.microsoft-security.ml/update"
            ]
        },
        {
            "name": "URL Shorteners",
            "links": [
                "https://bit.ly/xyz123",
                "https://tinyurl.com/abc456",
                "https://t.co/def789"
            ]
        },
        {
            "name": "Long Suspicious URLs",
            "links": [
                "https://very-long-suspicious-domain-name-that-looks-like-paypal.com/login?redirect=https://real-paypal.com&verify=true&urgent=yes&expires=today",
                "http://secure.verify.account.update.microsoft.fake-domain.ru/login"
            ]
        }
    ]
    
    print("Testing Enhanced Link Agent")
    print("=" * 60)
    
    for test_case in test_cases:
        print(f"\n🧪 Test: {test_case['name']}")
        print(f"URLs: {len(test_case['links'])} links")
        
        # Analyze the links
        result = await analyze_links(test_case['links'])
        
        print(f"\n📊 Overall Results:")
        print(f"  Score: {result['score']:.3f}")
        print(f"  Total Links: {result['total_links']}")
        print(f"  Suspicious: {result['suspicious_count']}")
        print(f"  Details: {result['details']}")
        
        print(f"\n🔍 Per-Link Analysis:")
        for i, link_result in enumerate(result['links'], 1):
            url = link_result['url']
            domain = link_result['domain']
            score = link_result['score']
            reasons = link_result['reasons']
            
            # Risk level
            if score >= 0.8:
                risk = "🔴 HIGH"
            elif score >= 0.5:
                risk = "🟡 MEDIUM"
            elif score >= 0.3:
                risk = "🟠 LOW"
            else:
                risk = "🟢 SAFE"
            
            print(f"  {i}. {url[:50]}{'...' if len(url) > 50 else ''}")
            print(f"     Domain: {domain}")
            print(f"     Score: {score:.3f} {risk}")
            if reasons:
                print(f"     Reasons: {', '.join(reasons)}")
            print()
        
        print("-" * 60)

async def test_url_extraction():
    """Test URL extraction from HTML and text content."""
    print("\n🧪 Testing URL Extraction")
    print("=" * 40)
    
    html_content = """
    <html>
    <body>
        <p>Click <a href="https://paypal-verify.com/login">here</a> to verify your account.</p>
        <p>Visit www.suspicious-bank.tk for updates.</p>
        <img src="http://192.168.1.100/tracking.gif" />
        <script src="https://evil-domain.ml/script.js"></script>
    </body>
    </html>
    """
    
    text_content = """
    Dear customer,
    
    Please visit https://secure-login.fake-amazon.ru/verify to update your account.
    
    You can also check www.phishing-site.com for more information.
    
    Contact us at support@real-company.com if you have questions.
    """
    
    agent = EnhancedLinkAgent()
    extracted_urls = agent.extract_urls_from_content(html_content, text_content)
    
    print(f"Extracted {len(extracted_urls)} URLs:")
    for i, url in enumerate(extracted_urls, 1):
        print(f"  {i}. {url}")
    
    # Analyze extracted URLs
    if extracted_urls:
        print(f"\n📊 Analysis of extracted URLs:")
        result = await analyze_links(extracted_urls)
        print(f"  Overall Score: {result['score']:.3f}")
        print(f"  Suspicious URLs: {result['suspicious_count']}/{result['total_links']}")

async def main():
    """Run all tests."""
    await test_link_agent()
    await test_url_extraction()

if __name__ == "__main__":
    asyncio.run(main())
