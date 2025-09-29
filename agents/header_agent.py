"""
Enhanced Header Agent for analyzing email headers and routing patterns.
"""

import re
import asyncio
import ipaddress
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
import email.utils
import warnings

# Domain analysis
import tldextract

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')


@dataclass
class RouteHop:
    """A single hop in the email routing path."""
    server: str
    ip_address: Optional[str]
    timestamp: Optional[datetime]
    raw_header: str


@dataclass
class RoutingAnalysis:
    """Analysis of email routing path."""
    total_hops: int
    route_hops: List[RouteHop]
    origin_server: Optional[str]
    origin_ip: Optional[str]
    final_server: Optional[str]
    suspicious_hops: List[str]


class EnhancedHeaderAgent:
    """Enhanced header agent for analyzing email headers and routing patterns."""
    
    def __init__(self):
        # Known legitimate email service providers
        self.legitimate_providers = {
            'gmail.com': ['gmail.com', 'google.com', 'googlemail.com'],
            'outlook.com': ['outlook.com', 'hotmail.com', 'live.com', 'office365.com'],
            'yahoo.com': ['yahoo.com', 'yahoomail.com', 'ymail.com'],
            'apple.com': ['apple.com', 'icloud.com', 'me.com', 'mac.com'],
            'amazon.com': ['amazon.com', 'amazonaws.com', 'amazon.ses'],
            'paypal.com': ['paypal.com', 'paypalobjects.com'],
            'microsoft.com': ['microsoft.com', 'office.com', 'office365.com'],
            'facebook.com': ['facebook.com', 'facebookmail.com'],
            'twitter.com': ['twitter.com', 'x.com'],
        }
        
        # Suspicious countries/TLDs for email routing
        self.suspicious_tlds = [
            '.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq', '.cc', '.pw'
        ]
        
        # Common bulk email/spam indicators in routing
        self.bulk_indicators = [
            'bulk', 'mass', 'blast', 'campaign', 'newsletter', 'marketing',
            'mailgun', 'sendgrid', 'mandrill', 'mailchimp'
        ]
        
        # Expected maximum hops for legitimate emails
        self.max_normal_hops = 8
        
    async def analyze_headers(self, email_headers: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze email headers for routing patterns and identity mismatches.
        
        Args:
            email_headers: Dictionary of email headers
            
        Returns:
            Dict with score, verdict, routing_analysis, and details
        """
        if not email_headers:
            return {
                'score': 0.0,
                'verdict': 'normal',
                'routing_analysis': None,
                'details': 'No headers to analyze'
            }
        
        reasons = []
        score = 0.0
        
        # 1. Parse routing path from Received headers
        routing_analysis = self._parse_routing_path(email_headers)
        
        # 2. Analyze sender identity vs routing path
        identity_score, identity_reasons = self._analyze_sender_identity(
            email_headers, routing_analysis
        )
        score += identity_score
        reasons.extend(identity_reasons)
        
        # 3. Check for suspicious routing patterns
        routing_score, routing_reasons = self._analyze_routing_patterns(routing_analysis)
        score += routing_score
        reasons.extend(routing_reasons)
        
        # 4. Check authentication headers
        auth_score, auth_reasons = self._analyze_authentication_headers(email_headers)
        score += auth_score
        reasons.extend(auth_reasons)
        
        # 5. Check for header anomalies
        anomaly_score, anomaly_reasons = self._check_header_anomalies(email_headers)
        score += anomaly_score
        reasons.extend(anomaly_reasons)
        
        # 6. Determine verdict
        verdict = self._determine_verdict(score, identity_reasons, routing_reasons)
        
        # 7. Generate details
        details = self._generate_details(score, verdict, reasons, routing_analysis)
        
        return {
            'score': min(1.0, score),
            'verdict': verdict,
            'routing_analysis': routing_analysis,
            'reasons': reasons[:5],  # Limit to top 5 reasons
            'details': details,
            'confidence': min(0.95, 0.5 + score * 0.4)
        }
    
    def _parse_routing_path(self, headers: Dict[str, Any]) -> RoutingAnalysis:
        """Parse the routing path from Received headers."""
        received_headers = []
        
        # Extract all Received headers
        if 'Received' in headers:
            received = headers['Received']
            if isinstance(received, str):
                received_headers = [received]
            elif isinstance(received, list):
                received_headers = received
        
        route_hops = []
        suspicious_hops = []
        
        # Parse each Received header (reverse order - last received is first in path)
        for received in reversed(received_headers):
            hop = self._parse_received_header(received)
            if hop:
                route_hops.append(hop)
                
                # Check for suspicious elements in this hop
                if self._is_suspicious_hop(hop):
                    suspicious_hops.append(hop.server)
        
        # Determine origin and final servers
        origin_server = route_hops[0].server if route_hops else None
        origin_ip = route_hops[0].ip_address if route_hops else None
        final_server = route_hops[-1].server if route_hops else None
        
        return RoutingAnalysis(
            total_hops=len(route_hops),
            route_hops=route_hops,
            origin_server=origin_server,
            origin_ip=origin_ip,
            final_server=final_server,
            suspicious_hops=suspicious_hops
        )
    
    def _parse_received_header(self, received: str) -> Optional[RouteHop]:
        """Parse a single Received header."""
        if not received:
            return None
        
        # Extract server name - look for "from" or "by" clause
        server_match = re.search(r'(?:from|by)\s+([^\s\[\(]+)', received, re.IGNORECASE)
        server = server_match.group(1) if server_match else "unknown"
        
        # Extract IP address
        ip_match = re.search(r'\[([0-9a-fA-F:.]+)\]', received)
        ip_address = ip_match.group(1) if ip_match else None
        
        # Extract timestamp
        timestamp = None
        timestamp_match = re.search(r';\s*(.+)$', received)
        if timestamp_match:
            try:
                timestamp = email.utils.parsedate_to_datetime(timestamp_match.group(1))
            except Exception:
                pass
        
        return RouteHop(
            server=server.lower(),
            ip_address=ip_address,
            timestamp=timestamp,
            raw_header=received
        )
    
    def _is_suspicious_hop(self, hop: RouteHop) -> bool:
        """Check if a routing hop is suspicious."""
        server_lower = hop.server.lower()
        
        # Check for suspicious TLDs
        for tld in self.suspicious_tlds:
            if tld in server_lower:
                return True
        
        # Check for bulk/spam indicators
        for indicator in self.bulk_indicators:
            if indicator in server_lower:
                return True
        
        # Check if IP is in suspicious ranges
        if hop.ip_address:
            try:
                ip = ipaddress.ip_address(hop.ip_address)
                # Check for private/local IPs in routing (suspicious for external emails)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    return True
            except ValueError:
                pass
        
        return False
    
    def _analyze_sender_identity(self, headers: Dict[str, Any], 
                               routing: RoutingAnalysis) -> Tuple[float, List[str]]:
        """Analyze sender identity vs routing path for mismatches."""
        reasons = []
        score = 0.0
        
        # Extract sender domain
        from_header = headers.get('From', '')
        sender_domain = self._extract_domain_from_email(from_header)
        
        if not sender_domain:
            return 0.0, []
        
        # Check if sender domain matches routing path
        if routing.origin_server:
            origin_domain = self._extract_domain_from_server(routing.origin_server)
            
            # Check for direct domain mismatch
            if not self._domains_match(sender_domain, origin_domain):
                # Check if it's a known legitimate forwarding relationship
                if not self._is_legitimate_forwarding(sender_domain, origin_domain):
                    score += 0.4
                    reasons.append(f"Sender domain '{sender_domain}' doesn't match origin server '{origin_domain}'")
        
        # Check for display name spoofing
        display_name = self._extract_display_name(from_header)
        if display_name and sender_domain:
            spoof_score, spoof_reasons = self._check_display_name_spoofing(
                display_name, sender_domain, routing
            )
            score += spoof_score
            reasons.extend(spoof_reasons)
        
        # Check Return-Path vs From mismatch
        return_path = headers.get('Return-Path', '')
        if return_path and from_header:
            return_domain = self._extract_domain_from_email(return_path)
            if return_domain and not self._domains_match(sender_domain, return_domain):
                score += 0.2
                reasons.append(f"Return-Path domain '{return_domain}' differs from sender '{sender_domain}'")
        
        return score, reasons
    
    def _analyze_routing_patterns(self, routing: RoutingAnalysis) -> Tuple[float, List[str]]:
        """Analyze routing patterns for suspicious behavior."""
        reasons = []
        score = 0.0
        
        if not routing.route_hops:
            return 0.0, []
        
        # Check for excessive hops
        if routing.total_hops > self.max_normal_hops:
            score += 0.3
            reasons.append(f"Excessive routing hops: {routing.total_hops} (normal: ≤{self.max_normal_hops})")
        elif routing.total_hops > self.max_normal_hops * 0.75:
            score += 0.1
            reasons.append(f"Many routing hops: {routing.total_hops}")
        
        # Check for suspicious hops
        if routing.suspicious_hops:
            score += len(routing.suspicious_hops) * 0.2
            reasons.append(f"Suspicious routing servers: {', '.join(routing.suspicious_hops[:3])}")
        
        # Check for routing through suspicious countries
        country_score, country_reasons = self._check_routing_countries(routing)
        score += country_score
        reasons.extend(country_reasons)
        
        # Check for timing anomalies in routing
        timing_score, timing_reasons = self._check_routing_timing(routing)
        score += timing_score
        reasons.extend(timing_reasons)
        
        return score, reasons
    
    def _analyze_authentication_headers(self, headers: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Analyze authentication-related headers."""
        reasons = []
        score = 0.0
        
        # Check SPF results
        spf_score, spf_reasons = self._check_spf(headers)
        score += spf_score
        reasons.extend(spf_reasons)
        
        # Check DKIM results
        dkim_score, dkim_reasons = self._check_dkim(headers)
        score += dkim_score
        reasons.extend(dkim_reasons)
        
        # Check DMARC results
        dmarc_score, dmarc_reasons = self._check_dmarc(headers)
        score += dmarc_score
        reasons.extend(dmarc_reasons)
        
        return score, reasons
    
    def _check_spf(self, headers: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Check SPF authentication results."""
        reasons = []
        score = 0.0
        
        # Look for SPF results in various headers
        spf_headers = [
            'Received-SPF', 'Authentication-Results', 'X-Spam-Status'
        ]
        
        spf_result = None
        for header_name in spf_headers:
            header_value = headers.get(header_name, '')
            if 'spf=' in header_value.lower() or 'received-spf' in header_name.lower():
                spf_result = header_value
                break
        
        if spf_result:
            spf_lower = spf_result.lower()
            if 'fail' in spf_lower:
                score += 0.4
                reasons.append("SPF authentication failed")
            elif 'softfail' in spf_lower:
                score += 0.2
                reasons.append("SPF soft fail")
            elif 'none' in spf_lower or 'neutral' in spf_lower:
                score += 0.1
                reasons.append("No SPF record found")
        else:
            # No SPF information found
            score += 0.05
            reasons.append("SPF authentication not verified")
        
        return score, reasons
    
    def _check_dkim(self, headers: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Check DKIM authentication results."""
        reasons = []
        score = 0.0
        
        # Look for DKIM signature
        dkim_signature = headers.get('DKIM-Signature', '')
        auth_results = headers.get('Authentication-Results', '')
        
        if dkim_signature:
            # DKIM signature present
            if 'fail' in auth_results.lower() and 'dkim' in auth_results.lower():
                score += 0.3
                reasons.append("DKIM signature verification failed")
        else:
            # No DKIM signature
            score += 0.1
            reasons.append("No DKIM signature found")
        
        return score, reasons
    
    def _check_dmarc(self, headers: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Check DMARC authentication results."""
        reasons = []
        score = 0.0
        
        auth_results = headers.get('Authentication-Results', '')
        
        if auth_results:
            auth_lower = auth_results.lower()
            if 'dmarc=' in auth_lower:
                if 'dmarc=fail' in auth_lower:
                    score += 0.5
                    reasons.append("DMARC authentication failed")
                elif 'dmarc=none' in auth_lower:
                    score += 0.1
                    reasons.append("No DMARC policy found")
        
        return score, reasons
    
    def _check_header_anomalies(self, headers: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Check for various header anomalies."""
        reasons = []
        score = 0.0
        
        # Check for missing standard headers
        required_headers = ['From', 'To', 'Date', 'Message-ID']
        missing_headers = [h for h in required_headers if h not in headers]
        
        if missing_headers:
            score += len(missing_headers) * 0.1
            reasons.append(f"Missing standard headers: {', '.join(missing_headers)}")
        
        # Check for malformed Message-ID
        message_id = headers.get('Message-ID', '')
        if message_id and not re.match(r'^<[^@]+@[^>]+>$', message_id):
            score += 0.1
            reasons.append("Malformed Message-ID header")
        
        # Check for suspicious X-Mailer
        x_mailer = headers.get('X-Mailer', '')
        if x_mailer:
            x_mailer_lower = x_mailer.lower()
            for indicator in self.bulk_indicators:
                if indicator in x_mailer_lower:
                    score += 0.1
                    reasons.append(f"Bulk mailer detected: {x_mailer}")
                    break
        
        return score, reasons
    
    def _check_routing_countries(self, routing: RoutingAnalysis) -> Tuple[float, List[str]]:
        """Check for routing through suspicious countries."""
        reasons = []
        score = 0.0
        
        suspicious_countries = []
        
        for hop in routing.route_hops:
            try:
                extracted = tldextract.extract(hop.server)
                if extracted.suffix in [tld.lstrip('.') for tld in self.suspicious_tlds]:
                    suspicious_countries.append(extracted.suffix)
            except Exception:
                pass
        
        if suspicious_countries:
            score += len(set(suspicious_countries)) * 0.15
            reasons.append(f"Routing through suspicious countries: {', '.join(set(suspicious_countries))}")
        
        return score, reasons
    
    def _check_routing_timing(self, routing: RoutingAnalysis) -> Tuple[float, List[str]]:
        """Check for timing anomalies in routing."""
        reasons = []
        score = 0.0
        
        # Check for timestamps that are out of order or have unusual delays
        timestamps = [hop.timestamp for hop in routing.route_hops if hop.timestamp]
        
        if len(timestamps) >= 2:
            for i in range(1, len(timestamps)):
                time_diff = (timestamps[i] - timestamps[i-1]).total_seconds()
                
                # Check for negative time (out of order)
                if time_diff < 0:
                    score += 0.2
                    reasons.append("Timestamps out of order in routing path")
                    break
                
                # Check for excessive delays between hops
                if time_diff > 3600:  # More than 1 hour
                    score += 0.1
                    reasons.append("Unusual delays in email routing")
                    break
        
        return score, reasons
    
    def _check_display_name_spoofing(self, display_name: str, sender_domain: str, 
                                   routing: RoutingAnalysis) -> Tuple[float, List[str]]:
        """Check for display name spoofing attempts."""
        reasons = []
        score = 0.0
        
        display_lower = display_name.lower()
        
        # Check if display name mentions a different service
        for service, domains in self.legitimate_providers.items():
            if any(pattern in display_lower for pattern in domains):
                if service != sender_domain and not any(domain in sender_domain for domain in domains):
                    score += 0.3
                    reasons.append(f"Display name suggests '{service}' but sender is '{sender_domain}'")
                    break
        
        return score, reasons
    
    def _extract_domain_from_email(self, email_addr: str) -> Optional[str]:
        """Extract domain from email address."""
        if not email_addr:
            return None
        
        # Handle "Display Name <email@domain.com>" format
        email_match = re.search(r'<([^>]+)>', email_addr)
        if email_match:
            email_addr = email_match.group(1)
        
        # Extract domain
        if '@' in email_addr:
            return email_addr.split('@')[-1].lower()
        
        return None
    
    def _extract_domain_from_server(self, server: str) -> str:
        """Extract domain from server name."""
        try:
            extracted = tldextract.extract(server)
            return f"{extracted.domain}.{extracted.suffix}".lower()
        except Exception:
            return server.lower()
    
    def _extract_display_name(self, from_field: str) -> str:
        """Extract display name from From field."""
        if not from_field:
            return ""
        
        match = re.match(r'^(.+?)\s*<.*>$', from_field.strip())
        if match:
            return match.group(1).strip().strip('"\'')
        
        return ""
    
    def _domains_match(self, domain1: str, domain2: str) -> bool:
        """Check if two domains match or are related."""
        if not domain1 or not domain2:
            return False
        
        domain1 = domain1.lower()
        domain2 = domain2.lower()
        
        # Exact match
        if domain1 == domain2:
            return True
        
        # Check for subdomain relationships
        if domain1 in domain2 or domain2 in domain1:
            return True
        
        # Check for known legitimate relationships
        for service, domains in self.legitimate_providers.items():
            if domain1 in domains and domain2 in domains:
                return True
        
        return False
    
    def _is_legitimate_forwarding(self, sender_domain: str, origin_domain: str) -> bool:
        """Check if the forwarding relationship is legitimate."""
        # Check known legitimate forwarding services
        legitimate_forwarders = [
            'gmail.com', 'google.com', 'outlook.com', 'office365.com',
            'yahoo.com', 'icloud.com', 'protonmail.com'
        ]
        
        return origin_domain in legitimate_forwarders
    
    def _determine_verdict(self, score: float, identity_reasons: List[str], 
                          routing_reasons: List[str]) -> str:
        """Determine the final verdict based on score and reason types."""
        # Check for specific identity mismatch patterns
        has_identity_mismatch = any('domain' in reason.lower() and 'match' in reason.lower() 
                                  for reason in identity_reasons)
        
        # Check for excessive routing
        has_suspicious_routing = any('hop' in reason.lower() or 'routing' in reason.lower() 
                                   for reason in routing_reasons)
        
        if has_identity_mismatch and score >= 0.3:
            return "identity mismatch"
        elif has_suspicious_routing and score >= 0.4:
            return "suspicious routing"
        elif score >= 0.6:
            return "suspicious routing"  # High score defaults to suspicious routing
        else:
            return "normal"
    
    def _generate_details(self, score: float, verdict: str, reasons: List[str], 
                         routing: RoutingAnalysis) -> str:
        """Generate human-readable details."""
        details = []
        
        # Add verdict and score
        details.append(f"Header analysis verdict: {verdict} (score: {score:.2f})")
        
        # Add routing summary
        if routing and routing.total_hops > 0:
            details.append(f"Email routed through {routing.total_hops} servers")
            if routing.origin_server:
                details.append(f"Origin: {routing.origin_server}")
        else:
            details.append("No routing information available")
        
        # Add key issues
        if reasons:
            details.append(f"Key issues: {', '.join(reasons[:2])}")
        else:
            details.append("No significant header anomalies detected")
        
        return ". ".join(details)


# Global instance for performance
_header_agent = None

async def get_header_agent():
    """Get singleton header agent instance."""
    global _header_agent
    if _header_agent is None:
        _header_agent = EnhancedHeaderAgent()
    return _header_agent

async def analyze_headers(email_headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze email headers for routing patterns and identity mismatches.
    
    Args:
        email_headers: Dictionary of email headers
        
    Returns:
        Dict with keys: 'score', 'verdict', 'routing_analysis', 'reasons', 'details'
    """
    agent = await get_header_agent()
    return await agent.analyze_headers(email_headers)


# Backward compatibility class for orchestrator
class HeaderAgent:
    """Backward compatibility wrapper for the enhanced header agent."""
    
    def __init__(self):
        self.enhanced_agent = None
    
    async def _get_agent(self):
        if self.enhanced_agent is None:
            self.enhanced_agent = await get_header_agent()
        return self.enhanced_agent
    
    async def analyze(self, email_data: Dict[str, Any]):
        """Legacy analyze method for backward compatibility."""
        agent = await self._get_agent()
        
        # Extract headers from email data
        headers = email_data.get('headers', {})
        
        # Analyze headers
        result = await agent.analyze_headers(headers)
        
        # Return dictionary format for consistency with orchestrator
        return result
