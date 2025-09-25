"""
Enhanced Link Agent for analyzing URLs with sophisticated detection techniques.
"""

import re
import asyncio
import urllib.parse
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import warnings

# URL and domain analysis
import tldextract
from Levenshtein import distance as levenshtein_distance
import whois
import idna

# HTML parsing
from bs4 import BeautifulSoup

# Homoglyph detection
from confusable_homoglyphs import confusables

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')


@dataclass
class LinkAnalysisResult:
    """Result of link analysis."""
    score: float
    links: List[Dict[str, Any]]
    total_links: int
    suspicious_count: int
    details: str


class EnhancedLinkAgent:
    """Enhanced link agent with sophisticated URL analysis."""
    
    def __init__(self):
        # Trusted domain allowlist
        self.allowlist_domains = [
            "microsoft.com", "google.com", "paypal.com", "amazon.com",
            "apple.com", "facebook.com", "twitter.com", "linkedin.com",
            "github.com", "stackoverflow.com", "wikipedia.org", "youtube.com",
            "gmail.com", "outlook.com", "yahoo.com", "hotmail.com",
            "office.com", "live.com", "dropbox.com", "zoom.us"
        ]
        
        # URL shorteners
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'short.link', 'tiny.cc', 'rebrand.ly', 'clicky.me',
            'is.gd', 'buff.ly', 'cutt.ly', 'soo.gd'
        ]
        
        # Suspicious TLDs
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.ru', '.cn',
            '.cc', '.pw', '.top', '.click', '.download'
        ]
        
        # Common homoglyph characters
        self.homoglyph_map = {
            'a': ['а', 'α', 'à', 'á', 'â', 'ã', 'ä', 'å'],
            'e': ['е', 'ë', 'è', 'é', 'ê', 'ε'],
            'i': ['і', 'ï', 'ì', 'í', 'î', 'ι', '1', 'l'],
            'o': ['о', 'ο', 'ò', 'ó', 'ô', 'õ', 'ö', '0'],
            'u': ['υ', 'ù', 'ú', 'û', 'ü'],
            'p': ['р', 'ρ'],
            'c': ['с', 'ç'],
            'x': ['х', 'χ'],
            'y': ['у', 'ý', 'ÿ'],
            'n': ['п'],
            'm': ['м'],
            'h': ['һ'],
            'k': ['κ'],
            't': ['τ'],
            'b': ['в'],
            'g': ['ց'],
            'l': ['1', 'I', '|', 'ǀ'],
        }

    async def analyze_links(self, links: List[str]) -> Dict[str, Any]:
        """
        Analyze a list of URLs for phishing indicators.
        
        Args:
            links: List of URLs to analyze
            
        Returns:
            Dict with score, links analysis, and details
        """
        if not links:
            return {
                'score': 0.0,
                'links': [],
                'total_links': 0,
                'suspicious_count': 0,
                'details': 'No links to analyze'
            }
        
        analyzed_links = []
        total_score = 0.0
        suspicious_count = 0
        
        # Analyze each link
        for url in links:
            try:
                link_analysis = await self._analyze_single_link(url)
                analyzed_links.append(link_analysis)
                total_score += link_analysis['score']
                
                if link_analysis['score'] >= 0.5:
                    suspicious_count += 1
                    
            except Exception as e:
                # Handle malformed URLs
                analyzed_links.append({
                    'url': url,
                    'domain': 'invalid',
                    'score': 1.0,  # Malformed URLs are highly suspicious
                    'reasons': [f'Malformed URL: {str(e)}']
                })
                total_score += 1.0
                suspicious_count += 1
        
        # Calculate overall score
        overall_score = total_score / len(links) if links else 0.0
        
        # Generate details
        details = self._generate_details(analyzed_links, suspicious_count, len(links))
        
        return {
            'score': min(1.0, overall_score),
            'links': analyzed_links,
            'total_links': len(links),
            'suspicious_count': suspicious_count,
            'details': details
        }
    
    async def _analyze_single_link(self, url: str) -> Dict[str, Any]:
        """Analyze a single URL comprehensively."""
        reasons = []
        score = 0.0
        
        # Parse URL
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.scheme:
                url = 'http://' + url
                parsed = urllib.parse.urlparse(url)
        except Exception as e:
            return {
                'url': url,
                'domain': 'invalid',
                'score': 1.0,
                'reasons': [f'URL parsing failed: {str(e)}']
            }
        
        # Extract domain information
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}".lower()
            subdomain = extracted.subdomain.lower() if extracted.subdomain else ""
            full_domain = f"{subdomain}.{domain}" if subdomain else domain
        except Exception:
            domain = parsed.netloc.lower()
            full_domain = domain
            subdomain = ""
        
        # 1. Check if domain is an IP address
        if self._is_ip_address(parsed.netloc):
            score += 0.8
            reasons.append("Uses IP address instead of domain")
        
        # 2. Check against allowlist (Levenshtein distance)
        allowlist_score = self._check_allowlist_similarity(domain)
        if allowlist_score > 0:
            score += allowlist_score
            if allowlist_score >= 0.5:
                closest_domain = self._find_closest_allowlist_domain(domain)
                reasons.append(f"Similar to trusted domain '{closest_domain}' (possible typosquatting)")
        
        # 3. Check for URL shorteners
        if domain in self.url_shorteners:
            score += 0.3
            reasons.append("Uses URL shortening service")
        
        # 4. Check for suspicious TLDs
        tld = f".{extracted.suffix}" if extracted.suffix else ""
        if tld in self.suspicious_tlds:
            score += 0.4
            reasons.append(f"Uses suspicious TLD: {tld}")
        
        # 5. Punycode detection
        punycode_score, punycode_reasons = self._check_punycode(full_domain)
        score += punycode_score
        reasons.extend(punycode_reasons)
        
        # 6. Homoglyph detection
        homoglyph_score, homoglyph_reasons = self._check_homoglyphs(domain)
        score += homoglyph_score
        reasons.extend(homoglyph_reasons)
        
        # 7. WHOIS creation date check
        whois_score, whois_reasons = await self._check_whois_date(domain)
        score += whois_score
        reasons.extend(whois_reasons)
        
        # 8. Suspicious URL patterns
        pattern_score, pattern_reasons = self._check_url_patterns(url)
        score += pattern_score
        reasons.extend(pattern_reasons)
        
        # 9. Check subdomain characteristics
        if subdomain:
            subdomain_score, subdomain_reasons = self._check_subdomain(subdomain, domain)
            score += subdomain_score
            reasons.extend(subdomain_reasons)
        
        return {
            'url': url,
            'domain': domain,
            'score': min(1.0, score),
            'reasons': reasons[:5]  # Limit to top 5 reasons
        }
    
    def _is_ip_address(self, netloc: str) -> bool:
        """Check if netloc is an IP address."""
        # Remove port if present
        host = netloc.split(':')[0]
        
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, host):
            # Validate octets
            try:
                octets = host.split('.')
                return all(0 <= int(octet) <= 255 for octet in octets)
            except ValueError:
                return False
        
        # IPv6 pattern (simplified)
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        return bool(re.match(ipv6_pattern, host))
    
    def _check_allowlist_similarity(self, domain: str) -> float:
        """Check similarity to allowlist domains using Levenshtein distance."""
        if domain in self.allowlist_domains:
            return 0.0  # Exact match, trusted
        
        min_distance = float('inf')
        closest_domain = None
        
        for allowed_domain in self.allowlist_domains:
            dist = levenshtein_distance(domain, allowed_domain)
            if dist < min_distance:
                min_distance = dist
                closest_domain = allowed_domain
        
        # Calculate similarity score
        if closest_domain:
            max_len = max(len(domain), len(closest_domain))
            similarity = 1 - (min_distance / max_len)
            
            # High similarity to trusted domain is suspicious (typosquatting)
            if similarity >= 0.8 and min_distance <= 3:
                return 0.6
            elif similarity >= 0.7 and min_distance <= 2:
                return 0.4
            elif similarity >= 0.6 and min_distance == 1:
                return 0.3
        
        return 0.0
    
    def _find_closest_allowlist_domain(self, domain: str) -> str:
        """Find the closest allowlist domain to the given domain."""
        min_distance = float('inf')
        closest_domain = ""
        
        for allowed_domain in self.allowlist_domains:
            dist = levenshtein_distance(domain, allowed_domain)
            if dist < min_distance:
                min_distance = dist
                closest_domain = allowed_domain
        
        return closest_domain
    
    def _check_punycode(self, domain: str) -> Tuple[float, List[str]]:
        """Check for punycode domains (internationalized domain names)."""
        reasons = []
        score = 0.0
        
        try:
            # Check if domain contains punycode
            if 'xn--' in domain:
                score += 0.3
                reasons.append("Contains punycode (internationalized characters)")
                
                # Try to decode punycode
                try:
                    decoded = idna.decode(domain)
                    if decoded != domain:
                        score += 0.2
                        reasons.append(f"Punycode decodes to: {decoded}")
                except Exception:
                    score += 0.1
                    reasons.append("Invalid punycode encoding")
            
            # Check each part of domain for non-ASCII characters
            parts = domain.split('.')
            for part in parts:
                try:
                    # Try to encode as ASCII
                    part.encode('ascii')
                except UnicodeEncodeError:
                    score += 0.2
                    reasons.append("Contains non-ASCII characters")
                    break
                    
        except Exception:
            pass
        
        return score, reasons
    
    def _check_homoglyphs(self, domain: str) -> Tuple[float, List[str]]:
        """Check for homoglyph characters in domain."""
        reasons = []
        score = 0.0
        
        try:
            # Check for confusable characters
            suspicious_chars = []
            
            for char in domain:
                if confusables.is_confusable(char, prefer_ascii=True):
                    suspicious_chars.append(char)
            
            if suspicious_chars:
                score += len(suspicious_chars) * 0.1
                reasons.append(f"Contains potentially confusing characters: {''.join(set(suspicious_chars))}")
            
            # Additional check using our homoglyph map
            for ascii_char, similar_chars in self.homoglyph_map.items():
                for char in domain:
                    if char in similar_chars:
                        score += 0.1
                        reasons.append(f"Character '{char}' resembles '{ascii_char}'")
                        break
                        
        except Exception:
            pass
        
        return min(0.5, score), reasons
    
    async def _check_whois_date(self, domain: str) -> Tuple[float, List[str]]:
        """Check WHOIS creation date (with fallback to mocked recent date)."""
        reasons = []
        score = 0.0
        
        try:
            # Try to get WHOIS information
            w = whois.whois(domain)
            creation_date = None
            
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
            
            if creation_date:
                # Check if domain is very new (created within last 30 days)
                days_old = (datetime.now() - creation_date).days
                
                if days_old < 7:
                    score += 0.5
                    reasons.append(f"Domain registered very recently ({days_old} days ago)")
                elif days_old < 30:
                    score += 0.3
                    reasons.append(f"Domain registered recently ({days_old} days ago)")
                elif days_old < 90:
                    score += 0.1
                    reasons.append(f"Domain is relatively new ({days_old} days ago)")
            else:
                # Fallback: assume recent creation for unknown domains
                score += 0.2
                reasons.append("Domain creation date unknown (assumed recent)")
                
        except Exception:
            # WHOIS lookup failed - fallback to mocked recent date
            score += 0.2
            reasons.append("WHOIS lookup failed (assumed recent registration)")
        
        return score, reasons
    
    def _check_url_patterns(self, url: str) -> Tuple[float, List[str]]:
        """Check for suspicious URL patterns."""
        reasons = []
        score = 0.0
        
        # Check for suspicious query parameters
        suspicious_params = ['redirect', 'goto', 'url', 'link', 'target', 'forward']
        parsed = urllib.parse.urlparse(url)
        
        if parsed.query:
            query_params = urllib.parse.parse_qs(parsed.query)
            for param in suspicious_params:
                if param in query_params:
                    score += 0.2
                    reasons.append(f"Contains suspicious parameter: {param}")
        
        # Check for excessive redirects in URL
        if url.lower().count('redirect') > 1 or url.lower().count('goto') > 0:
            score += 0.3
            reasons.append("Multiple redirect indicators in URL")
        
        # Check for suspicious URL length
        if len(url) > 200:
            score += 0.2
            reasons.append("Unusually long URL")
        
        # Check for suspicious path patterns
        suspicious_paths = ['/login', '/verify', '/confirm', '/update', '/secure']
        for path in suspicious_paths:
            if path in parsed.path.lower():
                score += 0.1
                reasons.append(f"Contains suspicious path: {path}")
        
        # Check for HTTPS vs HTTP
        if parsed.scheme == 'http' and 'login' in url.lower():
            score += 0.3
            reasons.append("HTTP used for login page (insecure)")
        
        return score, reasons
    
    def _check_subdomain(self, subdomain: str, domain: str) -> Tuple[float, List[str]]:
        """Check subdomain characteristics."""
        reasons = []
        score = 0.0
        
        # Check for excessive subdomain levels
        subdomain_parts = subdomain.split('.')
        if len(subdomain_parts) > 3:
            score += 0.2
            reasons.append("Excessive subdomain levels")
        
        # Check for suspicious subdomain patterns
        suspicious_subdomains = ['secure', 'verify', 'login', 'account', 'update', 'confirm']
        for suspicious in suspicious_subdomains:
            if suspicious in subdomain.lower():
                score += 0.15
                reasons.append(f"Suspicious subdomain: {suspicious}")
        
        # Check for long subdomain
        if len(subdomain) > 20:
            score += 0.1
            reasons.append("Unusually long subdomain")
        
        return score, reasons
    
    def _generate_details(self, analyzed_links: List[Dict], suspicious_count: int, total_count: int) -> str:
        """Generate human-readable details about the link analysis."""
        if total_count == 0:
            return "No links analyzed"
        
        details = [f"Analyzed {total_count} links"]
        
        if suspicious_count > 0:
            details.append(f"{suspicious_count} suspicious links detected")
            
            # Add details about most suspicious links
            high_risk_links = [link for link in analyzed_links if link['score'] >= 0.7]
            if high_risk_links:
                details.append(f"{len(high_risk_links)} high-risk links found")
        else:
            details.append("No highly suspicious links detected")
        
        return ". ".join(details)
    
    def extract_urls_from_content(self, body_html: str = "", body_text: str = "") -> List[str]:
        """Extract URLs from HTML and text content using BeautifulSoup and regex."""
        urls = set()
        
        # Extract from HTML using BeautifulSoup
        if body_html:
            try:
                soup = BeautifulSoup(body_html, 'html.parser')
                
                # Extract from href attributes
                for link in soup.find_all('a', href=True):
                    urls.add(link['href'])
                
                # Extract from src attributes (images, scripts, etc.)
                for element in soup.find_all(['img', 'script', 'iframe'], src=True):
                    urls.add(element['src'])
                
            except Exception:
                pass
        
        # Extract from text using regex
        combined_text = f"{body_html} {body_text}"
        url_patterns = [
            r'https?://[^\s<>"\'`]+',  # Standard HTTP/HTTPS URLs
            r'www\.[^\s<>"\'`]+',      # www. URLs without protocol
            r'ftp://[^\s<>"\'`]+',     # FTP URLs
        ]
        
        for pattern in url_patterns:
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            urls.update(matches)
        
        # Clean and validate URLs
        cleaned_urls = []
        for url in urls:
            # Remove trailing punctuation
            url = re.sub(r'[.,;!?)\]}>"\']$', '', url)
            
            # Add protocol if missing
            if url.startswith('www.') and not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Basic validation
            if len(url) > 10 and ('.' in url or '//' in url):
                cleaned_urls.append(url)
        
        return list(set(cleaned_urls))


# Global instance for performance
_link_agent = None

async def get_link_agent():
    """Get singleton link agent instance."""
    global _link_agent
    if _link_agent is None:
        _link_agent = EnhancedLinkAgent()
    return _link_agent

async def analyze_links(links: List[str]) -> Dict[str, Any]:
    """
    Analyze a list of URLs for phishing indicators.
    
    Args:
        links: List of URLs to analyze
        
    Returns:
        Dict with keys: 'score', 'links', 'total_links', 'suspicious_count', 'details'
    """
    agent = await get_link_agent()
    return await agent.analyze_links(links)


# Backward compatibility class for orchestrator
class LinkAgent:
    """Backward compatibility wrapper for the enhanced link agent."""
    
    def __init__(self):
        self.enhanced_agent = None
    
    async def _get_agent(self):
        if self.enhanced_agent is None:
            self.enhanced_agent = await get_link_agent()
        return self.enhanced_agent
    
    async def analyze(self, email_data: Dict[str, Any]):
        """Legacy analyze method for backward compatibility."""
        agent = await self._get_agent()
        
        # Extract URLs from email data
        provided_links = email_data.get('links', [])
        body_html = email_data.get('body_html', '')
        body_text = email_data.get('body_text', '')
        
        # Extract additional URLs from content
        extracted_urls = agent.extract_urls_from_content(body_html, body_text)
        
        # Combine all URLs
        all_urls = list(set(provided_links + extracted_urls))
        
        # Analyze URLs
        result = await agent.analyze_links(all_urls)
        
        # Convert to legacy format
        from dataclasses import dataclass
        
        @dataclass
        class LinkAnalysisResultLegacy:
            total_links: int
            suspicious_links: List[str]
            shortened_links: List[str] 
            suspicious_domains: List[str]
            ip_addresses: List[str]
            redirect_chains: List[str]
            score: float
            confidence: float
            details: str
        
        # Extract legacy data from new format
        suspicious_links = [link['url'] for link in result['links'] if link['score'] >= 0.5]
        ip_addresses = [link['url'] for link in result['links'] 
                       if any('IP address' in reason for reason in link['reasons'])]
        
        return LinkAnalysisResultLegacy(
            total_links=result['total_links'],
            suspicious_links=suspicious_links,
            shortened_links=[],  # Could extract from reasons if needed
            suspicious_domains=[link['domain'] for link in result['links'] if link['score'] >= 0.5],
            ip_addresses=ip_addresses,
            redirect_chains=[],  # Could extract from reasons if needed
            score=result['score'],
            confidence=min(0.95, 0.3 + result['score'] * 0.5),
            details=result['details']
        )
