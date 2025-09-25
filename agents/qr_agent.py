"""
QR Code Agent for analyzing QR codes in emails for phishing indicators.
"""

import re
import base64
import io
import asyncio
from typing import Dict, List, Any, Tuple, Optional, Union
from dataclasses import dataclass
import urllib.parse
from datetime import datetime
import warnings

# QR Code processing
try:
    import cv2
    import numpy as np
    from PIL import Image
    from pyzbar import pyzbar
    import qrcode
except ImportError as e:
    print(f"Warning: QR code dependencies not installed: {e}")
    print("Run: pip install qrcode[pil] pyzbar opencv-python Pillow")

# HTML parsing
from bs4 import BeautifulSoup

# URL analysis (reuse from link agent)
import tldextract

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')


@dataclass
class QRCodeData:
    """Data extracted from a QR code."""
    content: str
    content_type: str  # 'url', 'text', 'vcard', 'wifi', 'email', 'sms', 'phone', 'unknown'
    raw_data: bytes
    format: str  # QR code format (usually 'QRCODE')
    location: str  # Where the QR code was found (e.g., 'embedded_image', 'attachment')


@dataclass
class QRAnalysisResult:
    """Result of QR code analysis."""
    score: float
    qr_codes: List[Dict[str, Any]]
    total_qr_codes: int
    suspicious_count: int
    details: str
    confidence: float


class QRCodeAgent:
    """Agent for analyzing QR codes in emails."""
    
    def __init__(self):
        # Suspicious patterns in QR code content
        self.suspicious_keywords = [
            'urgent', 'verify', 'suspend', 'limited', 'expired', 'confirm',
            'update', 'secure', 'click', 'act now', 'immediate', 'winner',
            'congratulations', 'prize', 'bitcoin', 'crypto', 'investment',
            'inheritance', 'lawsuit', 'tax', 'refund', 'irs', 'police'
        ]
        
        # Suspicious URL patterns (reuse link agent logic)
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.ru', '.cn',
            '.cc', '.pw', '.top', '.click', '.download'
        ]
        
        # URL shorteners
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'short.link', 'tiny.cc', 'rebrand.ly', 'clicky.me',
            'is.gd', 'buff.ly', 'cutt.ly', 'soo.gd'
        ]
        
        # Trusted domains
        self.trusted_domains = [
            'microsoft.com', 'google.com', 'paypal.com', 'amazon.com',
            'apple.com', 'facebook.com', 'twitter.com', 'linkedin.com',
            'github.com', 'stackoverflow.com', 'wikipedia.org', 'youtube.com'
        ]

    async def analyze(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze QR codes in email data.
        
        Args:
            email_data: Dictionary containing email fields
            
        Returns:
            Dictionary with analysis results including score, qr_codes, total_qr_codes, suspicious_count, details, confidence
        """
        # Extract QR codes from email
        qr_codes = await self._extract_qr_codes(email_data)
        
        if not qr_codes:
            return {
                'score': 0.0,
                'qr_codes': [],
                'total_qr_codes': 0,
                'suspicious_count': 0,
                'details': "No QR codes found in email",
                'confidence': 1.0
            }
        
        # Analyze each QR code
        analyzed_qr_codes = []
        total_score = 0.0
        suspicious_count = 0
        
        for qr_data in qr_codes:
            try:
                analysis = await self._analyze_single_qr_code(qr_data)
                analyzed_qr_codes.append(analysis)
                total_score += analysis['score']
                
                if analysis['score'] >= 0.5:
                    suspicious_count += 1
                    
            except Exception as e:
                # Handle malformed QR codes
                analyzed_qr_codes.append({
                    'content': qr_data.content,
                    'content_type': qr_data.content_type,
                    'location': qr_data.location,
                    'score': 0.8,  # Unknown QR codes are moderately suspicious
                    'reasons': [f'QR code analysis failed: {str(e)}']
                })
                total_score += 0.8
                suspicious_count += 1
        
        # Calculate overall score
        overall_score = total_score / len(qr_codes) if qr_codes else 0.0
        
        # Calculate confidence based on successful analysis
        confidence = min(0.95, 0.7 + (len(analyzed_qr_codes) / max(len(qr_codes), 1)) * 0.25)
        
        # Generate details
        details = self._generate_details(analyzed_qr_codes, suspicious_count, len(qr_codes))
        
        return {
            'score': min(1.0, overall_score),
            'qr_codes': analyzed_qr_codes,
            'total_qr_codes': len(qr_codes),
            'suspicious_count': suspicious_count,
            'details': details,
            'confidence': confidence
        }

    async def _extract_qr_codes(self, email_data: Dict[str, Any]) -> List[QRCodeData]:
        """Extract QR codes from email content."""
        qr_codes = []
        
        # Extract from HTML images
        body_html = email_data.get('body_html', '')
        if body_html:
            html_qr_codes = await self._extract_from_html(body_html)
            qr_codes.extend(html_qr_codes)
        
        # Extract from attachments (if provided)
        attachments = email_data.get('attachments', [])
        for attachment in attachments:
            attachment_qr_codes = await self._extract_from_attachment(attachment)
            qr_codes.extend(attachment_qr_codes)
        
        return qr_codes

    async def _extract_from_html(self, html_content: str) -> List[QRCodeData]:
        """Extract QR codes from HTML image tags."""
        qr_codes = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Find all img tags
            img_tags = soup.find_all('img')
            
            for i, img in enumerate(img_tags):
                src = img.get('src', '')
                
                # Check for base64 encoded images
                if src.startswith('data:image/'):
                    try:
                        # Extract base64 data
                        header, data = src.split(',', 1)
                        image_data = base64.b64decode(data)
                        
                        # Decode QR codes from image
                        qr_data_list = await self._decode_qr_from_bytes(image_data, 'embedded_image')
                        qr_codes.extend(qr_data_list)
                        
                    except Exception as e:
                        # Skip invalid base64 images
                        continue
                
                # Check for QR code URLs (external images)
                elif src and any(keyword in src.lower() for keyword in ['qr', 'code', 'barcode']):
                    qr_codes.append(QRCodeData(
                        content=f"External QR image: {src}",
                        content_type='external_image',
                        raw_data=b'',
                        format='UNKNOWN',
                        location='external_image'
                    ))
        
        except Exception as e:
            # HTML parsing failed
            pass
        
        return qr_codes

    async def _extract_from_attachment(self, attachment: Dict[str, Any]) -> List[QRCodeData]:
        """Extract QR codes from email attachment."""
        qr_codes = []
        
        try:
            # Get attachment data
            content = attachment.get('content', '')
            content_type = attachment.get('content_type', '')
            filename = attachment.get('filename', '')
            
            # Only process image attachments
            if content_type.startswith('image/') or any(ext in filename.lower() for ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']):
                # Decode base64 attachment
                image_data = base64.b64decode(content)
                
                # Decode QR codes from image
                qr_data_list = await self._decode_qr_from_bytes(image_data, f'attachment:{filename}')
                qr_codes.extend(qr_data_list)
        
        except Exception as e:
            # Skip invalid attachments
            pass
        
        return qr_codes

    async def _decode_qr_from_bytes(self, image_data: bytes, location: str) -> List[QRCodeData]:
        """Decode QR codes from image bytes."""
        qr_codes = []
        
        try:
            # Convert bytes to PIL Image
            image = Image.open(io.BytesIO(image_data))
            
            # Convert to RGB if needed (pyzbar works better with RGB/grayscale)
            if image.mode not in ('RGB', 'L'):
                image = image.convert('RGB')
            
            # Try direct pyzbar decode on PIL image first
            decoded_objects = pyzbar.decode(image)
            
            # If that fails, try with OpenCV processing
            if not decoded_objects:
                try:
                    # Convert to numpy array for OpenCV
                    img_array = np.array(image)
                    
                    # Convert to grayscale if needed
                    if len(img_array.shape) == 3:
                        if img_array.shape[2] == 4:  # RGBA
                            img_gray = cv2.cvtColor(img_array, cv2.COLOR_RGBA2GRAY)
                        else:  # RGB
                            img_gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
                    else:
                        img_gray = img_array
                    
                    # Apply some image processing to improve detection
                    # Threshold the image
                    _, img_thresh = cv2.threshold(img_gray, 127, 255, cv2.THRESH_BINARY)
                    
                    # Try decoding the thresholded image
                    decoded_objects = pyzbar.decode(img_thresh)
                    
                    # If still no luck, try with morphological operations
                    if not decoded_objects:
                        kernel = np.ones((2,2), np.uint8)
                        img_morph = cv2.morphologyEx(img_thresh, cv2.MORPH_CLOSE, kernel)
                        decoded_objects = pyzbar.decode(img_morph)
                        
                except Exception as cv_error:
                    # OpenCV processing failed, but we might have gotten results from PIL
                    pass
            
            # Process any found QR codes
            for obj in decoded_objects:
                # Extract QR code data
                content = obj.data.decode('utf-8', errors='ignore')
                content_type = self._classify_content(content)
                
                qr_codes.append(QRCodeData(
                    content=content,
                    content_type=content_type,
                    raw_data=obj.data,
                    format=obj.type,
                    location=location
                ))
        
        except Exception as e:
            # QR code decoding failed
            pass
        
        return qr_codes

    def _classify_content(self, content: str) -> str:
        """Classify QR code content type."""
        content_lower = content.lower()
        
        # URL detection
        if content.startswith(('http://', 'https://', 'ftp://')):
            return 'url'
        
        # Email detection
        if content.startswith('mailto:') or '@' in content and '.' in content:
            return 'email'
        
        # Phone detection
        if content.startswith('tel:') or re.match(r'^[\+]?[\d\s\-\(\)]{7,15}$', content):
            return 'phone'
        
        # SMS detection
        if content.startswith('sms:') or content.startswith('smsto:'):
            return 'sms'
        
        # vCard detection
        if content.startswith('BEGIN:VCARD') or 'VCARD' in content_lower:
            return 'vcard'
        
        # WiFi detection
        if content.startswith('WIFI:') or 'wifi:' in content_lower:
            return 'wifi'
        
        # App store links
        if any(store in content_lower for store in ['play.google.com', 'apps.apple.com', 'microsoft.com/store']):
            return 'app_store'
        
        # Plain text
        return 'text'

    async def _analyze_single_qr_code(self, qr_data: QRCodeData) -> Dict[str, Any]:
        """Analyze a single QR code for suspicious patterns."""
        reasons = []
        score = 0.0
        
        content = qr_data.content
        content_type = qr_data.content_type
        
        # Base score for having a QR code (slightly suspicious by default)
        score += 0.1
        reasons.append("Contains QR code (requires user interaction)")
        
        # Analyze based on content type
        if content_type == 'url':
            url_score, url_reasons = await self._analyze_qr_url(content)
            score += url_score
            reasons.extend(url_reasons)
        
        elif content_type == 'text':
            text_score, text_reasons = self._analyze_qr_text(content)
            score += text_score
            reasons.extend(text_reasons)
        
        elif content_type == 'vcard':
            vcard_score, vcard_reasons = self._analyze_qr_vcard(content)
            score += vcard_score
            reasons.extend(vcard_reasons)
        
        elif content_type == 'wifi':
            wifi_score, wifi_reasons = self._analyze_qr_wifi(content)
            score += wifi_score
            reasons.extend(wifi_reasons)
        
        elif content_type == 'external_image':
            score += 0.3
            reasons.append("QR code loaded from external source")
        
        # Check for suspicious keywords across all content types
        keyword_score, keyword_reasons = self._check_suspicious_keywords(content)
        score += keyword_score
        reasons.extend(keyword_reasons)
        
        return {
            'content': content[:100] + ('...' if len(content) > 100 else ''),  # Truncate for display
            'content_type': content_type,
            'location': qr_data.location,
            'score': min(1.0, score),
            'reasons': reasons[:5]  # Limit to top 5 reasons
        }

    async def _analyze_qr_url(self, url: str) -> Tuple[float, List[str]]:
        """Analyze URL content in QR code."""
        reasons = []
        score = 0.0
        
        try:
            # Parse URL
            parsed = urllib.parse.urlparse(url)
            
            # Extract domain
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}".lower()
            
            # Check if it's an IP address
            if self._is_ip_address(parsed.netloc):
                score += 0.7
                reasons.append("QR URL uses IP address")
            
            # Check for suspicious TLDs
            tld = f".{extracted.suffix}"
            if tld in self.suspicious_tlds:
                score += 0.4
                reasons.append(f"QR URL uses suspicious TLD: {tld}")
            
            # Check for URL shorteners
            if domain in self.url_shorteners:
                score += 0.5
                reasons.append("QR URL uses shortening service")
            
            # Check if domain is trusted
            if domain in self.trusted_domains:
                score = max(0, score - 0.2)  # Reduce suspicion for trusted domains
            
            # Check for HTTPS
            if parsed.scheme == 'http':
                score += 0.2
                reasons.append("QR URL uses insecure HTTP")
            
            # Check for suspicious paths
            suspicious_paths = ['/login', '/verify', '/confirm', '/update', '/secure', '/download']
            for path in suspicious_paths:
                if path in parsed.path.lower():
                    score += 0.2
                    reasons.append(f"QR URL contains suspicious path: {path}")
            
        except Exception as e:
            score += 0.5
            reasons.append("QR URL is malformed")
        
        return score, reasons

    def _analyze_qr_text(self, text: str) -> Tuple[float, List[str]]:
        """Analyze plain text content in QR code."""
        reasons = []
        score = 0.0
        
        # Check for cryptocurrency addresses
        crypto_patterns = [
            r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',  # Bitcoin
            r'\b0x[a-fA-F0-9]{40}\b',  # Ethereum
            r'\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b'  # Litecoin
        ]
        
        for pattern in crypto_patterns:
            if re.search(pattern, text):
                score += 0.6
                reasons.append("QR contains cryptocurrency address")
                break
        
        # Check for bank account patterns
        bank_patterns = [
            r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',  # Card number pattern
            r'\biban[\s:]*[a-z]{2}\d{2}[a-z0-9]{4}\d{7}[a-z0-9]{0,16}\b',  # IBAN
            r'\brouting[\s:]*\d{9}\b',  # US routing number
        ]
        
        for pattern in bank_patterns:
            if re.search(pattern, text.lower()):
                score += 0.7
                reasons.append("QR contains financial information")
                break
        
        return score, reasons

    def _analyze_qr_vcard(self, vcard: str) -> Tuple[float, List[str]]:
        """Analyze vCard content in QR code."""
        reasons = []
        score = 0.0
        
        # vCards are generally legitimate, but check for suspicious content
        vcard_lower = vcard.lower()
        
        # Check for suspicious organization names
        suspicious_orgs = ['bank', 'police', 'irs', 'government', 'security', 'microsoft', 'apple', 'google']
        for org in suspicious_orgs:
            if org in vcard_lower:
                score += 0.3
                reasons.append(f"vCard claims affiliation with {org}")
        
        # Check for multiple phone numbers (could be scammer pattern)
        phone_count = vcard.count('TEL:')
        if phone_count > 3:
            score += 0.2
            reasons.append("vCard contains many phone numbers")
        
        return score, reasons

    def _analyze_qr_wifi(self, wifi: str) -> Tuple[float, List[str]]:
        """Analyze WiFi configuration in QR code."""
        reasons = []
        score = 0.0
        
        # WiFi QR codes can be used for evil twin attacks
        score += 0.3
        reasons.append("WiFi QR code (potential security risk)")
        
        # Check for open networks
        if 'nopass' in wifi.lower() or 'open' in wifi.lower():
            score += 0.2
            reasons.append("WiFi QR code for open network")
        
        # Check for suspicious network names
        wifi_lower = wifi.lower()
        suspicious_names = ['free', 'public', 'guest', 'open', 'wifi', 'internet']
        for name in suspicious_names:
            if name in wifi_lower:
                score += 0.1
                reasons.append(f"WiFi network name contains '{name}'")
        
        return score, reasons

    def _check_suspicious_keywords(self, content: str) -> Tuple[float, List[str]]:
        """Check for suspicious keywords in QR content."""
        reasons = []
        score = 0.0
        
        content_lower = content.lower()
        found_keywords = []
        
        for keyword in self.suspicious_keywords:
            if keyword in content_lower:
                found_keywords.append(keyword)
        
        if found_keywords:
            score += len(found_keywords) * 0.1
            reasons.append(f"Contains suspicious keywords: {', '.join(found_keywords[:3])}")
        
        return min(0.5, score), reasons

    def _is_ip_address(self, netloc: str) -> bool:
        """Check if netloc is an IP address."""
        # Remove port if present
        host = netloc.split(':')[0]
        
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, host):
            try:
                octets = host.split('.')
                return all(0 <= int(octet) <= 255 for octet in octets)
            except ValueError:
                return False
        
        # IPv6 pattern (simplified)
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        return bool(re.match(ipv6_pattern, host))

    def _generate_details(self, analyzed_qr_codes: List[Dict], suspicious_count: int, total_count: int) -> str:
        """Generate human-readable details about the QR analysis."""
        if total_count == 0:
            return "No QR codes analyzed"
        
        details = [f"Analyzed {total_count} QR codes"]
        
        if suspicious_count > 0:
            details.append(f"{suspicious_count} suspicious QR codes detected")
            
            # Add details about QR code types
            type_counts = {}
            for qr_data in analyzed_qr_codes:
                content_type = qr_data['content_type']
                type_counts[content_type] = type_counts.get(content_type, 0) + 1
            
            if type_counts:
                type_summary = ', '.join([f"{count} {type_}" for type_, count in type_counts.items()])
                details.append(f"Types found: {type_summary}")
        else:
            details.append("No highly suspicious QR codes detected")
        
        return ". ".join(details)


# Global instance for performance
_qr_agent = None

async def get_qr_agent():
    """Get singleton QR agent instance."""
    global _qr_agent
    if _qr_agent is None:
        _qr_agent = QRCodeAgent()
    return _qr_agent

async def analyze_qr_codes(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze QR codes in email data.
    
    Args:
        email_data: Dictionary containing email fields
        
    Returns:
        Dict with keys: 'score', 'qr_codes', 'total_qr_codes', 'suspicious_count', 'details', 'confidence'
    """
    agent = await get_qr_agent()
    result = await agent.analyze(email_data)
    
    # Convert dataclass to dict for compatibility
    return {
        'score': result.score,
        'qr_codes': result.qr_codes,
        'total_qr_codes': result.total_qr_codes,
        'suspicious_count': result.suspicious_count,
        'details': result.details,
        'confidence': result.confidence
    }
