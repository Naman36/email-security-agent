"""
Enhanced Behavior Agent for analyzing email metadata and sender patterns.
"""

import re
import asyncio
import json
import os
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
import email.utils
import warnings

# Database support
import aiosqlite
# import aioredis  # Commented out due to Python 3.11+ compatibility issues

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')


@dataclass
class SenderHistory:
    """Sender history information."""
    email: str
    message_count: int
    first_seen: datetime
    last_seen: datetime
    display_names: List[str]
    reply_to_addresses: List[str]


@dataclass 
class BehaviorAnalysisResult:
    """Result of behavior analysis."""
    sender_reputation: str
    timing_anomalies: List[str]
    header_anomalies: List[str]
    authentication_issues: List[str]
    spoofing_indicators: List[str]
    score: float
    confidence: float
    details: str


class EmailStore:
    """Base class for email storage backends."""
    
    async def get_sender_history(self, sender_email: str) -> Optional[SenderHistory]:
        """Get sender history from storage."""
        raise NotImplementedError
    
    async def record_email(self, sender_email: str, display_name: str, reply_to: str, timestamp: datetime):
        """Record email in storage."""
        raise NotImplementedError
    
    async def close(self):
        """Close storage connection."""
        pass


class SQLiteEmailStore(EmailStore):
    """SQLite-based email storage."""
    
    def __init__(self, db_path: str = "data/email_behavior.db"):
        self.db_path = db_path
        self._db = None
    
    async def _get_connection(self):
        """Get database connection."""
        if self._db is None:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            self._db = await aiosqlite.connect(self.db_path)
            await self._create_tables()
        return self._db
    
    async def _create_tables(self):
        """Create database tables."""
        db = await self._get_connection()
        
        await db.execute("""
            CREATE TABLE IF NOT EXISTS sender_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_email TEXT NOT NULL,
                display_name TEXT,
                reply_to TEXT,
                timestamp DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_sender_email 
            ON sender_history(sender_email)
        """)
        
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp 
            ON sender_history(timestamp)
        """)
        
        await db.commit()
    
    async def get_sender_history(self, sender_email: str) -> Optional[SenderHistory]:
        """Get sender history from SQLite."""
        db = await self._get_connection()
        
        cursor = await db.execute("""
            SELECT sender_email, display_name, reply_to, timestamp
            FROM sender_history 
            WHERE sender_email = ?
            ORDER BY timestamp ASC
        """, (sender_email.lower(),))
        
        rows = await cursor.fetchall()
        
        if not rows:
            return None
        
        # Process results
        display_names = set()
        reply_to_addresses = set()
        timestamps = []
        
        for row in rows:
            if row[1]:  # display_name
                display_names.add(row[1])
            if row[2]:  # reply_to
                reply_to_addresses.add(row[2])
            timestamps.append(datetime.fromisoformat(row[3]))
        
        return SenderHistory(
            email=sender_email,
            message_count=len(rows),
            first_seen=min(timestamps),
            last_seen=max(timestamps),
            display_names=list(display_names),
            reply_to_addresses=list(reply_to_addresses)
        )
    
    async def record_email(self, sender_email: str, display_name: str, reply_to: str, timestamp: datetime):
        """Record email in SQLite."""
        db = await self._get_connection()
        
        await db.execute("""
            INSERT INTO sender_history (sender_email, display_name, reply_to, timestamp)
            VALUES (?, ?, ?, ?)
        """, (sender_email.lower(), display_name, reply_to, timestamp.isoformat()))
        
        await db.commit()
    
    async def close(self):
        """Close SQLite connection."""
        if self._db:
            await self._db.close()
            self._db = None


# RedisEmailStore class commented out due to aioredis Python 3.11+ compatibility issues
# To re-enable Redis support, upgrade aioredis to a compatible version and uncomment this class
#
# class RedisEmailStore(EmailStore):
#     """Redis-based email storage."""
#     
#     def __init__(self, redis_url: str = "redis://localhost:6379"):
#         self.redis_url = redis_url
#         self._redis = None
#     
#     async def _get_connection(self):
#         """Get Redis connection."""
#         if self._redis is None:
#             self._redis = aioredis.from_url(self.redis_url, decode_responses=True)
#         return self._redis
#     
#     async def get_sender_history(self, sender_email: str) -> Optional[SenderHistory]:
#         """Get sender history from Redis."""
#         # Implementation details omitted
#         pass
#     
#     async def record_email(self, sender_email: str, display_name: str, reply_to: str, timestamp: datetime):
#         """Record email in Redis."""
#         # Implementation details omitted
#         pass
#     
#     async def close(self):
#         """Close Redis connection."""
#         # Implementation details omitted
#         pass


class EnhancedBehaviorAgent:
    """Enhanced behavior agent with sender tracking and behavioral analysis."""
    
    def __init__(self):
        # Known legitimate display name patterns
        self.legitimate_patterns = {
            'amazon': ['amazon', 'amazon.com', 'amazon customer service', 'amazon support'],
            'paypal': ['paypal', 'paypal.com', 'paypal service', 'paypal support'],
            'microsoft': ['microsoft', 'microsoft.com', 'microsoft support', 'microsoft team'],
            'google': ['google', 'google.com', 'google team', 'google support'],
            'apple': ['apple', 'apple.com', 'apple support', 'apple team'],
            'facebook': ['facebook', 'facebook.com', 'meta'],
            'twitter': ['twitter', 'twitter.com', 'x.com'],
            'linkedin': ['linkedin', 'linkedin.com'],
        }
    
    async def analyze_behavior(self, email_json: Dict[str, Any], store: EmailStore) -> Dict[str, Any]:
        """
        Analyze email behavior patterns and sender history.
        
        Args:
            email_json: Email data dictionary
            store: Storage backend for sender history
            
        Returns:
            Dict with score, reasons, and sender history
        """
        reasons = []
        score = 0.0
        
        # Extract email components
        sender_email = email_json.get('from', '').lower()
        reply_to = email_json.get('reply_to', email_json.get('headers', {}).get('Reply-To', '')).lower()
        display_name = self._extract_display_name(email_json.get('from', ''))
        timestamp = self._parse_timestamp(email_json.get('headers', {}).get('Date', ''))
        
        # Get sender history
        sender_history = await store.get_sender_history(sender_email)
        
        # Heuristic 1: New sender check
        if sender_history is None:
            score += 0.4
            reasons.append("Sender has no prior message history (new sender)")
            is_new_sender = True
        else:
            is_new_sender = False
            
            # Check for sender pattern changes
            pattern_score, pattern_reasons = self._check_sender_patterns(
                sender_history, display_name, reply_to
            )
            score += pattern_score
            reasons.extend(pattern_reasons)
        
        # Heuristic 2: Reply-To mismatch
        if reply_to and sender_email:
            reply_score, reply_reasons = self._check_reply_to_mismatch(sender_email, reply_to)
            score += reply_score
            reasons.extend(reply_reasons)
        
        # Heuristic 3: Display name mismatch
        if display_name and sender_email:
            display_score, display_reasons = self._check_display_name_mismatch(
                display_name, sender_email
            )
            score += display_score
            reasons.extend(display_reasons)
        
        # Additional heuristics
        additional_score, additional_reasons = self._additional_heuristics(email_json)
        score += additional_score
        reasons.extend(additional_reasons)
        
        # Record this email for future analysis
        try:
            await store.record_email(sender_email, display_name, reply_to, timestamp)
        except Exception as e:
            print(f"Warning: Could not record email: {e}")
        
        # Prepare sender history info
        history_info = self._format_sender_history(sender_history, is_new_sender)
        
        return {
            'score': min(1.0, score),
            'reasons': reasons[:5],  # Limit to top 5 reasons
            'sender_history': history_info,
            'details': self._generate_details(score, reasons, sender_history)
        }
    
    def _extract_display_name(self, from_field: str) -> str:
        """Extract display name from email 'From' field."""
        if not from_field:
            return ""
        
        # Handle "Display Name <email@domain.com>" format
        match = re.match(r'^(.+?)\s*<.*>$', from_field.strip())
        if match:
            display_name = match.group(1).strip().strip('"\'')
            return display_name
        
        # Handle cases where there's no display name
        return ""
    
    def _parse_timestamp(self, date_str: str) -> datetime:
        """Parse email date string to datetime."""
        if not date_str:
            return datetime.now()
        
        try:
            # Try parsing with email.utils
            timestamp = email.utils.parsedate_to_datetime(date_str)
            return timestamp.replace(tzinfo=None)  # Remove timezone for simplicity
        except Exception:
            # Fallback to current time
            return datetime.now()
    
    def _check_reply_to_mismatch(self, sender_email: str, reply_to: str) -> tuple[float, List[str]]:
        """Check for Reply-To header mismatch."""
        if not reply_to or not sender_email:
            return 0.0, []
        
        # Extract local parts (before @)
        sender_local = sender_email.split('@')[0] if '@' in sender_email else sender_email
        reply_local = reply_to.split('@')[0] if '@' in reply_to else reply_to
        
        if sender_local != reply_local:
            return 0.3, [f"Reply-To local part '{reply_local}' differs from sender '{sender_local}'"]
        
        return 0.0, []
    
    def _check_display_name_mismatch(self, display_name: str, sender_email: str) -> tuple[float, List[str]]:
        """Check for display name spoofing."""
        if not display_name or not sender_email:
            return 0.0, []
        
        reasons = []
        score = 0.0
        
        display_lower = display_name.lower()
        sender_domain = sender_email.split('@')[1] if '@' in sender_email else ""
        
        # Check if display name mentions a different service than the sender domain
        for service, patterns in self.legitimate_patterns.items():
            if any(pattern in display_lower for pattern in patterns):
                if service not in sender_domain.lower():
                    score += 0.2
                    reasons.append(f"Display name suggests '{service}' but sender domain is '{sender_domain}'")
                    break
        
        # Check for email address in display name
        if '@' in display_name:
            score += 0.15
            reasons.append("Display name contains email address")
        
        # Check for suspicious display name patterns
        suspicious_patterns = [
            'customer service', 'support team', 'security alert', 'account team',
            'billing department', 'verification team', 'no-reply', 'automated'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in display_lower and pattern not in sender_domain.lower():
                score += 0.1
                reasons.append(f"Generic display name '{pattern}' with unrelated domain")
                break
        
        return score, reasons
    
    def _check_sender_patterns(self, history: SenderHistory, current_display: str, 
                              current_reply_to: str) -> tuple[float, List[str]]:
        """Check for changes in sender patterns."""
        reasons = []
        score = 0.0
        
        # Check for new display names
        if current_display and current_display not in history.display_names:
            if len(history.display_names) > 0:
                score += 0.2
                reasons.append(f"New display name '{current_display}' (previous: {', '.join(history.display_names[:2])})")
        
        # Check for new reply-to addresses
        if current_reply_to and current_reply_to not in history.reply_to_addresses:
            if len(history.reply_to_addresses) > 0:
                score += 0.15
                reasons.append(f"New reply-to address '{current_reply_to}'")
        
        # Check message frequency (potential burst)
        if history.message_count > 1:
            time_span = (history.last_seen - history.first_seen).total_seconds()
            if time_span > 0:
                messages_per_day = history.message_count / (time_span / 86400)
                if messages_per_day > 10:  # More than 10 messages per day
                    score += 0.1
                    reasons.append(f"High message frequency ({messages_per_day:.1f} per day)")
        
        return score, reasons
    
    def _additional_heuristics(self, email_json: Dict[str, Any]) -> tuple[float, List[str]]:
        """Additional behavioral heuristics."""
        reasons = []
        score = 0.0
        
        headers = email_json.get('headers', {})
        subject = email_json.get('subject', '')
        
        # Check for missing or suspicious headers
        if not headers.get('Message-ID'):
            score += 0.1
            reasons.append("Missing Message-ID header")
        
        # Check for suspicious X-Mailer
        x_mailer = headers.get('X-Mailer', '')
        if x_mailer and any(term in x_mailer.lower() for term in ['bulk', 'mass', 'blast']):
            score += 0.15
            reasons.append(f"Suspicious mailer: {x_mailer}")
        
        # Check for time zone anomalies
        date_header = headers.get('Date', '')
        if date_header:
            try:
                parsed_date = email.utils.parsedate_to_datetime(date_header)
                # Check if email was sent at an unusual hour (2-6 AM local time)
                hour = parsed_date.hour
                if 2 <= hour <= 6:
                    score += 0.05
                    reasons.append(f"Email sent at unusual hour ({hour}:00)")
            except Exception:
                pass
        
        # Check for urgent subject patterns
        urgent_patterns = ['urgent', 'immediate', 'asap', 'expires', 'suspended']
        if any(pattern in subject.lower() for pattern in urgent_patterns):
            score += 0.1
            reasons.append("Subject contains urgency indicators")
        
        return score, reasons
    
    def _format_sender_history(self, history: Optional[SenderHistory], is_new: bool) -> Dict[str, Any]:
        """Format sender history for response."""
        if is_new or history is None:
            return {
                'is_new_sender': True,
                'message_count': 0,
                'first_seen': None,
                'last_seen': None,
                'display_names': [],
                'reply_to_addresses': []
            }
        
        return {
            'is_new_sender': False,
            'message_count': history.message_count,
            'first_seen': history.first_seen.isoformat(),
            'last_seen': history.last_seen.isoformat(),
            'display_names': history.display_names,
            'reply_to_addresses': history.reply_to_addresses,
            'days_since_first_seen': (datetime.now() - history.first_seen).days
        }
    
    def _generate_details(self, score: float, reasons: List[str], 
                         history: Optional[SenderHistory]) -> str:
        """Generate human-readable details."""
        details = []
        
        if score >= 0.7:
            details.append("High behavioral suspicion detected")
        elif score >= 0.4:
            details.append("Moderate behavioral anomalies found")
        elif score > 0:
            details.append("Minor behavioral inconsistencies detected")
        else:
            details.append("No significant behavioral anomalies")
        
        if history:
            details.append(f"Sender has {history.message_count} previous messages")
        else:
            details.append("First message from this sender")
        
        if reasons:
            details.append(f"Key issues: {', '.join(reasons[:2])}")
        
        return ". ".join(details)


# Storage factory function
def create_email_store(store_type: str = "sqlite", **kwargs) -> EmailStore:
    """Create email storage backend."""
    if store_type.lower() == "sqlite":
        db_path = kwargs.get("db_path", "data/email_behavior.db")
        return SQLiteEmailStore(db_path)
    elif store_type.lower() == "redis":
        # Redis is currently disabled due to aioredis Python 3.11+ compatibility issues
        # Falling back to SQLite storage
        print("Warning: Redis storage is currently disabled. Using SQLite instead.")
        db_path = kwargs.get("db_path", "data/email_behavior.db")
        return SQLiteEmailStore(db_path)
    else:
        raise ValueError(f"Unsupported store type: {store_type}")


# Global instances for performance
_behavior_agent = None
_default_store = None

async def get_behavior_agent():
    """Get singleton behavior agent instance."""
    global _behavior_agent
    if _behavior_agent is None:
        _behavior_agent = EnhancedBehaviorAgent()
    return _behavior_agent

async def get_default_store():
    """Get default storage instance."""
    global _default_store
    if _default_store is None:
        _default_store = create_email_store("sqlite")
    return _default_store

async def analyze_behavior(email_json: Dict[str, Any], store: Optional[EmailStore] = None) -> Dict[str, Any]:
    """
    Analyze email behavior patterns and sender history.
    
    Args:
        email_json: Email data dictionary
        store: Optional storage backend (uses default SQLite if None)
        
    Returns:
        Dict with keys: 'score', 'reasons', 'sender_history', 'details'
    """
    agent = await get_behavior_agent()
    if store is None:
        store = await get_default_store()
    
    return await agent.analyze_behavior(email_json, store)


# Backward compatibility class for orchestrator
class BehaviorAgent:
    """Backward compatibility wrapper for the enhanced behavior agent."""
    
    def __init__(self):
        self.enhanced_agent = None
        self.store = None
    
    async def _get_agent(self):
        if self.enhanced_agent is None:
            self.enhanced_agent = await get_behavior_agent()
        return self.enhanced_agent
    
    async def _get_store(self):
        if self.store is None:
            self.store = await get_default_store()
        return self.store
    
    async def analyze(self, email_data: Dict[str, Any]):
        """Legacy analyze method for backward compatibility."""
        agent = await self._get_agent()
        store = await self._get_store()
        
        # Analyze behavior
        result = await agent.analyze_behavior(email_data, store)
        
        # Convert to legacy format
        from dataclasses import dataclass
        
        @dataclass
        class BehaviorAnalysisResultLegacy:
            sender_reputation: str
            timing_anomalies: List[str]
            header_anomalies: List[str]
            authentication_issues: List[str]
            spoofing_indicators: List[str]
            score: float
            confidence: float
            details: str
        
        # Extract legacy data from new format
        reasons = result['reasons']
        score = result['score']
        
        # Categorize reasons
        spoofing_indicators = [r for r in reasons if 'display name' in r.lower() or 'reply-to' in r.lower()]
        timing_anomalies = [r for r in reasons if 'hour' in r.lower() or 'frequency' in r.lower()]
        header_anomalies = [r for r in reasons if 'header' in r.lower() or 'message-id' in r.lower()]
        
        # Determine sender reputation
        if score >= 0.7:
            reputation = "suspicious"
        elif score >= 0.4:
            reputation = "questionable"
        elif result['sender_history']['is_new_sender']:
            reputation = "unknown"
        else:
            reputation = "established"
        
        return BehaviorAnalysisResultLegacy(
            sender_reputation=reputation,
            timing_anomalies=timing_anomalies,
            header_anomalies=header_anomalies,
            authentication_issues=[],  # Not implemented in new version
            spoofing_indicators=spoofing_indicators,
            score=score,
            confidence=min(0.95, 0.4 + score * 0.5),
            details=result['details']
        )
