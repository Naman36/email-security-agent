"""
Enhanced Content Agent for analyzing email content using ML models.
"""

import re
import asyncio
import pickle
import os
from typing import Dict, List, Any, Tuple
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
# Temporarily commented out due to compatibility issues
# from sentence_transformers import SentenceTransformer
import nltk
from nltk.corpus import stopwords
import warnings

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

# Download required NLTK data
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt', quiet=True)

try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords', quiet=True)


class EnhancedContentAgent:
    """Enhanced content agent with ML-based phishing detection."""
    
    def __init__(self):
        # Phishing keywords for rule-based detection
        self.phishing_keywords = [
            'urgent', 'immediate', 'verify', 'suspend', 'expire', 'confirm',
            'update', 'click here', 'act now', 'limited time', 'offer expires',
            'congratulations', 'winner', 'prize', 'inheritance', 'lottery',
            'tax refund', 'covid', 'stimulus', 'social security', 'account suspended',
            'temporary suspension', 'your account will be closed', 'final notice',
            'last chance', 'expires today', 'within 24 hours', 'immediately',
            'password', 'username', 'login', 'credentials', 'identity',
            'refund', 'claim', 'bonus', 'free', 'guaranteed', 'exclusive',
            'limited offer', 'act fast', 'don\'t miss', 'hurry', 'rush'
        ]
        
        # Suspicious punctuation patterns
        self.suspicious_patterns = [
            r'!{2,}',  # Multiple exclamation marks
            r'\${2,}',  # Multiple dollar signs
            r'[A-Z]{5,}',  # Long sequences of capital letters
            r'[0-9]{10,}',  # Long sequences of numbers
            r'www\.[^.\s]+\.[a-z]{2,}',  # URLs
            r'http[s]?://[^\s]+',  # HTTP URLs
        ]
        
        # Initialize models
        self.sentence_model = None
        self.classifier = None
        self.tfidf_vectorizer = None
        self.model_path = 'models/phishing_classifier.pkl'
        
        # Initialize models asynchronously
        self._model_initialized = False
    
    async def _initialize_models(self):
        """Initialize ML models."""
        if self._model_initialized:
            return
        
        try:
            # Load sentence transformer (temporarily disabled)
            # self.sentence_model = SentenceTransformer('all-MiniLM-L6-v2')
            self.sentence_model = None  # Placeholder
            
            # Try to load existing classifier
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    model_data = pickle.load(f)
                    self.classifier = model_data['classifier']
                    self.tfidf_vectorizer = model_data['tfidf']
            else:
                # Train new classifier with synthetic data
                await self._train_classifier()
            
            self._model_initialized = True
            
        except Exception as e:
            print(f"Warning: Could not initialize ML models: {e}")
            # Fall back to rule-based detection only
            self._model_initialized = False
    
    async def _train_classifier(self):
        """Train classifier with synthetic data."""
        # Generate synthetic training data
        legitimate_emails = [
            "Thank you for your purchase. Your order has been confirmed.",
            "Meeting scheduled for tomorrow at 2 PM in conference room A.",
            "Your monthly newsletter with the latest updates and news.",
            "Quarterly report is now available for download.",
            "Reminder: Company picnic this Saturday at Central Park.",
            "Your subscription renewal is due next month.",
            "New product features have been added to your account.",
            "Weekly team update and project status report.",
            "Invoice for services rendered last month is attached.",
            "System maintenance scheduled for this weekend.",
            "Welcome to our platform! Here's how to get started.",
            "Your flight booking confirmation for next week's trip.",
            "Course enrollment confirmation and next steps.",
            "Job application received. We'll review and get back to you.",
            "Your package has been shipped and tracking info is available.",
            "Annual conference registration is now open.",
            "Performance review meeting scheduled for next week.",
            "New employee onboarding materials attached.",
            "Software update available for download.",
            "Holiday schedule and office closure dates.",
        ]
        
        phishing_emails = [
            "URGENT: Your account will be suspended unless you verify immediately!",
            "Congratulations! You've won $1,000,000 in the lottery! Click here now!",
            "FINAL NOTICE: Update your payment information or lose access forever!",
            "Your PayPal account has been limited. Verify now to restore access.",
            "SECURITY ALERT: Suspicious activity detected. Confirm your identity immediately.",
            "You have inherited $5 million from a distant relative. Claim now!",
            "Your Amazon account will be closed in 24 hours. Verify here immediately!",
            "URGENT TAX REFUND: You're owed $2,500. Click to claim before it expires!",
            "Your bank account has been compromised. Update your login details now!",
            "Limited time offer: Get rich quick with this amazing investment opportunity!",
            "Your Microsoft account will expire today. Renew immediately to avoid loss!",
            "WINNER: You've been selected for a special prize worth $10,000!",
            "Your email account will be deleted unless you confirm your password now!",
            "Urgent: Your credit card has been charged $500. Dispute immediately!",
            "You have unclaimed Bitcoin worth $50,000. Access your wallet now!",
            "Your Google account was accessed from an unknown device. Secure it now!",
            "FINAL WARNING: Your account will be permanently deleted in 2 hours!",
            "You've received a government stimulus check. Click to claim $1,200!",
            "Your Apple ID has been locked for security. Unlock it immediately!",
            "URGENT: Your package is being returned. Confirm delivery address now!",
        ]
        
        # Prepare training data
        texts = legitimate_emails + phishing_emails
        labels = [0] * len(legitimate_emails) + [1] * len(phishing_emails)
        
        # Create TF-IDF features
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2),
            lowercase=True
        )
        
        tfidf_features = self.tfidf_vectorizer.fit_transform(texts)
        
        # Get sentence embeddings
        embeddings = self.sentence_model.encode(texts)
        
        # Combine TF-IDF and embeddings
        combined_features = np.hstack([tfidf_features.toarray(), embeddings])
        
        # Train logistic regression
        self.classifier = LogisticRegression(random_state=42, max_iter=1000)
        self.classifier.fit(combined_features, labels)
        
        # Save the model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump({
                'classifier': self.classifier,
                'tfidf': self.tfidf_vectorizer
            }, f)
    
    async def analyze_content(self, body_text: str, subject: str) -> Dict[str, Any]:
        """
        Analyze email content for phishing indicators.
        
        Args:
            body_text: Email body text
            subject: Email subject line
            
        Returns:
            Dict with score, highlights, and explanation
        """
        await self._initialize_models()
        
        # Combine subject and body for analysis
        full_text = f"{subject} {body_text}".lower()
        
        # 1. Rule-based keyword detection
        keyword_score, keyword_matches = self._analyze_keywords(full_text)
        
        # 2. ML-based prediction
        ml_score = 0.0
        if self._model_initialized and self.classifier:
            try:
                ml_score = await self._ml_predict(full_text)
            except Exception as e:
                print(f"ML prediction failed: {e}")
                ml_score = 0.0
        
        # 3. Combine scores (60% ML, 40% keywords)
        if ml_score > 0:
            final_score = 0.6 * ml_score + 0.4 * keyword_score
        else:
            final_score = keyword_score
        
        # 4. Find highlights
        highlights = await self._find_highlights(body_text, subject, keyword_matches)
        
        # 5. Generate explanation
        explanation = self._generate_explanation(keyword_score, ml_score, keyword_matches, highlights)
        
        return {
            'score': float(final_score),
            'highlights': highlights,
            'explain': explanation
        }
    
    def _analyze_keywords(self, text: str) -> Tuple[float, List[str]]:
        """Analyze text for phishing keywords."""
        matches = []
        score = 0.0
        
        # Check for phishing keywords
        for keyword in self.phishing_keywords:
            if keyword in text:
                matches.append(keyword)
                score += 0.1
        
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, text):
                matches.append(f"pattern:{pattern}")
                score += 0.05
        
        return min(1.0, score), matches
    
    async def _ml_predict(self, text: str) -> float:
        """Get ML prediction for phishing probability."""
        try:
            # Get TF-IDF features
            tfidf_features = self.tfidf_vectorizer.transform([text])
            
            # Check if sentence model is available
            if self.sentence_model is not None:
                # Get sentence embedding
                embedding = self.sentence_model.encode([text])
                # Combine features
                combined_features = np.hstack([tfidf_features.toarray(), embedding])
            else:
                # Use only TF-IDF features when sentence model is not available
                combined_features = tfidf_features.toarray()
            
            # Get prediction probability
            prob = self.classifier.predict_proba(combined_features)[0][1]
            return float(prob)
            
        except Exception as e:
            print(f"ML prediction error: {e}")
            return 0.0
    
    async def _find_highlights(self, body_text: str, subject: str, keyword_matches: List[str]) -> List[Dict[str, Any]]:
        """Find top-5 suspicious spans to highlight."""
        highlights = []
        full_text = f"{subject} {body_text}"
        
        # Find keyword matches with positions
        for keyword in keyword_matches:
            if keyword.startswith('pattern:'):
                continue
                
            # Find all occurrences of this keyword
            start = 0
            while True:
                pos = full_text.lower().find(keyword.lower(), start)
                if pos == -1:
                    break
                
                highlights.append({
                    'start': pos,
                    'end': pos + len(keyword),
                    'reason': 'suspicious_keyword',
                    'token': full_text[pos:pos + len(keyword)]
                })
                start = pos + 1
        
        # Add pattern-based highlights
        for pattern in self.suspicious_patterns:
            matches = re.finditer(pattern, full_text, re.IGNORECASE)
            for match in matches:
                highlights.append({
                    'start': match.start(),
                    'end': match.end(),
                    'reason': 'suspicious_pattern',
                    'token': match.group()
                })
        
        # Use TF-IDF to find additional suspicious terms
        if self._model_initialized and self.tfidf_vectorizer:
            try:
                tfidf_highlights = self._get_tfidf_highlights(full_text)
                highlights.extend(tfidf_highlights)
            except Exception as e:
                print(f"TF-IDF highlighting failed: {e}")
        
        # Sort by position and return top 5
        highlights.sort(key=lambda x: x['start'])
        return highlights[:5]
    
    def _get_tfidf_highlights(self, text: str) -> List[Dict[str, Any]]:
        """Get highlights based on TF-IDF scores."""
        highlights = []
        
        try:
            # Get TF-IDF scores
            tfidf_matrix = self.tfidf_vectorizer.transform([text])
            feature_names = self.tfidf_vectorizer.get_feature_names_out()
            
            # Get scores for each term
            scores = tfidf_matrix.toarray()[0]
            
            # Find top scoring terms that are also suspicious
            term_scores = list(zip(feature_names, scores))
            term_scores.sort(key=lambda x: x[1], reverse=True)
            
            for term, score in term_scores[:10]:  # Check top 10 TF-IDF terms
                if score > 0 and any(keyword in term.lower() for keyword in self.phishing_keywords):
                    # Find positions of this term in text
                    start = 0
                    while True:
                        pos = text.lower().find(term.lower(), start)
                        if pos == -1:
                            break
                        
                        highlights.append({
                            'start': pos,
                            'end': pos + len(term),
                            'reason': 'high_tfidf_suspicious',
                            'token': text[pos:pos + len(term)]
                        })
                        start = pos + 1
                        break  # Only add first occurrence
                        
        except Exception as e:
            print(f"TF-IDF highlighting error: {e}")
        
        return highlights
    
    def _generate_explanation(self, keyword_score: float, ml_score: float, 
                            keyword_matches: List[str], highlights: List[Dict]) -> str:
        """Generate human-readable explanation."""
        explanation_parts = []
        
        if keyword_score > 0.3:
            explanation_parts.append(f"High keyword suspicion (score: {keyword_score:.2f})")
            if keyword_matches:
                non_pattern_matches = [m for m in keyword_matches if not m.startswith('pattern:')]
                if non_pattern_matches:
                    explanation_parts.append(f"Found suspicious keywords: {', '.join(non_pattern_matches[:3])}")
        
        if ml_score > 0.5:
            explanation_parts.append(f"ML model predicts high phishing probability ({ml_score:.2f})")
        elif ml_score > 0:
            explanation_parts.append(f"ML model shows moderate suspicion ({ml_score:.2f})")
        
        if highlights:
            explanation_parts.append(f"Identified {len(highlights)} suspicious text spans")
        
        if not explanation_parts:
            explanation_parts.append("No significant phishing indicators detected")
        
        return ". ".join(explanation_parts)


# Global instance for backward compatibility and performance
_content_agent = None

async def get_content_agent():
    """Get singleton content agent instance."""
    global _content_agent
    if _content_agent is None:
        _content_agent = EnhancedContentAgent()
    return _content_agent

async def analyze_content(body_text: str, subject: str) -> Dict[str, Any]:
    """
    Analyze email content for phishing indicators.
    
    Args:
        body_text: Email body text
        subject: Email subject line
        
    Returns:
        Dict with keys: 'score', 'highlights', 'explain'
    """
    agent = await get_content_agent()
    return await agent.analyze_content(body_text, subject)
