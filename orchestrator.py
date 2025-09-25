"""
Orchestrator for coordinating multiple email analysis agents.
"""

import asyncio
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass, asdict

from agents.content_agent import analyze_content
from agents.link_agent import LinkAgent, LinkAnalysisResult
from agents.behavior_agent import BehaviorAgent, BehaviorAnalysisResult
from agents.qr_agent import QRCodeAgent, QRAnalysisResult


# ============================================================================
# NEW ORCHESTRATION FUNCTIONS
# ============================================================================

@dataclass
class OrchestrationConfig:
    """Configuration for orchestration weights."""
    content_weight: float = 0.35
    link_weight: float = 0.25
    behavior_weight: float = 0.25
    qr_weight: float = 0.15
    
    def __post_init__(self):
        """Validate weights sum to 1.0."""
        total = self.content_weight + self.link_weight + self.behavior_weight + self.qr_weight
        if abs(total - 1.0) > 0.001:
            raise ValueError(f"Weights must sum to 1.0, got {total}")


@dataclass
class OrchestrationResult:
    """Result of orchestration analysis."""
    final_score: float
    action: str
    confidence: float
    summary: str
    detailed_reasons: List[Dict[str, Any]]


async def orchestrate(
    content_out: Dict[str, Any], 
    link_out: Dict[str, Any], 
    behavior_out: Dict[str, Any],
    qr_out: Dict[str, Any],
    config: Optional[OrchestrationConfig] = None
) -> OrchestrationResult:
    """
    Orchestrate multiple agent outputs with configurable weights.
    
    Args:
        content_out: Content agent output with keys: score, highlights, explain
        link_out: Link agent output with keys: score, links, details
        behavior_out: Behavior agent output with keys: score, reasons, sender_history, details
        qr_out: QR code agent output with keys: score, qr_codes, details
        config: Optional configuration for weights (default: content=0.35, link=0.25, behavior=0.25, qr=0.15)
        
    Returns:
        OrchestrationResult with final score, action, and summary
    """
    if config is None:
        config = OrchestrationConfig()
    
    # Extract scores
    content_score = content_out.get('score', 0.0)
    link_score = link_out.get('score', 0.0)
    behavior_score = behavior_out.get('score', 0.0)
    qr_score = qr_out.get('score', 0.0)
    
    # Calculate weighted final score
    final_score = (
        content_score * config.content_weight +
        link_score * config.link_weight +
        behavior_score * config.behavior_weight +
        qr_score * config.qr_weight
    )
    
    # Determine action based on score thresholds
    if final_score >= 0.7:
        action = "quarantine"
    elif final_score >= 0.4:
        action = "flag"
    else:
        action = "allow"
    
    # Apply override rules for high-confidence indicators
    if link_score >= 0.8 and len(link_out.get('links', [])) > 0:
        # Check for IP addresses or very suspicious links
        suspicious_links = [link for link in link_out.get('links', []) 
                          if link.get('score', 0) >= 0.8]
        if suspicious_links:
            action = "quarantine"
    
    if behavior_score >= 0.8:
        # High behavior suspicion should escalate action
        if action == "allow":
            action = "flag"
        elif action == "flag":
            action = "quarantine"
    
    if qr_score >= 0.8 and qr_out.get('suspicious_count', 0) > 0:
        # High QR suspicion should escalate action
        if action == "allow":
            action = "flag"
        elif action == "flag":
            action = "quarantine"
    
    # Calculate confidence
    confidence = _calculate_confidence(content_score, link_score, behavior_score, qr_score, final_score)
    
    # Collect detailed reasons from all agents
    detailed_reasons = _collect_detailed_reasons(content_out, link_out, behavior_out, qr_out)
    
    # Generate human-readable summary
    summary = generate_summary(content_out, link_out, behavior_out, qr_out, final_score, detailed_reasons)
    
    return OrchestrationResult(
        final_score=final_score,
        action=action,
        confidence=confidence,
        summary=summary,
        detailed_reasons=detailed_reasons
    )


def generate_summary(
    content_out: Dict[str, Any],
    link_out: Dict[str, Any], 
    behavior_out: Dict[str, Any],
    qr_out: Dict[str, Any],
    final_score: float,
    detailed_reasons: List[Dict[str, Any]]
) -> str:
    """
    Generate a short human-readable summary explaining top 3 reasons across agents.
    
    Args:
        content_out: Content agent output
        link_out: Link agent output  
        behavior_out: Behavior agent output
        qr_out: QR code agent output
        final_score: Overall risk score
        detailed_reasons: Collected reasons from all agents
        
    Returns:
        Human-readable summary string
    """
    # Determine risk level
    if final_score >= 0.7:
        risk_level = "HIGH"
        risk_emoji = "🔴"
    elif final_score >= 0.4:
        risk_level = "MEDIUM"
        risk_emoji = "🟡"
    else:
        risk_level = "LOW"
        risk_emoji = "🟢"
    
    # Start with risk assessment
    summary_parts = [f"{risk_emoji} {risk_level} RISK (Score: {final_score:.2f})"]
    
    # Get top 3 reasons across all agents
    top_reasons = _get_top_reasons(detailed_reasons, limit=3)
    
    if top_reasons:
        reasons_text = "; ".join([reason['text'] for reason in top_reasons])
        summary_parts.append(f"Key concerns: {reasons_text}")
    else:
        summary_parts.append("No significant threats detected")
    
    # Add agent-specific highlights
    agent_highlights = []
    
    if content_out.get('score', 0) >= 0.5:
        highlights = content_out.get('highlights', [])
        if highlights:
            agent_highlights.append(f"Content: {len(highlights)} suspicious elements")
        else:
            agent_highlights.append("Content: High ML suspicion")
    
    if link_out.get('score', 0) >= 0.5:
        suspicious_count = link_out.get('suspicious_count', 0)
        total_links = link_out.get('total_links', 0)
        if suspicious_count > 0:
            agent_highlights.append(f"Links: {suspicious_count}/{total_links} suspicious")
    
    if behavior_out.get('score', 0) >= 0.5:
        if behavior_out.get('sender_history', {}).get('is_new_sender'):
            agent_highlights.append("Behavior: New sender")
        else:
            agent_highlights.append("Behavior: Pattern anomalies")
    
    if qr_out.get('score', 0) >= 0.5:
        qr_count = qr_out.get('total_qr_codes', 0)
        suspicious_qr_count = qr_out.get('suspicious_count', 0)
        if suspicious_qr_count > 0:
            agent_highlights.append(f"QR Codes: {suspicious_qr_count}/{qr_count} suspicious")
        else:
            agent_highlights.append(f"QR Codes: {qr_count} detected")
    
    if agent_highlights:
        summary_parts.append(f"Analysis: {'; '.join(agent_highlights)}")
    
    return ". ".join(summary_parts)


def _calculate_confidence(content_score: float, link_score: float, 
                         behavior_score: float, qr_score: float, final_score: float) -> float:
    """Calculate confidence based on score distribution and agreement."""
    scores = [content_score, link_score, behavior_score, qr_score]
    
    # Base confidence from final score
    base_confidence = 0.6 + (final_score * 0.3)
    
    # Bonus for score agreement (all agents agree)
    score_std = np.std(scores) if len(scores) > 1 else 0
    agreement_bonus = max(0, 0.1 - score_std)
    
    # Bonus for high individual scores
    high_score_bonus = sum(0.05 for score in scores if score >= 0.8)
    
    confidence = base_confidence + agreement_bonus + high_score_bonus
    return min(0.99, confidence)


def _collect_detailed_reasons(content_out: Dict[str, Any], link_out: Dict[str, Any], 
                             behavior_out: Dict[str, Any], qr_out: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Collect and prioritize reasons from all agents."""
    reasons = []
    
    # Content agent reasons
    content_score = content_out.get('score', 0.0)
    if content_score > 0:
        content_explain = content_out.get('explain', '')
        if content_explain:
            reasons.append({
                'agent': 'content',
                'score': content_score,
                'weight': 0.5,
                'priority': content_score * 0.5,
                'text': f"Content: {content_explain}"
            })
    
    # Link agent reasons  
    link_score = link_out.get('score', 0.0)
    if link_score > 0:
        link_details = link_out.get('details', '')
        if link_details:
            reasons.append({
                'agent': 'link',
                'score': link_score,
                'weight': 0.3,
                'priority': link_score * 0.3,
                'text': f"Links: {link_details}"
            })
        
        # Add specific link reasons
        for link_data in link_out.get('links', []):
            if link_data.get('score', 0) >= 0.5:
                link_reasons = link_data.get('reasons', [])
                for reason in link_reasons[:2]:  # Top 2 per link
                    reasons.append({
                        'agent': 'link',
                        'score': link_data.get('score', 0),
                        'weight': 0.3,
                        'priority': link_data.get('score', 0) * 0.3,
                        'text': f"Link {link_data.get('domain', 'unknown')}: {reason}"
                    })
    
    # Behavior agent reasons
    behavior_score = behavior_out.get('score', 0.0)
    if behavior_score > 0:
        behavior_reasons = behavior_out.get('reasons', [])
        for reason in behavior_reasons:
            reasons.append({
                'agent': 'behavior',
                'score': behavior_score,
                'weight': 0.25,
                'priority': behavior_score * 0.25,
                'text': f"Behavior: {reason}"
            })
    
    # QR code agent reasons
    qr_score = qr_out.get('score', 0.0)
    if qr_score > 0:
        qr_details = qr_out.get('details', '')
        if qr_details:
            reasons.append({
                'agent': 'qr',
                'score': qr_score,
                'weight': 0.15,
                'priority': qr_score * 0.15,
                'text': f"QR Codes: {qr_details}"
            })
        
        # Add specific QR code reasons
        for qr_data in qr_out.get('qr_codes', []):
            if qr_data.get('score', 0) >= 0.5:
                qr_reasons = qr_data.get('reasons', [])
                for reason in qr_reasons[:2]:  # Top 2 per QR code
                    reasons.append({
                        'agent': 'qr',
                        'score': qr_data.get('score', 0),
                        'weight': 0.15,
                        'priority': qr_data.get('score', 0) * 0.15,
                        'text': f"QR Code ({qr_data.get('content_type', 'unknown')}): {reason}"
                    })
    
    # Sort by priority (score * weight)
    reasons.sort(key=lambda x: x['priority'], reverse=True)
    
    return reasons


def _get_top_reasons(detailed_reasons: List[Dict[str, Any]], limit: int = 3) -> List[Dict[str, Any]]:
    """Get top N reasons by priority."""
    return detailed_reasons[:limit]


# Add numpy import for std calculation
try:
    import numpy as np
except ImportError:
    # Fallback implementation
    def _std(values):
        if len(values) <= 1:
            return 0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5
    
    class np:
        @staticmethod
        def std(values):
            return _std(values)


# ============================================================================
# LEGACY ORCHESTRATOR CLASS (for backward compatibility)
# ============================================================================

@dataclass
class EmailAnalysisRequest:
    """Request model for email analysis."""
    subject: str
    from_address: str
    to: str
    body_html: str
    body_text: str
    headers: Dict[str, Any]
    links: List[str]


@dataclass
class EmailAnalysisResponse:
    """Response model for email analysis."""
    content_analysis: Dict[str, Any]
    link_analysis: Dict[str, Any]
    behavior_analysis: Dict[str, Any]
    qr_analysis: Dict[str, Any]
    final_score: float
    action: str
    confidence: float
    summary: str


class EmailAnalysisOrchestrator:
    """Orchestrator that coordinates multiple agents for email analysis."""
    
    def __init__(self):
        self.link_agent = LinkAgent()
        self.behavior_agent = BehaviorAgent()
        self.qr_agent = QRCodeAgent()
    
    async def analyze_email(self, email_data: Dict[str, Any]) -> EmailAnalysisResponse:
        """
        Analyze email using all agents in parallel.
        
        Args:
            email_data: Dictionary containing email fields
            
        Returns:
            EmailAnalysisResponse with combined analysis results
        """
        # Prepare email data for agents
        agent_data = {
            'subject': email_data.get('subject', ''),
            'from': email_data.get('from', ''),
            'to': email_data.get('to', ''),
            'body_html': email_data.get('body_html', ''),
            'body_text': email_data.get('body_text', ''),
            'headers': email_data.get('headers', {}),
            'links': email_data.get('links', [])
        }
        
        # Run all agents in parallel
        try:
            content_result, link_result, behavior_result, qr_result = await asyncio.gather(
                analyze_content(agent_data['body_text'], agent_data['subject']),
                self.link_agent.analyze(agent_data),
                self.behavior_agent.analyze(agent_data),
                self.qr_agent.analyze(agent_data),
                return_exceptions=True
            )
            
            # Handle any exceptions
            if isinstance(content_result, Exception):
                content_result = self._get_default_content_result(str(content_result))
            
            if isinstance(link_result, Exception):
                link_result = self._get_default_link_result(str(link_result))
            
            if isinstance(behavior_result, Exception):
                behavior_result = self._get_default_behavior_result(str(behavior_result))
            
            if isinstance(qr_result, Exception):
                qr_result = self._get_default_qr_result(str(qr_result))
            
        except Exception as e:
            # Fallback in case of complete failure
            content_result = self._get_default_content_result(str(e))
            link_result = self._get_default_link_result(str(e))
            behavior_result = self._get_default_behavior_result(str(e))
            qr_result = self._get_default_qr_result(str(e))
        
        # Calculate final score and determine action
        final_score, action, confidence = self._calculate_final_assessment(
            content_result, link_result, behavior_result, qr_result
        )
        
        # Generate summary
        summary = self._generate_summary(content_result, link_result, behavior_result, qr_result, final_score)
        
        return EmailAnalysisResponse(
            content_analysis=content_result,
            link_analysis=asdict(link_result),
            behavior_analysis=asdict(behavior_result),
            qr_analysis=qr_result,
            final_score=final_score,
            action=action,
            confidence=confidence,
            summary=summary
        )
    
    def _calculate_final_assessment(self, content_result: Dict[str, Any],
                                   link_result: LinkAnalysisResult,
                                   behavior_result: BehaviorAnalysisResult,
                                   qr_result: Dict[str, Any]) -> tuple[float, str, float]:
        """
        Calculate final phishing score and recommended action.
        
        Returns:
            Tuple of (final_score, action, confidence)
        """
        # Weighted average of agent scores
        # Content analysis: 35%, Link analysis: 25%, Behavior analysis: 25%, QR analysis: 15%
        final_score = (
            content_result.get('score', 0.0) * 0.35 +
            link_result.score * 0.25 +
            behavior_result.score * 0.25 +
            qr_result.get('score', 0.0) * 0.15
        )
        
        # Calculate overall confidence (content agent doesn't provide confidence, use score as proxy)
        content_confidence = min(0.9, content_result.get('score', 0.0) + 0.1)
        qr_confidence = qr_result.get('confidence', 0.8)  # QR agent provides confidence
        confidence = (
            content_confidence * 0.35 +
            link_result.confidence * 0.25 +
            behavior_result.confidence * 0.25 +
            qr_confidence * 0.15
        )
        
        # Determine action based on score thresholds
        if final_score >= 0.8:
            action = "BLOCK"
        elif final_score >= 0.6:
            action = "QUARANTINE"
        elif final_score >= 0.3:
            action = "FLAG"
        else:
            action = "ALLOW"
        
        # Adjust action based on high-confidence high-risk indicators
        if behavior_result.score >= 0.7 and behavior_result.confidence >= 0.8:
            if action == "ALLOW":
                action = "FLAG"
            elif action == "FLAG":
                action = "QUARANTINE"
        
        if link_result.score >= 0.8 and len(link_result.ip_addresses) > 0:
            action = "BLOCK"
        
        # QR code override rules
        if qr_result.get('score', 0.0) >= 0.8 and qr_result.get('suspicious_count', 0) > 0:
            if action == "ALLOW":
                action = "FLAG"
            elif action == "FLAG":
                action = "QUARANTINE"
        
        return final_score, action, confidence
    
    def _generate_summary(self, content_result: Dict[str, Any],
                         link_result: LinkAnalysisResult,
                         behavior_result: BehaviorAnalysisResult,
                         qr_result: Dict[str, Any],
                         final_score: float) -> str:
        """Generate a human-readable summary of the analysis."""
        risk_level = "LOW"
        if final_score >= 0.7:
            risk_level = "HIGH"
        elif final_score >= 0.4:
            risk_level = "MEDIUM"
        
        summary_parts = [f"Risk Level: {risk_level} (Score: {final_score:.2f})"]
        
        # Add key findings
        key_findings = []
        
        if content_result.get('score', 0.0) >= 0.5:
            highlights_count = len(content_result.get('highlights', []))
            if highlights_count > 0:
                key_findings.append(f"Content: {highlights_count} suspicious elements found")
            else:
                key_findings.append("Content: High phishing indicators detected")
        
        if link_result.score >= 0.5:
            if link_result.ip_addresses:
                key_findings.append(f"Links: {len(link_result.ip_addresses)} IP-based URLs detected")
            elif link_result.suspicious_links:
                key_findings.append(f"Links: {len(link_result.suspicious_links)} suspicious links found")
        
        if behavior_result.score >= 0.5:
            if behavior_result.authentication_issues:
                key_findings.append(f"Behavior: Authentication failures detected")
            elif behavior_result.spoofing_indicators:
                key_findings.append(f"Behavior: Spoofing indicators found")
        
        if qr_result.get('score', 0.0) >= 0.5:
            qr_count = qr_result.get('total_qr_codes', 0)
            suspicious_qr_count = qr_result.get('suspicious_count', 0)
            if suspicious_qr_count > 0:
                key_findings.append(f"QR Codes: {suspicious_qr_count}/{qr_count} suspicious codes detected")
            elif qr_count > 0:
                key_findings.append(f"QR Codes: {qr_count} codes found requiring verification")
        
        if key_findings:
            summary_parts.append("Key findings: " + "; ".join(key_findings))
        else:
            summary_parts.append("No significant threats detected")
        
        return ". ".join(summary_parts)
    
    def _get_default_content_result(self, error_msg: str) -> Dict[str, Any]:
        """Get default content analysis result in case of error."""
        return {
            'score': 0.0,
            'highlights': [],
            'explain': f"Content analysis failed: {error_msg}"
        }
    
    def _get_default_link_result(self, error_msg: str) -> LinkAnalysisResult:
        """Get default link analysis result in case of error."""
        return LinkAnalysisResult(
            total_links=0,
            suspicious_links=[],
            shortened_links=[],
            suspicious_domains=[],
            ip_addresses=[],
            redirect_chains=[],
            score=0.0,
            confidence=0.0,
            details=f"Link analysis failed: {error_msg}"
        )
    
    def _get_default_behavior_result(self, error_msg: str) -> BehaviorAnalysisResult:
        """Get default behavior analysis result in case of error."""
        return BehaviorAnalysisResult(
            sender_reputation="unknown",
            timing_anomalies=[],
            header_anomalies=[],
            authentication_issues=[],
            spoofing_indicators=[],
            score=0.0,
            confidence=0.0,
            details=f"Behavior analysis failed: {error_msg}"
        )
    
    def _get_default_qr_result(self, error_msg: str) -> Dict[str, Any]:
        """Get default QR analysis result in case of error."""
        return {
            'score': 0.0,
            'qr_codes': [],
            'total_qr_codes': 0,
            'suspicious_count': 0,
            'details': f"QR code analysis failed: {error_msg}",
            'confidence': 0.0
        }
