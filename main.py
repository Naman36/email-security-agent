"""
FastAPI application for email phishing analysis service.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
import uvicorn
import logging
from datetime import datetime
from dataclasses import asdict

from orchestrator import EmailAnalysisOrchestrator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Email Phishing Analysis Service",
    description="Multi-agent email analysis service for detecting phishing attempts",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize orchestrator
orchestrator = EmailAnalysisOrchestrator()


class EmailAnalysisRequest(BaseModel):
    """Request model for email analysis."""
    subject: str = Field(..., description="Email subject line")
    from_address: str = Field(..., alias="from", description="Sender email address")
    to: str = Field(..., description="Recipient email address")
    body_html: str = Field(..., description="HTML body content")
    body_text: str = Field(..., description="Plain text body content")
    headers: Dict[str, Any] = Field(..., description="Email headers")
    links: List[str] = Field(..., description="List of URLs found in email")

    class Config:
        allow_population_by_field_name = True
        schema_extra = {
            "example": {
                "subject": "Urgent: Verify Your Account",
                "from": "security@paypal-support.com",
                "to": "user@example.com",
                "body_html": "<html><body><p>Dear customer, your account will be suspended unless you <a href='http://paypal-verify.com'>click here</a> to verify.</p></body></html>",
                "body_text": "Dear customer, your account will be suspended unless you click the link to verify.",
                "headers": {
                    "From": "security@paypal-support.com",
                    "To": "user@example.com",
                    "Date": "Wed, 21 Sep 2023 10:30:00 +0000",
                    "Message-ID": "<12345@paypal-support.com>",
                    "Received-SPF": "fail"
                },
                "links": ["http://paypal-verify.com", "http://192.168.1.100/login"]
            }
        }


class AgentAnalysisResult(BaseModel):
    """Individual agent analysis result."""
    score: float = Field(..., description="Phishing score (0.0 to 1.0)")
    confidence: float = Field(..., description="Confidence in the analysis (0.0 to 1.0)")
    details: str = Field(..., description="Human-readable details")


class HighlightSpan(BaseModel):
    """Highlighted text span."""
    start: int = Field(..., description="Start position of highlight")
    end: int = Field(..., description="End position of highlight")
    reason: str = Field(..., description="Reason for highlighting")
    token: str = Field(..., description="Highlighted text")


class ContentAnalysisResult(BaseModel):
    """Content agent analysis result."""
    score: float = Field(..., description="Phishing score (0.0 to 1.0)")
    highlights: List[HighlightSpan] = Field(..., description="Suspicious text spans")
    explain: str = Field(..., description="Human-readable explanation")


class LinkAnalysisResult(AgentAnalysisResult):
    """Link agent analysis result."""
    total_links: int = Field(..., description="Total number of links analyzed")
    suspicious_links: List[str] = Field(..., description="Suspicious links found")
    shortened_links: List[str] = Field(..., description="Shortened URLs found")
    suspicious_domains: List[str] = Field(..., description="Suspicious domains found")
    ip_addresses: List[str] = Field(..., description="Links with IP addresses")
    redirect_chains: List[str] = Field(..., description="Links with potential redirects")


class BehaviorAnalysisResult(AgentAnalysisResult):
    """Behavior agent analysis result."""
    sender_reputation: str = Field(..., description="Sender reputation assessment")
    timing_anomalies: List[str] = Field(..., description="Timing-related anomalies")
    header_anomalies: List[str] = Field(..., description="Header-related anomalies")
    authentication_issues: List[str] = Field(..., description="Email authentication issues")
    spoofing_indicators: List[str] = Field(..., description="Email spoofing indicators")


class HeaderAnalysisResult(AgentAnalysisResult):
    """Header agent analysis result."""
    verdict: str = Field(..., description="Verdict of the header analysis")
    routing_analysis: Optional[Dict[str, Any]] = Field(..., description="Analysis of the email routing path")
    reasons: List[str] = Field(..., description="Reasons for the verdict")


class QRCodeData(BaseModel):
    """Individual QR code analysis result."""
    content: str = Field(..., description="QR code content (truncated if long)")
    content_type: str = Field(..., description="Type of QR content (url, text, vcard, wifi, etc.)")
    location: str = Field(..., description="Where QR code was found")
    score: float = Field(..., description="Suspicion score for this QR code (0.0 to 1.0)")
    reasons: List[str] = Field(..., description="Reasons for suspicion")


class QRAnalysisResult(BaseModel):
    """QR code agent analysis result."""
    score: float = Field(..., description="Overall QR code suspicion score (0.0 to 1.0)")
    qr_codes: List[QRCodeData] = Field(..., description="Individual QR code analyses")
    total_qr_codes: int = Field(..., description="Total number of QR codes found")
    suspicious_count: int = Field(..., description="Number of suspicious QR codes")
    details: str = Field(..., description="Human-readable analysis details")
    confidence: float = Field(..., description="Confidence in the QR analysis (0.0 to 1.0)")


class EmailAnalysisResponse(BaseModel):
    """Response model for email analysis."""
    content_analysis: ContentAnalysisResult = Field(..., description="Content analysis results")
    link_analysis: LinkAnalysisResult = Field(..., description="Link analysis results")
    behavior_analysis: BehaviorAnalysisResult = Field(..., description="Behavior analysis results")
    header_analysis: HeaderAnalysisResult = Field(..., description="Header analysis results")
    qr_analysis: QRAnalysisResult = Field(..., description="QR code analysis results")
    final_score: float = Field(..., description="Overall phishing score (0.0 to 1.0)")
    action: str = Field(..., description="Recommended action (ALLOW, FLAG, QUARANTINE, BLOCK)")
    confidence: float = Field(..., description="Overall confidence in the assessment")
    summary: str = Field(..., description="Human-readable summary of the analysis")
    timestamp: str = Field(..., description="Analysis timestamp")


@app.get("/")
async def root():
    """Root endpoint with service information."""
    return {
        "service": "Email Phishing Analysis Service",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "analyze": "/analyze_email",
            "health": "/health",
            "docs": "/docs"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "agents": {
            "content_agent": "operational",
            "link_agent": "operational",
            "behavior_agent": "operational",
            "qr_agent": "operational"
        }
    }


@app.post("/analyze_email", response_model=EmailAnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest):
    """
    Analyze email for phishing indicators using multiple agents.
    
    This endpoint accepts email data and runs it through three specialized agents:
    - Content Agent: Analyzes email content for suspicious words and patterns
    - Link Agent: Analyzes URLs and links for malicious indicators
    - Behavior Agent: Analyzes email metadata and behavioral patterns
    
    The agents run in parallel for optimal performance, and their results are
    combined to produce a final phishing score and recommended action.
    """
    try:
        logger.info(f"Received email analysis request for: {request.subject}")
        
        # Convert request to dictionary for orchestrator
        email_data = {
            "subject": request.subject,
            "from": request.from_address,
            "to": request.to,
            "body_html": request.body_html,
            "body_text": request.body_text,
            "headers": request.headers,
            "links": request.links
        }
        
        # Analyze email using orchestrator
        analysis_result = await orchestrator.analyze_email(email_data)
        
        # Convert result to response model
        # Convert highlights to HighlightSpan objects
        highlights = [HighlightSpan(**highlight) for highlight in analysis_result.content_analysis.get('highlights', [])]
        
        # Convert QR codes to QRCodeData objects
        qr_codes = [QRCodeData(**qr_code) for qr_code in analysis_result.qr_analysis.get('qr_codes', [])]

        # Convert routing_analysis to dict
        if 'routing_analysis' in analysis_result.header_analysis and analysis_result.header_analysis['routing_analysis'] is not None:
            analysis_result.header_analysis['routing_analysis'] = asdict(analysis_result.header_analysis['routing_analysis'])
        
        response = EmailAnalysisResponse(
            content_analysis=ContentAnalysisResult(
                score=analysis_result.content_analysis.get('score', 0.0),
                highlights=highlights,
                explain=analysis_result.content_analysis.get('explain', '')
            ),
            link_analysis=LinkAnalysisResult(**analysis_result.link_analysis),
            behavior_analysis=BehaviorAnalysisResult(**analysis_result.behavior_analysis),
            header_analysis=HeaderAnalysisResult(**analysis_result.header_analysis),
            qr_analysis=QRAnalysisResult(
                score=analysis_result.qr_analysis.get('score', 0.0),
                qr_codes=qr_codes,
                total_qr_codes=analysis_result.qr_analysis.get('total_qr_codes', 0),
                suspicious_count=analysis_result.qr_analysis.get('suspicious_count', 0),
                details=analysis_result.qr_analysis.get('details', ''),
                confidence=analysis_result.qr_analysis.get('confidence', 0.0)
            ),
            final_score=analysis_result.final_score,
            action=analysis_result.action,
            confidence=analysis_result.confidence,
            summary=analysis_result.summary,
            timestamp=datetime.utcnow().isoformat()
        )
        
        logger.info(f"Analysis complete. Score: {response.final_score:.2f}, Action: {response.action}")
        
        return response
        
    except Exception as e:
        logger.error(f"Error analyzing email: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error during email analysis: {str(e)}"
        )


@app.get("/agents/status")
async def agents_status():
    """Get status of all agents."""
    return {
        "agents": {
            "content_agent": {
                "status": "operational",
                "description": "Analyzes email content for phishing indicators"
            },
            "link_agent": {
                "status": "operational", 
                "description": "Analyzes URLs and links for malicious indicators"
            },
            "behavior_agent": {
                "status": "operational",
                "description": "Analyzes email metadata and behavioral patterns"
            },
            "qr_agent": {
                "status": "operational", 
                "description": "Analyzes QR codes in emails for malicious content"
            }
        },
        "orchestrator": {
            "status": "operational",
            "description": "Coordinates agent execution and combines results"
        }
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
