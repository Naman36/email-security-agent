"""
Streamlit UI for Email Phishing Analysis Service
"""

import streamlit as st
import requests
import json
import re
from typing import Dict, Any, List, Optional
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd

# Configure page
st.set_page_config(
    page_title="Email Phishing Analyzer", 
    page_icon="🛡️",
    layout="wide"
)

# Demo email examples
DEMO_EMAILS = {
    "Select a demo email...": {},
    "Legitimate - Meeting Invitation": {
        "subject": "Team Meeting Tomorrow - 2 PM",
        "from": "sarah.johnson@company.com",
        "to": "team@company.com", 
        "body_html": "<html><body><p>Hi Team,</p><p>Just a reminder that we have our weekly team meeting tomorrow at 2 PM in Conference Room A.</p><p>Agenda:</p><ul><li>Project updates</li><li>Q4 planning</li><li>New hire introductions</li></ul><p>Best regards,<br>Sarah</p></body></html>",
        "body_text": "Hi Team,\n\nJust a reminder that we have our weekly team meeting tomorrow at 2 PM in Conference Room A.\n\nAgenda:\n- Project updates\n- Q4 planning\n- New hire introductions\n\nBest regards,\nSarah",
        "headers": {
            "From": "sarah.johnson@company.com",
            "To": "team@company.com",
            "Date": "Wed, 21 Oct 2024 10:30:00 +0000",
            "Message-ID": "<meeting-reminder-12345@company.com>",
            "Subject": "Team Meeting Tomorrow - 2 PM"
        },
        "links": []
    },
    "Phishing - Fake PayPal Alert": {
        "subject": "URGENT: Your PayPal account will be suspended!",
        "from": "PayPal Security <security@paypal-verification.tk>", 
        "to": "user@example.com",
        "body_html": "<html><body><div style='background:#003087;color:white;padding:20px'><h2>PayPal Security Alert</h2></div><p><strong>URGENT ACTION REQUIRED</strong></p><p>Dear PayPal User,</p><p>We have detected suspicious activity on your account. Your account will be <span style='color:red;font-weight:bold'>PERMANENTLY SUSPENDED</span> within 24 hours unless you verify your identity immediately.</p><p><a href='http://192.168.1.100/paypal-verify' style='background:#0070ba;color:white;padding:10px 20px;text-decoration:none'>VERIFY ACCOUNT NOW</a></p><p>If you do not act within 24 hours, you will lose access to your account forever.</p><p>Thank you,<br>PayPal Security Team</p></body></html>",
        "body_text": "URGENT ACTION REQUIRED\n\nDear PayPal User,\n\nWe have detected suspicious activity on your account. Your account will be PERMANENTLY SUSPENDED within 24 hours unless you verify your identity immediately.\n\nClick here to verify: http://192.168.1.100/paypal-verify\n\nIf you do not act within 24 hours, you will lose access to your account forever.\n\nThank you,\nPayPal Security Team",
        "headers": {
            "From": "PayPal Security <security@paypal-verification.tk>",
            "To": "user@example.com", 
            "Date": "Wed, 21 Oct 2024 03:15:00 +0000",
            "Reply-To": "noreply@suspicious-sender.com",
            "Subject": "URGENT: Your PayPal account will be suspended!"
        },
        "links": ["http://192.168.1.100/paypal-verify"]
    },
    "Phishing - Lottery Scam": {
        "subject": "🎉 CONGRATULATIONS! You've Won $1,000,000!!!",
        "from": "International Lottery Commission <winner@lottery-commission.ml>",
        "to": "lucky.winner@example.com",
        "body_html": "<html><body style='background:#gold'><h1 style='color:red'>🎉 CONGRATULATIONS! 🎉</h1><p><strong>YOU ARE THE LUCKY WINNER!</strong></p><p>The International Lottery Commission is pleased to inform you that you have won the sum of <strong style='color:green;font-size:20px'>$1,000,000.00</strong> in our monthly lottery draw!</p><p>Your winning numbers were: 7-14-23-35-42-49</p><p><strong>CLAIM YOUR PRIZE NOW!</strong></p><p>To claim your winnings, click here: <a href='https://bit.ly/claim-million'>CLAIM NOW</a></p><p>This offer expires in 48 hours!</p><p>Lottery Reference: LTC/2024/WIN/001</p></body></html>",
        "body_text": "🎉 CONGRATULATIONS! 🎉\n\nYOU ARE THE LUCKY WINNER!\n\nThe International Lottery Commission is pleased to inform you that you have won the sum of $1,000,000.00 in our monthly lottery draw!\n\nYour winning numbers were: 7-14-23-35-42-49\n\nCLAIM YOUR PRIZE NOW!\n\nTo claim your winnings, visit: https://bit.ly/claim-million\n\nThis offer expires in 48 hours!\n\nLottery Reference: LTC/2024/WIN/001",
        "headers": {
            "From": "International Lottery Commission <winner@lottery-commission.ml>",
            "To": "lucky.winner@example.com",
            "Date": "Wed, 21 Oct 2024 15:45:00 +0000",
            "Subject": "🎉 CONGRATULATIONS! You've Won $1,000,000!!!"
        },
        "links": ["https://bit.ly/claim-million"]
    },
    "Suspicious - Microsoft Spoofing": {
        "subject": "Microsoft Account Security Alert",
        "from": "Microsoft Security <alerts@microsoft-security.tk>",
        "to": "user@company.com",
        "body_html": "<html><body><div style='background:#0078d4;color:white;padding:15px'><h3>Microsoft Account Security</h3></div><p>Hello,</p><p>We detected an unusual sign-in to your Microsoft account from a new device:</p><ul><li>Location: Russia</li><li>Device: Unknown Device</li><li>Time: Today at 2:30 AM</li></ul><p>If this wasn't you, please secure your account immediately by clicking the link below:</p><p><a href='https://microsft-secure.tk/verify'>Secure Your Account</a></p><p>If you don't recognize this activity, your account may be compromised.</p><p>Thanks,<br>Microsoft Account Team</p></body></html>",
        "body_text": "Hello,\n\nWe detected an unusual sign-in to your Microsoft account from a new device:\n\n- Location: Russia\n- Device: Unknown Device  \n- Time: Today at 2:30 AM\n\nIf this wasn't you, please secure your account immediately: https://microsft-secure.tk/verify\n\nIf you don't recognize this activity, your account may be compromised.\n\nThanks,\nMicrosoft Account Team",
        "headers": {
            "From": "Microsoft Security <alerts@microsoft-security.tk>",
            "To": "user@company.com",
            "Date": "Wed, 21 Oct 2024 08:30:00 +0000",
            "Subject": "Microsoft Account Security Alert"
        },
        "links": ["https://microsft-secure.tk/verify"]
    },
    "Legitimate - Newsletter": {
        "subject": "Your Weekly Tech Newsletter - AI Advances",
        "from": "TechNews Weekly <newsletter@technews.com>",
        "to": "subscriber@example.com", 
        "body_html": "<html><body><div style='background:#f8f9fa;padding:20px'><h2>TechNews Weekly</h2><p>Your trusted source for technology news</p></div><h3>This Week's Headlines</h3><ul><li><a href='https://technews.com/ai-breakthrough'>Major AI Breakthrough in Natural Language Processing</a></li><li><a href='https://technews.com/quantum-computing'>Quantum Computing Milestone Reached</a></li><li><a href='https://technews.com/cybersecurity'>New Cybersecurity Framework Released</a></li></ul><p>Read more at <a href='https://technews.com'>TechNews.com</a></p><p><small>Unsubscribe: <a href='https://technews.com/unsubscribe?id=12345'>Click here</a></small></p></body></html>",
        "body_text": "TechNews Weekly\nYour trusted source for technology news\n\nThis Week's Headlines:\n\n- Major AI Breakthrough in Natural Language Processing\n  https://technews.com/ai-breakthrough\n\n- Quantum Computing Milestone Reached\n  https://technews.com/quantum-computing\n\n- New Cybersecurity Framework Released\n  https://technews.com/cybersecurity\n\nRead more at https://technews.com\n\nUnsubscribe: https://technews.com/unsubscribe?id=12345",
        "headers": {
            "From": "TechNews Weekly <newsletter@technews.com>",
            "To": "subscriber@example.com",
            "Date": "Wed, 21 Oct 2024 12:00:00 +0000",
            "Message-ID": "<newsletter-2024-42@technews.com>",
            "List-Unsubscribe": "<https://technews.com/unsubscribe?id=12345>",
            "Subject": "Your Weekly Tech Newsletter - AI Advances"
        },
        "links": [
            "https://technews.com/ai-breakthrough",
            "https://technews.com/quantum-computing", 
            "https://technews.com/cybersecurity",
            "https://technews.com",
            "https://technews.com/unsubscribe?id=12345"
        ]
    }
}

def highlight_text(text: str, highlights: List[Dict]) -> str:
    """Apply highlights to text using HTML spans."""
    if not highlights:
        return text
    
    # Sort highlights by start position (reverse order for replacement)
    sorted_highlights = sorted(highlights, key=lambda x: x['start'], reverse=True)
    
    highlighted_text = text
    for highlight in sorted_highlights:
        start = highlight['start']
        end = highlight['end']
        reason = highlight['reason']
        token = highlight['token']
        
        # Choose color based on reason
        color_map = {
            'suspicious_keyword': '#ff6b6b',
            'suspicious_pattern': '#ffa726', 
            'high_tfidf_suspicious': '#42a5f5'
        }
        color = color_map.get(reason, '#ff6b6b')
        
        # Replace with highlighted span
        replacement = f'<span style="background-color: {color}; color: white; padding: 2px 4px; border-radius: 3px; font-weight: bold;" title="{reason}">{token}</span>'
        highlighted_text = highlighted_text[:start] + replacement + highlighted_text[end:]
    
    return highlighted_text

def create_progress_bar(score: float, label: str, color: str = "blue") -> go.Figure:
    """Create a horizontal progress bar."""
    fig = go.Figure()
    
    # Background bar
    fig.add_trace(go.Bar(
        y=[label],
        x=[1.0],
        orientation='h',
        marker=dict(color='lightgray'),
        showlegend=False,
        hoverinfo='skip'
    ))
    
    # Progress bar
    fig.add_trace(go.Bar(
        y=[label],
        x=[score],
        orientation='h',
        marker=dict(color=color),
        showlegend=False,
        text=[f'{score:.2f}'],
        textposition='inside',
        hovertemplate=f'<b>{label}</b><br>Score: {score:.3f}<extra></extra>'
    ))
    
    fig.update_layout(
        barmode='overlay',
        height=60,
        margin=dict(l=0, r=0, t=0, b=0),
        xaxis=dict(range=[0, 1], showticklabels=False, showgrid=False),
        yaxis=dict(showticklabels=False, showgrid=False),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)'
    )
    
    return fig

def get_risk_color(action: str) -> str:
    """Get color for risk level."""
    colors = {
        'allow': '#4caf50',
        'flag': '#ff9800', 
        'quarantine': '#f44336'
    }
    return colors.get(action.lower(), '#666666')

def display_links_table(links_data: List[Dict]) -> None:
    """Display links analysis in a table."""
    if not links_data:
        st.info("No links found in email")
        return
    
    # Prepare data for table
    table_data = []
    for link in links_data:
        score = link.get('score', 0.0)
        risk_level = "🔴 High" if score >= 0.7 else "🟡 Medium" if score >= 0.4 else "🟢 Low"
        
        table_data.append({
            'URL': link.get('url', 'Unknown')[:50] + ('...' if len(link.get('url', '')) > 50 else ''),
            'Domain': link.get('domain', 'Unknown'),
            'Risk Score': f"{score:.2f}",
            'Risk Level': risk_level,
            'Reasons': '; '.join(link.get('reasons', [])[:2])  # Show first 2 reasons
        })
    
    if table_data:
        df = pd.DataFrame(table_data)
        st.dataframe(df, use_container_width=True)

def parse_email_text(email_text: str) -> Dict[str, Any]:
    """Parse raw email text into structured format."""
    lines = email_text.strip().split('\n')
    
    headers = {}
    body_lines = []
    in_headers = True
    
    for line in lines:
        if in_headers:
            if line.strip() == '':
                in_headers = False
                continue
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        else:
            body_lines.append(line)
    
    body_text = '\n'.join(body_lines)
    
    # Extract basic fields
    subject = headers.get('Subject', '')
    from_addr = headers.get('From', '')
    to_addr = headers.get('To', '')
    
    # Simple link extraction
    links = re.findall(r'https?://[^\s<>"\'\`]+', body_text)
    
    return {
        'subject': subject,
        'from': from_addr,
        'to': to_addr,
        'body_html': f'<p>{body_text.replace(chr(10), "</p><p>")}</p>',
        'body_text': body_text,
        'headers': headers,
        'links': links
    }

def main():
    """Main Streamlit app."""
    
    # Header
    st.title("🛡️ Email Phishing Analyzer")
    st.markdown("**AI-powered email security analysis using multiple detection agents**")
    
    # Sidebar configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        api_url = st.text_input("API URL", value="http://localhost:8000", help="URL of the FastAPI backend")
        
        st.markdown("---")
        st.markdown("**About this tool:**")
        st.markdown("This tool analyzes emails using three specialized AI agents:")
        st.markdown("- 🔍 **Content Agent**: ML-based text analysis")
        st.markdown("- 🔗 **Link Agent**: URL and domain analysis") 
        st.markdown("- 👤 **Behavior Agent**: Sender pattern analysis")
    
    # Main content
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.header("📧 Email Input")
        
        # Demo dropdown
        demo_choice = st.selectbox(
            "Try a demo email:",
            list(DEMO_EMAILS.keys()),
            help="Select a pre-configured email example"
        )
        
        # Input tabs
        tab1, tab2 = st.tabs(["📝 Raw Email", "📁 JSON Upload"])
        
        email_data = None
        
        with tab1:
            if demo_choice != "Select a demo email...":
                email_data = DEMO_EMAILS[demo_choice]
                
                # Show demo email in text area
                demo_text = f"""Subject: {email_data.get('subject', '')}
From: {email_data.get('from', '')}
To: {email_data.get('to', '')}

{email_data.get('body_text', '')}"""
                
                email_text = st.text_area(
                    "Email content:",
                    value=demo_text,
                    height=300,
                    help="Paste raw email content here"
                )
            else:
                email_text = st.text_area(
                    "Email content:",
                    height=300,
                    placeholder="Paste raw email content here...\n\nSubject: Your subject here\nFrom: sender@example.com\nTo: recipient@example.com\n\nEmail body content...",
                    help="Paste raw email content here"
                )
            
            if email_text and demo_choice == "Select a demo email...":
                email_data = parse_email_text(email_text)
        
        with tab2:
            uploaded_file = st.file_uploader(
                "Upload JSON file",
                type=['json'],
                help="Upload a JSON file with email data"
            )
            
            if uploaded_file:
                try:
                    email_data = json.load(uploaded_file)
                    st.success("JSON file loaded successfully!")
                except json.JSONDecodeError:
                    st.error("Invalid JSON file")
    
    with col2:
        st.header("🚀 Analysis")
        
        analyze_button = st.button(
            "🔍 Analyze Email",
            type="primary",
            use_container_width=True,
            disabled=not email_data
        )
        
        if email_data:
            st.success("✅ Email data loaded")
            with st.expander("📋 View email data"):
                st.json(email_data)
    
    # Analysis results
    if analyze_button and email_data:
        with st.spinner("🔍 Analyzing email..."):
            try:
                # Make API request
                response = requests.post(
                    f"{api_url}/analyze_email",
                    json=email_data,
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Display results
                    st.header("📊 Analysis Results")
                    
                    # Risk banner
                    action = result.get('action', 'unknown').upper()
                    final_score = result.get('final_score', 0.0)
                    risk_color = get_risk_color(action)
                    
                    st.markdown(f"""
                    <div style="background-color: {risk_color}; color: white; padding: 20px; border-radius: 10px; text-align: center; margin: 20px 0;">
                        <h2 style="margin: 0; color: white;">🛡️ RISK ASSESSMENT: {action}</h2>
                        <h3 style="margin: 10px 0; color: white;">Overall Score: {final_score:.3f}</h3>
                        <p style="margin: 0; color: white;">{result.get('summary', '')}</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Agent scores
                    st.subheader("🤖 Agent Scores")
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        content_score = result.get('content_analysis', {}).get('score', 0.0)
                        st.plotly_chart(
                            create_progress_bar(content_score, "Content Agent", "#ff6b6b"),
                            use_container_width=True,
                            config={'displayModeBar': False}
                        )
                    
                    with col2:
                        link_score = result.get('link_analysis', {}).get('score', 0.0)
                        st.plotly_chart(
                            create_progress_bar(link_score, "Link Agent", "#42a5f5"),
                            use_container_width=True,
                            config={'displayModeBar': False}
                        )
                    
                    with col3:
                        behavior_score = result.get('behavior_analysis', {}).get('score', 0.0)
                        st.plotly_chart(
                            create_progress_bar(behavior_score, "Behavior Agent", "#66bb6a"),
                            use_container_width=True,
                            config={'displayModeBar': False}
                        )
                    
                    # Detailed analysis tabs
                    tab1, tab2, tab3, tab4 = st.tabs(["📝 Content Analysis", "🔗 Link Analysis", "👤 Behavior Analysis", "📧 Original Email"])
                    
                    with tab1:
                        st.subheader("🔍 Content Analysis")
                        content_analysis = result.get('content_analysis', {})
                        
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            st.metric("Content Score", f"{content_analysis.get('score', 0.0):.3f}")
                        with col2:
                            highlights_count = len(content_analysis.get('highlights', []))
                            st.metric("Suspicious Elements", highlights_count)
                        
                        st.markdown("**Explanation:**")
                        st.write(content_analysis.get('explain', 'No explanation available'))
                        
                        # Highlighted content
                        if content_analysis.get('highlights'):
                            st.markdown("**Highlighted Text:**")
                            email_text = email_data.get('body_text', '')
                            highlighted = highlight_text(email_text, content_analysis.get('highlights', []))
                            st.markdown(f'<div style="border: 1px solid #ddd; padding: 15px; border-radius: 5px;">{highlighted}</div>', unsafe_allow_html=True)
                            
                            # Highlights details
                            with st.expander("🎯 View highlight details"):
                                for i, highlight in enumerate(content_analysis.get('highlights', []), 1):
                                    st.write(f"**{i}.** `{highlight.get('token', '')}` - {highlight.get('reason', '')}")
                    
                    with tab2:
                        st.subheader("🔗 Link Analysis")
                        link_analysis = result.get('link_analysis', {})
                        
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Link Score", f"{link_analysis.get('score', 0.0):.3f}")
                        with col2:
                            st.metric("Total Links", link_analysis.get('total_links', 0))
                        with col3:
                            st.metric("Suspicious Links", link_analysis.get('suspicious_count', 0))
                        
                        st.markdown("**Analysis:**")
                        st.write(link_analysis.get('details', 'No details available'))
                        
                        # Links table
                        if link_analysis.get('suspicious_links'):
                            st.markdown("**Suspicious Links Found:**")
                            display_links_table(link_analysis.get('suspicious_links', []))
                    
                    with tab3:
                        st.subheader("👤 Behavior Analysis")
                        behavior_analysis = result.get('behavior_analysis', {})
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric("Behavior Score", f"{behavior_analysis.get('score', 0.0):.3f}")
                        with col2:
                            reputation = behavior_analysis.get('sender_reputation', 'unknown')
                            st.metric("Sender Reputation", reputation.title())
                        
                        st.markdown("**Analysis:**")
                        st.write(behavior_analysis.get('details', 'No details available'))
                        
                        # Behavior issues
                        issues = [
                            ("Timing Anomalies", behavior_analysis.get('timing_anomalies', [])),
                            ("Header Anomalies", behavior_analysis.get('header_anomalies', [])),
                            ("Authentication Issues", behavior_analysis.get('authentication_issues', [])),
                            ("Spoofing Indicators", behavior_analysis.get('spoofing_indicators', []))
                        ]
                        
                        for category, items in issues:
                            if items:
                                st.markdown(f"**{category}:**")
                                for item in items:
                                    st.write(f"- {item}")
                    
                    with tab4:
                        st.subheader("📧 Original Email")
                        
                        # Email headers
                        with st.expander("📋 Email Headers"):
                            headers = email_data.get('headers', {})
                            for key, value in headers.items():
                                st.write(f"**{key}:** {value}")
                        
                        # Email body
                        st.markdown("**Email Body:**")
                        if email_data.get('body_html'):
                            st.components.v1.html(email_data['body_html'], height=300, scrolling=True)
                        else:
                            st.text(email_data.get('body_text', ''))
                    
                    # Feedback section
                    st.header("💬 Feedback")
                    
                    col1, col2, col3 = st.columns([1, 1, 2])
                    
                    with col1:
                        if st.button("👍 Correct Analysis", use_container_width=True):
                            st.success("Thank you for the feedback!")
                    
                    with col2:
                        if st.button("👎 Incorrect Analysis", use_container_width=True):
                            st.error("Thank you for the feedback! This helps us improve.")
                    
                    with col3:
                        feedback_text = st.text_input("Additional comments:", placeholder="Optional feedback...")
                        if feedback_text:
                            st.info("Feedback recorded: " + feedback_text)
                
                else:
                    st.error(f"API Error: {response.status_code} - {response.text}")
                    
            except requests.exceptions.RequestException as e:
                st.error(f"Connection Error: Could not connect to API at {api_url}")
                st.error(f"Error details: {str(e)}")
                st.info("Make sure the FastAPI backend is running at the specified URL")
            
            except Exception as e:
                st.error(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    main()
