# 🛡️ Email Phishing Analyzer - Streamlit UI

A comprehensive web interface for analyzing emails using AI-powered phishing detection.

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the FastAPI Backend

```bash
python main.py
```

The API will be available at `http://localhost:8000`

### 3. Start the Streamlit UI

```bash
streamlit run streamlit_app.py
```

Or use the helper script:

```bash
python run_streamlit.py
```

The UI will be available at `http://localhost:8501`

## 🎯 Features

### 📧 Email Input Options

- **Raw Email**: Paste email content directly
- **JSON Upload**: Upload structured email data
- **Demo Examples**: 5 curated examples (legitimate and phishing)

### 🔍 Analysis Display

- **Risk Banner**: Color-coded overall assessment (Allow/Flag/Quarantine)
- **Agent Scores**: Visual progress bars for each AI agent
- **Content Highlights**: Suspicious text spans highlighted in context
- **Link Analysis**: Detailed table of suspicious URLs
- **Behavior Analysis**: Sender pattern and metadata analysis
- **Original Email**: Clean display of email content

### 💬 Feedback System

- **Correct/Incorrect** buttons for model improvement
- **Text feedback** for additional comments

## 📋 Demo Examples

### 1. Legitimate - Meeting Invitation

- Clean corporate communication
- No suspicious indicators
- Expected to score: **Allow**

### 2. Phishing - Fake PayPal Alert

- Urgent language, suspicious domain
- IP-based verification link
- Expected to score: **Quarantine**

### 3. Phishing - Lottery Scam

- Classic lottery scam patterns
- URL shortener, excessive urgency
- Expected to score: **Quarantine**

### 4. Suspicious - Microsoft Spoofing

- Domain typosquatting (.tk TLD)
- Impersonates Microsoft security
- Expected to score: **Flag**

### 5. Legitimate - Newsletter

- Proper unsubscribe headers
- Legitimate domain and content
- Expected to score: **Allow**

## 🎨 UI Components

### Main Interface

- **Left Panel**: Email input (text area, file upload, demos)
- **Right Panel**: Analysis controls and configuration
- **Results Area**: Comprehensive analysis display

### Analysis Sections

1. **Risk Assessment Banner**

   - Color-coded by risk level
   - Overall score and action
   - Summary explanation

2. **Agent Score Bars**

   - Content Agent (red) - Text analysis
   - Link Agent (blue) - URL analysis
   - Behavior Agent (green) - Metadata analysis

3. **Detailed Tabs**
   - Content: Highlights and explanations
   - Links: Suspicious URL table
   - Behavior: Sender patterns
   - Original: Clean email display

### Color Coding

- 🟢 **Green**: Safe/Allow (score < 0.4)
- 🟡 **Yellow**: Suspicious/Flag (0.4 ≤ score < 0.7)
- 🔴 **Red**: Dangerous/Quarantine (score ≥ 0.7)

## ⚙️ Configuration

### API Settings

- **API URL**: Configure backend endpoint (default: http://localhost:8000)
- **Timeout**: 30-second request timeout

### Sidebar Information

- Tool description and agent explanations
- Real-time configuration options

## 🔧 Troubleshooting

### Common Issues

**"Connection Error"**

- Ensure FastAPI backend is running on port 8000
- Check API URL in sidebar configuration
- Verify no firewall blocking localhost connections

**"Module not found"**

- Install all dependencies: `pip install -r requirements.txt`
- Ensure you're in the correct virtual environment

**"Invalid JSON"**

- Check JSON file format matches expected schema
- Use demo examples as reference format

### Expected JSON Format

```json
{
  "subject": "Email subject",
  "from": "sender@domain.com",
  "to": "recipient@domain.com",
  "body_html": "<html>...</html>",
  "body_text": "Plain text version",
  "headers": {
    "From": "sender@domain.com",
    "Date": "Wed, 21 Oct 2024 10:30:00 +0000",
    "Message-ID": "<id@domain.com>"
  },
  "links": ["http://example.com"]
}
```

## 🚀 Production Deployment

### Environment Variables

```bash
export STREAMLIT_SERVER_PORT=8501
export STREAMLIT_SERVER_ADDRESS=0.0.0.0
export API_BASE_URL=http://backend:8000
```

### Docker Deployment

```bash
# Build and run with docker-compose
docker-compose up --build

# Access UI at http://localhost:8501
# API available at http://localhost:8000
```

## 📊 Performance

- **Response Time**: Typically 2-5 seconds for analysis
- **Concurrent Users**: Supports multiple simultaneous analyses
- **File Size Limit**: Recommended max 1MB for JSON uploads
- **Browser Support**: Chrome, Firefox, Safari, Edge

## 🛡️ Security Notes

- The UI is designed for internal/demo use
- In production, add authentication and rate limiting
- Validate all uploaded content thoroughly
- Use HTTPS in production environments

## 📱 Mobile Support

The interface is responsive and works on:

- Desktop browsers (optimal experience)
- Tablets (good experience)
- Mobile phones (basic functionality)

## 🎓 Usage Tips

1. **Try Demo Examples First**: Understand the tool capabilities
2. **Check All Tabs**: Each provides unique insights
3. **Review Highlights**: See exactly what triggered alerts
4. **Provide Feedback**: Help improve the model accuracy
5. **Monitor Scores**: Understand how different content affects scoring

## 🔄 Updates

The UI automatically reflects backend improvements:

- New agent features appear immediately
- Updated scoring algorithms show in real-time
- Additional analysis data displays automatically

For the latest updates, restart both backend and frontend services.
