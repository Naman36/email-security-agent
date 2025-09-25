#!/usr/bin/env python3
"""
Helper script to run the Streamlit app.
"""

import subprocess
import sys
import os

def main():
    """Run the Streamlit app."""
    
    print("🚀 Starting Email Phishing Analyzer UI...")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not os.path.exists("streamlit_app.py"):
        print("❌ Error: streamlit_app.py not found!")
        print("Please run this script from the email-phishing directory.")
        sys.exit(1)
    
    # Check if FastAPI backend is recommended to be running
    print("📋 Before starting the UI, make sure:")
    print("   1. Install dependencies: pip install -r requirements.txt")
    print("   2. Start FastAPI backend: python main.py")
    print("   3. Backend should be running on http://localhost:8000")
    print()
    
    try:
        # Run Streamlit
        print("🌐 Starting Streamlit app...")
        print("   URL: http://localhost:8501")
        print("   To stop: Press Ctrl+C")
        print()
        
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", 
            "streamlit_app.py",
            "--server.port=8501",
            "--server.address=localhost"
        ])
        
    except KeyboardInterrupt:
        print("\n👋 Streamlit app stopped.")
    except FileNotFoundError:
        print("❌ Error: Streamlit not found!")
        print("Please install: pip install streamlit")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
