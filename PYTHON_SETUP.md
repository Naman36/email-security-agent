# 🐍 Python Setup Guide for Email Phishing Analyzer

Quick guide to set up Python 3.11 and resolve compatibility issues.

## 🚨 Issue: Python 3.13 Compatibility

If you're getting scikit-learn installation errors, it's because **Python 3.13 is too new**. Most ML packages work best with Python 3.11 or 3.12.

## 🛠️ Solution: Install Python 3.11

### Option 1: Using Homebrew (macOS - Recommended)

```bash
# 1. Install Python 3.11
brew install python@3.11

# 2. Verify installation
python3.11 --version  # Should show Python 3.11.x

# 3. Create virtual environment
cd email-phishing
python3.11 -m venv venv

# 4. Activate virtual environment
source venv/bin/activate

# 5. Upgrade pip
pip install --upgrade pip

# 6. Install dependencies
pip install -r requirements.txt
```

### Option 2: Using pyenv (Cross-platform)

```bash
# 1. Install pyenv (if not installed)
# macOS:
brew install pyenv

# Add to your shell profile (~/.zshrc or ~/.bash_profile):
echo 'export PATH="$HOME/.pyenv/bin:$PATH"' >> ~/.zshrc
echo 'eval "$(pyenv init -)"' >> ~/.zshrc
source ~/.zshrc

# 2. Install Python 3.11
pyenv install 3.11.10

# 3. Set Python 3.11 for this project
cd email-phishing
pyenv local 3.11.10

# 4. Create virtual environment
python -m venv venv
source venv/bin/activate

# 5. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Option 3: Using conda (Alternative)

```bash
# 1. Install/update conda
# Download from: https://docs.conda.io/en/latest/miniconda.html

# 2. Create environment with Python 3.11
conda create -n email-phishing python=3.11

# 3. Activate environment
conda activate email-phishing

# 4. Install core ML packages via conda (more reliable)
conda install -c conda-forge scikit-learn=1.3.0 numpy scipy

# 5. Install remaining packages via pip
pip install sentence-transformers streamlit fastapi uvicorn beautifulsoup4 aiosqlite
```

## ✅ Verification Steps

After setup, verify everything works:

```bash
# 1. Check Python version
python --version  # Should be 3.11.x

# 2. Test imports
python -c "import sklearn; print('scikit-learn:', sklearn.__version__)"
python -c "import sentence_transformers; print('sentence-transformers: OK')"
python -c "import streamlit; print('streamlit: OK')"

# 3. Test the app
python main.py  # Should start without errors
```

## 🔧 Troubleshooting

### Issue: "command not found: python3.11"

```bash
# Check what Python versions are available
ls /usr/bin/python*
ls /opt/homebrew/bin/python*

# Use the full path if needed
/opt/homebrew/bin/python3.11 -m venv venv
```

### Issue: "No module named '\_ctypes'"

```bash
# Install additional dependencies (macOS)
xcode-select --install
brew install libffi

# Reinstall Python
brew reinstall python@3.11
```

### Issue: Still getting compilation errors

```bash
# Use pre-compiled wheels only
pip install --only-binary=all scikit-learn==1.3.0
pip install --only-binary=all numpy scipy
```

### Issue: OpenMP errors on macOS

```bash
# Install OpenMP support
brew install libomp

# Set environment variables
export CC=/usr/bin/clang
export CXX=/usr/bin/clang++
pip install -r requirements.txt
```

## 🚀 Quick Recovery Script

Save this as `setup.sh` and run `bash setup.sh`:

```bash
#!/bin/bash
set -e

echo "🐍 Setting up Python 3.11 for Email Phishing Analyzer"

# Check if Python 3.11 is available
if command -v python3.11 &> /dev/null; then
    echo "✅ Python 3.11 found"
    PYTHON_CMD="python3.11"
elif command -v python3 &> /dev/null && python3 --version | grep -q "3.11"; then
    echo "✅ Python 3.11 found as python3"
    PYTHON_CMD="python3"
else
    echo "❌ Python 3.11 not found. Installing via Homebrew..."
    brew install python@3.11
    PYTHON_CMD="python3.11"
fi

# Setup virtual environment
echo "📦 Creating virtual environment..."
$PYTHON_CMD -m venv venv
source venv/bin/activate

# Install dependencies
echo "📚 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "✅ Setup complete! Run:"
echo "  source venv/bin/activate"
echo "  python main.py"
```

## 📋 Alternative: Docker (Skip Python Issues)

If Python setup is problematic, use Docker:

```bash
# Build and run with Docker
docker-compose up --build

# Access API at http://localhost:8000
```

---

**Need help?** Check which Python version you're currently using:

```bash
python --version
python3 --version
which python
which python3
```
