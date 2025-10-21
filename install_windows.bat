@echo off
chcp 65001 >nul
title Network Anomaly Detection - Windows Installer

echo.
echo ============================================================
echo 📦 Network Anomaly Detection - Windows Installer
echo ============================================================
echo 🔧 Optimized for different Windows environments
echo 🐍 Handles Python installation variations
echo 📊 Installs all required dependencies
echo ============================================================
echo.

:: Check if Python is installed
echo 🔍 Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo.
    echo 💡 Please install Python 3.7+ from https://python.org
    echo 💡 Make sure to check "Add Python to PATH" during installation
    echo.
    pause
    exit /b 1
)

:: Get Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo ✅ Python version: %PYTHON_VERSION%

:: Check if we're in the right directory
if not exist "requirements.txt" (
    echo ❌ Please run this script from the network_anomaly_detection directory
    echo.
    pause
    exit /b 1
)

:: Check for admin privileges
net session >nul 2>&1
if errorlevel 1 (
    echo ⚠️  Running without administrator privileges
    echo 💡 Some packages may require admin privileges
    echo.
) else (
    echo ✅ Running with administrator privileges
    echo.
)

:: Create virtual environment if it doesn't exist
if not exist "venv" (
    echo 🔧 Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo ❌ Failed to create virtual environment
        echo 💡 Try running as Administrator
        pause
        exit /b 1
    )
    echo ✅ Virtual environment created
) else (
    echo ✅ Virtual environment already exists
)

:: Activate virtual environment
echo 🔄 Activating virtual environment...
call venv\Scripts\activate.bat

:: Upgrade pip
echo 📦 Upgrading pip...
python -m pip install --upgrade pip --quiet
if errorlevel 1 (
    echo ⚠️  Could not upgrade pip, continuing...
)

:: Install Visual C++ Redistributable check
echo 🔧 Checking Visual C++ Redistributable...
if exist "C:\Windows\System32\vcruntime140.dll" (
    echo ✅ Visual C++ Redistributable found
) else (
    echo ⚠️  Visual C++ Redistributable not found
    echo 💡 Some packages may fail without it
    echo 💡 Download from: https://aka.ms/vs/17/release/vc_redist.x64.exe
)

:: Install dependencies with Windows-optimized method
echo 📦 Installing dependencies...
echo 💡 This may take a few minutes...

:: Try installing from requirements.txt first
python -m pip install --upgrade --no-cache-dir -r requirements.txt
if errorlevel 1 (
    echo ⚠️  Some packages failed, trying individual installation...
    
    :: Install packages individually
    echo Installing Flask...
    python -m pip install --upgrade flask flask-socketio
    
    echo Installing Scapy...
    python -m pip install --upgrade scapy
    
    echo Installing ML packages...
    python -m pip install --upgrade scikit-learn numpy pandas joblib
    
    echo Installing visualization packages...
    python -m pip install --upgrade matplotlib seaborn plotly
    
    if errorlevel 1 (
        echo ❌ Some packages failed to install
        echo 💡 Try running as Administrator
        echo 💡 Or install Visual C++ Redistributable
        pause
        exit /b 1
    )
)

:: Create necessary directories
if not exist "models" (
    echo 📁 Creating models directory...
    mkdir models
)

if not exist "templates" (
    echo 📁 Creating templates directory...
    mkdir templates
)

:: Test installation
echo 🧪 Testing installation...
python -c "import flask, scapy, sklearn, numpy, pandas; print('✅ All packages imported successfully')"
if errorlevel 1 (
    echo ❌ Installation test failed
    echo 💡 Some packages may not be working correctly
    pause
    exit /b 1
)

echo.
echo ✅ Installation completed successfully!
echo.
echo 🚀 You can now run the application:
echo    start.bat    - Windows batch file
echo    start.py     - Python startup script
echo.
echo 📊 The dashboard will be available at: http://localhost:5000
echo.
pause
