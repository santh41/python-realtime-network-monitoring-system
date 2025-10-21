@echo off
chcp 65001 >nul
title Network Anomaly Detection System

echo.
echo ============================================================
echo 🛡️  Network Anomaly Detection System - Optimized
echo ============================================================
echo 📊 Real-time network security monitoring
echo 🔍 Machine learning-based threat detection
echo 🌐 Beautiful web dashboard
echo ============================================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo 💡 Please install Python 3.7+ from https://python.org
    echo.
    pause
    exit /b 1
)

:: Check if we're in the right directory
if not exist "app.py" (
    echo ❌ Please run this script from the network_anomaly_detection directory
    echo.
    pause
    exit /b 1
)

:: Check for admin privileges (recommended for packet capture)
net session >nul 2>&1
if errorlevel 1 (
    echo ⚠️  Running without administrator privileges
    echo 💡 For best results, run as Administrator
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
        pause
        exit /b 1
    )
)

:: Activate virtual environment
echo 🔄 Activating virtual environment...
call venv\Scripts\activate.bat

:: Install/upgrade pip
echo 📦 Upgrading pip...
python -m pip install --upgrade pip --quiet

:: Install dependencies using Windows-optimized method
echo 📦 Installing dependencies...
python install_dependencies.py
if errorlevel 1 (
    echo ❌ Failed to install dependencies
    echo 💡 Trying alternative installation method...
    call install_windows.bat
    if errorlevel 1 (
        echo ❌ All installation methods failed
        echo 💡 Please check your Python installation and try again
        pause
        exit /b 1
    )
)

:: Create models directory if it doesn't exist
if not exist "models" (
    echo 📁 Creating models directory...
    mkdir models
)

:: Start the application
echo.
echo 🚀 Starting Network Anomaly Detection System...
echo 📊 Dashboard will be available at: http://localhost:5000
echo 💡 Press Ctrl+C to stop gracefully
echo.

:: Run the optimized startup script
python start.py

:: If we get here, the application has stopped
echo.
echo 👋 Application stopped
pause 