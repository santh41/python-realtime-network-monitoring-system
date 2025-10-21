#!/usr/bin/env python3
"""
Windows-optimized dependency installer for Network Anomaly Detection System
Handles different Windows environments and Python installations
"""

import os
import sys
import subprocess
import platform
import urllib.request
from pathlib import Path

def print_header():
    """Print installation header"""
    print("=" * 60)
    print("📦 Network Anomaly Detection - Dependency Installer")
    print("=" * 60)
    print(f"🖥️  Platform: {platform.system()} {platform.release()}")
    print(f"🐍 Python: {sys.version.split()[0]}")
    print("=" * 60)

def check_python_installation():
    """Check Python installation and pip"""
    print("\n🔍 Checking Python installation...")
    
    # Check Python version
    if sys.version_info < (3, 7):
        print("❌ Python 3.7+ is required")
        print(f"Current version: {sys.version}")
        return False
    
    print(f"✅ Python version: {sys.version.split()[0]}")
    
    # Check pip
    try:
        import pip
        print("✅ pip is available")
    except ImportError:
        print("❌ pip is not available")
        print("💡 Installing pip...")
        try:
            subprocess.check_call([sys.executable, '-m', 'ensurepip', '--upgrade'])
            print("✅ pip installed successfully")
        except subprocess.CalledProcessError:
            print("❌ Failed to install pip")
            return False
    
    return True

def upgrade_pip():
    """Upgrade pip to latest version"""
    print("\n🔄 Upgrading pip...")
    try:
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("✅ pip upgraded successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"⚠️  Could not upgrade pip: {e}")
        print("💡 Continuing with current pip version...")
        return True

def install_requirements():
    """Install requirements from requirements.txt"""
    print("\n📋 Installing requirements...")
    
    requirements_file = Path("requirements.txt")
    if not requirements_file.exists():
        print("❌ requirements.txt not found")
        return False
    
    try:
        # Install with Windows-optimized flags
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install',
            '--upgrade',
            '--no-cache-dir',
            '--disable-pip-version-check',
            '-r', str(requirements_file)
        ])
        print("✅ Requirements installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install requirements: {e}")
        return False

def install_individual_packages():
    """Install packages individually for better error handling"""
    print("\n📦 Installing packages individually...")
    
    packages = [
        'flask>=2.0.0',
        'flask-socketio>=5.0.0',
        'scapy>=2.4.0',
        'scikit-learn>=1.0.0',
        'numpy>=1.20.0',
        'pandas>=1.3.0',
        'joblib>=1.0.0',
        'matplotlib>=3.5.0',
        'seaborn>=0.11.0',
        'plotly>=5.0.0'
    ]
    
    failed_packages = []
    
    for package in packages:
        print(f"Installing {package}...")
        try:
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install',
                '--upgrade',
                '--no-cache-dir',
                package
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"✅ {package}")
        except subprocess.CalledProcessError:
            print(f"❌ {package}")
            failed_packages.append(package)
    
    if failed_packages:
        print(f"\n⚠️  Failed to install: {', '.join(failed_packages)}")
        print("💡 You may need to install these manually")
        return False
    
    return True

def check_visual_cpp_redistributable():
    """Check for Visual C++ Redistributable (required for some packages)"""
    print("\n🔧 Checking Visual C++ Redistributable...")
    
    # Check common installation paths
    vcredist_paths = [
        r"C:\Windows\System32\vcruntime140.dll",
        r"C:\Windows\SysWOW64\vcruntime140.dll"
    ]
    
    for path in vcredist_paths:
        if os.path.exists(path):
            print("✅ Visual C++ Redistributable found")
            return True
    
    print("⚠️  Visual C++ Redistributable not found")
    print("💡 Some packages may fail to install without it")
    print("💡 Download from: https://aka.ms/vs/17/release/vc_redist.x64.exe")
    return False

def create_venv_if_needed():
    """Create virtual environment if it doesn't exist"""
    print("\n🏠 Checking virtual environment...")
    
    venv_path = Path("venv")
    if venv_path.exists():
        print("✅ Virtual environment exists")
        return True
    
    print("🔧 Creating virtual environment...")
    try:
        subprocess.check_call([
            sys.executable, '-m', 'venv', 'venv'
        ])
        print("✅ Virtual environment created")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create virtual environment: {e}")
        return False

def main():
    """Main installation function"""
    try:
        print_header()
        
        # Check Python installation
        if not check_python_installation():
            sys.exit(1)
        
        # Upgrade pip
        upgrade_pip()
        
        # Check Visual C++ Redistributable
        check_visual_cpp_redistributable()
        
        # Create virtual environment if needed
        create_venv_if_needed()
        
        # Try to install requirements
        if not install_requirements():
            print("\n🔄 Trying individual package installation...")
            if not install_individual_packages():
                print("\n❌ Installation failed")
                print("💡 Try running: pip install -r requirements.txt manually")
                sys.exit(1)
        
        print("\n✅ Installation completed successfully!")
        print("🚀 You can now run: start.bat or start.py")
        
    except KeyboardInterrupt:
        print("\n🛑 Installation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Installation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
