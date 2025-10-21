#!/usr/bin/env python3
"""
Optimized Startup Script for Network Anomaly Detection System
Handles dependencies, permissions, and system initialization
"""

import os
import sys
import subprocess
import platform
import time
import signal
import threading
from pathlib import Path

def print_banner():
    """Print startup banner"""
    print("=" * 60)
    print("🛡️  Network Anomaly Detection System - Optimized")
    print("=" * 60)
    print("📊 Real-time network security monitoring")
    print("🔍 Machine learning-based threat detection")
    print("🌐 Beautiful web dashboard")
    print("=" * 60)

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    print(f"✅ Python version: {sys.version.split()[0]}")
    
    # Check Python installation type on Windows
    if platform.system() == "Windows":
        python_path = sys.executable
        if "Microsoft Store" in python_path:
            print("   Python Source: Microsoft Store")
        elif "Anaconda" in python_path or "conda" in python_path:
            print("   Python Source: Anaconda/Conda")
        elif "Python" in python_path:
            print("   Python Source: Official Python.org")
        else:
            print("   Python Source: Custom/Portable")

def check_platform():
    """Check platform compatibility"""
    system = platform.system()
    print(f"🖥️  Platform: {system}")
    
    if system == "Windows":
        print("⚠️  Windows detected - Admin privileges may be required")
        # Check Windows version
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                version = winreg.QueryValueEx(key, "ProductName")[0]
                print(f"   Windows Version: {version}")
        except:
            print("   Windows Version: Unknown")
        
        # Check if running in different environments
        if os.environ.get('VIRTUAL_ENV'):
            print("   Virtual Environment: Active")
        elif os.environ.get('CONDA_DEFAULT_ENV'):
            print("   Conda Environment: Active")
        else:
            print("   Environment: System Python")
            
    elif system == "Linux":
        print("🐧 Linux detected - Root privileges may be required")
    elif system == "Darwin":
        print("🍎 macOS detected - Root privileges may be required")
    
    return system

def check_dependencies():
    """Check and install required dependencies"""
    print("\n📦 Checking dependencies...")
    
    required_packages = [
        'flask',
        'flask-socketio',
        'scapy',
        'scikit-learn',
        'numpy',
        'pandas',
        'joblib',
        'matplotlib',
        'seaborn',
        'plotly',
        'secrets'  # Built-in module
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"✅ {package}")
        except ImportError:
            print(f"❌ {package} - Missing")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n🔧 Installing missing packages: {', '.join(missing_packages)}")
        
        # Try different installation methods for Windows compatibility
        installation_methods = [
            # Method 1: Install from requirements.txt
            lambda: subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', 
                '--upgrade', '--no-cache-dir', '-r', 'requirements.txt'
            ]),
            # Method 2: Install packages individually
            lambda: subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', 
                '--upgrade', '--no-cache-dir'
            ] + missing_packages),
            # Method 3: Install with Windows-specific flags
            lambda: subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', 
                '--upgrade', '--no-cache-dir', '--disable-pip-version-check'
            ] + missing_packages)
        ]
        
        success = False
        for i, method in enumerate(installation_methods, 1):
            try:
                print(f"🔄 Trying installation method {i}...")
                method()
                print("✅ Dependencies installed successfully")
                success = True
                break
            except subprocess.CalledProcessError as e:
                print(f"❌ Method {i} failed: {e}")
                if i < len(installation_methods):
                    print("🔄 Trying next method...")
        
        if not success:
            print("❌ All installation methods failed")
            print("💡 Try running: install_windows.bat")
            print("💡 Or install Visual C++ Redistributable")
            sys.exit(1)
    else:
        print("✅ All dependencies are installed")

def check_permissions():
    """Check if we have necessary permissions"""
    print("\n🔐 Checking permissions...")
    
    # Check if we can create files in current directory
    try:
        test_file = "test_permissions.tmp"
        with open(test_file, 'w') as f:
            f.write("test")
        os.remove(test_file)
        print("✅ File write permissions: OK")
    except Exception as e:
        print(f"❌ File write permissions: {e}")
        sys.exit(1)
    
    # Check if models directory exists
    models_dir = Path("models")
    if not models_dir.exists():
        try:
            models_dir.mkdir()
            print("✅ Created models directory")
        except Exception as e:
            print(f"❌ Failed to create models directory: {e}")
            sys.exit(1)
    else:
        print("✅ Models directory exists")

def check_network_interface():
    """Check network interface availability"""
    print("\n🌐 Checking network interfaces...")
    
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        
        if interfaces:
            print(f"✅ Found {len(interfaces)} network interface(s)")
            for i, iface in enumerate(interfaces[:3]):  # Show first 3
                print(f"   {i+1}. {iface}")
            if len(interfaces) > 3:
                print(f"   ... and {len(interfaces) - 3} more")
        else:
            print("⚠️  No network interfaces found")
            
    except Exception as e:
        print(f"⚠️  Could not check network interfaces: {e}")
        print("💡 This might be normal if running without admin privileges")

def create_default_model():
    """Create default ML model if it doesn't exist"""
    print("\n🤖 Checking ML model...")
    
    model_path = Path("models/network_anomaly_model.pkl")
    
    if model_path.exists():
        print("✅ ML model exists")
        return
    
    print("🔧 Creating default ML model...")
    try:
        from ml_model import MLModel
        model = MLModel()
        model._create_default_model()
        print("✅ Default ML model created")
    except Exception as e:
        print(f"❌ Failed to create default model: {e}")
        print("💡 The system will create one automatically when needed")

def check_configuration():
    """Check and create configuration if needed"""
    print("\n⚙️ Checking configuration...")
    
    try:
        from config import config
        config.show_config()
        print("✅ Configuration loaded successfully")
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        print("💡 The system will create default configuration")

def check_port_availability():
    """Check if port 5000 is available"""
    print("\n🔌 Checking port availability...")
    
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('localhost', 5000))
            print("✅ Port 5000 is available")
    except OSError:
        print("⚠️  Port 5000 is already in use")
        print("💡 The system will try to use an alternative port")

def start_application():
    """Start the main application"""
    print("\n🚀 Starting Network Anomaly Detection System...")
    print("📊 Dashboard will be available at: http://localhost:5000")
    print("💡 Press Ctrl+C to stop gracefully")
    print("-" * 60)
    
    try:
        # Import and run the main application
        from app import app, socketio
        from config import DEBUG, HOST, PORT
        
        # Start the application with optimized settings
        socketio.run(
            app,
            debug=DEBUG,
            host=HOST,
            port=PORT,
            use_reloader=False,
            allow_unsafe_werkzeug=True
        )
        
    except KeyboardInterrupt:
        print("\n🛑 Shutdown requested by user")
    except Exception as e:
        print(f"\n❌ Application error: {e}")
        print("💡 Check the logs above for more details")
    finally:
        print("\n👋 Goodbye!")

def main():
    """Main startup function"""
    try:
        print_banner()
        
        # System checks
        check_python_version()
        system = check_platform()
        check_dependencies()
        check_permissions()
        check_network_interface()
        create_default_model()
        check_configuration()
        check_port_availability()
        
        # Start application
        start_application()
        
    except KeyboardInterrupt:
        print("\n🛑 Startup interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Startup failed: {e}")
        print("💡 Please check the error messages above")
        sys.exit(1)

if __name__ == "__main__":
    main() 