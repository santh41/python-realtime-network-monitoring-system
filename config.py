import os
import secrets
import string
from pathlib import Path

class Config:
    """Configuration class for the Network Anomaly Detection System"""
    
    def __init__(self):
        self.config_file = Path("config.json")
        self.load_config()
    
    def generate_secret_key(self, length=32):
        """Generate a secure random secret key"""
        # Use a combination of letters, digits, and special characters
        characters = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(characters) for _ in range(length))
    
    def load_config(self):
        """Load configuration from file or create default"""
        if self.config_file.exists():
            try:
                import json
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                
                # Set configuration values
                self.SECRET_KEY = config_data.get('SECRET_KEY', self.generate_secret_key())
                self.DEBUG = config_data.get('DEBUG', False)
                self.HOST = config_data.get('HOST', '0.0.0.0')
                self.PORT = config_data.get('PORT', 5000)
                self.MAX_CONTENT_LENGTH = config_data.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024)  # 16MB
                
                print(f"Configuration loaded from {self.config_file}")
                
            except Exception as e:
                print(f"Error loading config: {e}")
                self.create_default_config()
        else:
            self.create_default_config()
    
    def create_default_config(self):
        """Create default configuration"""
        print("🔧 Creating default configuration...")
        
        self.SECRET_KEY = self.generate_secret_key()
        self.DEBUG = False
        self.HOST = '0.0.0.0'
        self.PORT = 5000
        self.MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
        
        self.save_config()
        print("✅ Default configuration created")
    
    def save_config(self):
        """Save configuration to file"""
        try:
            import json
            config_data = {
                'SECRET_KEY': self.SECRET_KEY,
                'DEBUG': self.DEBUG,
                'HOST': self.HOST,
                'PORT': self.PORT,
                'MAX_CONTENT_LENGTH': self.MAX_CONTENT_LENGTH
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            print(f"✅ Configuration saved to {self.config_file}")
            
        except Exception as e:
            print(f"❌ Error saving config: {e}")
    
    def regenerate_secret_key(self):
        """Regenerate the secret key"""
        print("🔄 Regenerating secret key...")
        self.SECRET_KEY = self.generate_secret_key()
        self.save_config()
        print("✅ Secret key regenerated")
        return self.SECRET_KEY
    
    def get_secret_key(self):
        """Get the current secret key"""
        return self.SECRET_KEY
    
    def show_config(self):
        """Display current configuration (without showing secret key)"""
        print("\n📋 Current Configuration:")
        print(f"   Debug Mode: {self.DEBUG}")
        print(f"   Host: {self.HOST}")
        print(f"   Port: {self.PORT}")
        print(f"   Max Content Length: {self.MAX_CONTENT_LENGTH} bytes")
        print(f"   Secret Key: {'*' * 20} (hidden)")
        print(f"   Config File: {self.config_file}")

# Create global config instance
config = Config()

# Export configuration values
SECRET_KEY = config.get_secret_key()
DEBUG = config.DEBUG
HOST = config.HOST
PORT = config.PORT
MAX_CONTENT_LENGTH = config.MAX_CONTENT_LENGTH 