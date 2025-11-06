"""
Configuration File for AI Web Blocker - COMPLETE
"""

# Model Configuration
MODEL_PATH = "model/model.pkl"
VECTORIZER_PATH = "model/vectorizer.pkl"
VECT_PATH = "model/vectorizer.pkl"  # Backward compatibility

# System Configuration
HOSTS_FILE_PATH = r"C:\Windows\System32\drivers\etc\hosts"
LOG_PATH = "ai_blocker.log"
LOG_FILE = "ai_blocker.log"  # Alternative name

# Network Configuration
FILTER = "outbound and (tcp.DstPort == 80 or tcp.DstPort == 443)"

# Comprehensive Whitelist
WHITELIST = {
    "localhost",
    "127.0.0.1",
    # Microsoft Services
    "microsoft.com",
    "live.com",
    "msftconnecttest.com",
    "login.live.com",
    "windows.com",
    "windowsupdate.com",
    
    # Google Services
    "google.com",
    "googleapis.com",
    "googlevideo.com",
    "gstatic.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "youtube.com",
    "ytimg.com",
    "ggpht.com",
    
    # CDNs and Essential Services
    "cloudflare.com",
    "amazonaws.com",
    "azure.com",
    "akamai.com",
    "fastly.com",
    "jsdelivr.net",
    
    # Social Media Essential
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "twitter.com",
    "linkedin.com",
    "discord.com"
}

# False Positive Prevention
CONFIDENCE_THRESHOLD = 0.85
ENABLE_ADAPTIVE_LEARNING = True
ENABLE_BACKGROUND_DETECTION = True
NOTIFY_UNCERTAIN_BLOCKS = True

# Background Patterns
BACKGROUND_PATTERNS = [
    'cdn', 'static', 'assets', 'media', 'images',
    'fonts', 'videos', 'api', 'analytics',
    'telemetry', 'metrics', 'logging', 'tracking'
]
