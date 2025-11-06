"""
Logger Module with Safe Import and Error Handling
"""

import logging
import os
from datetime import datetime

# Safe import with fallback
try:
    from config import LOG_PATH
except ImportError:
    try:
        from config import LOG_FILE as LOG_PATH
    except ImportError:
        LOG_PATH = "ai_blocker.log"

# Ensure log directory exists
log_dir = os.path.dirname(LOG_PATH) if os.path.dirname(LOG_PATH) else "."
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Configure logging
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def log(message):
    """Log message to both console and file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_message = f"[{timestamp}] {message}"
    
    # Print to console
    print(formatted_message)
    
    # Log to file
    try:
        logging.info(message)
    except Exception as e:
        print(f"Failed to write to log file: {e}")

def log_error(message):
    """Log error message"""
    log(f"ERROR: {message}")

def log_info(message):
    """Log info message"""
    log(f"INFO: {message}")
