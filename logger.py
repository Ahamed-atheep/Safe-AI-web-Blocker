"""
Logger Module with Safe Import and Error Handling
"""

import sys
import logging
import os
from datetime import datetime

# Try to reconfigure stdout/stderr to UTF-8 to natively handle emojis
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
if hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass


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

def safe_print(message):
    """Safely print a message, falling back to character replacement on UnicodeEncodeError"""
    try:
        print(message)
    except UnicodeEncodeError:
        try:
            encoding = sys.stdout.encoding or 'utf-8'
            clean_msg = message.encode(encoding, errors='replace').decode(encoding)
            print(clean_msg)
        except Exception:
            try:
                print(message.encode('ascii', errors='replace').decode('ascii'))
            except Exception:
                pass

def log(message):
    """Log message to both console and file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_message = f"[{timestamp}] {message}"
    
    # Print safely to console
    safe_print(formatted_message)
    
    # Log to file
    try:
        logging.info(message)
    except Exception as e:
        safe_print(f"Failed to write to log file: {e}")

def log_error(message):
    """Log error message"""
    log(f"ERROR: {message}")

def log_info(message):
    """Log info message"""
    log(f"INFO: {message}")
