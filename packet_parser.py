"""
Network Packet Parser for HTTP/HTTPS Traffic
"""

def extract_host_from_http(payload):
    """Extract hostname from HTTP request"""
    try:
        text = payload.decode('utf-8', errors='ignore')
        
        # Check if it's an HTTP request
        if not any(text.startswith(method) for method in ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS']):
            return None
        
        # Find Host header
        for line in text.split('\r\n'):
            if line.lower().startswith('host:'):
                _, host = line.split(':', 1)
                return host.strip().lower()
        
        return None
        
    except Exception:
        return None

def extract_sni_from_tls(data):
    """Extract Server Name Indication (SNI) from TLS ClientHello"""
    try:
        # Basic TLS parsing
        if len(data) < 5 or data[0] != 0x16:  # Not TLS handshake
            return None
        
        # Check if ClientHello
        if len(data) < 6 or data[5] != 0x01:
            return None
        
        # Navigate to extensions
        idx = 5  # Start after TLS record header
        idx += 4  # Skip handshake header
        idx += 2  # Skip version
        idx += 32  # Skip random
        
        if idx >= len(data):
            return None
        
        # Skip session ID
        session_id_len = data[idx]
        idx += 1 + session_id_len
        
        if idx + 2 > len(data):
            return None
        
        # Skip cipher suites
        cipher_suites_len = int.from_bytes(data[idx:idx+2], 'big')
        idx += 2 + cipher_suites_len
        
        if idx >= len(data):
            return None
        
        # Skip compression methods
        compression_len = data[idx]
        idx += 1 + compression_len
        
        if idx + 2 > len(data):
            return None
        
        # Parse extensions
        extensions_len = int.from_bytes(data[idx:idx+2], 'big')
        idx += 2
        extensions_end = idx + extensions_len
        
        # Look for SNI extension (type 0x0000)
        while idx + 4 <= extensions_end and idx + 4 <= len(data):
            ext_type = int.from_bytes(data[idx:idx+2], 'big')
            ext_len = int.from_bytes(data[idx+2:idx+4], 'big')
            idx += 4
            
            if ext_type == 0x0000:  # Server Name extension
                if idx + 2 > len(data):
                    return None
                
                server_name_list_len = int.from_bytes(data[idx:idx+2], 'big')
                idx += 2
                
                if idx + 3 > len(data):
                    return None
                
                name_type = data[idx]
                name_len = int.from_bytes(data[idx+1:idx+3], 'big')
                idx += 3
                
                if name_type == 0 and idx + name_len <= len(data):  # hostname
                    hostname = data[idx:idx+name_len].decode('utf-8', errors='ignore')
                    return hostname.lower()
            else:
                idx += ext_len
        
        return None
        
    except Exception:
        return None

def is_valid_hostname(hostname):
    """Validate if hostname format is correct"""
    if not hostname or len(hostname) < 3 or len(hostname) > 100:
        return False
    
    # Must contain at least one dot
    if '.' not in hostname:
        return False
    
    # Valid characters
    valid_chars = set('abcdefghijklmnopqrstuvwxyz0123456789.-')
    if not set(hostname.lower()).issubset(valid_chars):
        return False
    
    # Must not start or end with dash or dot
    if hostname.startswith('-') or hostname.endswith('-'):
        return False
    if hostname.startswith('.') or hostname.endswith('.'):
        return False
    
    return True
