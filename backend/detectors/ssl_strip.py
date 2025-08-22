import scapy.all as scapy
import threading
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Set, List, Optional

class SSLStripDetector:
    """SSL Strip Attack Detector"""
    
    def __init__(self, interface: str = None):
        self.interface = interface
        self.http_sessions = defaultdict(dict)  # Track HTTP sessions
        self.https_sessions = defaultdict(dict)  # Track HTTPS sessions
        self.ssl_redirects = defaultdict(list)  # Track SSL redirect patterns
        self.suspicious_sessions = set()
        self.is_running = False
        self.logger = logging.getLogger(__name__)
    
    def detect_ssl_strip(self, packet):
        """Analyze packets for SSL stripping indicators"""
        try:
            if packet.haslayer(scapy.TCP):
                tcp_layer = packet[scapy.TCP]
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                
                # HTTP traffic (port 80)
                if dst_port == 80 or src_port == 80:
                    if packet.haslayer(scapy.Raw):
                        payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                        self._analyze_http_traffic(payload, src_ip, dst_ip, src_port, dst_port)
                
                # HTTPS traffic (port 443)
                elif dst_port == 443 or src_port == 443:
                    self._analyze_https_traffic(packet, src_ip, dst_ip, src_port, dst_port)
                
                # Check for SSL/TLS handshake patterns
                if packet.haslayer(scapy.Raw):
                    self._analyze_ssl_handshake(packet, src_ip, dst_ip, src_port, dst_port)
                    
        except Exception as e:
            self.logger.error(f"Error in SSL strip detection: {e}")
    
    def _analyze_http_traffic(self, payload: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        """Analyze HTTP traffic for SSL stripping indicators"""
        try:
            session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            
            # Check if this is an HTTP request
            if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                self._analyze_http_request(payload, session_key, src_ip, dst_ip)
            
            # Check if this is an HTTP response
            elif payload.startswith('HTTP/'):
                self._analyze_http_response(payload, session_key, src_ip, dst_ip)
                
        except Exception as e:
            self.logger.error(f"Error analyzing HTTP traffic: {e}")
    
    def _analyze_http_request(self, payload: str, session_key: str, src_ip: str, dst_ip: str):
        """Analyze HTTP request for SSL stripping indicators"""
        try:
            lines = payload.split('\r\n')
            request_line = lines[0] if lines else ""
            
            # Parse request line
            parts = request_line.split()
            if len(parts) >= 2:
                method = parts[0]
                url = parts[1]
                
                # Extract headers
                headers = {}
                for line in lines[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()
                
                # Check for suspicious patterns
                self._check_ssl_strip_patterns(method, url, headers, session_key, src_ip, dst_ip)
                
                # Store session info
                self.http_sessions[session_key] = {
                    "timestamp": datetime.now(),
                    "method": method,
                    "url": url,
                    "headers": headers,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip
                }
                
        except Exception as e:
            self.logger.error(f"Error analyzing HTTP request: {e}")
    
    def _analyze_http_response(self, payload: str, session_key: str, src_ip: str, dst_ip: str):
        """Analyze HTTP response for SSL stripping indicators"""
        try:
            lines = payload.split('\r\n')
            status_line = lines[0] if lines else ""
            
            # Parse status line
            if status_line.startswith('HTTP/'):
                parts = status_line.split()
                if len(parts) >= 2:
                    status_code = parts[1]
                    
                    # Extract headers
                    headers = {}
                    body_start = False
                    body = ""
                    
                    for line in lines[1:]:
                        if not line.strip() and not body_start:
                            body_start = True
                            continue
                        
                        if body_start:
                            body += line + "\n"
                        elif ':' in line:
                            key, value = line.split(':', 1)
                            headers[key.strip().lower()] = value.strip()
                    
                    # Check for redirect patterns
                    self._check_redirect_patterns(status_code, headers, body, session_key, src_ip, dst_ip)
                    
                    # Check for SSL downgrade patterns
                    self._check_ssl_downgrade_patterns(headers, body, session_key, src_ip, dst_ip)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing HTTP response: {e}")
    
    def _check_ssl_strip_patterns(self, method: str, url: str, headers: Dict, session_key: str, src_ip: str, dst_ip: str):
        """Check for SSL stripping patterns in HTTP requests"""
        try:
            # Check for HTTPS URLs being requested over HTTP
            if 'https://' in url:
                self._generate_alert("https_over_http", {
                    "session_key": session_key,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "url": url,
                    "method": method,
                    "severity": "high",
                    "description": "HTTPS URL requested over HTTP connection"
                })
            
            # Check for sensitive form data over HTTP
            host = headers.get('host', '')
            if self._is_sensitive_site(host):
                if method == 'POST':
                    self._generate_alert("sensitive_post_over_http", {
                        "session_key": session_key,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "host": host,
                        "url": url,
                        "severity": "critical",
                        "description": f"Sensitive POST data to {host} over HTTP"
                    })
            
            # Check for suspicious referer headers
            referer = headers.get('referer', '')
            if referer.startswith('https://') and not url.startswith('https://'):
                self._generate_alert("https_to_http_transition", {
                    "session_key": session_key,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "referer": referer,
                    "url": url,
                    "severity": "medium",
                    "description": "Transition from HTTPS to HTTP detected"
                })
                
        except Exception as e:
            self.logger.error(f"Error checking SSL strip patterns: {e}")
    
    def _check_redirect_patterns(self, status_code: str, headers: Dict, body: str, session_key: str, src_ip: str, dst_ip: str):
        """Check for suspicious redirect patterns"""
        try:
            # Check for HTTPS to HTTP redirects
            if status_code in ['301', '302', '303', '307', '308']:
                location = headers.get('location', '')
                
                if location:
                    # Check if redirect is from HTTPS to HTTP
                    if session_key in self.https_sessions:
                        original_session = self.https_sessions[session_key]
                        if location.startswith('http://') and not location.startswith('https://'):
                            self._generate_alert("https_to_http_redirect", {
                                "session_key": session_key,
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "redirect_location": location,
                                "status_code": status_code,
                                "severity": "high",
                                "description": "Redirect from HTTPS to HTTP detected"
                            })
            
            # Check for modified HTTPS links in HTML content
            if 'content-type' in headers and 'text/html' in headers['content-type']:
                self._check_html_modifications(body, session_key, src_ip, dst_ip)
                
        except Exception as e:
            self.logger.error(f"Error checking redirect patterns: {e}")
    
    def _check_ssl_downgrade_patterns(self, headers: Dict, body: str, session_key: str, src_ip: str, dst_ip: str):
        """Check for SSL downgrade attack patterns"""
        try:
            # Check for missing security headers that should be present
            security_headers = [
                'strict-transport-security',
                'content-security-policy',
                'x-content-type-options',
                'x-frame-options'
            ]
            
            missing_headers = []
            for header in security_headers:
                if header not in headers:
                    missing_headers.append(header)
            
            if missing_headers:
                self._generate_alert("missing_security_headers", {
                    "session_key": session_key,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "missing_headers": missing_headers,
                    "severity": "medium",
                    "description": f"Missing security headers: {', '.join(missing_headers)}"
                })
            
            # Check for HSTS bypass attempts
            hsts_header = headers.get('strict-transport-security', '')
            if hsts_header and 'max-age=0' in hsts_header:
                self._generate_alert("hsts_bypass_attempt", {
                    "session_key": session_key,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "hsts_header": hsts_header,
                    "severity": "high",
                    "description": "HSTS bypass attempt detected (max-age=0)"
                })
                
        except Exception as e:
            self.logger.error(f"Error checking SSL downgrade patterns: {e}")
    
    def _check_html_modifications(self, html_content: str, session_key: str, src_ip: str, dst_ip: str):
        """Check for modified HTTPS links in HTML content"""
        try:
            # Look for suspicious JavaScript that might be modifying links
            suspicious_js_patterns = [
                r'location\.protocol\s*=\s*["\']http:',
                r'window\.location\s*=\s*["\']http:',
                r'href\s*=\s*["\']http://.*["\']',
                r'action\s*=\s*["\']http://.*["\']',
                r'replace\(["\']https:["\'],\s*["\']http:["\']',
            ]
            
            for pattern in suspicious_js_patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    self._generate_alert("suspicious_link_modification", {
                        "session_key": session_key,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "pattern_matched": pattern,
                        "severity": "high",
                        "description": "Suspicious JavaScript modifying HTTPS links detected"
                    })
                    break
                    
        except Exception as e:
            self.logger.error(f"Error checking HTML modifications: {e}")
    
    def _analyze_https_traffic(self, packet, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        """Analyze HTTPS traffic patterns"""
        try:
            session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            
            # Track HTTPS sessions
            self.https_sessions[session_key] = {
                "timestamp": datetime.now(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing HTTPS traffic: {e}")
    
    def _analyze_ssl_handshake(self, packet, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        """Analyze SSL/TLS handshake for anomalies"""
        try:
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load
                
                # Check for TLS handshake patterns
                if len(payload) > 5:
                    # TLS record header: Content Type (1 byte) + Version (2 bytes) + Length (2 bytes)
                    content_type = payload[0]
                    
                    # Handshake protocol (content type 22)
                    if content_type == 0x16:
                        # Check TLS version
                        tls_version = (payload[1] << 8) | payload[2]
                        
                        # Detect downgrade attacks (forcing older TLS versions)
                        if tls_version < 0x0303:  # Less than TLS 1.2
                            self._generate_alert("tls_downgrade_attempt", {
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "tls_version": hex(tls_version),
                                "severity": "medium",
                                "description": f"TLS downgrade detected: version {hex(tls_version)}"
                            })
                            
        except Exception as e:
            self.logger.error(f"Error analyzing SSL handshake: {e}")
    
    def _is_sensitive_site(self, hostname: str) -> bool:
        """Check if hostname belongs to a sensitive site"""
        sensitive_keywords = [
            'bank', 'login', 'auth', 'secure', 'payment', 'paypal',
            'credit', 'account', 'admin', 'portal', 'mail', 'webmail'
        ]
        
        hostname_lower = hostname.lower()
        return any(keyword in hostname_lower for keyword in sensitive_keywords)
    
    def _generate_alert(self, alert_type: str, details: Dict):
        """Generate security alert"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "detector": "ssl_strip",
            "alert_type": alert_type,
            "details": details
        }
        
        self.logger.warning(f"SSL Strip Alert: {alert}")
        return alert
    
    def start_monitoring(self):
        """Start SSL stripping detection"""
        if self.is_running:
            return
            
        self.is_running = True
        self.logger.info("Starting SSL stripping detection")
        
        def monitor():
            try:
                scapy.sniff(
                    iface=self.interface,
                    filter="tcp port 80 or tcp port 443",
                    prn=self.detect_ssl_strip,
                    stop_filter=lambda x: not self.is_running
                )
            except Exception as e:
                self.logger.error(f"Error in SSL strip monitoring: {e}")
        
        self.monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop SSL stripping detection"""
        self.is_running = False
        self.logger.info("Stopping SSL stripping detection")