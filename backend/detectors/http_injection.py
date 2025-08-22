import scapy.all as scapy
import threading
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Set
from urllib.parse import unquote

class HTTPInjectionDetector:
    """HTTP Injection Attack Detector"""
    
    def __init__(self, interface: str = None):
        self.interface = interface
        self.http_sessions = defaultdict(dict)  # Track HTTP sessions
        self.injection_patterns = self._load_injection_patterns()
        self.is_running = False
        self.logger = logging.getLogger(__name__)
    
    def _load_injection_patterns(self) -> Dict[str, List[str]]:
        """Load patterns for different injection attacks"""
        return {
            "sql_injection": [
                r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
                r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
                r"(\%27)|(\')|(\")|(\%22)",
                r"union.*select",
                r"insert.*into",
                r"delete.*from",
                r"drop.*table",
                r"exec(\s|\+)+(s|x)p\w+",
                r"or\s+1\s*=\s*1",
                r"and\s+1\s*=\s*1",
                r"having\s+1\s*=\s*1"
            ],
            "xss_injection": [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"vbscript:",
                r"onload\s*=",
                r"onerror\s*=",
                r"onclick\s*=",
                r"onmouseover\s*=",
                r"<iframe[^>]*>",
                r"<object[^>]*>",
                r"<embed[^>]*>",
                r"<applet[^>]*>",
                r"<meta[^>]*>",
                r"<img[^>]*onerror[^>]*>",
                r"eval\s*\(",
                r"setTimeout\s*\(",
                r"setInterval\s*\("
            ],
            "command_injection": [
                r"[;&|`]\s*(ls|dir|cat|type|more|less)",
                r"[;&|`]\s*(rm|del|mv|copy|cp)",
                r"[;&|`]\s*(nc|netcat|telnet|ssh)",
                r"[;&|`]\s*(wget|curl|fetch)",
                r"[;&|`]\s*(ps|top|kill|killall)",
                r"[;&|`]\s*(id|whoami|groups)",
                r"\$\(.*\)",
                r"`.*`",
                r"\|\s*(nc|netcat|sh|bash|cmd)",
                r"&&\s*(wget|curl)"
            ],
            "ldap_injection": [
                r"\*\)\(.*=",
                r"\)\(\|.*=",
                r"\)\(&.*=",
                r"\*\)\(.*\|\(",
                r"\*\)\(.*&\("
            ],
            "xpath_injection": [
                r"(\x27|\')(\s)*(or|and)(\s)*(\x27|\')(\s)*=(\s)*(\x27|\')",
                r"(\x22|\")(\s)*(or|and)(\s)*(\x22|\")(\s)*=(\s)*(\x22|\")",
                r"or\s+1\s*=\s*1",
                r"and\s+1\s*=\s*1"
            ]
        }
    
    def detect_http_injection(self, packet):
        """Analyze HTTP packets for injection attacks"""
        try:
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "unknown"
                dst_ip = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "unknown"
                
                # Check if this is an HTTP request
                if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                    self._analyze_http_request(payload, src_ip, dst_ip)
                # Check if this is an HTTP response
                elif payload.startswith('HTTP/'):
                    self._analyze_http_response(payload, src_ip, dst_ip)
                    
        except Exception as e:
            self.logger.error(f"Error in HTTP injection detection: {e}")
    
    def _analyze_http_request(self, payload: str, src_ip: str, dst_ip: str):
        """Analyze HTTP request for injection patterns"""
        try:
            lines = payload.split('\r\n')
            request_line = lines[0] if lines else ""
            headers = {}
            body = ""
            
            # Parse headers and body
            in_body = False
            for line in lines[1:]:
                if not line.strip() and not in_body:
                    in_body = True
                    continue
                
                if in_body:
                    body += line + "\n"
                else:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()
            
            # Extract HTTP method, URL, and parameters
            parts = request_line.split()
            if len(parts) >= 2:
                method = parts[0]
                url = parts[1]
                
                # URL decode for analysis
                decoded_url = unquote(url)
                decoded_body = unquote(body)
                
                # Check for injection patterns in URL
                self._check_injection_patterns(decoded_url, "url", src_ip, dst_ip, method)
                
                # Check for injection patterns in body (POST data)
                if body:
                    self._check_injection_patterns(decoded_body, "body", src_ip, dst_ip, method)
                
                # Check specific headers for injection
                for header_name, header_value in headers.items():
                    if header_name in ['user-agent', 'referer', 'cookie', 'x-forwarded-for']:
                        decoded_header = unquote(header_value)
                        self._check_injection_patterns(decoded_header, f"header_{header_name}", src_ip, dst_ip, method)
                
                # Detect suspicious patterns in request
                self._detect_suspicious_request_patterns(method, decoded_url, headers, decoded_body, src_ip, dst_ip)
                
        except Exception as e:
            self.logger.error(f"Error analyzing HTTP request: {e}")
    
    def _analyze_http_response(self, payload: str, src_ip: str, dst_ip: str):
        """Analyze HTTP response for injection indicators"""
        try:
            lines = payload.split('\r\n')
            status_line = lines[0] if lines else ""
            
            # Check for SQL error messages in response
            sql_error_patterns = [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"PostgreSQL.*ERROR",
                r"Warning.*pg_.*",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"Driver.*SQL.*Server",
                r"OLE DB.*SQL Server",
                r"(\[SQL Server\])",
                r"ODBC.*SQL Server",
                r"SQLServer JDBC Driver",
                r"SqlException",
                r"Oracle error",
                r"Oracle.*Driver",
                r"Warning.*oci_.*",
                r"Warning.*ora_.*"
            ]
            
            for pattern in sql_error_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    self._generate_alert("sql_error_disclosure", {
                        "source_ip": dst_ip,  # Server IP
                        "target_ip": src_ip,  # Client IP
                        "pattern_matched": pattern,
                        "severity": "medium",
                        "description": "SQL error message detected in HTTP response"
                    })
                    break
                    
        except Exception as e:
            self.logger.error(f"Error analyzing HTTP response: {e}")
    
    def _check_injection_patterns(self, content: str, location: str, src_ip: str, dst_ip: str, method: str):
        """Check content against injection patterns"""
        try:
            for injection_type, patterns in self.injection_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self._generate_alert("injection_attempt", {
                            "injection_type": injection_type,
                            "source_ip": src_ip,
                            "target_ip": dst_ip,
                            "http_method": method,
                            "location": location,
                            "pattern_matched": pattern,
                            "content_sample": content[:200],
                            "severity": self._get_severity_by_type(injection_type),
                            "description": f"{injection_type.replace('_', ' ').title()} attempt detected in {location}"
                        })
                        return  # Stop after first match to avoid spam
                        
        except Exception as e:
            self.logger.error(f"Error checking injection patterns: {e}")
    
    def _detect_suspicious_request_patterns(self, method: str, url: str, headers: Dict, body: str, src_ip: str, dst_ip: str):
        """Detect suspicious HTTP request patterns"""
        try:
            # Detect directory traversal attempts
            traversal_patterns = [
                r"\.\.[\\/]",
                r"%2e%2e[\\/]",
                r"\.\.%2f",
                r"\.\.%5c",
                r"%252e%252e",
                r"..%c0%af",
                r"..%c1%9c"
            ]
            
            for pattern in traversal_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    self._generate_alert("directory_traversal", {
                        "source_ip": src_ip,
                        "target_ip": dst_ip,
                        "http_method": method,
                        "url": url,
                        "pattern_matched": pattern,
                        "severity": "high",
                        "description": "Directory traversal attempt detected"
                    })
                    break
            
            # Detect file inclusion attempts
            file_inclusion_patterns = [
                r"(file|php|data)://",
                r"expect://",
                r"zip://",
                r"include\s*\(",
                r"require\s*\(",
                r"include_once\s*\(",
                r"require_once\s*\("
            ]
            
            content_to_check = url + " " + body
            for pattern in file_inclusion_patterns:
                if re.search(pattern, content_to_check, re.IGNORECASE):
                    self._generate_alert("file_inclusion", {
                        "source_ip": src_ip,
                        "target_ip": dst_ip,
                        "http_method": method,
                        "url": url,
                        "pattern_matched": pattern,
                        "severity": "high",
                        "description": "File inclusion attempt detected"
                    })
                    break
            
            # Detect excessive parameter pollution
            if '&' in url:
                param_count = url.count('&') + 1
                if param_count > 50:  # Threshold for suspicious parameter count
                    self._generate_alert("parameter_pollution", {
                        "source_ip": src_ip,
                        "target_ip": dst_ip,
                        "http_method": method,
                        "parameter_count": param_count,
                        "severity": "medium",
                        "description": f"Excessive parameters detected: {param_count}"
                    })
            
            # Detect suspicious user agents
            user_agent = headers.get('user-agent', '').lower()
            suspicious_ua_patterns = [
                r"sqlmap",
                r"havij",
                r"nmap",
                r"nikto",
                r"w3af",
                r"acunetix",
                r"netsparker",
                r"burp",
                r"paros",
                r"webscarab",
                r"python-requests",
                r"curl",
                r"wget"
            ]
            
            for pattern in suspicious_ua_patterns:
                if re.search(pattern, user_agent):
                    self._generate_alert("suspicious_user_agent", {
                        "source_ip": src_ip,
                        "target_ip": dst_ip,
                        "user_agent": user_agent,
                        "pattern_matched": pattern,
                        "severity": "medium",
                        "description": "Suspicious User-Agent detected"
                    })
                    break
                    
        except Exception as e:
            self.logger.error(f"Error detecting suspicious patterns: {e}")
    
    def _get_severity_by_type(self, injection_type: str) -> str:
        """Get severity level based on injection type"""
        severity_map = {
            "sql_injection": "high",
            "xss_injection": "high", 
            "command_injection": "critical",
            "ldap_injection": "high",
            "xpath_injection": "high"
        }
        return severity_map.get(injection_type, "medium")
    
    def _generate_alert(self, alert_type: str, details: Dict):
        """Generate security alert"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "detector": "http_injection",
            "alert_type": alert_type,
            "details": details
        }
        
        self.logger.warning(f"HTTP Injection Alert: {alert}")
        return alert
    
    def start_monitoring(self):
        """Start HTTP injection detection"""
        if self.is_running:
            return
            
        self.is_running = True
        self.logger.info("Starting HTTP injection detection")
        
        def monitor():
            try:
                scapy.sniff(
                    iface=self.interface,
                    filter="tcp port 80 or tcp port 8080 or tcp port 3000",
                    prn=self.detect_http_injection,
                    stop_filter=lambda x: not self.is_running
                )
            except Exception as e:
                self.logger.error(f"Error in HTTP monitoring: {e}")
        
        self.monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop HTTP injection detection"""
        self.is_running = False
        self.logger.info("Stopping HTTP injection detection")