import scapy.all as scapy
import threading
import logging
import socket
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Set

class DNSSpoofDetector:
    """DNS Spoofing Attack Detector"""
    
    def __init__(self, interface: str = None, trusted_dns_servers: List[str] = None):
        self.interface = interface
        self.trusted_dns_servers = set(trusted_dns_servers) if trusted_dns_servers else set()
        self.dns_cache = {}  # Domain -> IP mapping
        self.dns_responses = defaultdict(list)  # Track multiple responses
        self.suspicious_domains = set()
        self.is_running = False
        self.logger = logging.getLogger(__name__)
        
        # Common legitimate DNS servers
        self.known_dns_servers = {
            "8.8.8.8", "8.8.4.4",  # Google
            "1.1.1.1", "1.0.0.1",  # Cloudflare
            "208.67.222.222", "208.67.220.220",  # OpenDNS
            "9.9.9.9", "149.112.112.112"  # Quad9
        }
    
    def detect_dns_spoof(self, packet):
        """Analyze DNS packets for spoofing indicators"""
        try:
            if packet.haslayer(scapy.DNS):
                dns_layer = packet[scapy.DNS]
                
                # Only analyze DNS responses
                if dns_layer.qr == 1:  # DNS Response
                    self._analyze_dns_response(packet)
                    
        except Exception as e:
            self.logger.error(f"Error in DNS spoof detection: {e}")
    
    def _analyze_dns_response(self, packet):
        """Analyze DNS response for spoofing indicators"""
        try:
            dns_layer = packet[scapy.DNS]
            src_ip = packet[scapy.IP].src
            
            # Extract query information
            if dns_layer.qd:
                query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                query_type = dns_layer.qd.qtype
                
                # Extract answer information
                answers = []
                if dns_layer.an:
                    for i in range(dns_layer.ancount):
                        if i < len(dns_layer.an):
                            answer = dns_layer.an[i]
                            if hasattr(answer, 'rdata'):
                                answers.append(str(answer.rdata))
                
                response_info = {
                    "timestamp": datetime.now(),
                    "server_ip": src_ip,
                    "query_name": query_name,
                    "query_type": query_type,
                    "answers": answers,
                    "transaction_id": dns_layer.id
                }
                
                # Track responses for the same query
                query_key = f"{query_name}:{query_type}"
                self.dns_responses[query_key].append(response_info)
                
                # Clean old responses (older than 1 minute)
                cutoff_time = datetime.now() - timedelta(minutes=1)
                self.dns_responses[query_key] = [
                    resp for resp in self.dns_responses[query_key]
                    if resp["timestamp"] > cutoff_time
                ]
                
                # Detect multiple conflicting responses
                self._detect_conflicting_responses(query_key)
                
                # Detect responses from unauthorized servers
                self._detect_unauthorized_server(response_info)
                
                # Detect suspicious domain resolutions
                self._detect_suspicious_resolutions(response_info)
                
                # Check for DNS cache poisoning indicators
                self._detect_cache_poisoning(response_info)
                
        except Exception as e:
            self.logger.error(f"Error analyzing DNS response: {e}")
    
    def _detect_conflicting_responses(self, query_key: str):
        """Detect conflicting DNS responses for same query"""
        try:
            responses = self.dns_responses[query_key]
            if len(responses) < 2:
                return
            
            # Group responses by server
            servers_responses = defaultdict(list)
            for response in responses:
                servers_responses[response["server_ip"]].append(response)
            
            # Check for different answers from different servers
            unique_answers = set()
            servers_with_answers = {}
            
            for server_ip, server_responses in servers_responses.items():
                for response in server_responses:
                    answer_key = tuple(sorted(response["answers"]))
                    unique_answers.add(answer_key)
                    servers_with_answers[server_ip] = answer_key
            
            # Alert if different servers give different answers
            if len(unique_answers) > 1:
                self._generate_alert("conflicting_dns_responses", {
                    "query": query_key,
                    "servers_count": len(servers_with_answers),
                    "unique_answers_count": len(unique_answers),
                    "servers_responses": dict(servers_with_answers),
                    "severity": "high",
                    "description": "Multiple DNS servers giving different answers for same query"
                })
                
        except Exception as e:
            self.logger.error(f"Error detecting conflicting responses: {e}")
    
    def _detect_unauthorized_server(self, response_info: Dict):
        """Detect responses from unauthorized DNS servers"""
        try:
            server_ip = response_info["server_ip"]
            
            # Skip if no trusted servers configured
            if not self.trusted_dns_servers:
                return
            
            # Check if response is from untrusted server
            if (server_ip not in self.trusted_dns_servers and 
                server_ip not in self.known_dns_servers):
                
                self._generate_alert("unauthorized_dns_server", {
                    "server_ip": server_ip,
                    "query_name": response_info["query_name"],
                    "answers": response_info["answers"],
                    "severity": "medium",
                    "description": f"DNS response from unauthorized server: {server_ip}"
                })
                
        except Exception as e:
            self.logger.error(f"Error detecting unauthorized server: {e}")
    
    def _detect_suspicious_resolutions(self, response_info: Dict):
        """Detect suspicious domain resolutions"""
        try:
            query_name = response_info["query_name"]
            answers = response_info["answers"]
            
            # Check for suspicious patterns
            suspicious_patterns = [
                # Legitimate domains resolving to private IPs
                lambda domain, ips: (
                    any(domain.endswith(tld) for tld in ['.com', '.org', '.net', '.gov']) and
                    any(ip.startswith(('192.168.', '10.', '172.')) for ip in ips)
                ),
                # Popular domains resolving to unusual IPs
                lambda domain, ips: (
                    any(popular in domain for popular in ['google', 'facebook', 'microsoft', 'apple']) and
                    not any(self._is_legitimate_ip_for_domain(domain, ip) for ip in ips)
                )
            ]
            
            for pattern in suspicious_patterns:
                if pattern(query_name, answers):
                    self._generate_alert("suspicious_dns_resolution", {
                        "query_name": query_name,
                        "answers": answers,
                        "server_ip": response_info["server_ip"],
                        "severity": "medium",
                        "description": f"Suspicious DNS resolution for {query_name}"
                    })
                    break
                    
        except Exception as e:
            self.logger.error(f"Error detecting suspicious resolutions: {e}")
    
    def _detect_cache_poisoning(self, response_info: Dict):
        """Detect DNS cache poisoning attempts"""
        try:
            query_name = response_info["query_name"]
            transaction_id = response_info["transaction_id"]
            
            # Check for duplicate transaction IDs (potential poisoning)
            if hasattr(self, 'recent_transaction_ids'):
                if transaction_id in self.recent_transaction_ids:
                    self._generate_alert("duplicate_transaction_id", {
                        "transaction_id": transaction_id,
                        "query_name": query_name,
                        "server_ip": response_info["server_ip"],
                        "severity": "high",
                        "description": "Duplicate DNS transaction ID detected - possible cache poisoning"
                    })
            else:
                self.recent_transaction_ids = set()
            
            self.recent_transaction_ids.add(transaction_id)
            
            # Keep only recent transaction IDs (last 1000)
            if len(self.recent_transaction_ids) > 1000:
                self.recent_transaction_ids = set(list(self.recent_transaction_ids)[-500:])
                
        except Exception as e:
            self.logger.error(f"Error detecting cache poisoning: {e}")
    
    def _is_legitimate_ip_for_domain(self, domain: str, ip: str) -> bool:
        """Check if IP is legitimate for given domain (simplified check)"""
        try:
            # This is a simplified check - in production, you'd want more sophisticated validation
            # For example, checking against known IP ranges for major services
            return True  # Placeholder
        except Exception:
            return False
    
    def _generate_alert(self, alert_type: str, details: Dict):
        """Generate security alert"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "detector": "dns_spoof",
            "alert_type": alert_type,
            "details": details
        }
        
        self.logger.warning(f"DNS Spoofing Alert: {alert}")
        return alert
    
    def start_monitoring(self):
        """Start DNS spoofing detection"""
        if self.is_running:
            return
            
        self.is_running = True
        self.logger.info("Starting DNS spoofing detection")
        
        def monitor():
            try:
                scapy.sniff(
                    iface=self.interface,
                    filter="udp port 53",
                    prn=self.detect_dns_spoof,
                    stop_filter=lambda x: not self.is_running
                )
            except Exception as e:
                self.logger.error(f"Error in DNS monitoring: {e}")
        
        self.monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop DNS spoofing detection"""
        self.is_running = False
        self.logger.info("Stopping DNS spoofing detection")