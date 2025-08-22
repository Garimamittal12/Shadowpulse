import scapy.all as scapy
import threading
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Set, List

class ICMPRedirectDetector:
    """ICMP Redirect Attack Detector"""
    
    def __init__(self, interface: str = None, legitimate_gateways: List[str] = None):
        self.interface = interface
        self.legitimate_gateways = set(legitimate_gateways) if legitimate_gateways else set()
        self.redirect_sources = defaultdict(list)  # Track redirect sources
        self.routing_table = {}  # Track routing changes
        self.is_running = False
        self.logger = logging.getLogger(__name__)
    
    def detect_icmp_redirect(self, packet):
        """Analyze ICMP packets for redirect attacks"""
        try:
            if packet.haslayer(scapy.ICMP):
                icmp_layer = packet[scapy.ICMP]
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                
                # Check for ICMP Redirect messages (Type 5)
                if icmp_layer.type == 5:
                    self._analyze_icmp_redirect(packet, src_ip, dst_ip, icmp_layer)
                
                # Check for other suspicious ICMP types
                elif icmp_layer.type in [0, 8]:  # Echo Reply/Request
                    self._analyze_icmp_echo(packet, src_ip, dst_ip, icmp_layer)
                    
        except Exception as e:
            self.logger.error(f"Error in ICMP redirect detection: {e}")
    
    def _analyze_icmp_redirect(self, packet, src_ip: str, dst_ip: str, icmp_layer):
        """Analyze ICMP Redirect message"""
        try:
            # Extract redirect information
            redirect_code = icmp_layer.code
            
            # ICMP Redirect codes:
            # 0: Network Redirect
            # 1: Host Redirect  
            # 2: Type of Service and Network Redirect
            # 3: Type of Service and Host Redirect
            
            redirect_types = {
                0: "Network Redirect",
                1: "Host Redirect",
                2: "TOS Network Redirect", 
                3: "TOS Host Redirect"
            }
            
            redirect_type = redirect_types.get(redirect_code, "Unknown")
            
            # Extract gateway IP from ICMP redirect
            if hasattr(icmp_layer, 'gw'):
                new_gateway = icmp_layer.gw
            else:
                # Try to extract from payload
                if packet.haslayer(scapy.Raw):
                    payload = packet[scapy.Raw].load
                    if len(payload) >= 8:
                        # Gateway IP is typically at offset 4-7 in ICMP redirect
                        new_gateway = ".".join(str(b) for b in payload[4:8])
                    else:
                        new_gateway = "unknown"
                else:
                    new_gateway = "unknown"
            
            redirect_info = {
                "timestamp": datetime.now(),
                "source_ip": src_ip,
                "target_ip": dst_ip,
                "redirect_type": redirect_type,
                "redirect_code": redirect_code,
                "new_gateway": new_gateway
            }
            
            # Track redirect sources
            self.redirect_sources[src_ip].append(redirect_info)
            
            # Clean old redirects (older than 10 minutes)
            cutoff_time = datetime.now() - timedelta(minutes=10)
            self.redirect_sources[src_ip] = [
                redirect for redirect in self.redirect_sources[src_ip]
                if redirect["timestamp"] > cutoff_time
            ]
            
            # Check if redirect is from unauthorized source
            if self.legitimate_gateways and src_ip not in self.legitimate_gateways:
                self._generate_alert("unauthorized_icmp_redirect", {
                    "source_ip": src_ip,
                    "target_ip": dst_ip,
                    "redirect_type": redirect_type,
                    "new_gateway": new_gateway,
                    "severity": "high",
                    "description": f"ICMP redirect from unauthorized source: {src_ip}"
                })
            
            # Check for excessive redirects from same source
            if len(self.redirect_sources[src_ip]) > 10:
                self._generate_alert("excessive_icmp_redirects", {
                    "source_ip": src_ip,
                    "redirect_count": len(self.redirect_sources[src_ip]),
                    "time_window": "10 minutes",
                    "severity": "medium",
                    "description": f"Excessive ICMP redirects from {src_ip}"
                })
            
            # Check for suspicious gateway changes
            self._detect_suspicious_gateway_changes(redirect_info)
            
            # Log the redirect for analysis
            self.logger.info(f"ICMP Redirect: {src_ip} -> {dst_ip} via {new_gateway} ({redirect_type})")
            
        except Exception as e:
            self.logger.error(f"Error analyzing ICMP redirect: {e}")
    
    def _analyze_icmp_echo(self, packet, src_ip: str, dst_ip: str, icmp_layer):
        """Analyze ICMP Echo for reconnaissance detection"""
        try:
            # Detect potential network reconnaissance
            echo_type = "Echo Request" if icmp_layer.type == 8 else "Echo Reply"
            
            # Track echo patterns for potential scanning
            if not hasattr(self, 'echo_patterns'):
                self.echo_patterns = defaultdict(list)
            
            current_time = datetime.now()
            self.echo_patterns[src_ip].append({
                "timestamp": current_time,
                "target_ip": dst_ip,
                "echo_type": echo_type
            })
            
            # Clean old patterns (older than 5 minutes)
            cutoff_time = current_time - timedelta(minutes=5)
            self.echo_patterns[src_ip] = [
                echo for echo in self.echo_patterns[src_ip]
                if echo["timestamp"] > cutoff_time
            ]
            
            # Detect ping sweep (many targets from same source)
            if len(self.echo_patterns[src_ip]) > 20:
                unique_targets = set(echo["target_ip"] for echo in self.echo_patterns[src_ip])
                if len(unique_targets) > 10:
                    self._generate_alert("icmp_ping_sweep", {
                        "source_ip": src_ip,
                        "target_count": len(unique_targets),
                        "total_pings": len(self.echo_patterns[src_ip]),
                        "severity": "low",
                        "description": f"Potential ICMP ping sweep from {src_ip}"
                    })
                    
        except Exception as e:
            self.logger.error(f"Error analyzing ICMP echo: {e}")
    
    def _detect_suspicious_gateway_changes(self, redirect_info: Dict):
        """Detect suspicious gateway changes"""
        try:
            target_ip = redirect_info["target_ip"]
            new_gateway = redirect_info["new_gateway"]
            source_ip = redirect_info["source_ip"]
            
            # Check if this target had a different gateway before
            if target_ip in self.routing_table:
                old_gateway = self.routing_table[target_ip]
                if old_gateway != new_gateway:
                    self._generate_alert("gateway_change_detected", {
                        "target_ip": target_ip,
                        "old_gateway": old_gateway,
                        "new_gateway": new_gateway,
                        "redirect_source": source_ip,
                        "severity": "medium",
                        "description": f"Gateway changed for {target_ip}: {old_gateway} -> {new_gateway}"
                    })
            
            # Update routing table
            self.routing_table[target_ip] = new_gateway
            
            # Check for private IP ranges being redirected to external gateways
            if (target_ip.startswith(('192.168.', '10.', '172.')) and 
                not new_gateway.startswith(('192.168.', '10.', '172.'))):
                
                self._generate_alert("private_to_public_redirect", {
                    "target_ip": target_ip,
                    "new_gateway": new_gateway,
                    "redirect_source": source_ip,
                    "severity": "high",
                    "description": f"Private IP {target_ip} redirected to external gateway {new_gateway}"
                })
                
        except Exception as e:
            self.logger.error(f"Error detecting suspicious gateway changes: {e}")
    
    def _generate_alert(self, alert_type: str, details: Dict):
        """Generate security alert"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "detector": "icmp_redirect",
            "alert_type": alert_type,
            "details": details
        }
        
        self.logger.warning(f"ICMP Redirect Alert: {alert}")
        return alert
    
    def start_monitoring(self):
        """Start ICMP redirect detection"""
        if self.is_running:
            return
            
        self.is_running = True
        self.logger.info("Starting ICMP redirect detection")
        
        def monitor():
            try:
                scapy.sniff(
                    iface=self.interface,
                    filter="icmp",
                    prn=self.detect_icmp_redirect,
                    stop_filter=lambda x: not self.is_running
                )
            except Exception as e:
                self.logger.error(f"Error in ICMP monitoring: {e}")
        
        self.monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop ICMP redirect detection"""
        self.is_running = False
        self.logger.info("Stopping ICMP redirect detection")