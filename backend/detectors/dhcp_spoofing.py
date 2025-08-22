import scapy.all as scapy
import threading
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Set, List

class DHCPSpoofingDetector:
    """DHCP Spoofing Attack Detector"""
    
    def __init__(self, interface: str = None, authorized_servers: List[str] = None):
        self.interface = interface
        self.authorized_servers = set(authorized_servers) if authorized_servers else set()
        self.dhcp_servers = {}  # MAC -> IP mapping of detected DHCP servers
        self.dhcp_offers = defaultdict(list)  # Track DHCP offers
        self.is_running = False
        self.logger = logging.getLogger(__name__)
    
    def detect_dhcp_spoofing(self, packet):
        """Analyze DHCP packets for spoofing indicators"""
        try:
            if packet.haslayer(scapy.DHCP):
                dhcp_layer = packet[scapy.DHCP]
                
                # Extract DHCP options
                dhcp_options = {}
                for option in dhcp_layer.options:
                    if isinstance(option, tuple) and len(option) == 2:
                        dhcp_options[option[0]] = option[1]
                
                message_type = dhcp_options.get('message-type')
                server_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else None
                server_mac = packet[scapy.Ether].src if packet.haslayer(scapy.Ether) else None
                
                # DHCP Offer Analysis
                if message_type == 2:  # DHCP Offer
                    self._analyze_dhcp_offer(packet, server_ip, server_mac, dhcp_options)
                
                # DHCP ACK Analysis
                elif message_type == 5:  # DHCP ACK
                    self._analyze_dhcp_ack(packet, server_ip, server_mac, dhcp_options)
                
                # Track all DHCP servers
                if server_ip and server_mac and message_type in [2, 5]:
                    if server_mac in self.dhcp_servers:
                        if self.dhcp_servers[server_mac] != server_ip:
                            self._generate_alert("dhcp_server_ip_change", {
                                "server_mac": server_mac,
                                "old_ip": self.dhcp_servers[server_mac],
                                "new_ip": server_ip,
                                "severity": "medium"
                            })
                    else:
                        self.dhcp_servers[server_mac] = server_ip
                        
                        # Check if this is an unauthorized server
                        if self.authorized_servers and server_ip not in self.authorized_servers:
                            self._generate_alert("unauthorized_dhcp_server", {
                                "server_ip": server_ip,
                                "server_mac": server_mac,
                                "severity": "high",
                                "description": "Unauthorized DHCP server detected"
                            })
                
        except Exception as e:
            self.logger.error(f"Error in DHCP spoof detection: {e}")
    
    def _analyze_dhcp_offer(self, packet, server_ip: str, server_mac: str, options: Dict):
        """Analyze DHCP Offer packet"""
        try:
            offered_ip = packet[scapy.BOOTP].yiaddr
            subnet_mask = options.get('subnet_mask')
            router = options.get('router')
            dns_servers = options.get('name_server')
            
            offer_info = {
                "timestamp": datetime.now(),
                "server_ip": server_ip,
                "server_mac": server_mac,
                "offered_ip": offered_ip,
                "subnet_mask": subnet_mask,
                "router": router,
                "dns_servers": dns_servers
            }
            
            # Track multiple offers for same client
            client_mac = packet[scapy.Ether].dst
            self.dhcp_offers[client_mac].append(offer_info)
            
            # Clean old offers (older than 5 minutes)
            cutoff_time = datetime.now() - timedelta(minutes=5)
            self.dhcp_offers[client_mac] = [
                offer for offer in self.dhcp_offers[client_mac] 
                if offer["timestamp"] > cutoff_time
            ]
            
            # Detect multiple DHCP servers offering to same client
            unique_servers = set()
            for offer in self.dhcp_offers[client_mac]:
                unique_servers.add(offer["server_mac"])
            
            if len(unique_servers) > 1:
                self._generate_alert("multiple_dhcp_offers", {
                    "client_mac": client_mac,
                    "server_count": len(unique_servers),
                    "servers": list(unique_servers),
                    "severity": "high",
                    "description": "Multiple DHCP servers responding to same client"
                })
            
            # Detect suspicious network configurations
            self._detect_suspicious_config(offer_info)
            
        except Exception as e:
            self.logger.error(f"Error analyzing DHCP offer: {e}")
    
    def _analyze_dhcp_ack(self, packet, server_ip: str, server_mac: str, options: Dict):
        """Analyze DHCP ACK packet"""
        try:
            assigned_ip = packet[scapy.BOOTP].yiaddr
            client_mac = packet[scapy.Ether].dst
            
            # Log successful DHCP assignment
            self.logger.info(f"DHCP assignment: {assigned_ip} -> {client_mac} via {server_ip}")
            
        except Exception as e:
            self.logger.error(f"Error analyzing DHCP ACK: {e}")
    
    def _detect_suspicious_config(self, offer_info: Dict):
        """Detect suspicious DHCP configurations"""
        try:
            # Check for suspicious DNS servers
            dns_servers = offer_info.get("dns_servers")
            if dns_servers:
                # Common malicious DNS servers or unusual configurations
                suspicious_dns = ["8.8.4.4", "1.1.1.1"]  # Example - customize based on environment
                
            # Check for suspicious default gateway
            router = offer_info.get("router")
            if router and router != offer_info.get("server_ip"):
                # Different router and DHCP server might indicate spoofing
                pass
            
            # Check for private IP ranges being offered from external servers
            offered_ip = offer_info.get("offered_ip", "")
            if (offered_ip.startswith("192.168.") or 
                offered_ip.startswith("10.") or 
                offered_ip.startswith("172.")):
                server_ip = offer_info.get("server_ip", "")
                if not (server_ip.startswith("192.168.") or 
                       server_ip.startswith("10.") or 
                       server_ip.startswith("172.")):
                    self._generate_alert("suspicious_ip_range", {
                        "server_ip": server_ip,
                        "offered_ip": offered_ip,
                        "severity": "medium",
                        "description": "External server offering private IP range"
                    })
                    
        except Exception as e:
            self.logger.error(f"Error detecting suspicious config: {e}")
    
    def _generate_alert(self, alert_type: str, details: Dict):
        """Generate security alert"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "detector": "dhcp_spoofing",
            "alert_type": alert_type,
            "details": details
        }
        
        self.logger.warning(f"DHCP Spoofing Alert: {alert}")
        return alert
    
    def start_monitoring(self):
        """Start DHCP spoofing detection"""
        if self.is_running:
            return
            
        self.is_running = True
        self.logger.info("Starting DHCP spoofing detection")
        
        def monitor():
            try:
                scapy.sniff(
                    iface=self.interface,
                    filter="udp port 67 or udp port 68",
                    prn=self.detect_dhcp_spoofing,
                    stop_filter=lambda x: not self.is_running
                )
            except Exception as e:
                self.logger.error(f"Error in DHCP monitoring: {e}")
        
        self.monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop DHCP spoofing detection"""
        self.is_running = False
        self.logger.info("Stopping DHCP spoofing detection")
