import scapy.all as scapy
import threading
import time
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional

class ARPSpoofDetector:
    """ARP Spoofing Attack Detector"""
    
    def __init__(self, interface: str = None, threshold: int = 10, time_window: int = 60):
        self.interface = interface
        self.threshold = threshold  # Max ARP requests per IP in time window
        self.time_window = time_window  # Time window in seconds
        self.arp_table = {}  # IP -> MAC mapping
        self.arp_requests = defaultdict(list)  # IP -> list of timestamps
        self.suspicious_ips = set()
        self.is_running = False
        self.logger = logging.getLogger(__name__)
        
    def get_mac_address(self, ip: str) -> Optional[str]:
        """Get MAC address for given IP using ARP request"""
        try:
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            if answered_list:
                return answered_list[0][1].hwsrc
            return None
        except Exception as e:
            self.logger.error(f"Error getting MAC for {ip}: {e}")
            return None
    
    def detect_arp_spoof(self, packet):
        """Analyze ARP packet for spoofing indicators"""
        try:
            if packet.haslayer(scapy.ARP):
                arp_layer = packet[scapy.ARP]
                src_ip = arp_layer.psrc
                src_mac = arp_layer.hwsrc
                dst_ip = arp_layer.pdst
                op_code = arp_layer.op
                
                current_time = datetime.now()
                
                # Track ARP request frequency
                if op_code == 1:  # ARP Request
                    self.arp_requests[src_ip].append(current_time)
                    
                    # Remove old requests outside time window
                    cutoff_time = current_time - timedelta(seconds=self.time_window)
                    self.arp_requests[src_ip] = [
                        req_time for req_time in self.arp_requests[src_ip] 
                        if req_time > cutoff_time
                    ]
                    
                    # Check if requests exceed threshold
                    if len(self.arp_requests[src_ip]) > self.threshold:
                        self.suspicious_ips.add(src_ip)
                        self._generate_alert("high_arp_frequency", {
                            "source_ip": src_ip,
                            "source_mac": src_mac,
                            "request_count": len(self.arp_requests[src_ip]),
                            "time_window": self.time_window,
                            "severity": "medium"
                        })
                
                # Track ARP responses for MAC conflicts
                elif op_code == 2:  # ARP Reply
                    if src_ip in self.arp_table:
                        stored_mac = self.arp_table[src_ip]
                        if stored_mac != src_mac:
                            # Potential ARP spoofing detected
                            self._generate_alert("arp_spoofing", {
                                "source_ip": src_ip,
                                "original_mac": stored_mac,
                                "spoofed_mac": src_mac,
                                "target_ip": dst_ip,
                                "severity": "high",
                                "description": "MAC address conflict detected - possible ARP spoofing"
                            })
                    else:
                        self.arp_table[src_ip] = src_mac
                
                # Detect gratuitous ARP (potential spoofing)
                if op_code == 2 and src_ip == dst_ip:
                    self._generate_alert("gratuitous_arp", {
                        "source_ip": src_ip,
                        "source_mac": src_mac,
                        "severity": "medium",
                        "description": "Gratuitous ARP detected - possible network reconnaissance"
                    })
                    
        except Exception as e:
            self.logger.error(f"Error in ARP spoof detection: {e}")
    
    def _generate_alert(self, alert_type: str, details: Dict):
        """Generate security alert"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "detector": "arp_spoof",
            "alert_type": alert_type,
            "details": details
        }
        
        self.logger.warning(f"ARP Spoofing Alert: {alert}")
        # Here you would typically send to alert management system
        return alert
    
    def start_monitoring(self):
        """Start ARP spoofing detection"""
        if self.is_running:
            return
            
        self.is_running = True
        self.logger.info("Starting ARP spoofing detection")
        
        def monitor():
            try:
                scapy.sniff(
                    iface=self.interface,
                    filter="arp",
                    prn=self.detect_arp_spoof,
                    stop_filter=lambda x: not self.is_running
                )
            except Exception as e:
                self.logger.error(f"Error in ARP monitoring: {e}")
        
        self.monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop ARP spoofing detection"""
        self.is_running = False
        self.logger.info("Stopping ARP spoofing detection")