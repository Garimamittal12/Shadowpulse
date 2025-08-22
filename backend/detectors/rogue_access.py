import scapy.all as scapy
import threading
import logging
import hashlib
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Set, List, Optional

class RogueAccessDetector:
    """Rogue Access Point Detector"""
    
    def __init__(self, interface: str = None, authorized_aps: List[Dict] = None):
        self.interface = interface
        self.authorized_aps = {}  # BSSID -> AP info mapping
        if authorized_aps:
            for ap in authorized_aps:
                self.authorized_aps[ap.get('bssid', '').lower()] = ap
        
        self.detected_aps = {}  # Track all detected APs
        self.suspicious_aps = set()
        self.beacon_frames = defaultdict(list)
        self.is_running = False
        self.logger = logging.getLogger(__name__)
    
    def detect_rogue_access(self, packet):
        """Analyze 802.11 packets for rogue access points"""
        try:
            # Check for 802.11 management frames
            if packet.haslayer(scapy.Dot11):
                self._analyze_802_11_frame(packet)
                
        except Exception as e:
            self.logger.error(f"Error in rogue access detection: {e}")
    
    def _analyze_802_11_frame(self, packet):
        """Analyze 802.11 management frames"""
        try:
            dot11_layer = packet[scapy.Dot11]
            
            # Check frame type and subtype
            frame_type = packet.type
            frame_subtype = packet.subtype
            
            # Management frames (type 0)
            if frame_type == 0:
                if frame_subtype == 8:  # Beacon frame
                    self._analyze_beacon_frame(packet)
                elif frame_subtype == 5:  # Probe response
                    self._analyze_probe_response(packet)
                elif frame_subtype == 4:  # Probe request
                    self._analyze_probe_request(packet)
                elif frame_subtype in [0, 2]:  # Association frames
                    self._analyze_association_frame(packet)
            
            # Data frames (type 2) - check for evil twin attacks
            elif frame_type == 2:
                self._analyze_data_frame(packet)
                
        except Exception as e:
            self.logger.error(f"Error analyzing 802.11 frame: {e}")
    
    def _analyze_beacon_frame(self, packet):
        """Analyze beacon frames for rogue APs"""
        try:
            dot11_layer = packet[scapy.Dot11]
            bssid = dot11_layer.addr3.lower() if dot11_layer.addr3 else "unknown"
            
            if packet.haslayer(scapy.Dot11Beacon):
                beacon = packet[scapy.Dot11Beacon]
                
                # Extract AP information
                ap_info = {
                    "bssid": bssid,
                    "timestamp": datetime.now(),
                    "beacon_interval": beacon.beacon_interval,
                    "capabilities": beacon.cap,
                    "channel": self._get_channel_from_packet(packet),
                    "rssi": self._get_signal_strength(packet),
                    "ssid": None,
                    "encryption": None,
                    "vendor": self._get_vendor_from_mac(bssid)
                }
                
                # Extract SSID and encryption info from information elements
                if packet.haslayer(scapy.Dot11Elt):
                    self._parse_information_elements(packet, ap_info)
                
                # Track beacon frames
                self.beacon_frames[bssid].append(ap_info)
                
                # Clean old beacon frames (older than 5 minutes)
                cutoff_time = datetime.now() - timedelta(minutes=5)
                self.beacon_frames[bssid] = [
                    beacon for beacon in self.beacon_frames[bssid]
                    if beacon["timestamp"] > cutoff_time
                ]
                
                # Update detected APs
                self.detected_aps[bssid] = ap_info
                
                # Check for rogue AP indicators
                self._check_rogue_indicators(ap_info)
                
        except Exception as e:
            self.logger.error(f"Error analyzing beacon frame: {e}")
    
    def _analyze_probe_response(self, packet):
        """Analyze probe response frames"""
        try:
            dot11_layer = packet[scapy.Dot11]
            bssid = dot11_layer.addr3.lower() if dot11_layer.addr3 else "unknown"
            
            # Similar to beacon analysis but for probe responses
            if bssid not in self.detected_aps:
                ap_info = {
                    "bssid": bssid,
                    "timestamp": datetime.now(),
                    "detected_via": "probe_response",
                    "channel": self._get_channel_from_packet(packet),
                    "rssi": self._get_signal_strength(packet),
                    "vendor": self._get_vendor_from_mac(bssid)
                }
                
                if packet.haslayer(scapy.Dot11Elt):
                    self._parse_information_elements(packet, ap_info)
                
                self.detected_aps[bssid] = ap_info
                self._check_rogue_indicators(ap_info)
                
        except Exception as e:
            self.logger.error(f"Error analyzing probe response: {e}")
    
    def _analyze_probe_request(self, packet):
        """Analyze probe request frames for client behavior"""
        try:
            dot11_layer = packet[scapy.Dot11]
            client_mac = dot11_layer.addr2.lower() if dot11_layer.addr2 else "unknown"
            
            # Track probe requests for potential evil twin detection
            if not hasattr(self, 'probe_requests'):
                self.probe_requests = defaultdict(list)
            
            ssid = ""
            if packet.haslayer(scapy.Dot11Elt):
                elt = packet[scapy.Dot11Elt]
                while elt:
                    if elt.ID == 0:  # SSID element
                        ssid = elt.info.decode('utf-8', errors='ignore')
                        break
                    elt = elt.payload if hasattr(elt, 'payload') else None
            
            probe_info = {
                "timestamp": datetime.now(),
                "client_mac": client_mac,
                "ssid": ssid
            }
            
            self.probe_requests[client_mac].append(probe_info)
            
            # Clean old probe requests (older than 2 minutes)
            cutoff_time = datetime.now() - timedelta(minutes=2)
            self.probe_requests[client_mac] = [
                probe for probe in self.probe_requests[client_mac]
                if probe["timestamp"] > cutoff_time
            ]
            
        except Exception as e:
            self.logger.error(f"Error analyzing probe request: {e}")
    
    def _analyze_association_frame(self, packet):
        """Analyze association frames"""
        try:
            dot11_layer = packet[scapy.Dot11]
            client_mac = dot11_layer.addr2.lower() if dot11_layer.addr2 else "unknown"
            ap_mac = dot11_layer.addr1.lower() if dot11_layer.addr1 else "unknown"
            
            # Check if client is associating with suspicious AP
            if ap_mac in self.suspicious_aps:
                self._generate_alert("client_connected_to_rogue_ap", {
                    "client_mac": client_mac,
                    "rogue_ap_mac": ap_mac,
                    "ap_info": self.detected_aps.get(ap_mac, {}),
                    "severity": "high",
                    "description": f"Client {client_mac} connected to suspected rogue AP {ap_mac}"
                })
                
        except Exception as e:
            self.logger.error(f"Error analyzing association frame: {e}")
    
    def _analyze_data_frame(self, packet):
        """Analyze data frames for additional indicators"""
        try:
            # This could be extended to analyze data patterns
            # for more sophisticated rogue AP detection
            pass
        except Exception as e:
            self.logger.error(f"Error analyzing data frame: {e}")
    
    def _parse_information_elements(self, packet, ap_info: Dict):
        """Parse 802.11 information elements"""
        try:
            elt = packet[scapy.Dot11Elt]
            
            while elt:
                if elt.ID == 0:  # SSID
                    ap_info["ssid"] = elt.info.decode('utf-8', errors='ignore')
                elif elt.ID == 3:  # DS Parameter Set (Channel)
                    if len(elt.info) >= 1:
                        ap_info["channel"] = elt.info[0]
                elif elt.ID == 48:  # RSN (WPA2)
                    ap_info["encryption"] = "WPA2"
                elif elt.ID == 221:  # Vendor Specific (might be WPA)
                    if len(elt.info) >= 4 and elt.info[:4] == b'\x00\x50\xf2\x01':
                        ap_info["encryption"] = "WPA"
                
                # Move to next element
                if hasattr(elt, 'payload') and elt.payload:
                    elt = elt.payload
                else:
                    break
                    
        except Exception as e:
            self.logger.error(f"Error parsing information elements: {e}")
    
    def _check_rogue_indicators(self, ap_info: Dict):
        """Check for rogue AP indicators"""
        try:
            bssid = ap_info["bssid"]
            
            # Check if AP is in authorized list
            if self.authorized_aps and bssid not in self.authorized_aps:
                # Check for SSID impersonation
                ssid = ap_info.get("ssid", "")
                for auth_bssid, auth_ap in self.authorized_aps.items():
                    if auth_ap.get("ssid") == ssid and auth_bssid != bssid:
                        self.suspicious_aps.add(bssid)
                        self._generate_alert("ssid_impersonation", {
                            "rogue_bssid": bssid,
                            "legitimate_bssid": auth_bssid,
                            "ssid": ssid,
                            "ap_info": ap_info,
                            "severity": "critical",
                            "description": f"Rogue AP impersonating SSID '{ssid}'"
                        })
                        return
                
                # Unauthorized AP detected
                self._generate_alert("unauthorized_access_point", {
                    "bssid": bssid,
                    "ssid": ssid,
                    "ap_info": ap_info,
                    "severity": "medium",
                    "description": f"Unauthorized access point detected: {ssid} ({bssid})"
                })
            
            # Check for suspicious characteristics
            self._check_suspicious_characteristics(ap_info)
            
            # Check for evil twin patterns
            self._check_evil_twin_patterns(ap_info)
            
        except Exception as e:
            self.logger.error(f"Error checking rogue indicators: {e}")
    
    def _check_suspicious_characteristics(self, ap_info: Dict):
        """Check for suspicious AP characteristics"""
        try:
            bssid = ap_info["bssid"]
            
            # Check for hidden SSID
            if not ap_info.get("ssid") or ap_info.get("ssid") == "":
                self._generate_alert("hidden_ssid_detected", {
                    "bssid": bssid,
                    "ap_info": ap_info,
                    "severity": "low",
                    "description": f"Hidden SSID detected from {bssid}"
                })
            
            # Check for no encryption (open network)
            if ap_info.get("encryption") is None:
                capabilities = ap_info.get("capabilities", 0)
                # Check privacy bit (bit 4) in capabilities
                if not (capabilities & 0x0010):
                    self._generate_alert("open_network_detected", {
                        "bssid": bssid,
                        "ssid": ap_info.get("ssid", ""),
                        "ap_info": ap_info,
                        "severity": "medium",
                        "description": f"Open network detected: {ap_info.get('ssid', 'Hidden')} ({bssid})"
                    })
            
            # Check for suspicious vendor (randomized MAC)
            if self._is_randomized_mac(bssid):
                self._generate_alert("randomized_mac_detected", {
                    "bssid": bssid,
                    "ap_info": ap_info,
                    "severity": "medium",
                    "description": f"AP with randomized MAC detected: {bssid}"
                })
            
            # Check for excessive beacon interval changes
            if len(self.beacon_frames[bssid]) > 5:
                intervals = [beacon.get("beacon_interval", 100) for beacon in self.beacon_frames[bssid]]
                if len(set(intervals)) > 2:  # More than 2 different intervals
                    self._generate_alert("beacon_interval_variation", {
                        "bssid": bssid,
                        "intervals": list(set(intervals)),
                        "ap_info": ap_info,
                        "severity": "low",
                        "description": f"Suspicious beacon interval variations from {bssid}"
                    })
                    
        except Exception as e:
            self.logger.error(f"Error checking suspicious characteristics: {e}")
    
    def _check_evil_twin_patterns(self, ap_info: Dict):
        """Check for evil twin attack patterns"""
        try:
            bssid = ap_info["bssid"]
            ssid = ap_info.get("ssid", "")
            channel = ap_info.get("channel")
            
            # Look for similar APs with different BSSIDs
            for other_bssid, other_ap in self.detected_aps.items():
                if other_bssid != bssid and other_ap.get("ssid") == ssid:
                    # Same SSID, different BSSID - potential evil twin
                    
                    # Check signal strength difference
                    rssi_diff = abs(ap_info.get("rssi", 0) - other_ap.get("rssi", 0))
                    
                    # Check channel difference
                    other_channel = other_ap.get("channel")
                    channel_diff = abs(channel - other_channel) if channel and other_channel else 0
                    
                    # Check vendor similarity
                    vendor1 = ap_info.get("vendor", "")
                    vendor2 = other_ap.get("vendor", "")
                    different_vendors = vendor1 != vendor2 and vendor1 and vendor2
                    
                    # Calculate suspicion score
                    suspicion_score = 0
                    if rssi_diff > 20:  # Significant signal strength difference
                        suspicion_score += 2
                    if channel_diff > 0:  # Different channels
                        suspicion_score += 1
                    if different_vendors:  # Different vendors
                        suspicion_score += 3
                    
                    if suspicion_score >= 3:
                        self.suspicious_aps.add(bssid)
                        self.suspicious_aps.add(other_bssid)
                        
                        self._generate_alert("evil_twin_detected", {
                            "ap1_bssid": bssid,
                            "ap2_bssid": other_bssid,
                            "ssid": ssid,
                            "suspicion_score": suspicion_score,
                            "rssi_diff": rssi_diff,
                            "channel_diff": channel_diff,
                            "different_vendors": different_vendors,
                            "ap1_info": ap_info,
                            "ap2_info": other_ap,
                            "severity": "critical",
                            "description": f"Potential evil twin attack detected for SSID '{ssid}'"
                        })
                        
        except Exception as e:
            self.logger.error(f"Error checking evil twin patterns: {e}")
    
    def _get_channel_from_packet(self, packet) -> Optional[int]:
        """Extract channel information from packet"""
        try:
            # Try to get channel from RadioTap header
            if packet.haslayer(scapy.RadioTap):
                radiotap = packet[scapy.RadioTap]
                # This would need more sophisticated parsing based on RadioTap fields
                pass
            
            # Fallback to DS parameter set in information elements
            return None
        except Exception:
            return None
    
    def _get_signal_strength(self, packet) -> int:
        """Extract signal strength from packet"""
        try:
            if packet.haslayer(scapy.RadioTap):
                # This would extract RSSI from RadioTap header
                # Implementation depends on RadioTap structure
                pass
            return 0
        except Exception:
            return 0
    
    def _get_vendor_from_mac(self, mac_address: str) -> str:
        """Get vendor from MAC address OUI"""
        try:
            # Extract OUI (first 3 octets)
            oui = mac_address.replace(':', '').upper()[:6]
            
            # Common OUI mappings (simplified)
            oui_mapping = {
                '000C29': 'VMware',
                '001B63': 'Apple',
                '00E04C': 'Realtek',
                '001E2A': 'The Linksys Group',
                '00226B': 'Netgear',
                '001F3F': 'Netgear',
                '002454': 'Netgear',
                '0016B6': 'Cisco',
                '00A0C9': 'Intel'
            }
            
            return oui_mapping.get(oui, 'Unknown')
        except Exception:
            return 'Unknown'
    
    def _is_randomized_mac(self, mac_address: str) -> bool:
        """Check if MAC address appears to be randomized"""
        try:
            # Check locally administered bit (bit 1 of first octet)
            first_octet = int(mac_address.split(':')[0], 16)
            return bool(first_octet & 0x02)
        except Exception:
            return False
    
    def _generate_alert(self, alert_type: str, details: Dict):
        """Generate security alert"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "detector": "rogue_access",
            "alert_type": alert_type,
            "details": details
        }
        
        self.logger.warning(f"Rogue Access Alert: {alert}")
        return alert
    
    def start_monitoring(self):
        """Start rogue access point detection"""
        if self.is_running:
            return
            
        self.is_running = True
        self.logger.info("Starting rogue access point detection")
        
        def monitor():
            try:
                # Monitor 802.11 management frames
                scapy.sniff(
                    iface=self.interface,
                    prn=self.detect_rogue_access,
                    stop_filter=lambda x: not self.is_running
                )
            except Exception as e:
                self.logger.error(f"Error in rogue access monitoring: {e}")
        
        self.monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop rogue access point detection"""
        self.is_running = False
        self.logger.info("Stopping rogue access point detection")