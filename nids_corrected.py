#!/usr/bin/env python3
"""
Basic Network Intrusion Detection System (NIDS)
This script demonstrates fundamental NIDS functionality including:
- Packet capture and inspection
- Traffic analysis for potential threats
- Alert generation for suspicious activities
"""

import argparse
import datetime
import ipaddress
import logging
import sys
import re

import time
from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple, DefaultDict, Deque

try:
    import scapy.all as scapy
except ImportError:
    print("This script requires scapy. Install it with: pip install scapy")
    sys.exit(1)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("nids.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('NIDS')

class NetworkIDS:
    """Basic Network Intrusion Detection System implementation"""
    
    def __init__(self, interface: str = None, pcap_file: str = None,
                 threshold_port_scan: int = 15, threshold_ddos: int = 100,
                 whitelist: List[str] = None):
        """
        Initialize the NIDS with detection parameters
        
        Args:
            interface: Network interface to monitor
            pcap_file: PCAP file to analyze (alternative to live capture)
            threshold_port_scan: Number of ports to trigger port scan alert
            threshold_ddos: Number of packets to trigger DDoS alert
            whitelist: List of IP addresses to exclude from monitoring
        """
        self.interface = interface
        self.pcap_file = pcap_file
        self.threshold_port_scan = threshold_port_scan
        self.threshold_ddos = threshold_ddos
        self.whitelist = set()
        
        if whitelist:
            for ip in whitelist:
                try:
                    self.whitelist.add(str(ipaddress.ip_address(ip)))
                except ValueError:
                    logger.warning(f"Invalid IP in whitelist: {ip}")
        
        # Data structures for tracking activity
        self.port_scan_tracker: Dict[str, Set[int]] = defaultdict(set)
        self.syn_flood_tracker: Dict[str, int] = defaultdict(int)
        self.icmp_flood_tracker: DefaultDict[str, int] = defaultdict(int)
        self.packet_count: DefaultDict[str, int] = defaultdict(int)
        self.connection_tracker: DefaultDict[Tuple[str, str], int] = defaultdict(int)
        
        # Recent alerts to prevent duplicates
        self.recent_alerts: Deque[Tuple[str, str, float]] = deque(maxlen=100)
        
        # Time window for rate-based detection (in seconds)
        self.time_window = 60
        self.last_cleanup = time.time()
        
        # Known bad patterns (simple signatures)
        self.bad_patterns = [
            b"SELECT.*FROM.*WHERE",  # SQL Injection attempt
            b"<script>.*</script>",   # XSS attempt
            b"../../../",             # Path traversal
            b"cmd.exe",               # Command execution
            b"exec(",                 # Code execution
        ]
        
        logger.info("NIDS initialized with the following parameters:")
        logger.info(f"Interface: {interface}")
        logger.info(f"PCAP file: {pcap_file}")
        logger.info(f"Port scan threshold: {threshold_port_scan}")
        logger.info(f"DDoS threshold: {threshold_ddos}")
        logger.info(f"Whitelist: {self.whitelist}")
    
    def is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is in the whitelist"""
        return ip in self.whitelist
    
    def process_packet(self, packet):
        """Process a single packet and check for suspicious activity"""
        # Periodically clean up tracking data structures
        current_time = time.time()
        if current_time - self.last_cleanup > self.time_window:
            self._cleanup_old_data()
            self.last_cleanup = current_time
        
        # Basic packet info extraction
        if scapy.IP in packet:
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            
            # Skip whitelisted IPs
            if self.is_whitelisted(ip_src) or self.is_whitelisted(ip_dst):
                return
            
            # Track packet counts
            self.packet_count[ip_src] += 1
            
            # Detect abnormally high traffic (potential DDoS)
            if self.packet_count[ip_src] > self.threshold_ddos:
                self._generate_alert("DDoS", ip_src, f"High packet rate: {self.packet_count[ip_src]} packets")
            
            # TCP-specific checks
            if scapy.TCP in packet:
                self._analyze_tcp_packet(packet, ip_src, ip_dst)
            
            # UDP-specific checks
            elif scapy.UDP in packet:
                self._analyze_udp_packet(packet, ip_src, ip_dst)
            
            # ICMP-specific checks
            elif scapy.ICMP in packet:
                self._analyze_icmp_packet(packet, ip_src, ip_dst)
            
            # Check for known bad patterns in packet payload
            self._check_payload_patterns(packet, ip_src)
    
    def _analyze_tcp_packet(self, packet, ip_src, ip_dst):
        """Analyze TCP packets for suspicious behavior"""
        tcp = packet[scapy.TCP]
        dst_port = tcp.dport
        
        # Detect port scanning
        if tcp.flags == 'S':  # SYN flag
            # Track ports being scanned by this source
            self.port_scan_tracker[ip_src].add(dst_port)
            
            # Port scan detection
            if len(self.port_scan_tracker[ip_src]) > self.threshold_port_scan:
                ports = sorted(list(self.port_scan_tracker[ip_src]))
                self._generate_alert("Port Scan", ip_src, f"Scanned {len(ports)} ports: {ports[:5]}...")
            
            # SYN flood detection
            conn_key = (ip_src, ip_dst)
            self.connection_tracker[conn_key] += 1
            if self.connection_tracker[conn_key] > self.threshold_ddos // 2:
                self._generate_alert("SYN Flood", ip_src, 
                                    f"High SYN rate to {ip_dst}: {self.connection_tracker[conn_key]} packets")
    
    def _analyze_udp_packet(self, packet, ip_src, ip_dst):
        """Analyze UDP packets for suspicious behavior"""
        udp = packet[scapy.UDP]
        
        # Check for DNS amplification attack
        if udp.dport == 53 and packet.haslayer(scapy.DNS):
            dns = packet[scapy.DNS]
            if dns.qr == 0 and dns.opcode == 0:  # It's a query
                # Check if it's a suspicious query that could be used for amplification
                if dns.qd and dns.qd.qtype in (255, 16):  # ANY or TXT record
                    self._generate_alert("DNS Amplification", ip_src, 
                                        f"Potential DNS amplification query to {ip_dst}")
    
    def _analyze_icmp_packet(self, packet, ip_src, ip_dst):
        """Analyze ICMP packets for suspicious behavior"""
        icmp = packet[scapy.ICMP]
        
        # ICMP flood detection
        self.icmp_flood_tracker[ip_src] += 1
        if self.icmp_flood_tracker[ip_src] > self.threshold_ddos // 2:
            self._generate_alert("ICMP Flood", ip_src, 
                               f"High ICMP rate: {self.syn_flood_tracker[ip_src]} packets")
    
    def _check_payload_patterns(self, packet, ip_src):
        """Check packet payload for known malicious patterns"""
        # Extract payload if available
        if scapy.Raw in packet:
            payload = bytes(packet[scapy.Raw])
            
            # Check against known bad patterns
            for pattern in self.bad_patterns:
                try:
                    if re.search(pattern.decode('utf-8'), payload.decode('utf-8', errors='ignore')):
                        self._generate_alert("Malicious Pattern", ip_src, 
                                           f"Detected pattern: {pattern.decode('utf-8', errors='replace')}")
                except Exception as e:
                    logger.debug(f"Pattern matching error: {e}")

    
    def _generate_alert(self, alert_type: str, source: str, details: str):
        """Generate an alert for suspicious activity"""
        # Check if this alert was recently generated
        now = time.time()
        for recent_type, recent_source, timestamp in list(self.recent_alerts):
            if (recent_type == alert_type and 
                recent_source == source and 
                now - timestamp < 300):  # Suppress duplicate alerts for 5 minutes
                return
        
        # Add to recent alerts
        self.recent_alerts.append((alert_type, source, now))
        
        # Log the alert
        alert_msg = f"ALERT: {alert_type} detected from {source} - {details}"
        logger.warning(alert_msg)
    
    def _cleanup_old_data(self):
        """Clean up tracking data structures to prevent memory issues"""
        logger.debug("Cleaning up tracking data structures")
        self.port_scan_tracker.clear()
        self.syn_flood_tracker.clear()
        self.packet_count.clear()
        self.connection_tracker.clear()
    
    def start(self):
        """Start the NIDS capturing and analyzing packets"""
        logger.info("Starting Network Intrusion Detection System...")
        
        try:
            if self.pcap_file:
                logger.info(f"Reading packets from {self.pcap_file}")
                scapy.sniff(offline=self.pcap_file, prn=self.process_packet, store=False)
            else:
                logger.info(f"Capturing packets on interface {self.interface}")
                scapy.sniff(iface=self.interface, prn=self.process_packet, store=False)
        except KeyboardInterrupt:
            logger.info("NIDS stopped by user")
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
        finally:
            logger.info("NIDS shutting down")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Network Intrusion Detection System")
    parser.add_argument("-i", "--interface", help="Network interface to monitor")
    parser.add_argument("-r", "--read", help="Read packets from PCAP file instead of live capture")
    parser.add_argument("-p", "--portscan", type=int, default=15, 
                      help="Port scan detection threshold (default: 15 ports)")
    parser.add_argument("-d", "--ddos", type=int, default=100, 
                      help="DDoS detection threshold (default: 100 packets)")
    parser.add_argument("-w", "--whitelist", nargs="+", help="IP addresses to whitelist")
    
    args = parser.parse_args()
    
    # Ensure interface or PCAP file is specified
    if not args.interface and not args.read:
        logger.error("Either network interface (-i) or PCAP file (-r) must be specified")
        parser.print_help()
        sys.exit(1)
    
    # Create and start the NIDS
    nids = NetworkIDS(
        interface=args.interface,
        pcap_file=args.read,
        threshold_port_scan=args.portscan,
        threshold_ddos=args.ddos,
        whitelist=args.whitelist
    )
    
    nids.start()