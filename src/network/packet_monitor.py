#!/usr/bin/env python3
"""
Packet Monitor - Enhanced Detection
Captures and analyzes network packets to detect port scans and attack attempts
"""

from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from collections import defaultdict
import time
import os

class PacketMonitor:
    def __init__(self, log_dir='logs', alert_callback=None):
        self.log_dir = log_dir
        self.alert_callback = alert_callback
        
        # Track connection attempts per source IP
        self.scan_tracker = defaultdict(lambda: {
            'syn_count': 0,
            'ports': set(),
            'first_seen': None,
            'last_seen': None
        })
        
        # Detection thresholds
        self.port_scan_threshold = 5  # Different ports from same IP
        self.time_window = 10  # Seconds
        
        # Ensure log directory exists
        os.makedirs(self.log_dir, exist_ok=True)
        
    def log_alert(self, message, severity="PACKET_ALERT"):
        """Log packet-level alerts"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] [{severity}] {message}"
        
        # Print to console
        print(f"\n{'='*70}")
        print(f"🚨 {severity}: {message}")
        print(f"{'='*70}\n")
        
        # Write to log
        log_file = os.path.join(self.log_dir, 'packet_alerts.log')
        with open(log_file, 'a') as f:
            f.write(log_message + '\n')
        
        # Callback to main monitor if provided
        if self.alert_callback:
            self.alert_callback(message, severity)
    
    def log_packet(self, packet_info):
        """Log detailed packet information"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] {packet_info}"
        
        log_file = os.path.join(self.log_dir, 'all_packets.log')
        with open(log_file, 'a') as f:
            f.write(log_message + '\n')
    
    def analyze_packet(self, packet):
        """Analyze individual packet for threats"""
        try:
            # Only analyze IP packets
            if not packet.haslayer(IP):
                return
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Check for TCP packets (most common for port scans)
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                
                # Detect SYN packets (connection attempts)
                if flags & 0x02:  # SYN flag set
                    self.detect_port_scan(src_ip, dst_ip, dst_port, 'TCP')
                    
                    packet_info = (
                        f"SYN | Source: {src_ip}:{src_port} -> "
                        f"Dest: {dst_ip}:{dst_port} | Protocol: TCP"
                    )
                    self.log_packet(packet_info)
            
            # Check for UDP packets
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                
                self.detect_port_scan(src_ip, dst_ip, dst_port, 'UDP')
                
                packet_info = (
                    f"UDP | Source: {src_ip}:{src_port} -> "
                    f"Dest: {dst_ip}:{dst_port} | Protocol: UDP"
                )
                self.log_packet(packet_info)
                
        except Exception as e:
            print(f"Error analyzing packet: {e}")
    
    def detect_port_scan(self, src_ip, dst_ip, dst_port, protocol):
        """Detect port scanning behavior"""
        current_time = time.time()
        
        # Initialize tracking if first time seeing this IP
        if self.scan_tracker[src_ip]['first_seen'] is None:
            self.scan_tracker[src_ip]['first_seen'] = current_time
        
        self.scan_tracker[src_ip]['last_seen'] = current_time
        self.scan_tracker[src_ip]['ports'].add(dst_port)
        
        # Clean old entries outside time window
        if current_time - self.scan_tracker[src_ip]['first_seen'] > self.time_window:
            # Reset tracking for this IP
            self.scan_tracker[src_ip] = {
                'syn_count': 0,
                'ports': {dst_port},
                'first_seen': current_time,
                'last_seen': current_time
            }
        
        # Check if threshold exceeded
        unique_ports = len(self.scan_tracker[src_ip]['ports'])
        if unique_ports >= self.port_scan_threshold:
            ports_list = sorted(list(self.scan_tracker[src_ip]['ports']))
            time_span = current_time - self.scan_tracker[src_ip]['first_seen']
            
            self.log_alert(
                f"PORT SCAN DETECTED | Source: {src_ip} -> Target: {dst_ip} | "
                f"Scanned {unique_ports} ports in {time_span:.1f}s | "
                f"Ports: {ports_list[:10]}{'...' if len(ports_list) > 10 else ''} | "
                f"Protocol: {protocol}",
                severity="PORT_SCAN"
            )
            
            # Reset after alert to avoid spam
            self.scan_tracker[src_ip]['ports'] = set()
            self.scan_tracker[src_ip]['first_seen'] = current_time
    
    def start_sniffing(self, interface=None, filter_exp="tcp or udp"):
        """Start packet capture"""
        print("🔍 Packet Monitor Started")
        print(f"Capturing on interface: {interface if interface else 'all'}")
        print(f"Filter: {filter_exp}")
        print(f"Port scan threshold: {self.port_scan_threshold} ports in {self.time_window}s")
        print(f"Logs: {os.path.abspath(self.log_dir)}")
        print("\nPress Ctrl+C to stop\n")
        
        try:
            sniff(
                iface=interface,
                filter=filter_exp,
                prn=self.analyze_packet,
                store=False  # Don't store packets in memory
            )
        except KeyboardInterrupt:
            print("\n\n🛑 Packet Monitor Stopped")
            print(f"Logs saved to: {os.path.abspath(self.log_dir)}/")

if __name__ == "__main__":
    # Run packet monitor standalone
    monitor = PacketMonitor()
    monitor.start_sniffing()
