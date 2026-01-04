#!/usr/bin/env python3
"""
Network Monitor - Component 1 (Enhanced)
Detects INBOUND connection attempts and attacks against YOUR machine
"""

import psutil
import time
from datetime import datetime
import os
import socket

class NetworkMonitor:
    def __init__(self, log_dir='logs'):
        self.log_dir = log_dir
        self.local_ips = self.get_local_ips()
        
        # Ensure log directory exists
        os.makedirs(self.log_dir, exist_ok=True)
        
        print(f"🔍 Your machine IPs: {', '.join(self.local_ips)}")
        
    def get_local_ips(self):
        """Get all local IP addresses of this machine"""
        local_ips = set()
        
        # Get all network interfaces
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4
                    local_ips.add(addr.address)
        
        return local_ips
    
    def log_alert(self, message, severity="ALERT"):
        """Write alert to log file and print to console"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] [{severity}] {message}"
        
        # Print to console with visual emphasis
        print(f"\n{'='*70}")
        print(f"🚨 {severity}: {message}")
        print(f"{'='*70}\n")
        
        # Write to log file
        log_file = os.path.join(self.log_dir, 'network_alerts.log')
        with open(log_file, 'a') as f:
            f.write(log_message + '\n')
    
    def log_connection(self, conn_info):
        """Log every connection for evidence"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] {conn_info}"
        
        # Write to detailed connection log
        log_file = os.path.join(self.log_dir, 'all_connections.log')
        with open(log_file, 'a') as f:
            f.write(log_message + '\n')
    
    def is_listening_port(self, conn):
        """Check if this is a listening port (potential target for attacks)"""
        return conn.status == 'LISTEN'
    
    def is_inbound_connection(self, conn):
        """Detect if this is someone connecting TO us (inbound threat)"""
        # If we're listening and someone connects, that's inbound
        if conn.status == 'ESTABLISHED':
            # Check if local address is one of our IPs and we have a remote address
            if conn.laddr and conn.raddr:
                local_ip = conn.laddr.ip
                remote_ip = conn.raddr.ip
                
                # If remote IP is trying to reach our listening service
                # AND it's not localhost, it's potentially suspicious
                if local_ip in self.local_ips and remote_ip not in self.local_ips:
                    # Filter out localhost connections
                    if not remote_ip.startswith('127.'):
                        return True
        return False
    
    def analyze_connection(self, conn):
        """Analyze a connection for threats"""
        try:
            # Get connection details
            if conn.laddr:
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
            else:
                local_addr = "N/A"
            
            if conn.raddr:
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"
                remote_ip = conn.raddr.ip
            else:
                remote_addr = "N/A"
                remote_ip = None
            
            status = conn.status
            pid = conn.pid
            
            # Get process name if available
            try:
                if pid:
                    process = psutil.Process(pid)
                    process_name = process.name()
                else:
                    process_name = "Unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = "Unknown"
            
            conn_info = (
                f"Local: {local_addr} | Remote: {remote_addr} | "
                f"Status: {status} | Process: {process_name} (PID: {pid})"
            )
            
            # Log every connection for evidence
            self.log_connection(conn_info)
            
            # Check for inbound threats
            if self.is_inbound_connection(conn):
                self.log_alert(
                    f"INBOUND CONNECTION DETECTED - "
                    f"Remote IP: {remote_ip} attempting to connect to your machine at {local_addr} | "
                    f"Process: {process_name} (PID: {pid})",
                    severity="THREAT"
                )
                return True
            
            # Check for listening ports (potential attack surface)
            if self.is_listening_port(conn):
                print(f"⚠️  Listening port detected: {local_addr} (Process: {process_name})")
                
        except Exception as e:
            print(f"Error analyzing connection: {e}")
        
        return False
    
    def monitor(self, interval=1):
        """Main monitoring loop - checks every second for threats"""
        print("\n🛡️  SOVEREIGN NETWORK DEFENSE - ACTIVE")
        print("="*70)
        print("Monitoring for INBOUND threats against your machine")
        print(f"Checking every {interval} second(s)")
        print(f"All connections logged to: {os.path.abspath(self.log_dir)}")
        print("="*70)
        print("\nPress Ctrl+C to stop\n")
        
        seen_connections = set()
        
        try:
            while True:
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    # Create unique identifier for this connection
                    try:
                        if conn.laddr and conn.raddr:
                            conn_id = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}-{conn.status}"
                        elif conn.laddr:
                            conn_id = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.status}"
                        else:
                            continue
                        
                        # Only analyze new connections
                        if conn_id not in seen_connections:
                            seen_connections.add(conn_id)
                            self.analyze_connection(conn)
                    
                    except Exception as e:
                        continue
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Network Monitor Stopped")
            print(f"All logs saved to: {os.path.abspath(self.log_dir)}/")
            print(f"  - network_alerts.log (threats only)")
            print(f"  - all_connections.log (complete evidence)")

if __name__ == "__main__":
    # Requires elevated privileges to see all connections
    monitor = NetworkMonitor()
    monitor.monitor()
