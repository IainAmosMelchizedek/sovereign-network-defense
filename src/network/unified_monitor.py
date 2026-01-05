#!/usr/bin/env python3
"""
Unified Network Monitor
Combines connection-level and packet-level monitoring
"""

import threading
import signal
import sys
from monitor import NetworkMonitor
from packet_monitor import PacketMonitor

class UnifiedMonitor:
    def __init__(self, log_dir='logs'):
        self.log_dir = log_dir
        self.running = True
        
        # Initialize both monitors
        self.connection_monitor = NetworkMonitor(log_dir=log_dir)
        self.packet_monitor = PacketMonitor(
            log_dir=log_dir,
            alert_callback=self.handle_packet_alert
        )
        
        # Setup signal handler for clean shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def handle_packet_alert(self, message, severity):
        """Handle alerts from packet monitor"""
        # Can add additional processing here if needed
        pass
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        print("\n\n🛑 Shutting down monitors...")
        self.running = False
        sys.exit(0)
    
    def start(self):
        """Start both monitors in separate threads"""
        print("🛡️  UNIFIED SOVEREIGN NETWORK DEFENSE")
        print("="*70)
        print("Starting dual-layer monitoring:")
        print("  • Layer 1: Connection Monitor (established connections)")
        print("  • Layer 2: Packet Monitor (all network traffic)")
        print("="*70)
        print()
        
        # Start connection monitor in a thread
        connection_thread = threading.Thread(
            target=self.connection_monitor.monitor,
            daemon=True
        )
        connection_thread.start()
        
        # Start packet monitor in main thread (requires root)
        # This blocks, so it runs in the main thread
        self.packet_monitor.start_sniffing()

if __name__ == "__main__":
    import os
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("❌ Error: This script requires root privileges")
        print("Run with: sudo python3 src/network/unified_monitor.py")
        sys.exit(1)
    
    monitor = UnifiedMonitor()
    monitor.start()
