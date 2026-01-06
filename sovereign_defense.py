#!/usr/bin/env python3
"""
Sovereign Network Defense - Master Control
Runs all monitoring components simultaneously
"""

import os
import sys
import threading
import signal

# Add src directory to path
sys.path.append('src')

from network.unified_monitor import UnifiedMonitor
from files.file_monitor import start_monitoring as start_file_monitor
from process.process_monitor import ProcessMonitor


class SovereignDefense:
    def __init__(self):
        self.running = True
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        print("\n\n🛑 Shutting down Sovereign Defense System...")
        self.running = False
        sys.exit(0)
    
    def start(self):
        """Start all monitoring components"""
        print("="*70)
        print("🛡️  SOVEREIGN NETWORK DEFENSE SYSTEM")
        print("="*70)
        print("\nStarting all monitoring components:")
        print("  ✓ Network Monitor (Layer 1: Connections)")
        print("  ✓ Packet Monitor (Layer 2: Raw packets)")
        print("  ✓ File Access Monitor (Documents, Downloads, Desktop)")
        print("  ✓ Process Monitor (CPU, Memory, Suspicious processes)")
        print("="*70)
        print("\nAll systems active. Press Ctrl+C to stop all monitors.\n")
        
        # Start file monitor in a thread
        file_thread = threading.Thread(
            target=start_file_monitor,
            daemon=True
        )
        file_thread.start()
        
        # Start process monitor in a thread
        process_monitor = ProcessMonitor()
        process_thread = threading.Thread(
            target=process_monitor.monitor,
            daemon=True
        )
        process_thread.start()
        
        # Start unified network monitor (blocks in main thread)
        network_monitor = UnifiedMonitor()
        network_monitor.start()


if __name__ == "__main__":
    # Check for root privileges
    if os.geteuid() != 0:
        print("❌ Error: This system requires root privileges for network monitoring")
        print("Run with: sudo python3 sovereign_defense.py")
        sys.exit(1)
    
    defense = SovereignDefense()
    defense.start()
