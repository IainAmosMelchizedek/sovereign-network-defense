#!/usr/bin/env python3
"""
File Access Monitor - Component 2
Monitors file system for unauthorized access attempts
"""

import os
import sys
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Add parent directory to path for alert system
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network.alert_system import AlertSystem


class FileAccessMonitor(FileSystemEventHandler):
    def __init__(self, log_dir='logs', monitored_paths=None):
        self.log_dir = log_dir
        self.alert_system = AlertSystem(log_dir=log_dir)
        self.monitored_paths = monitored_paths or []
        
        # Ensure log directory exists
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Track events to avoid duplicate alerts
        self.recent_events = {}
        self.event_window = 1  # seconds to consider events as duplicates
        
    def log_file_event(self, event_type, path):
        """Log file system events"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] {event_type}: {path}"
        
        # Write to file access log
        log_file = os.path.join(self.log_dir, 'file_access.log')
        with open(log_file, 'a') as f:
            f.write(log_message + '\n')
    
    def should_alert(self, event_key):
        """Check if we should alert (avoid spam from rapid events)"""
        current_time = time.time()
        
        if event_key in self.recent_events:
            if current_time - self.recent_events[event_key] < self.event_window:
                return False
        
        self.recent_events[event_key] = current_time
        return True
    
    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return
        
        self.log_file_event("MODIFIED", event.src_path)
        
        event_key = f"modified:{event.src_path}"
        if self.should_alert(event_key):
            self.alert_system.send_alert(
                f"File modified: {event.src_path}",
                severity="FILE_MODIFIED",
                play_sound=False  # Don't play sound for modifications (too noisy)
            )
    
    def on_created(self, event):
        """Handle file creation events"""
        if event.is_directory:
            return
        
        self.log_file_event("CREATED", event.src_path)
        
        event_key = f"created:{event.src_path}"
        if self.should_alert(event_key):
            self.alert_system.send_alert(
                f"File created: {event.src_path}",
                severity="FILE_CREATED",
                play_sound=False
            )
    
    def on_deleted(self, event):
        """Handle file deletion events - CRITICAL"""
        if event.is_directory:
            return
        
        self.log_file_event("DELETED", event.src_path)
        
        # File deletions are critical - always alert with sound
        self.alert_system.send_alert(
            f"FILE DELETION DETECTED: {event.src_path}",
            severity="FILE_DELETED",
            play_sound=True  # Sound alert for deletions
        )
    
    def on_moved(self, event):
        """Handle file move/rename events"""
        if event.is_directory:
            return
        
        self.log_file_event(f"MOVED from {event.src_path} to {event.dest_path}", "")
        
        self.alert_system.send_alert(
            f"File moved: {event.src_path} -> {event.dest_path}",
            severity="FILE_MOVED",
            play_sound=False
        )


def start_monitoring(paths_to_monitor=None):
    """Start file monitoring on specified paths"""
    if not paths_to_monitor:
        # Default: monitor user's home directory critical folders
        home = os.path.expanduser("~")
        paths_to_monitor = [
            os.path.join(home, "Documents"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
        ]
        # Filter to only existing directories
        paths_to_monitor = [p for p in paths_to_monitor if os.path.exists(p)]
    
    print("🔍 FILE ACCESS MONITOR - ACTIVE")
    print("="*70)
    print("Monitoring the following directories:")
    for path in paths_to_monitor:
        print(f"  📁 {path}")
    print("="*70)
    print("\nDetecting: File creation, modification, deletion, and moves")
    print("⚠️  File deletions will trigger audio alerts")
    print("\nPress Ctrl+C to stop\n")
    
    # Create monitor and observer
    event_handler = FileAccessMonitor(monitored_paths=paths_to_monitor)
    observer = Observer()
    
    # Schedule monitoring for each path
    for path in paths_to_monitor:
        observer.schedule(event_handler, path, recursive=True)
    
    # Start monitoring
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n🛑 File Monitor Stopped")
        observer.stop()
    
    observer.join()


if __name__ == "__main__":
    start_monitoring()
