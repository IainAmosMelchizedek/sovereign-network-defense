#!/usr/bin/env python3
"""
Alert System - Multi-channel threat notifications
Sends alerts via sound, desktop notifications, and terminal
"""

import os
import sys
import subprocess
from datetime import datetime

class AlertSystem:
    def __init__(self, log_dir='logs'):
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
    
    def play_alert_sound(self):
        """Play system alert sound with multiple beeps"""
        try:
            # Multiple beeps for attention
            for i in range(3):
                sys.stdout.write('\a')
                sys.stdout.flush()
            
            # Also try to play system sound
            try:
                subprocess.run(['paplay', '/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga'], 
                             check=False, stderr=subprocess.DEVNULL, timeout=2)
            except:
                pass
        except Exception as e:
            pass  # Sound not critical
    
    def send_desktop_notification(self, title, message, urgency='critical'):
        """Send desktop notification that appears over all windows"""
        try:
            # For WSL - use Windows MessageBox (works reliably)
            # Remove exclamation marks and quotes to avoid bash issues
            clean_title = title.replace('!', '').replace('"', "'")
            clean_message = message.replace('!', '').replace('"', "'")[:200]
            
            subprocess.Popen([
                'powershell.exe',
                '-Command',
                f"Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('{clean_message}', '{clean_title}', 'OK', 'Warning')"
            ], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            
        except Exception as e:
            pass  # Notifications not critical if unavailable
    
    def send_alert(self, message, severity="ALERT", play_sound=True, notify=True):
        """Send multi-channel alert"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # 1. Play sound (with beeps)
        if play_sound:
            self.play_alert_sound()
        
        # 2. Desktop notification (Windows popup)
        if notify:
            title = f"🚨 {severity}"
            # Truncate message for notification (first 200 chars)
            short_message = message[:200] + "..." if len(message) > 200 else message
            self.send_desktop_notification(title, short_message)
        
        # 3. Terminal output
        print(f"\n{'='*70}")
        print(f"🚨 {severity}: {message}")
        print(f"{'='*70}\n")
        
        # 4. Log to file
        log_message = f"[{timestamp}] [{severity}] {message}"
        log_file = os.path.join(self.log_dir, 'alerts.log')
        with open(log_file, 'a') as f:
            f.write(log_message + '\n')

if __name__ == "__main__":
    # Test the alert system
    print("Testing alert system...")
    alert = AlertSystem()
    alert.send_alert(
        "TEST ALERT - Port scan detected from 192.168.1.100",
        severity="PORT_SCAN"
    )
    print("Alert sent! Check if you heard sound and saw notification.")
