#!/usr/bin/env python3
"""
Process Monitor - Component 3
Monitors running processes for suspicious activity
"""

import os
import sys
import time
import psutil
from datetime import datetime
from collections import defaultdict

# Add parent directory to path for alert system
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network.alert_system import AlertSystem


class ProcessMonitor:
    def __init__(self, log_dir='logs'):
        self.log_dir = log_dir
        self.alert_system = AlertSystem(log_dir=log_dir)
        
        # Ensure log directory exists
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Track known processes to detect new ones
        self.known_processes = set()
        self.suspicious_names = [
            'nc', 'netcat', 'nmap', 'masscan', 'hping',  # Network scanning tools
            'metasploit', 'msfconsole', 'armitage',      # Exploitation frameworks
            'mimikatz', 'procdump', 'pwdump',            # Credential dumpers
            'keylogger', 'logger',                        # Keyloggers
            'cryptominer', 'xmrig', 'minergate',         # Crypto miners
            'backdoor', 'trojan', 'rootkit',             # Malware
        ]
        
        # Resource usage thresholds
        self.cpu_threshold = 80  # CPU usage percentage
        self.memory_threshold = 80  # Memory usage percentage
        
        # Track high resource processes
        self.high_resource_tracker = defaultdict(int)
        self.alert_threshold = 3  # Alert after 3 consecutive high readings
        
    def log_process_event(self, event_type, message):
        """Log process events"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] {event_type}: {message}"
        
        log_file = os.path.join(self.log_dir, 'process_monitor.log')
        with open(log_file, 'a') as f:
            f.write(log_message + '\n')
    
    def is_suspicious_name(self, process_name):
        """Check if process name matches suspicious patterns"""
        process_name_lower = process_name.lower()
        for suspicious in self.suspicious_names:
            if suspicious in process_name_lower:
                return True
        return False
    
    def check_new_processes(self):
        """Detect newly started processes"""
        current_processes = set()
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                username = proc.info['username']
                cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                
                current_processes.add(pid)
                
                # Check for new processes
                if pid not in self.known_processes:
                    self.log_process_event(
                        "NEW_PROCESS",
                        f"PID: {pid}, Name: {name}, User: {username}, Command: {cmdline[:100]}"
                    )
                    
                    # Check if suspicious
                    if self.is_suspicious_name(name):
                        self.alert_system.send_alert(
                            f"SUSPICIOUS PROCESS DETECTED | Name: {name} | PID: {pid} | "
                            f"User: {username} | Command: {cmdline[:100]}",
                            severity="SUSPICIOUS_PROCESS",
                            play_sound=True
                        )
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Update known processes
        self.known_processes = current_processes
    
    def check_resource_usage(self):
        """Monitor CPU and memory usage"""
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                cpu_percent = proc.info['cpu_percent']
                memory_percent = proc.info['memory_percent']
                
                # Check for high CPU usage
                if cpu_percent > self.cpu_threshold:
                    self.high_resource_tracker[f"cpu_{pid}"] += 1
                    
                    if self.high_resource_tracker[f"cpu_{pid}"] >= self.alert_threshold:
                        self.log_process_event(
                            "HIGH_CPU",
                            f"PID: {pid}, Name: {name}, CPU: {cpu_percent:.1f}%"
                        )
                        
                        self.alert_system.send_alert(
                            f"HIGH CPU USAGE | Process: {name} (PID: {pid}) | "
                            f"CPU: {cpu_percent:.1f}% (threshold: {self.cpu_threshold}%)",
                            severity="HIGH_CPU",
                            play_sound=False  # Don't play sound for resource alerts
                        )
                        
                        # Reset counter after alert
                        self.high_resource_tracker[f"cpu_{pid}"] = 0
                else:
                    # Reset counter if below threshold
                    self.high_resource_tracker[f"cpu_{pid}"] = 0
                
                # Check for high memory usage
                if memory_percent > self.memory_threshold:
                    self.high_resource_tracker[f"mem_{pid}"] += 1
                    
                    if self.high_resource_tracker[f"mem_{pid}"] >= self.alert_threshold:
                        self.log_process_event(
                            "HIGH_MEMORY",
                            f"PID: {pid}, Name: {name}, Memory: {memory_percent:.1f}%"
                        )
                        
                        self.alert_system.send_alert(
                            f"HIGH MEMORY USAGE | Process: {name} (PID: {pid}) | "
                            f"Memory: {memory_percent:.1f}% (threshold: {self.memory_threshold}%)",
                            severity="HIGH_MEMORY",
                            play_sound=False
                        )
                        
                        self.high_resource_tracker[f"mem_{pid}"] = 0
                else:
                    self.high_resource_tracker[f"mem_{pid}"] = 0
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    
    def get_process_summary(self):
        """Get summary of running processes"""
        total_processes = len(list(psutil.process_iter()))
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        
        return {
            'total_processes': total_processes,
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'memory_available_gb': memory.available / (1024**3)
        }
    
    def monitor(self, interval=5):
        """Main monitoring loop"""
        print("🔍 PROCESS MONITOR - ACTIVE")
        print("="*70)
        print(f"Monitoring system processes every {interval} seconds")
        print(f"CPU threshold: {self.cpu_threshold}%")
        print(f"Memory threshold: {self.memory_threshold}%")
        print(f"Tracking {len(self.suspicious_names)} suspicious process patterns")
        print("="*70)
        print("\nPress Ctrl+C to stop\n")
        
        # Initialize known processes
        self.known_processes = {proc.info['pid'] for proc in psutil.process_iter(['pid'])}
        
        try:
            while True:
                # Check for new processes
                self.check_new_processes()
                
                # Check resource usage
                self.check_resource_usage()
                
                # Display summary
                summary = self.get_process_summary()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"Processes: {summary['total_processes']} | "
                      f"CPU: {summary['cpu_percent']:.1f}% | "
                      f"Memory: {summary['memory_percent']:.1f}% | "
                      f"Available: {summary['memory_available_gb']:.2f} GB")
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Process Monitor Stopped")
            print(f"Logs saved to: {os.path.abspath(self.log_dir)}/process_monitor.log")


if __name__ == "__main__":
    monitor = ProcessMonitor()
    monitor.monitor()
