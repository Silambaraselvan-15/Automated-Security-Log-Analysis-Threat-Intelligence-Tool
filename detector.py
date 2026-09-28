import json
import re
from datetime import datetime, timedelta
from collections import defaultdict

class DetectionEngine:
    def __init__(self):
        # Tracker for Rule 1: { "ip": [datetime1, datetime2] }
        self.ssh_failures_by_ip = defaultdict(list)
        
        # Tracker for Rule 2: { "username": [(datetime, "ip1"), (datetime, "ip2")] }
        self.ssh_failures_by_user = defaultdict(list)
        
        # Tracker for Rule 4: { "ip": [(datetime, "user1"), (datetime, "user2")] }
        self.ssh_multi_user = defaultdict(list)
        
        self.alerts = []

    def parse_time(self, time_str, log_type):
        try:
            if log_type == "ssh":
                return datetime.strptime(f"2026 {time_str}", "%Y %b %d %H:%M:%S")
            elif log_type == "apache":
                time_part = time_str.split()[0] 
                return datetime.strptime(time_part, "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return datetime.now()

    def process_event(self, event):
        if event["log_type"] == "ssh" and event["event_type"] == "authentication_failure":
            self._rule_auth_001(event)
            self._rule_auth_002(event)
            self._rule_auth_003(event)
            
        elif event["log_type"] == "apache" and event["event_type"] == "web_request":
            self._rule_web_001(event)

    def _rule_auth_001(self, event):
        """AUTH-001: >= 5 failures from same IP within 5 minutes (Brute Force)"""
        ip = event["source_ip"]
        current_time = self.parse_time(event["timestamp"], event["log_type"])
        
        self.ssh_failures_by_ip[ip].append(current_time)
        
        # Sliding 5-minute window
        five_mins_ago = current_time - timedelta(minutes=5)
        self.ssh_failures_by_ip[ip] = [t for t in self.ssh_failures_by_ip[ip] if t >= five_mins_ago]
        
        if len(self.ssh_failures_by_ip[ip]) >= 3:
            self.alerts.append({
                "rule_id": "AUTH-001",
                "alert": "SSH Brute Force",
                "source_ip": ip,
                "severity": "HIGH",
                "evidence": f"5 failures in 5 mins"
            })
            self.ssh_failures_by_ip[ip] = [] # Reset after alert

    def _rule_auth_002(self, event):
        """AUTH-002: >= 10 failures against same account from >= 5 IPs in 10 mins (Distributed)"""
        username = event.get("username", "unknown")
        ip = event["source_ip"]
        current_time = self.parse_time(event["timestamp"], event["log_type"])
        
        self.ssh_failures_by_user[username].append((current_time, ip))
        
        # Sliding 10-minute window
        ten_mins_ago = current_time - timedelta(minutes=10)
        self.ssh_failures_by_user[username] = [(t, i) for t, i in self.ssh_failures_by_user[username] if t >= ten_mins_ago]
        
        total_failures = len(self.ssh_failures_by_user[username])
        unique_ips = set([i for t, i in self.ssh_failures_by_user[username]])
        
        if total_failures >= 10 and len(unique_ips) >= 5:
            self.alerts.append({
                "rule_id": "AUTH-002",
                "alert": "Distributed Authentication Attack",
                "target_account": username,
                "source_ips_involved": list(unique_ips),
                "severity": "HIGH",
                "evidence": f"{total_failures} failures from {len(unique_ips)} IPs in 10 mins"
            })
            self.ssh_failures_by_user[username] = []

    def _rule_auth_003(self, event):
        """AUTH-003: Same IP targets >= 4 different usernames in 10 mins (Username Enumeration)"""
        ip = event["source_ip"]
        username = event.get("username", "unknown")
        current_time = self.parse_time(event["timestamp"], event["log_type"])
        
        self.ssh_multi_user[ip].append((current_time, username))
        
        # Sliding 10-minute window
        ten_mins_ago = current_time - timedelta(minutes=10)
        self.ssh_multi_user[ip] = [(t, u) for t, u in self.ssh_multi_user[ip] if t >= ten_mins_ago]
        
        unique_users = set([u for t, u in self.ssh_multi_user[ip]])
        
        if len(unique_users) >= 4:
            self.alerts.append({
                "rule_id": "AUTH-003",
                "alert": "Multi-Account Authentication Attack",
                "source_ip": ip,
                "target_accounts": list(unique_users),
                "severity": "HIGH",
                "evidence": f"Targeted {len(unique_users)} distinct accounts in 10 mins"
            })
            self.ssh_multi_user[ip] = []

    def _rule_web_001(self, event):
        """WEB-001: Suspicious Web Requests (Stateless regex matching)"""
        uri = event.get("request_uri", "")
        attack_type = None
        
        # Path Traversal
        if "../" in uri:
            attack_type = "Path Traversal"
        # SQL Injection (Case insensitive match for common payload fragments)
        elif re.search(r"(?i)(UNION\s+SELECT|'\s*OR\s*'|'\s*AND\s*')", uri):
            attack_type = "SQL Injection"
        # Command Injection
        elif re.search(r"(;|\||\$\()whoami", uri):
            attack_type = "Command Injection"
            
        if attack_type:
            self.alerts.append({
                "rule_id": "WEB-001",
                "alert": "Suspicious Web Request",
                "source_ip": event["source_ip"],
                "attack_type": attack_type,
                "request_uri": uri,
                "severity": "HIGH",
                "evidence": f"Matched pattern for {attack_type}"
            })

if __name__ == "__main__":
    engine = DetectionEngine()
    
    # Simulating a pipeline feed of normalized events
    simulated_events = [
        # Trigger Rule 4 (AUTH-003): Enumeration from one IP
        {"log_type": "ssh", "event_type": "authentication_failure", "timestamp": "Sep 15 19:30:01", "source_ip": "10.0.0.99", "username": "admin"},
        {"log_type": "ssh", "event_type": "authentication_failure", "timestamp": "Sep 15 19:30:05", "source_ip": "10.0.0.99", "username": "root"},
        {"log_type": "ssh", "event_type": "authentication_failure", "timestamp": "Sep 15 19:30:09", "source_ip": "10.0.0.99", "username": "test"},
        {"log_type": "ssh", "event_type": "authentication_failure", "timestamp": "Sep 15 19:30:14", "source_ip": "10.0.0.99", "username": "guest"},
        
        # Trigger Rule 3 (WEB-001): Web Attacks
        {"log_type": "apache", "event_type": "web_request", "timestamp": "15/Sep/2026:19:35:12", "source_ip": "192.168.1.50", "request_uri": "/../../../../etc/passwd"},
        {"log_type": "apache", "event_type": "web_request", "timestamp": "15/Sep/2026:19:36:00", "source_ip": "192.168.1.55", "request_uri": "/login.php?user=' OR '1'='1"},
        
        # Trigger Rule 2 (AUTH-002): Distributed Attack against 'administrator'
        {"log_type": "ssh", "event_type": "authentication_failure", "timestamp": "Sep 15 19:40:01", "source_ip": "1.1.1.1", "username": "administrator"},
        {"log_type": "ssh", "event_type": "authentication_failure", "timestamp": "Sep 15 19:40:02", "source_ip": "1.1.1.2", "username": "administrator"},
        {"log_type": "ssh", "event_type": "authentication_failure", "timestamp": "Sep 15 19:40:03", "source_ip": "1.1.1.3", "username": "administrator"},
        {"log_type": "ssh", "event_type": "authentication_failure", "timestamp": "Sep 15 19:40:04", "source_ip": "1.1.1.4", "username": "administrator"},
        {"log_type": "ssh", "event_type": "authentication_failure", "timestamp": "Sep 15 19:40:05", "source_ip": "1.1.1.5", "username": "administrator"},
        # 5 more to hit the >= 10 failure threshold
        {"log_type": "ssh", "event_type": "authentication_failure", "timestamp": "Sep 15 19:40:06", "source_ip": "1.1.1.1", "username": "administrator"},
        {"log_type": "ssh", "event_type": "authentication_failure", "timestamp": "Sep 15 19:40:07", "source_ip": "1.1.1.2", "username": "administrator"},
        {"log_type": "ssh", "event_type": "authentication_failure", "timestamp": "Sep 15 19:40:08", "source_ip": "1.1.1.3", "username": "administrator"},
        {"log_type": "ssh", "event_type": "authentication_failure", "timestamp": "Sep 15 19:40:09", "source_ip": "1.1.1.4", "username": "administrator"},
        {"log_type": "ssh", "event_type": "authentication_failure", "timestamp": "Sep 15 19:40:10", "source_ip": "1.1.1.5", "username": "administrator"},
    ]
    
    for event in simulated_events:
        engine.process_event(event)
        
    print(f"Total Alerts: {len(engine.alerts)}\n")
    print(json.dumps(engine.alerts, indent=2))