import re
import json


# To parse and extract useful and strucured logs from the unstructured logs/strings

def parse_ssh_log(log_line):

    """ we have to extract 1.timestamp
                           2.hostname
                           3.pid
                           4.auth_result
                           5.username
                           6.IP
                           7.port"""

    pattern = r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<auth_result>Failed|Accepted)\s+password\s+for\s+(invalid\s+user\s+)?(?P<username>\S+)\s+from\s+(?P<source_ip>\S+)\s+port\s+(?P<source_port>\d+)"
    match = re.search(pattern, log_line)
    if match:
        event_type = "authentication_failure" if match.group('auth_result') == "Failed" else "authentication_success"
        return {
            "log_type": "ssh",
            "event_type": event_type,
            "timestamp": match.group('timestamp'),
            "source_ip": match.group('source_ip'),
            # SSH-specific fields
            "hostname": match.group('hostname'),
            "username": match.group('username'),
            "source_port": int(match.group('source_port'))
        }
    return None

def parse_apache_log(log_line):

    """
   We have to extract 1.IP
                      2.timestamp
                      3.method
                      4.URI
                      5.status code
                      6.response size.
    """
    # Regex to parse the Common/Combined Log Format

    pattern = r'^(?P<source_ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<request_uri>\S+)\s+(?P<http_version>[^"]+)"\s+(?P<status_code>\d{3})\s+(?P<response_size>\d+|-)'
    match = re.search(pattern, log_line)
    if match:
        size = match.group('response_size')
        response_size = "Response Size Not Available" if size == '-' else int(size)
        return {
            "log_type": "apache",
            "event_type": "web_request",
            "timestamp": match.group('timestamp'),
            "source_ip": match.group('source_ip'),
            # Apache-specific fields
            "http_method": match.group('method'),
            "request_uri": match.group('request_uri'),
            "status_code": int(match.group('status_code')),
            "response_size": response_size
        }
    return None

def parse_log(log_line):
    """
    Unified router that attempts to parse a log line using available parsers.
    Returns the normalized event dictionary, or None if unrecognized.
    """
    # Try SSH first based on a quick keyword check to save regex processing time
    if "sshd[" in log_line:
        return parse_ssh_log(log_line)
    
    # Try Apache parser
    apache_event = parse_apache_log(log_line)
    if apache_event:
        return apache_event
        
    # If it matches neither (e.g., a background cron log), drop it
    return None

if __name__ == "__main__":
    # A mix of logs simulating a raw stream from a server
    raw_logs = [
        "Sep 15 19:30:01 cyberdoc sshd[1201]: Failed password for admin from 192.168.1.50 port 54321 ssh2",
        '10.10.10.10 - - [15/Sep/2026:19:35:12 +0530] "GET /index.php?cmd=whoami HTTP/1.1" 200 1542',
        "Sep 15 19:31:00 cyberdoc CRON[1250]: pam_unix(cron:session): session opened for user root",
        "Sep 15 19:36:44 cyberdoc sshd[1305]: Accepted password for root from 10.0.0.5 port 2222 ssh2"
    ]
    
    print("--- Unified Log Processing Stream ---")
    for line in raw_logs:
        event = parse_log(line)
        if event:
            print(f"[+] Successfully normalized {event['log_type'].upper()} event from {event['source_ip']}")
            print(json.dumps(event, indent=2))
        else:
            print(f"[-] Dropped unrecognized log format: {line[:50]}...")