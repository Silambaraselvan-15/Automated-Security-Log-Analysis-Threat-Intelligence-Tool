import json
import random
from datetime import datetime, timedelta

def generate_ssh_log(timestamp, ip, user, success=False):
    status = "Accepted" if success else "Failed"
    return f"{timestamp.strftime('%b %d %H:%M:%S')} cyberdoc sshd[{random.randint(1000,9999)}]: {status} password for {user} from {ip} port {random.randint(10000, 60000)} ssh2"

def generate_apache_log(timestamp, ip, uri, status_code=200):
    return f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S")} +0530] "GET {uri} HTTP/1.1" {status_code} {random.randint(500, 5000)}'

def build_datasets():
    scenarios = []
    raw_logs = []
    base_time = datetime(2026, 9, 15, 12, 0, 0)
    scenario_id = 1
    
    # ---------------------------------------------------------
    # 1. SSH Brute Force (AUTH-001) - Scenarios 1 to 20
    # ---------------------------------------------------------
    for i in range(20):
        ip = f"192.168.10.{i}"
        attempts = random.choice([3, 4, 5, 7, 10]) # Mix of above and below threshold
        should_detect = attempts >= 5
        
        scenario_logs = []
        for j in range(attempts):
            log_time = base_time + timedelta(seconds=j*10)
            scenario_logs.append(generate_ssh_log(log_time, ip, "admin"))
            
        scenarios.append({
            "scenario_id": scenario_id,
            "category": "AUTH-001",
            "description": f"SSH Brute Force with {attempts} attempts",
            "source_ip": ip,
            "expected_detection": should_detect
        })
        raw_logs.extend(scenario_logs)
        scenario_id += 1
        base_time += timedelta(minutes=10)

    # ---------------------------------------------------------
    # 2. Distributed Auth Attack (AUTH-002) - Scenarios 21 to 35
    # ---------------------------------------------------------
    for i in range(15):
        target_user = f"service_account_{i}"
        num_ips = random.choice([3, 5, 7])
        total_attempts = random.choice([8, 10, 15])
        should_detect = num_ips >= 5 and total_attempts >= 10
        
        scenario_logs = []
        for j in range(total_attempts):
            ip = f"10.0.{i}.{j % num_ips}"
            log_time = base_time + timedelta(seconds=j*15)
            scenario_logs.append(generate_ssh_log(log_time, ip, target_user))
            
        scenarios.append({
            "scenario_id": scenario_id,
            "category": "AUTH-002",
            "description": f"Distributed attack from {num_ips} IPs",
            "target_user": target_user,
            "expected_detection": should_detect
        })
        raw_logs.extend(scenario_logs)
        scenario_id += 1
        base_time += timedelta(minutes=15)

    # ---------------------------------------------------------
    # 3. Multi-Account Attack (AUTH-003) - Scenarios 36 to 50
    # ---------------------------------------------------------
    for i in range(15):
        ip = f"172.16.50.{i}"
        num_users = random.choice([2, 3, 4, 6])
        should_detect = num_users >= 4
        
        scenario_logs = []
        for j in range(num_users):
            log_time = base_time + timedelta(seconds=j*5)
            scenario_logs.append(generate_ssh_log(log_time, ip, f"user_{j}"))
            
        scenarios.append({
            "scenario_id": scenario_id,
            "category": "AUTH-003",
            "description": f"Enumeration of {num_users} accounts",
            "source_ip": ip,
            "expected_detection": should_detect
        })
        raw_logs.extend(scenario_logs)
        scenario_id += 1
        base_time += timedelta(minutes=10)

    # ---------------------------------------------------------
    # 4. Web Attacks (WEB-001) - Scenarios 51 to 65
    # ---------------------------------------------------------
    payloads = [
        ("../../etc/passwd", True),
        ("index.php?id=' OR '1'='1", True),
        ("search?q=;whoami", True),
        ("about.html", False),           # Benign
        ("api/v1/health", False)         # Benign
    ]
    for i in range(15):
        ip = f"203.0.113.{i}"
        uri, should_detect = random.choice(payloads)
        
        scenarios.append({
            "scenario_id": scenario_id,
            "category": "WEB-001",
            "description": f"Web request to {uri}",
            "source_ip": ip,
            "expected_detection": should_detect
        })
        raw_logs.append(generate_apache_log(base_time, ip, f"/{uri}"))
        scenario_id += 1
        base_time += timedelta(minutes=5)
        
    # ---------------------------------------------------------
    # 5. Benign Traffic / Noise - Scenarios 66 to 70
    # ---------------------------------------------------------
    for i in range(5):
        ip = f"198.51.100.{i}"
        # A normal user mistyping a password twice, then succeeding
        raw_logs.append(generate_ssh_log(base_time, ip, "legit_user", success=False))
        raw_logs.append(generate_ssh_log(base_time + timedelta(seconds=10), ip, "legit_user", success=False))
        raw_logs.append(generate_ssh_log(base_time + timedelta(seconds=20), ip, "legit_user", success=True))
        
        scenarios.append({
            "scenario_id": scenario_id,
            "category": "BENIGN",
            "description": "Normal user password typo then success",
            "source_ip": ip,
            "expected_detection": False
        })
        scenario_id += 1
        base_time += timedelta(minutes=5)

    # Save outputs
    with open("scenarios.json", "w") as f:
        json.dump(scenarios, f, indent=4)
        
    with open("test_traffic.log", "w") as f:
        f.write("\n".join(raw_logs) + "\n")
        
    print(f"Generated {len(scenarios)} scenarios and {len(raw_logs)} raw log lines.")

if __name__ == "__main__":
    build_datasets()