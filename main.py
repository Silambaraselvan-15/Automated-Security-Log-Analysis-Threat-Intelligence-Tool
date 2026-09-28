import os
import time

# Import all our custom modules
from parser import parse_log
from detector import DetectionEngine
from threat_intel import ThreatIntel
from scorer import RiskScorer
from reporter import Reporter

def run_pipeline(log_file_path):
    print(f"[*] Starting Security Log Analysis Pipeline on: {log_file_path}")
    start_time = time.time()
    
    # 1. Initialize Components
    engine = DetectionEngine()
    intel = ThreatIntel()
    scorer = RiskScorer()
    reporter = Reporter()
    
    stats = {"ssh": 0, "apache": 0, "dropped": 0}
    
    # 2. Ingest & Parse Logs
    print("[*] Phase 1: Parsing and Normalization...")
    if not os.path.exists(log_file_path):
        print(f"[-] Error: {log_file_path} not found.")
        print("    Run 'python dataset_builder.py' first to generate test data.")
        return

    with open(log_file_path, "r") as f:
        for line in f:
            event = parse_log(line.strip())
            
            if event:
                stats[event["log_type"]] += 1
                # 3. Local Detection
                engine.process_event(event)
            else:
                stats["dropped"] += 1

    print(f"[+] Ingestion complete. Events parsed: SSH ({stats['ssh']}), Apache ({stats['apache']})")
    print(f"[+] Initial Alerts Generated: {len(engine.alerts)}")
    
    # 4. Threat Intelligence & Risk Scoring
    print("\n[*] Phase 2: Threat Intelligence & Risk Correlation...")
    enriched_alerts = []
    
    # To avoid querying AbuseIPDB for the same IP multiple times, we cache results
    ti_cache = {}
    
    for alert in engine.alerts:
        ip = alert.get("source_ip")
        
        # If the alert has an IP, check it against Threat Intel
        if ip:
            if ip not in ti_cache:
                ti_cache[ip] = intel.check_ip(ip)
            
            ti_data = ti_cache[ip]
        else:
            # Fallback for alerts that might not be IP-based (e.g., internal system alerts)
            ti_data = {}
            
        # Correlate local alert with external intel to get final risk score
        final_alert = scorer.evaluate(alert, ti_data)
        enriched_alerts.append(final_alert)

    # 5. Reporting
    print("\n[*] Phase 3: Generating Output Reports...")
    
    # Generate JSON
    json_path = reporter.generate_json_report(stats, enriched_alerts)
    print(f"[+] JSON report saved successfully to {json_path}")
    
    # Generate HTML
    html_path = reporter.generate_html_report(stats, enriched_alerts)
    print(f"[+] HTML dashboard saved successfully to {html_path}")
    
    # Print the analyst-friendly summary to the terminal
    reporter.print_soc_summary(stats, enriched_alerts)
    elapsed = time.time() - start_time
    print(f"\n[+] Pipeline completed in {elapsed:.2f} seconds.")

if __name__ == "__main__":
    # We will run this on the 70-scenario log file we generated in Step 6
    TEST_LOG_FILE = "test_traffic.log"
    run_pipeline(TEST_LOG_FILE)