import json

# Import the modules we built in Steps 1-5
from parser import parse_log
from detector import DetectionEngine

def run_tests():
    # 1. Load the ground-truth metadata
    print("Loading scenarios...")
    try:
        with open("scenarios.json", "r") as f:
            scenarios = json.load(f)
    except FileNotFoundError:
        print("Error: scenarios.json not found. Run dataset_builder.py first.")
        return

    # 2. Run the detection pipeline
    engine = DetectionEngine()
    print("Ingesting test_traffic.log into the detection engine...")
    with open("test_traffic.log", "r") as f:
        for line in f:
            # Step A: Parse raw string to normalized JSON dictionary
            event = parse_log(line.strip())
            if event:
                # Step B: Feed dictionary to the stateful rules engine
                engine.process_event(event)

    # 3. Extract the entities that triggered alerts
    # We use Sets here for fast lookup. 
    # AUTH-002 alerts on usernames; the rest alert on source IPs.
    alerted_ips = {alert.get("source_ip") for alert in engine.alerts if alert.get("source_ip")}
    alerted_users = {alert.get("target_account") for alert in engine.alerts if alert.get("target_account")}

    # 4. Evaluate engine accuracy
    true_positives = 0  # Attack occurred, alert fired
    false_positives = 0 # No attack, but alert fired (False Alarm)
    true_negatives = 0  # No attack, no alert (Normal Traffic)
    false_negatives = 0 # Attack occurred, no alert (Missed Detection)

    print("\n" + "="*70)
    print(f"{'ID':<5} | {'Category':<10} | {'Expected':<10} | {'Actual':<10} | {'Result'}")
    print("-" * 70)

    for s in scenarios:
        expected = s["expected_detection"]
        
        # Determine if our engine actually fired an alert for this scenario's actor
        if s["category"] == "AUTH-002":
            actual = s["target_user"] in alerted_users
        else:
            actual = s["source_ip"] in alerted_ips

        # Tally the results
        if expected and actual:
            result = "True Positive (Hit)"
            true_positives += 1
        elif not expected and not actual:
            result = "True Negative (Correct Reject)"
            true_negatives += 1
        elif expected and not actual:
            result = "False Negative (Miss)"
            false_negatives += 1
        elif not expected and actual:
            result = "False Positive (False Alarm)"
            false_positives += 1

        print(f"{s['scenario_id']:<5} | {s['category']:<10} | {str(expected):<10} | {str(actual):<10} | {result}")

    # 5. Final Report
    print("\n" + "="*50)
    print("TEST FRAMEWORK SUMMARY")
    print("="*50)
    print(f"Total Scenarios Evaluated : {len(scenarios)}")
    print(f"True Positives (Attacks caught)   : {true_positives}")
    print(f"True Negatives (Benign ignored)   : {true_negatives}")
    print(f"False Positives (False alarms)    : {false_positives}")
    print(f"False Negatives (Missed attacks)  : {false_negatives}")
    
    correct = true_positives + true_negatives
    accuracy = (correct / len(scenarios)) * 100
    print(f"\nOverall Detection Accuracy: {correct}/{len(scenarios)} ({accuracy:.2f}%)")

if __name__ == "__main__":
    run_tests()