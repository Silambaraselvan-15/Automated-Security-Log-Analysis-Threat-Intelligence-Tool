import json

class RiskScorer:
    def __init__(self):
        # Base scores define how inherently dangerous a local rule is
        self.base_scores = {
            "AUTH-001": 70,  # SSH Brute Force
            "AUTH-002": 85,  # Distributed Authentication Attack (Very dangerous)
            "AUTH-003": 75,  # Multi-Account Authentication Attack
            "WEB-001":  75   # Suspicious Web Request
        }

    def evaluate(self, alert, threat_intel):
        """
        Calculates a final risk score by combining local detection base scores
        with external threat intelligence modifiers.
        """
        # 1. Get the base score from the local detection rule
        rule_id = alert.get("rule_id", "UNKNOWN")
        base_score = self.base_scores.get(rule_id, 50)
        
        # 2. Calculate the threat intelligence modifier
        abuse_score = threat_intel.get("abuse_confidence_score", 0)
        intel_modifier = 0
        
        if abuse_score >= 80:
            intel_modifier = 20
        elif abuse_score >= 50:
            intel_modifier = 10
        elif abuse_score > 0:
            intel_modifier = 5
            
        # 3. Calculate final score (capped at 100)
        final_score = min(base_score + intel_modifier, 100)
        
        # 4. Determine final qualitative severity
        if final_score >= 80:
            severity = "CRITICAL"
        elif final_score >= 60:
            severity = "HIGH"
        elif final_score >= 30:
            severity = "MEDIUM"
        else:
            severity = "LOW"
            
        # 5. Build the enriched alert
        enriched_alert = alert.copy()
        enriched_alert["threat_intel"] = {
            "abuse_score": abuse_score,
            "country": threat_intel.get("country"),
            "isp": threat_intel.get("isp")
        }
        enriched_alert["risk_score"] = final_score
        enriched_alert["severity"] = severity
        
        return enriched_alert

if __name__ == "__main__":
    scorer = RiskScorer()
    
    # Simulating an alert from detector.py
    local_alert = {
        "rule_id": "AUTH-001",
        "alert": "SSH Brute Force",
        "source_ip": "192.168.10.5",
        "severity": "HIGH",
        "evidence": "5 failures in 5 mins"
    }
    
    # Simulating the response from threat_intel.py
    ti_response = {
        "ip": "192.168.10.5",
        "abuse_confidence_score": 92,
        "country": "XX",
        "isp": "Malicious Hosting Corp",
        "total_reports": 150
    }
    
    final_alert = scorer.evaluate(local_alert, ti_response)
    
    print("--- Enriched Security Alert ---")
    print(json.dumps(final_alert, indent=4))