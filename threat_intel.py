import requests
import json
import os

class ThreatIntel:
    def __init__(self, api_key=None):
        # Use provided key, check environment variables, or fallback to DEMO mode
        self.api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "DEMO_KEY")
        self.base_url = "https://api.abuseipdb.com/api/v2/check"

    def check_ip(self, ip_address):
        """
        Queries AbuseIPDB for an IP address. 
        Returns a dictionary containing the abuse confidence score and contextual metadata.
        """
        # Bypass network requests if using the demo key for offline testing
        if self.api_key == "DEMO_KEY":
            return self._mock_response(ip_address)

        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90'
        }

        try:
            response = requests.get(self.base_url, headers=headers, params=params, timeout=5)
            
            if response.status_code == 200:
                data = response.json()['data']
                return {
                    "ip": ip_address,
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "country": data.get("countryCode", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "domain": data.get("domain", "Unknown"),
                    "total_reports": data.get("totalReports", 0)
                }
            else:
                print(f"[-] AbuseIPDB API Error: HTTP {response.status_code}")
                return self._fallback_response(ip_address)
                
        except requests.exceptions.RequestException as e:
            print(f"[-] Threat Intel Connection Error: {e}")
            return self._fallback_response(ip_address)

    def _mock_response(self, ip_address):
        """
        Simulates AbuseIPDB responses for our 70-scenario test dataset.
        Ensures the pipeline can be demonstrated without exhausting API limits.
        """
        # We simulate high abuse scores for the IPs used in our attack scenarios
        if ip_address.startswith("192.168.10.") or ip_address.startswith("10.0."):
            return {
                "ip": ip_address,
                "abuse_confidence_score": 87,
                "country": "XX",
                "isp": "Simulated Malicious ISP",
                "domain": "attacker.net",
                "total_reports": 142
            }
            
        # Clean IPs return a score of 0
        return self._fallback_response(ip_address)

    def _fallback_response(self, ip_address):
        """Safe fallback to ensure the pipeline continues if the API is down."""
        return {
            "ip": ip_address,
            "abuse_confidence_score": 0,
            "country": "Unknown",
            "isp": "Unknown",
            "domain": "Unknown",
            "total_reports": 0
        }

if __name__ == "__main__":
    # Initialize without passing a key. It will automatically grab the environment variable you just set in the terminal.
    intel = ThreatIntel() 
    
    print("--- Testing Live Threat Intelligence API ---")
    
    # Test a known public DNS server (should return 0 abuse score)
    print("\n[+] Checking Google DNS (8.8.8.8):")
    print(json.dumps(intel.check_ip("8.8.8.8"), indent=4))
    
    # Test a random public IP to see a real internet payload
    print("\n[+] Checking a public IP (185.156.73.14):")
    print(json.dumps(intel.check_ip("185.156.73.14"), indent=4))