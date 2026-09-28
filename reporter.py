import json
import os
from datetime import datetime

class Reporter:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        self.report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_json_report(self, stats, alerts, filename="report.json"):
        filepath = os.path.join(self.output_dir, filename)
        report_data = {
            "metadata": {
                "analysis_time": self.report_time,
                "logs_analyzed": stats,
                "total_alerts": len(alerts)
            },
            "alerts": alerts
        }
        with open(filepath, "w") as f:
            json.dump(report_data, f, indent=4)
        return filepath

    def generate_html_report(self, stats, alerts, filename="report.html"):
        """
        Generates a static HTML SOC dashboard with color-coded severity badges.
        """
        filepath = os.path.join(self.output_dir, filename)
        
        # Calculate severity totals
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for a in alerts:
            sev = a.get("severity", "LOW")
            if sev in severity_counts:
                severity_counts[sev] += 1

        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>SOC Security Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #f4f7f6; margin: 0; padding: 20px; color: #333; }}
                .container {{ max-width: 1200px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
                h1 {{ color: #2c3e50; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }}
                .stats-grid {{ display: flex; gap: 20px; margin-bottom: 30px; }}
                .stat-box {{ flex: 1; background: #ecf0f1; padding: 20px; border-radius: 6px; text-align: center; }}
                .stat-box h3 {{ margin: 0 0 10px 0; color: #7f8c8d; font-size: 14px; text-transform: uppercase; }}
                .stat-box.critical h2 {{ color: #c0392b; margin: 0; font-size: 28px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #34495e; color: white; }}
                tr:hover {{ background-color: #f5f5f5; }}
                .badge {{ padding: 5px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; color: white; }}
                .badge.CRITICAL {{ background-color: #e74c3c; }}
                .badge.HIGH {{ background-color: #e67e22; }}
                .badge.MEDIUM {{ background-color: #f1c40f; color: #333; }}
                .badge.LOW {{ background-color: #3498db; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Security Analysis Report</h1>
                <p><strong>Generated:</strong> {self.report_time}</p>
                
                <div class="stats-grid">
                    <div class="stat-box">
                        <h3>Logs Analyzed</h3>
                        <h2>{stats.get('ssh', 0) + stats.get('apache', 0):,}</h2>
                    </div>
                    <div class="stat-box critical">
                        <h3>Critical Alerts</h3>
                        <h2>{severity_counts['CRITICAL']}</h2>
                    </div>
                    <div class="stat-box">
                        <h3>High Alerts</h3>
                        <h2><span style="color: #e67e22;">{severity_counts['HIGH']}</span></h2>
                    </div>
                    <div class="stat-box">
                        <h3>Total Alerts</h3>
                        <h2>{len(alerts)}</h2>
                    </div>
                </div>

                <h2>Detailed Alerts</h2>
                <table>
                    <tr>
                        <th>Severity</th>
                        <th>Rule</th>
                        <th>Source IP</th>
                        <th>Evidence</th>
                        <th>Threat Intel (Score)</th>
                    </tr>
        """
        
        # Sort alerts by risk score (highest first)
        sorted_alerts = sorted(alerts, key=lambda x: x.get("risk_score", 0), reverse=True)
        
        for alert in sorted_alerts:
            sev = alert.get("severity", "LOW")
            ti = alert.get("threat_intel", {})
            abuse_score = ti.get("abuse_score", 0)
            ti_text = f"{abuse_score}% ({ti.get('isp', 'Unknown')})" if abuse_score > 0 else "Clean (0%)"
            
            html_content += f"""
                    <tr>
                        <td><span class="badge {sev}">{sev}</span></td>
                        <td>{alert.get('rule_id')}</td>
                        <td><strong>{alert.get('source_ip')}</strong></td>
                        <td>{alert.get('evidence')}</td>
                        <td>{ti_text}</td>
                    </tr>
            """
            
        html_content += """
                </table>
            </div>
        </body>
        </html>
        """
        
        with open(filepath, "w") as f:
            f.write(html_content)
            
        return filepath

    def print_soc_summary(self, stats, alerts):
        # (Keep your existing print_soc_summary method here)
        print("\n" + "="*40)
        print("SECURITY ANALYSIS REPORT")
        print("="*40)
        print(f"Analysis Time: {self.report_time}")
        print(f"\nLogs Analyzed:")
        for log_type, count in stats.items():
            if log_type != "dropped":
                print(f"{log_type.upper():<10} {count:,}")
            
        print(f"\nTotal Alerts: {len(alerts)}")
        
        critical_alerts = [a for a in alerts if a.get("severity") in ["HIGH", "CRITICAL"]]
        if critical_alerts:
            print("\n" + "-"*40)
            print("CRITICAL & HIGH SEVERITY ALERTS")
            print("-"*40)
            for alert in critical_alerts:
                print(f"\nRule:         {alert.get('rule_id')} - {alert.get('alert')}")
                print(f"Source IP:    {alert.get('source_ip')}")
                if "target_account" in alert:
                    print(f"Target:       {alert.get('target_account')}")
                print(f"Severity:     {alert.get('severity')} (Score: {alert.get('risk_score', 'N/A')})")
                print(f"Evidence:     {alert.get('evidence')}")
                ti = alert.get("threat_intel", {})
                if ti.get("abuse_score", 0) > 0:
                    print(f"Threat Intel: AbuseIPDB Score {ti.get('abuse_score')}% ({ti.get('isp', 'Unknown')})")
        print("\n" + "="*40)