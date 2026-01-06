from datetime import datetime

def create_case(alert_type, details):
    print(f"[{datetime.now()}] CASE CREATED")
    print(f"Type: {alert_type}")
    print(f"Details: {details}")
    print("-" * 40)

def enrich_ip(ip):
    # Mock enrichment
    malicious_ips = ["192.168.1.100", "185.220.101.1"]
    return "Malicious" if ip in malicious_ips else "Clean"

alerts = [
    {"type": "brute_force", "ip": "192.168.1.50"},
    {"type": "malware", "host": "WIN-02"},
    {"type": "suspicious_ip", "ip": "192.168.1.100"}
]

for alert in alerts:
    if alert["type"] == "brute_force":
        create_case(
            "Brute Force",
            f"Source IP {alert['ip']} – Account locked (simulated)"
        )

    elif alert["type"] == "malware":
        create_case(
            "Malware Detection",
            f"Host {alert['host']} isolated (simulated)"
        )

    elif alert["type"] == "suspicious_ip":
        reputation = enrich_ip(alert["ip"])
        create_case(
            "Suspicious Network Activity",
            f"IP {alert['ip']} reputation: {reputation} – Firewall block simulated"
        )
