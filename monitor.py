from collections import Counter

THRESHOLD = 5


def detect_bruteforce(events, threshold=THRESHOLD):
    """Return alert dicts for users/IPs with >= threshold failed logins."""
    failed = [e for e in events if e.get("status") == "failed"]
    by_user = Counter(e["user"] for e in failed)
    by_ip = Counter(e["ip"] for e in failed if e["ip"] not in ("-", ""))

    alerts = []
    for user, count in by_user.items():
        if count >= threshold:
            alerts.append({"type": "bruteforce_user", "user": user, "count": count})
    for ip, count in by_ip.items():
        if count >= threshold:
            alerts.append({"type": "bruteforce_ip", "ip": ip, "count": count})
    return alerts