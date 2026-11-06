from collections import Counter

THRESHOLD = 5

def detect_bruteforce(events,threshold=THRESHOLD):
    alerts = []
    by_user = Counter(event['user'] for event in events if event['status'] == 'failed')
    by_ip = Counter(event['ip'] for event in events if event['status'] == 'failed')
    
    for user, count in by_user.items():
        if count >= threshold:
            alerts.append({'user': user, 'type': 'bruteforce_user'})

    for ip, count in by_ip.items():
        if count >= threshold:
            alerts.append({'ip': ip, 'type': 'bruteforce_ip'})

    return alerts