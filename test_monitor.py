from monitor import detect_bruteforce


def make_events(n, user="admin", ip="10.0.0.5", status="failed"):
    return [{"user": user, "ip": ip, "status": status} for _ in range(n)]


def test_no_events_no_alerts():
    assert detect_bruteforce([]) == []


def test_below_threshold_no_alert():
    assert detect_bruteforce(make_events(4)) == []


def test_at_threshold_alerts():
    alerts = detect_bruteforce(make_events(5))
    assert {"type": "bruteforce_user", "user": "admin", "count": 5} in alerts
    assert {"type": "bruteforce_ip", "ip": "10.0.0.5", "count": 5} in alerts


def test_dash_ip_is_ignored():
    alerts = detect_bruteforce(make_events(5, ip="-"))
    assert len(alerts) == 1
    assert alerts[0]["type"] == "bruteforce_user"


def test_successful_logins_are_not_counted():
    assert detect_bruteforce(make_events(10, status="success")) == []