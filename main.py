from collector import get_failed_logins
from monitor import detect_bruteforce


def main():
    events = get_failed_logins()
    print(f"{len(events)} failed logins in the last hour")
    for alert in detect_bruteforce(events):
        print(alert)


if __name__ == "__main__":
    main()