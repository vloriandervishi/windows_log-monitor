import json
import subprocess

LOOKBACK_MINUTES = 60

FAILED_LOGON_COMMAND = (
    "Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625; "
    "StartTime=(Get-Date).AddMinutes(-{minutes})}} | "
    "Select-Object "
    "@{{n='time';e={{$_.TimeCreated.ToString('o')}}}}, "
    "@{{n='user';e={{$_.Properties[5].Value}}}}, "
    "@{{n='ip';e={{$_.Properties[19].Value}}}} | ConvertTo-Json"
)

GENERIC_COMMAND = (
    "Get-WinEvent -FilterHashtable @{{LogName='{log}'; Id={ids}; "
    "StartTime=(Get-Date).AddMinutes(-{minutes})}} | "
    "Select-Object "
    "@{{n='time';e={{$_.TimeCreated.ToString('o')}}}}, "
    "Id, "
    "@{{n='message';e={{$_.Message}}}} | ConvertTo-Json"
)


def _run_powershell(command):
    """Run a PowerShell command and return its parsed JSON output as a list."""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        err = result.stderr.strip()
        if "No events were found" in err:
            return []  # nothing matched, which is a normal result
        raise RuntimeError(f"PowerShell exited {result.returncode}: {err}")

    output = result.stdout.strip()
    if not output:
        return []

    data = json.loads(output)
    return [data] if isinstance(data, dict) else data  # one result comes back as a dict


def get_failed_logins(minutes=LOOKBACK_MINUTES):
    """Return failed-logon events (4625) from the Windows Security log."""
    command = FAILED_LOGON_COMMAND.format(minutes=minutes)
    return [{**event, "status": "failed"} for event in _run_powershell(command)]


def get_events(log, ids, minutes=LOOKBACK_MINUTES):
    """Return events with the given IDs from a Windows event log."""
    command = GENERIC_COMMAND.format(
        log=log, ids=",".join(map(str, ids)), minutes=minutes
    )
    return _run_powershell(command)