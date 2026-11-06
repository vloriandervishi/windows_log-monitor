import json
import subprocess

LOOKBACK_MINUTES = 60

PS_COMMAND = (
    "Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625; "
    "StartTime=(Get-Date).AddMinutes(-{minutes})}} -ErrorAction SilentlyContinue | "
    "Select-Object "
    "@{{n='time';e={{$_.TimeCreated.ToString('o')}}}}, "
    "@{{n='user';e={{$_.Properties[5].Value}}}}, "
    "@{{n='ip';e={{$_.Properties[19].Value}}}} | ConvertTo-Json"
)


def get_failed_logins(minutes=LOOKBACK_MINUTES):
    """Return failed-logon events from the Windows Security log."""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", PS_COMMAND.format(minutes=minutes)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"PowerShell error: {result.stderr.strip()}")

    output = result.stdout.strip()
    if not output:
        return []

    data = json.loads(output)
    if isinstance(data, dict):  # PowerShell returns one object, not a list
        data = [data]
    return [{**event, "status": "failed"} for event in data]