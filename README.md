# Log Monitor

**Goal:** Detect brute-force login attempts on a Windows PC.
**Input:** Windows Security log, event ID 4625 (failed logon).
**Output:** An alert if one account or IP has 5 or more failures in 60 minutes.