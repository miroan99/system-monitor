# Python Project Template

A clean starter template for any Python project.

## Setup
1. Create a virtual environment:
   ```Powershell
   cd system-monitor 
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   python main.py 


2. Program elements

Network Connections
- Shows all active connections, which programs are connecting where, and groups them by process

Listening Ports
- Identifies programs waiting for incoming connections (potential backdoors or servers)

Process Analysis
- Scans for suspicious process names and identifies programs with high network usage

Network Statistics
- Overall data sent/received, errors, and packet counts

System Info
- Basic details about your computer and when the scan ran

3. For best results
- run as administrator (right-click Command Prompt/PowerShell → "Run as administrator" then run the script)

4. What to Look For
- Unknown processes with network connections
- Listening ports you don't recognize (common safe ones: 80/443 for web, 22 for SSH, 3389 for Remote Desktop)
- Suspicious names containing words like "miner", "keylog", etc.
- High network usage from unexpected programs

The script is safe to run and only reads information - it doesn't modify anything on your system. 