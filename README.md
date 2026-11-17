# Sideload Cert Bot

Discord bot that generates P12 + mobileprovision + password.txt and zips them for iOS/iPadOS sideloading.

## Setup

1. Install deps:
   pip install -r requirements.txt

2. Set your bot token in bot.py:
   BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"

3. Run:
   python bot.py

## Usage

/buildcert bundle_id:com.example.myapp team_id:ABC1234567

team_id defaults to ROOST00001 if skipped — works fine for AltStore/Sideloadly/TrollStore.

## Zip Contents

- {bundle_id}.p12              — encrypted with WonkaBar123
- {bundle_id}.mobileprovision  — sideload profile
- password.txt                 — WonkaBar123

## Free Deployment Options

### Replit (easiest)
1. replit.com → New Repl → Python
2. Paste bot.py contents
3. Add token to Secrets tab (lock icon)
4. Shell: pip install "discord.py>=2.3" cryptography
5. Hit Run
6. Set up UptimeRobot (uptimerobot.com) to ping your Replit URL every 5 mins to keep it alive

### Oracle Cloud (best)
1. cloud.oracle.com → free tier signup
2. Create ARM VM (Always Free)
3. SSH in:
   sudo apt update && sudo apt install python3-pip -y
   pip install -r requirements.txt
   python3 bot.py
4. Keep alive with systemd:
   See deploy/systemd/certbot.service

### Fly.io
1. fly.io → free account
2. fly auth login
3. fly launch
4. fly deploy

## Systemd (VPS keep-alive)

Copy deploy/systemd/certbot.service to /etc/systemd/system/
Edit WorkingDirectory and ExecStart paths
systemctl enable certbot
systemctl start certbot
