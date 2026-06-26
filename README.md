<div align="center">

<img src="https://i.ibb.co.com/XfC54RkC/robot-data-phishing-cyber-attack-cloud-security-identity-theft-password-illustration-svg-download-pn.png" alt="CyberGuard Pro" width="480"/>

# 🛡️ CyberGuard Pro

**Elite Threat Intelligence Telegram Bot**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Telegram Bot](https://img.shields.io/badge/Telegram-@CyberGuardAnalyzer__bot-26A5E4?logo=telegram&logoColor=white)](https://t.me/CyberGuardAnalyzer_bot)
[![Render](https://img.shields.io/badge/Deploy-Render-000000?logo=render&logoColor=white)](https://render.com)
[![Cloudflare Workers](https://img.shields.io/badge/Worker-Cloudflare-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com)
[![MIT License](https://img.shields.io/badge/License-MIT-2ea44f)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-shihab81x%2Fcyberguard--bot-181717?logo=github&logoColor=white)](https://github.com/shihab81x/cyberguard-bot)

*Multi-API Rotation · Concurrent Users · RAM Optimized · Group Auto-Scan · Anti-Spam Moderation*

[✨ Features](#-features) · [🎮 Commands](#-commands) · [🛡️ Z Bot](#-z-bot-moderation) · [🚀 Setup](#-setup) · [🔑 Environment Variables](#-environment-variables) · [🌐 Deployment](#-deployment)

</div>

---

## ✨ Features

| Category | Details |
|----------|---------|
| 🔍 **URL Scanning** | VirusTotal + Google Safe Browsing + URLScan.io — concurrent multi-engine scan |
| 🤖 **AI Analysis** | OpenAI দিয়ে automated risk assessment ও cybersecurity Q&A |
| 📸 **Screenshot** | Microlink (fullPage) + thum.io fallback |
| 🧬 **DNS Lookup** | A, MX, NS, TXT records via Google DNS API |
| 📋 **WHOIS** | Registrar, creation/expiry date, country |
| 🖥️ **IP Check** | Reverse DNS + ipinfo.io geo-location + organization |
| 🔒 **Headers Audit** | HSTS, CSP, X-Frame-Options, X-Content-Type — A–F grade |
| 🔄 **Auto-Scan** | Group এ link paste করলে automatic scan — command লাগবে না |
| ⚡ **API Rotation** | Multiple Google/URLScan keys — quota evenly distributed |
| 🛑 **Rate Limiting** | Per-user sliding window (5 req / 60s) |
| 🧠 **Smart Skip** | Trusted domains (YouTube, Google, Telegram etc.) auto-skip |
| 🛡️ **Z Bot Moderation** | Anti-spam + unicode bypass detection + domain blacklist + auto-ban |
| 🧵 **Thread Safe** | `threading.Lock` on all shared state — zero race conditions |
| ✂️ **Message Split** | Auto-splits long reports within Telegram's 4096 char limit |

---

## 🎮 Commands

```
/start           Welcome message + command list
/check <url>     Full multi-engine threat scan
/scan <url>      Alias for /check
/dns <domain>    DNS record lookup (A, MX, NS, TXT)
/whois <domain>  WHOIS registration info
/ip <address>    IP reputation & geo check
/headers <url>   HTTP security headers audit (A–F grade)
/github          View CyberGuard Pro source code repository
/ask <question>  AI cybersecurity expert Q&A
/ping            Bot latency check
/stats           Total scans & threats found
/help            Detailed help menu
```

> 💡 **Group এ যেকোনো link পাঠালে auto-scan হবে — কোনো command লাগবে না!**

> 🔗 **Source Code → [github.com/shihab81x/cyberguard-bot](https://github.com/shihab81x/cyberguard-bot)**

---

## 🖼️ Scan Flow

```
User sends link
       │
       ▼
🛡️ CyberGuard Scanning...
━━━━━━━━━━━━━━━━━━━━━
🔍 Resolving Infrastructure...
🧬 VirusTotal Multi-Engine Scan...
🛰️ Google Safe Browsing Check...
🧪 Sandbox Detonation...
📸 Capturing Screenshot...
🤖 AI Risk Correlation...
📊 Compiling Final Report...
━━━━━━━━━━━━━━━━━━━━━
       │
       ▼
📸 Screenshot + 📊 Full Report + 🔗 VT Link
```

### Risk Verdicts

| Score | Verdict | Meaning |
|:-----:|---------|---------|
| 0–20% | 🟢 **SAFE** | No active threats detected |
| 21–59% | 🟡 **SUSPICIOUS** | Indicators present — use isolated environment |
| 60–100% | 🔴 **HIGH RISK** | High-confidence threat — avoid & escalate |

---

## 🛡️ Z Bot Moderation

CyberGuard Pro এ built-in **Z Bot** moderation module আছে যা group এর spam, adult content ও ভুয়া advertisement automatically detect করে।

### Detection Pipeline

```
Message Received
       │
       ▼
🔄 Unicode Normalizer  ←── Cyrillic/Greek/invisible chars strip
       │
       ▼
🎯 Keyword Scorer      ←── Adult + advertisement keywords
       │
       ▼
🚫 Domain Checker      ←── Blacklisted domain detect
       │
       ▼
📊 Verdict Engine
━━━━━━━━━━━━━━━━━━━━━
🟢 SAFE      →  No action
🟡 SUSPICIOUS →  Warning issued
🟠 HIGH RISK  →  Delete + Warning
🔴 DANGER     →  Delete + Warning
━━━━━━━━━━━━━━━━━━━━━
       │
       ▼
⚠️ 3 Warnings → 🔨 Auto-Ban
```

### Bypass Detection
স্প্যামাররা যেসব trick use করে Z Bot সব ধরে ফেলে:

| Trick | Example | Normalized |
|-------|---------|------------|
| Cyrillic lookalike | `ѕеx` | `sex` |
| Invisible chars | `s​e​x` | `sex` |
| Emoji flags | 🇸🇪🇽 | `sex` |
| Math bold font | `𝐬𝐞𝐱` | `sex` |

### Moderation Commands

**Admin Commands:**
```
/zban            User ban করো
/zunban          User unban করো
/zmute           User mute করো
/zunmute         User unmute করো
/zwarn           Manual warning দাও
/warnings        User এর warnings দেখো
/clearwarnings   সব warnings মুছে দাও
/rules           Group rules দেখাও
```

**Creator-Only Commands:**
```
/zlogs           Last 10 spam detection log
/zdebug <text>   Normalizer + scorer live test
/zstats          Global bot statistics
/zblacklist      Domain blacklist manage করো
/zwhitelist      Domain whitelist manage করো
/zmaintenance    Maintenance mode toggle
/zupdate         Bot version info
```

---

## 🚀 Setup

### 1. Clone
```bash
git clone https://github.com/shihab81x/cyberguard-bot.git
cd cyberguard-bot
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Environment Variables সেট করো
```bash
# Render dashboard এ অথবা .env file এ
BOT_TOKEN=your_token_here
CREATOR_ID=your_telegram_id
VT_KEY=your_virustotal_key
```

### 4. Run Locally (Polling Mode)
```bash
python bot-2-1.py
```

---

## 🔑 Environment Variables

### ✅ Required

| Variable | Description | Where to Get |
|----------|-------------|--------------|
| `BOT_TOKEN` | Telegram bot token | [@BotFather](https://t.me/BotFather) |
| `CREATOR_ID` | তোমার Telegram user ID | [@userinfobot](https://t.me/userinfobot) |
| `VT_KEY` | VirusTotal API key | [virustotal.com](https://virustotal.com) |
| `GOOGLE_KEY1` | Google Safe Browsing key | [Google Cloud Console](https://console.cloud.google.com) |
| `URLSCAN_KEY1` | URLScan.io API key | [urlscan.io](https://urlscan.io) |

### ⬜ Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `GOOGLE_KEY2` | — | 2nd Google key (rotation) |
| `URLSCAN_KEY2` | — | 2nd URLScan key (rotation) |
| `OPENAI_KEY` | — | OpenAI key (AI features) |
| `WORKER_URL` | — | Cloudflare Worker webhook URL |
| `WORKER_SECRET` | — | Webhook verification secret |
| `ZBOT_DB` | `zbot.db` | SQLite database path |
| `WARN_LIMIT` | `3` | Auto-ban এর আগে warning limit |
| `PORT` | `8080` | Flask server port |

---

## 🌐 Deployment

### Render (Recommended)

1. এই repo fork করো
2. [Render](https://render.com) এ নতুন **Web Service** তৈরি করো
3. GitHub repo connect করো
4. সব environment variables Render dashboard এ দাও
5. **Start Command** সেট করো:
```
python bot-2-1.py
```
6. Deploy করো!

### Cloudflare Worker (Webhook Mode)

`WORKER_URL` ও `WORKER_SECRET` set করলে bot automatically webhook mode এ চলবে। Polling এর চেয়ে webhook অনেক দ্রুত ও efficient।

---

## 🗂️ Project Structure

```
cyberguard-bot/
├── bot-2-1.py        # Main bot — CyberGuard Pro
├── zbot.py           # Z Bot moderation module
├── requirements.txt  # Python dependencies
├── Procfile          # Render process file
└── README.md         # This file
```

---

## 📜 License

MIT License — free to use, modify, and distribute.

---

<div align="center">

**🤖 Try it now → [@CyberGuardAnalyzer_bot](https://t.me/CyberGuardAnalyzer_bot)**

⚡ Built with Python · python-telegram-bot · Flask · VirusTotal · Google Safe Browsing · URLScan.io · OpenAI

</div>
