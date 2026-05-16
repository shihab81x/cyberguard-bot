"""
╔══════════════════════════════════════════════════════╗
║           CyberGuard Pro  —  Telegram Bot            ║
║   Cloudflare Worker + Render  |  RAM Optimized       ║
║   Concurrent users ✅  Group link scan ✅            ║
╚══════════════════════════════════════════════════════╝
"""

import os, re, asyncio, base64, logging, socket, threading, time
from datetime import datetime, timezone
from collections import defaultdict

import httpx
from flask import Flask, request, Response
from telegram import Update, BotCommand, constants, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    CallbackQueryHandler, filters, ContextTypes,
)

# ══════════════════════════════════════════════════════
#  LOGGING
# ══════════════════════════════════════════════════════
logging.basicConfig(
    format="%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("CyberGuard")

# ══════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════
BOT_TOKEN     = os.environ.get("BOT_TOKEN",     "8961784854:AAELWCP6aliyzDX3x0F2ohLTwd2FZSu2tAA")
VT_KEY        = os.environ.get("VT_KEY",        "aa40f9a40b779d2e1684d10c11d23391538569ebc01a4fb82d62b9bfc5d157d0")
AI_KEY        = os.environ.get("AI_KEY",        "AIzaSyDk7FWMBKsNwjWFl3FTsejKtkCPpfsWQPE")
WORKER_SECRET = os.environ.get("WORKER_SECRET", "CyberGuardX2025")
WORKER_URL    = os.environ.get("WORKER_URL",    "")
PORT          = int(os.environ.get("PORT",      8080))

GOOGLE_KEYS  = [
    os.environ.get("GOOGLE_KEY1", "AIzaSyDV4BKDASUxA2OKvuPCjun-4_ABjLTxD6E"),
    os.environ.get("GOOGLE_KEY2", "AIzaSyDHA8tCLwxdu3TB3YY91AkCJx-sJ89HQsg"),
]
URLSCAN_KEYS = [
    os.environ.get("URLSCAN_KEY1", "019e2194-ea13-766f-bc24-285934b33d8b"),
    os.environ.get("URLSCAN_KEY2", "019e2195-ad51-7728-bd17-b687a47f6aab"),
]

AI_ENDPOINT = (
    "https://generativelanguage.googleapis.com"
    "/v1beta/models/gemini-1.5-flash-latest:generateContent"
)

TRUSTED_DOMAINS = {
    "youtube.com","youtu.be","google.com","facebook.com","instagram.com",
    "github.com","render.com","cloudflare.com","netflix.com","microsoft.com",
    "apple.com","amazon.com","twitter.com","x.com","linkedin.com","wikipedia.org",
    "stackoverflow.com","reddit.com","discord.com","telegram.org","tiktok.com",
    "whatsapp.com","zoom.us","dropbox.com","drive.google.com","docs.google.com",
}

RISKY_TLDS = {
    ".site",".xyz",".top",".online",".club",".icu",".pw",".tk",".ml",
    ".cf",".ga",".gq",".info",".biz",".vip",".work",".rest",".fun",
    ".live",".world",".uno",".click",".loan",".win",".download",".stream",
}

SUSPICIOUS_KW = {
    "girl","sex","xxx","porn","adult","nude","naked","escort","paid",
    "onlyfan","leak","free-money","win-prize","login-verify","verify-now",
    "account-suspend","limited-offer","claim-now","lucky-winner","bit.ly",
}

URL_RE = re.compile(r"(https?://)?([a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(/[^\s]*)?)")

# ══════════════════════════════════════════════════════
#  STATS & RATE LIMIT
# ══════════════════════════════════════════════════════
_stats = {"scans": 0, "threats": 0, "started": datetime.now(timezone.utc)}
_rate  = defaultdict(list)   # user_id → [timestamps]
RATE_LIMIT = 5               # max 5 scans per 60s per user

def _check_rate(user_id: int) -> bool:
    now = time.time()
    _rate[user_id] = [t for t in _rate[user_id] if now - t < 60]
    if len(_rate[user_id]) >= RATE_LIMIT:
        return False
    _rate[user_id].append(now)
    return True

# ══════════════════════════════════════════════════════
#  KEY ROTATION
# ══════════════════════════════════════════════════════
_gi = _ui = 0

def _next_keys():
    global _gi, _ui
    g = GOOGLE_KEYS[_gi  % len(GOOGLE_KEYS)]
    u = URLSCAN_KEYS[_ui % len(URLSCAN_KEYS)]
    _gi += 1; _ui += 1
    return g, u

# ══════════════════════════════════════════════════════
#  SCAN ENGINES  (সব asyncio → concurrent users OK)
# ══════════════════════════════════════════════════════

async def vt_scan(url: str) -> dict:
    out = {"malicious": 0, "suspicious": 0, "categories": [], "link": ""}
    try:
        uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(
                f"https://www.virustotal.com/api/v3/urls/{uid}",
                headers={"x-apikey": VT_KEY},
            )
            if r.status_code == 200:
                a = r.json()["data"]["attributes"]
                s = a.get("last_analysis_stats", {})
                out.update({
                    "malicious":  s.get("malicious",  0),
                    "suspicious": s.get("suspicious", 0),
                    "categories": list(a.get("categories", {}).values())[:3],
                    "link": f"https://www.virustotal.com/gui/url/{uid}",
                })
    except Exception as e:
        logger.warning(f"VT: {e}")
    return out


async def google_sb(url: str, key: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
                json={
                    "client": {"clientId": "cyberguard", "clientVersion": "2.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE","SOCIAL_ENGINEERING",
                                        "UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}],
                    },
                },
            )
            return bool(r.json().get("matches"))
    except:
        return False


async def urlscan(url: str, key: str) -> tuple:
    try:
        async with httpx.AsyncClient(timeout=35) as c:
            r = await c.post(
                "https://urlscan.io/api/v1/scan/",
                headers={"API-Key": key, "Content-Type": "application/json"},
                json={"url": url, "visibility": "private"},
            )
            uuid = r.json().get("uuid")
            if not uuid: return None, 0
            await asyncio.sleep(20)
            res   = await c.get(f"https://urlscan.io/api/v1/result/{uuid}/")
            score = res.json().get("verdicts", {}).get("overall", {}).get("score", 0)
            return f"https://urlscan.io/screenshots/{uuid}.png", score
    except Exception as e:
        logger.warning(f"URLScan: {e}")
        return None, 0


async def screenshot(url: str) -> str | None:
    try:
        shot = f"https://image.thum.io/get/width/1280/crop/800/noanimate/{url}"
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
            r = await c.get(shot)
            if r.status_code == 200 and "image" in r.headers.get("content-type", ""):
                return shot
    except:
        pass
    return None


async def http_headers(url: str) -> dict:
    """HTTP Security Headers check করো।"""
    checks = {
        "Strict-Transport-Security": "❌",
        "Content-Security-Policy":   "❌",
        "X-Frame-Options":           "❌",
        "X-Content-Type-Options":    "❌",
    }
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as c:
            r = await c.head(url)
            for h in checks:
                if h.lower() in {k.lower() for k in r.headers}:
                    checks[h] = "✅"
    except:
        pass
    return checks


async def dns_lookup(domain: str) -> dict:
    info = {"A": [], "MX": [], "NS": [], "TXT": []}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            for rt in ("A", "MX", "NS", "TXT"):
                r = await c.get(
                    "https://dns.google/resolve",
                    params={"name": domain, "type": rt}
                )
                info[rt] = [a["data"] for a in r.json().get("Answer", [])[:3]]
    except:
        pass
    return info


async def whois_lookup(domain: str) -> dict:
    info = {"registrar": "N/A", "created": "N/A", "expires": "N/A", "country": "N/A"}
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get(f"https://whoisjson.com/api/v1/whois?domain={domain}")
            if r.status_code == 200:
                d = r.json()
                info = {
                    "registrar": d.get("registrar",          "N/A"),
                    "created":   d.get("creation_date",      "N/A"),
                    "expires":   d.get("expiry_date",        "N/A"),
                    "country":   d.get("registrant_country", "N/A"),
                }
    except:
        pass
    return info

# ══════════════════════════════════════════════════════
#  AI ENGINE
# ══════════════════════════════════════════════════════
_SYSTEM = (
    "You are CyberGuard AI — an elite cybersecurity analyst. "
    "Give concise (2-3 sentence), technically precise, actionable security assessments. "
    "No greetings. No disclaimers. Pure signal only."
)
_SAFETY = [
    {"category": c, "threshold": "BLOCK_NONE"}
    for c in ["HARM_CATEGORY_HARASSMENT","HARM_CATEGORY_HATE_SPEECH",
              "HARM_CATEGORY_SEXUALLY_EXPLICIT","HARM_CATEGORY_DANGEROUS_CONTENT"]
]

async def _gemini(prompt: str, max_tokens: int = 220) -> str | None:
    try:
        async with httpx.AsyncClient(timeout=25) as c:
            r = await c.post(
                f"{AI_ENDPOINT}?key={AI_KEY}",
                json={
                    "system_instruction": {"parts": [{"text": _SYSTEM}]},
                    "contents":           [{"parts": [{"text": prompt}]}],
                    "safetySettings":     _SAFETY,
                    "generationConfig":   {"temperature": 0.2, "maxOutputTokens": max_tokens},
                },
            )
            return r.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
    except:
        return None

async def ai_url_insight(domain, vt, gs, us, risk) -> str:
    r = await _gemini(
        f"Domain:{domain} | VT:{vt['malicious']}M/{vt['suspicious']}S | "
        f"GoogleSB:{'THREAT' if gs else 'clean'} | Sandbox:{us}/100 | Risk:{risk}%\n"
        f"Categories:{', '.join(vt['categories']) or 'unknown'}\n"
        f"Write 2-3 sentence technical security assessment."
    )
    if r: return r
    if risk >= 60: return "High-confidence threat across multiple feeds. Avoid and report immediately."
    if risk >= 21: return "Suspicious signals detected. Use isolated environment before proceeding."
    return "No active threats. Maintain standard security hygiene."

async def ai_qa(q: str) -> str:
    r = await _gemini(q, max_tokens=450)
    return r or "⚠️ AI engine temporarily unavailable. Try again shortly."

# ══════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════
_STEPS = [
    ("🔍", "Resolving Infrastructure..."),
    ("🧬", "VirusTotal Multi-Engine Scan..."),
    ("🛰️", "Google Threat Intelligence..."),
    ("🧪", "Sandbox Detonation..."),
    ("📸", "Capturing Screenshot..."),
    ("🤖", "AI Risk Correlation..."),
    ("📊", "Compiling Final Report..."),
]

async def _animate(msg):
    for icon, step in _STEPS:
        try:
            await msg.edit_text(
                f"🛡️ *CyberGuard Scanning...*\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n"
                f"{icon} `{step}`\n"
                f"━━━━━━━━━━━━━━━━━━━━━",
                parse_mode="Markdown",
            )
            await asyncio.sleep(3)
        except:
            break

def _extract_url(text: str, entities=None) -> str | None:
    """Telegram entity থেকে link খোঁজো, না পেলে regex।"""
    for ent in (entities or []):
        if ent.type == "url":
            return text[ent.offset: ent.offset + ent.length]
        if ent.type == "text_link":
            return ent.url
    m = URL_RE.search(text)
    return m.group(0) if m else None

def _risk_score(vt, gs, us, domain, full_url) -> tuple:
    trusted = any(d in domain for d in TRUSTED_DOMAINS)
    if trusted:
        return 0, []

    tld       = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
    risky_tld = tld in RISKY_TLDS
    kw_hits   = [k for k in SUSPICIOUS_KW if k in full_url.lower()]

    risk = min(
        100,
        (50 if vt["malicious"] > 2 else 20 if vt["malicious"] > 0 else 0)
        + (50 if gs else 0)
        + int(us / 5)
        + (20 if risky_tld else 0)
        + (25 if kw_hits else 0),
    )

    flags = []
    if risky_tld:        flags.append(f"⚠️ High-risk TLD `{tld}`")
    if kw_hits:          flags.append(f"⚠️ Suspicious keywords: `{', '.join(kw_hits[:4])}`")
    if gs:               flags.append("⚠️ Google Safe Browsing threat match")
    if vt["malicious"]:  flags.append(f"⚠️ {vt['malicious']} AV engines flagged")

    return risk, flags

# ══════════════════════════════════════════════════════
#  COMMAND HANDLERS
# ══════════════════════════════════════════════════════

async def cmd_start(u: Update, _):
    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton("📖 Help",       callback_data="help"),
        InlineKeyboardButton("📊 Stats",      callback_data="stats"),
    ],[
        InlineKeyboardButton("🔍 Scan a URL", switch_inline_query_current_chat="/check "),
    ]])
    await u.message.reply_text(
        "🛡️ *CyberGuard Pro*\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "Elite threat intelligence for your group.\n\n"
        "📌 *Commands:*\n"
        "• `/check <url>` — Full URL threat scan\n"
        "• `/dns <domain>` — DNS records\n"
        "• `/whois <domain>` — Domain WHOIS\n"
        "• `/ip <address>` — IP reputation\n"
        "• `/headers <url>` — HTTP security headers\n"
        "• `/ask <question>` — AI security expert\n"
        "• `/ping` — Bot latency check\n"
        "• `/stats` — Scan statistics\n"
        "• `/help` — Full help menu\n\n"
        "💡 Group এ যেকোনো link পাঠালে auto-scan হবে!\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "⚡ VT · Google SB · URLScan · Gemini AI",
        parse_mode="Markdown",
        reply_markup=kb,
    )

async def cmd_help(u: Update, _):
    await u.message.reply_text(
        "🛡️ *CyberGuard Pro — Help*\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "🔍 *URL Scan:*\n"
        "`/check https://example.com`\n"
        "VirusTotal + Google SB + Sandbox + AI analysis\n\n"
        "🌐 *DNS Lookup:*\n"
        "`/dns google.com`\n"
        "A, MX, NS, TXT records\n\n"
        "📋 *WHOIS:*\n"
        "`/whois google.com`\n"
        "Registrar, dates, country\n\n"
        "🖥️ *IP Check:*\n"
        "`/ip 8.8.8.8`\n"
        "Hostname + PTR record\n\n"
        "🔒 *HTTP Headers:*\n"
        "`/headers https://example.com`\n"
        "Security headers audit\n\n"
        "🤖 *AI Expert:*\n"
        "`/ask What is phishing?`\n"
        "Cybersecurity Q&A\n\n"
        "📊 `/stats` — Total scan count\n"
        "🏓 `/ping` — Response time\n\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "💡 Group এ link paste করলে auto scan হয়!",
        parse_mode="Markdown",
    )

async def cmd_ping(u: Update, _):
    t = time.time()
    msg = await u.message.reply_text("🏓 Pinging...")
    ms  = int((time.time() - t) * 1000)
    await msg.edit_text(
        f"🏓 *Pong!*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ Latency: `{ms}ms`\n"
        f"🟢 Status: `Online`\n"
        f"━━━━━━━━━━━━━━━━━━━━━",
        parse_mode="Markdown",
    )

async def cmd_stats(u: Update, _):
    uptime = datetime.now(timezone.utc) - _stats["started"]
    hours  = int(uptime.total_seconds() // 3600)
    await u.message.reply_text(
        f"📊 *CyberGuard Stats*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔍 Total Scans:   `{_stats['scans']}`\n"
        f"🚨 Threats Found: `{_stats['threats']}`\n"
        f"⏱️ Uptime:        `{hours}h`\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ CyberGuard Pro",
        parse_mode="Markdown",
    )

async def cmd_check(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    user_id = u.effective_user.id
    if not _check_rate(user_id):
        await u.message.reply_text(
            "⏳ Too many requests! Wait 60 seconds.", parse_mode="Markdown"
        )
        return

    raw = re.sub(r"^/check\s*", "", u.message.text or "").strip()
    if not raw:
        await u.message.reply_text("❗ Usage: `/check <url>`", parse_mode="Markdown")
        return

    found = _extract_url(raw, u.message.entities)
    if not found:
        await u.message.reply_text("❗ No valid URL found.")
        return

    full_url = found if found.startswith("http") else "https://" + found
    domain   = re.sub(r"https?://", "", full_url).split("/")[0].lower()

    status = await u.message.reply_text("📡 *Initialising CyberGuard...*", parse_mode="Markdown")
    anim   = asyncio.create_task(_animate(status))

    gk, uk = _next_keys()

    # সব engine একসাথে চলে — concurrent users এ কোনো সমস্যা নেই
    vt, gs, (us_shot, us), shot = await asyncio.gather(
        vt_scan(full_url),
        google_sb(full_url, gk),
        urlscan(full_url, uk),
        screenshot(full_url),
    )
    anim.cancel()

    risk, flags = _risk_score(vt, gs, us, domain, full_url)
    _stats["scans"]  += 1
    if risk >= 60: _stats["threats"] += 1

    insight = await ai_url_insight(domain, vt, gs, us, risk)
    verdict = (
        "🔴 *HIGH RISK*"  if risk >= 60 else
        "🟡 *SUSPICIOUS*" if risk >= 21 else
        "🟢 *SAFE*"
    )
    bar = "█" * (risk // 10) + "░" * (10 - risk // 10)
    ts  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    report = (
        f"🛡️ *CyberGuard Threat Report*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔗 `{full_url[:55]}`\n"
        f"🌐 *Domain:* `{domain}`\n\n"
        f"🏁 *VERDICT:* {verdict}\n"
        f"📊 `[{bar}]` `{risk}%`\n\n"
        f"🧪 *Scan Results:*\n"
        f"  • VirusTotal  `{vt['malicious']}M / {vt['suspicious']}S`\n"
        f"  • Google SB   `{'⚠️ THREAT' if gs else '✅ Clean'}`\n"
        f"  • Sandbox     `{us}/100`\n"
    )
    if vt["categories"]:
        report += f"  • Category    `{', '.join(vt['categories'])}`\n"
    if flags:
        report += f"\n🚩 *Risk Flags:*\n" + "".join(f"  {f}\n" for f in flags)
    report += (
        f"\n🤖 *AI Insight:*\n_{insight}_\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ CyberGuard Pro · {ts}"
    )

    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton("🔗 VT Report", url=vt["link"]) if vt["link"] else
        InlineKeyboardButton("🛡️ CyberGuard", url="https://t.me"),
    ]]) if vt["link"] else None

    try: await status.delete()
    except: pass

    final_shot = (us_shot if (us_shot and risk >= 21) else None) or shot
    if final_shot:
        try:
            await u.message.reply_photo(
                photo=final_shot, caption=report,
                parse_mode=constants.ParseMode.MARKDOWN,
                reply_markup=kb,
            )
            return
        except: pass

    await u.message.reply_text(report, parse_mode="Markdown", reply_markup=kb)


async def cmd_dns(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await u.message.reply_text("❗ Usage: `/dns <domain>`", parse_mode="Markdown"); return
    domain = ctx.args[0].lower().strip()
    msg = await u.message.reply_text(f"🔍 `Resolving {domain}...`", parse_mode="Markdown")
    d   = await dns_lookup(domain)
    def fmt(lst): return "".join(f"  `{x}`\n" for x in lst) or "  `—`\n"
    await msg.edit_text(
        f"🌐 *DNS — {domain}*\n━━━━━━━━━━━━━━━━━━━━━\n"
        f"📍 *A:*\n{fmt(d['A'])}"
        f"📬 *MX:*\n{fmt(d['MX'])}"
        f"🗂️ *NS:*\n{fmt(d['NS'])}"
        f"📝 *TXT:*\n{fmt(d['TXT'])}"
        f"━━━━━━━━━━━━━━━━━━━━━\n⚡ CyberGuard DNS",
        parse_mode="Markdown",
    )


async def cmd_whois(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await u.message.reply_text("❗ Usage: `/whois <domain>`", parse_mode="Markdown"); return
    domain = ctx.args[0].lower().strip()
    msg    = await u.message.reply_text(f"🔍 `WHOIS {domain}...`", parse_mode="Markdown")
    d      = await whois_lookup(domain)
    await msg.edit_text(
        f"📋 *WHOIS — {domain}*\n━━━━━━━━━━━━━━━━━━━━━\n"
        f"🏢 *Registrar:* `{d['registrar']}`\n"
        f"📅 *Created:*   `{d['created']}`\n"
        f"⏳ *Expires:*   `{d['expires']}`\n"
        f"🌍 *Country:*   `{d['country']}`\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n⚡ CyberGuard WHOIS",
        parse_mode="Markdown",
    )


async def cmd_ip(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await u.message.reply_text("❗ Usage: `/ip <address>`", parse_mode="Markdown"); return
    ip       = ctx.args[0].strip()
    msg      = await u.message.reply_text(f"🔍 `Analysing {ip}...`", parse_mode="Markdown")
    hostname = "N/A"
    try: hostname = socket.gethostbyaddr(ip)[0]
    except: pass
    d = await dns_lookup(ip)
    await msg.edit_text(
        f"🖥️ *IP — {ip}*\n━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔀 *Hostname:* `{hostname}`\n"
        f"📡 *PTR:* `{d['A'][0] if d['A'] else 'N/A'}`\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n⚡ CyberGuard IP",
        parse_mode="Markdown",
    )


async def cmd_headers(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await u.message.reply_text("❗ Usage: `/headers <url>`", parse_mode="Markdown"); return
    url = ctx.args[0].strip()
    if not url.startswith("http"): url = "https://" + url
    msg     = await u.message.reply_text(f"🔒 `Checking headers...`", parse_mode="Markdown")
    headers = await http_headers(url)
    score   = sum(1 for v in headers.values() if v == "✅")
    grade   = "A" if score == 4 else "B" if score == 3 else "C" if score == 2 else "D" if score == 1 else "F"
    await msg.edit_text(
        f"🔒 *HTTP Headers — {url[:40]}*\n━━━━━━━━━━━━━━━━━━━━━\n"
        + "".join(f"  {v} `{h}`\n" for h, v in headers.items())
        + f"\n📊 *Security Grade:* `{grade}` ({score}/4)\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n⚡ CyberGuard Headers",
        parse_mode="Markdown",
    )


async def cmd_ask(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = re.sub(r"^/ask\s*", "", u.message.text or "").strip()
    if not q:
        await u.message.reply_text("❗ Usage: `/ask <question>`", parse_mode="Markdown"); return
    msg = await u.message.reply_text("🤖 `Consulting AI Expert...`", parse_mode="Markdown")
    ans = await ai_qa(q)
    await msg.edit_text(
        f"🤖 *CyberGuard AI Expert*\n━━━━━━━━━━━━━━━━━━━━━\n"
        f"❓ _{q}_\n\n{ans}\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n⚡ Gemini 1.5 Flash",
        parse_mode="Markdown",
    )


async def handle_text(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not u.message or not u.message.text: return
    text      = u.message.text.strip()
    chat_type = u.message.chat.type
    is_group  = chat_type in (constants.ChatType.GROUP, constants.ChatType.SUPERGROUP)
    is_private = chat_type == constants.ChatType.PRIVATE

    if is_group:
        found = _extract_url(text, u.message.entities)
        if not found: return   # normal text → সম্পূর্ণ ignore
        u.message.text = "/check " + found
        await cmd_check(u, ctx)

    elif is_private:
        if _extract_url(text, u.message.entities):
            u.message.text = "/check " + text
            await cmd_check(u, ctx)
        else:
            u.message.text = "/ask " + text
            await cmd_ask(u, ctx)


async def handle_callback(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = u.callback_query
    await q.answer()
    if q.data == "help":
        await cmd_help(u, ctx)
    elif q.data == "stats":
        await cmd_stats(u, ctx)

# ══════════════════════════════════════════════════════
#  FLASK
# ══════════════════════════════════════════════════════
flask_app   = Flask(__name__)
_ptb_app    = None
_event_loop = asyncio.new_event_loop()

def _run_loop():
    asyncio.set_event_loop(_event_loop)
    _event_loop.run_forever()

def _register_handlers(app):
    app.add_handler(CommandHandler("start",   cmd_start))
    app.add_handler(CommandHandler("help",    cmd_help))
    app.add_handler(CommandHandler("check",   cmd_check))
    app.add_handler(CommandHandler("scan",    cmd_check))   # alias
    app.add_handler(CommandHandler("dns",     cmd_dns))
    app.add_handler(CommandHandler("whois",   cmd_whois))
    app.add_handler(CommandHandler("ip",      cmd_ip))
    app.add_handler(CommandHandler("headers", cmd_headers))
    app.add_handler(CommandHandler("ask",     cmd_ask))
    app.add_handler(CommandHandler("ping",    cmd_ping))
    app.add_handler(CommandHandler("stats",   cmd_stats))
    app.add_handler(CallbackQueryHandler(handle_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

_COMMANDS = [
    BotCommand("start",   "Welcome & commands"),
    BotCommand("check",   "Full URL threat scan"),
    BotCommand("dns",     "DNS record lookup"),
    BotCommand("whois",   "Domain WHOIS info"),
    BotCommand("ip",      "IP reputation check"),
    BotCommand("headers", "HTTP security headers"),
    BotCommand("ask",     "Ask AI security expert"),
    BotCommand("ping",    "Bot latency check"),
    BotCommand("stats",   "Scan statistics"),
    BotCommand("help",    "Help menu"),
]

async def _boot():
    global _ptb_app
    _ptb_app = ApplicationBuilder().token(BOT_TOKEN).build()
    _register_handlers(_ptb_app)
    await _ptb_app.initialize()
    await _ptb_app.start()
    if WORKER_URL:
        wh = f"{WORKER_URL.rstrip('/')}/telegram"
        await _ptb_app.bot.set_webhook(url=wh, secret_token=WORKER_SECRET)
        logger.info(f"Webhook → {wh}")
    await _ptb_app.bot.set_my_commands(_COMMANDS)
    logger.info("CyberGuard Pro ready ✅")


@flask_app.route("/", methods=["GET"])
def health():
    return Response("🛡️ CyberGuard Pro — Online", status=200)


@flask_app.route("/telegram", methods=["POST"])
def tg_webhook():
    if request.headers.get("X-Worker-Secret", "") != WORKER_SECRET:
        return Response("Forbidden", status=403)
    data = request.get_json(force=True, silent=True)
    if not data: return Response("Bad Request", status=400)
    update = Update.de_json(data, _ptb_app.bot)
    asyncio.run_coroutine_threadsafe(_ptb_app.process_update(update), _event_loop)
    return Response("ok", status=200)

# ══════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════
if __name__ == "__main__":
    if WORKER_URL:
        # Webhook mode (Cloudflare আছে)
        threading.Thread(target=_run_loop, daemon=True).start()
        asyncio.run_coroutine_threadsafe(_boot(), _event_loop).result(timeout=30)
        logger.info(f"Webhook mode on :{PORT}")
        flask_app.run(host="0.0.0.0", port=PORT, use_reloader=False, threaded=True)
    else:
        # Polling mode (Cloudflare ছাড়া)
        logger.info("Polling mode...")
        poll = ApplicationBuilder().token(BOT_TOKEN).build()
        _register_handlers(poll)

        async def _post_init(app):
            await app.bot.set_my_commands(_COMMANDS)

        poll.post_init = _post_init
        threading.Thread(
            target=lambda: flask_app.run(host="0.0.0.0", port=PORT, use_reloader=False),
            daemon=True,
        ).start()
        poll.run_polling(allowed_updates=Update.ALL_TYPES)
