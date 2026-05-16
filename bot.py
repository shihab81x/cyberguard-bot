"""
╔══════════════════════════════════════════════════╗
║         CyberGuard Pro — Telegram Bot            ║
║    Architecture: Cloudflare Worker + Render      ║
║    Mode: Webhook Only  (RAM Optimized)           ║
╚══════════════════════════════════════════════════╝
"""

import os, re, asyncio, base64, logging, socket, threading
from datetime import datetime, timezone

import httpx
from flask import Flask, request, Response
from telegram import Update, BotCommand, constants
from telegram.ext import (
    ApplicationBuilder, CommandHandler,
    MessageHandler, filters, ContextTypes,
)

# ═══════════════════════════════════════════════════
#  LOGGING
# ═══════════════════════════════════════════════════
logging.basicConfig(
    format="%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("CyberGuard")

# ═══════════════════════════════════════════════════
#  CONFIG  ── all overridable via Render env vars
# ═══════════════════════════════════════════════════
BOT_TOKEN     = os.environ.get("BOT_TOKEN",     "8961784854:AAELWCP6aliyzDX3x0F2ohLTwd2FZSu2tAA")
VT_KEY        = os.environ.get("VT_KEY",        "aa40f9a40b779d2e1684d10c11d23391538569ebc01a4fb82d62b9bfc5d157d0")
AI_KEY        = os.environ.get("AI_KEY",        "AIzaSyDk7FWMBKsNwjWFl3FTsejKtkCPpfsWQPE")
WORKER_SECRET = os.environ.get("WORKER_SECRET", "CyberGuardX2025")   # shared with CF Worker
WORKER_URL    = os.environ.get("WORKER_URL",    "")                  # https://xxx.workers.dev
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
    "apple.com","amazon.com","twitter.com","x.com","linkedin.com",
    "wikipedia.org","stackoverflow.com","reddit.com","discord.com","telegram.org",
}

# TLD গুলো যেগুলো scammers বেশি ব্যবহার করে
RISKY_TLDS = {
    ".site", ".xyz", ".top", ".online", ".club", ".icu", ".pw",
    ".tk", ".ml", ".cf", ".ga", ".gq", ".info", ".biz", ".vip",
    ".work", ".rest", ".fun", ".live", ".world", ".uno", ".click",
}

# URL path/domain এ এগুলো থাকলে সরাসরি SUSPICIOUS
SUSPICIOUS_KEYWORDS = {
    "girl", "sex", "xxx", "porn", "adult", "nude", "naked", "escort",
    "paid", "onlyfan", "leak", "hack", "free-money", "win-prize",
    "login-verify", "account-suspend", "verify-now", "limited-offer",
}

URL_RE = re.compile(r"(https?://)?([a-zA-Z0-9\-]+\.[a-zA-Z0-9.\-]+(/[^\s]*)?)")

# ═══════════════════════════════════════════════════
#  KEY ROTATION
# ═══════════════════════════════════════════════════
_gi = _ui = 0

def _next_keys():
    global _gi, _ui
    g = GOOGLE_KEYS[_gi  % len(GOOGLE_KEYS)]
    u = URLSCAN_KEYS[_ui % len(URLSCAN_KEYS)]
    _gi += 1; _ui += 1
    return g, u

# ═══════════════════════════════════════════════════
#  SCAN ENGINES
# ═══════════════════════════════════════════════════

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
    payload = {
        "client": {"clientId": "cyberguard", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE","SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
                json=payload,
            )
            return bool(r.json().get("matches"))
    except:
        return False


async def urlscan(url: str, key: str) -> tuple:
    try:
        headers = {"API-Key": key, "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=35) as c:
            r = await c.post(
                "https://urlscan.io/api/v1/scan/",
                headers=headers,
                json={"url": url, "visibility": "private"},
            )
            uuid = r.json().get("uuid")
            if not uuid: return None, 0
            await asyncio.sleep(20)
            res  = await c.get(f"https://urlscan.io/api/v1/result/{uuid}/")
            score = res.json().get("verdicts", {}).get("overall", {}).get("score", 0)
            return f"https://urlscan.io/screenshots/{uuid}.png", score
    except Exception as e:
        logger.warning(f"URLScan: {e}")
        return None, 0


async def website_screenshot(url: str) -> str | None:
    """
    thum.io দিয়ে যেকোনো সাইটের screenshot নিয়ে আসে।
    Free, no API key, সবসময় কাজ করে।
    """
    try:
        shot_url = f"https://image.thum.io/get/width/1280/crop/800/noanimate/{url}"
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
            r = await c.get(shot_url)
            if r.status_code == 200 and "image" in r.headers.get("content-type", ""):
                return shot_url
    except Exception as e:
        logger.warning(f"Screenshot: {e}")
    return None


async def dns_lookup(domain: str) -> dict:
    info = {"A": [], "MX": [], "NS": []}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            for rt in ("A", "MX", "NS"):
                r = await c.get("https://dns.google/resolve", params={"name": domain, "type": rt})
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

# ═══════════════════════════════════════════════════
#  AI ENGINE (Gemini 1.5 Flash)
# ═══════════════════════════════════════════════════

_SYSTEM = (
    "You are CyberGuard AI — an elite threat intelligence analyst. "
    "You give concise (2-3 sentence), technically precise, actionable security assessments. "
    "No greetings. No disclaimers. Pure signal."
)
_SAFETY_OFF = [
    {"category": c, "threshold": "BLOCK_NONE"}
    for c in [
        "HARM_CATEGORY_HARASSMENT","HARM_CATEGORY_HATE_SPEECH",
        "HARM_CATEGORY_SEXUALLY_EXPLICIT","HARM_CATEGORY_DANGEROUS_CONTENT",
    ]
]


async def _gemini(prompt: str, max_tokens: int = 200) -> str | None:
    body = {
        "system_instruction": {"parts": [{"text": _SYSTEM}]},
        "contents":           [{"parts": [{"text": prompt}]}],
        "safetySettings": _SAFETY_OFF,
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": max_tokens},
    }
    try:
        async with httpx.AsyncClient(timeout=25) as c:
            r = await c.post(f"{AI_ENDPOINT}?key={AI_KEY}", json=body)
            return r.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
    except:
        return None


async def ai_url_insight(domain, vt, gs, us, risk) -> str:
    prompt = (
        f"Domain: {domain}\n"
        f"VirusTotal: {vt['malicious']} malicious / {vt['suspicious']} suspicious\n"
        f"Google Safe Browsing: {'THREAT' if gs else 'clean'}\n"
        f"Sandbox score: {us}/100  |  Aggregate risk: {risk}%\n"
        f"Categories: {', '.join(vt['categories']) or 'unknown'}\n"
        f"Write a 2-3 sentence technical security assessment."
    )
    result = await _gemini(prompt)
    if result: return result
    if risk >= 60: return "High-confidence threat detected across multiple intelligence feeds. Escalate to your security team."
    if risk >= 21: return "Suspicious signals present. Use an isolated environment before proceeding."
    return "No active threats identified. Maintain standard hygiene and monitor for anomalies."


async def ai_qa(question: str) -> str:
    result = await _gemini(question, max_tokens=400)
    return result or "⚠️ AI engine temporarily unavailable."

# ═══════════════════════════════════════════════════
#  ANIMATION
# ═══════════════════════════════════════════════════

_STEPS = [
    ("🔍", "Resolving Infrastructure..."),
    ("🧬", "VirusTotal Multi-Engine Scan..."),
    ("🛰️", "Google Threat Intelligence..."),
    ("🧪", "Sandbox Detonation..."),
    ("🤖", "AI Risk Correlation..."),
    ("📊", "Compiling Report..."),
]


async def animate(msg):
    for icon, step in _STEPS:
        try:
            await msg.edit_text(
                f"🛡️ *CyberGuard Analysis*\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n"
                f"{icon} `{step}`\n"
                f"━━━━━━━━━━━━━━━━━━━━━",
                parse_mode="Markdown",
            )
            await asyncio.sleep(3)
        except:
            break

# ═══════════════════════════════════════════════════
#  COMMAND HANDLERS
# ═══════════════════════════════════════════════════

async def cmd_start(u: Update, _):
    await u.message.reply_text(
        "🛡️ *CyberGuard Pro*\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Elite threat intelligence, zero compromise.\n\n"
        "📌 *Commands:*\n"
        "• `/check <url>` — Full URL threat scan\n"
        "• `/dns <domain>` — DNS record lookup\n"
        "• `/whois <domain>` — Domain WHOIS info\n"
        "• `/ip <address>` — IP reputation check\n"
        "• `/ask <question>` — AI security expert\n"
        "• `/help` — This menu\n\n"
        "💡 Send any URL directly in private chat for instant scan.\n\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "⚡ VirusTotal · Google SB · URLScan · Gemini AI",
        parse_mode="Markdown",
    )

async def cmd_help(u, c): await cmd_start(u, c)


async def cmd_check(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    raw = re.sub(r"^/check\s*", "", u.message.text or "").strip()
    if not raw:
        await u.message.reply_text("❗ Usage: `/check <url>`", parse_mode="Markdown")
        return

    m = URL_RE.search(raw)
    if not m:
        await u.message.reply_text("❗ No valid URL found.")
        return

    full_url = m.group(0)
    if not full_url.startswith("http"):
        full_url = "https://" + full_url
    domain      = m.group(2).split("/")[0].lower()
    full_lower  = full_url.lower()

    status = await u.message.reply_text("📡 *Initialising CyberGuard...*", parse_mode="Markdown")
    anim   = asyncio.create_task(animate(status))

    gk, uk = _next_keys()
    vt, gs, (us_shot, us), shot = await asyncio.gather(
        vt_scan(full_url),
        google_sb(full_url, gk),
        urlscan(full_url, uk),
        website_screenshot(full_url),
    )
    anim.cancel()

    # ── Risk scoring ───────────────────────────────
    trusted = any(d in domain for d in TRUSTED_DOMAINS)

    # Risky TLD check
    tld          = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
    risky_tld    = tld in RISKY_TLDS

    # Suspicious keyword in full URL
    kw_hits      = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_lower]
    has_sus_kw   = len(kw_hits) > 0

    if trusted:
        risk = 0
    else:
        risk = min(
            100,
            (50 if vt["malicious"] > 2 else 20 if vt["malicious"] > 0 else 0)
            + (50 if gs else 0)
            + int(us / 5)
            + (20 if risky_tld   else 0)   # .site / .xyz / .top এ +20
            + (25 if has_sus_kw  else 0),  # suspicious keyword এ +25
        )

    # Collect all warning flags for the report
    flags = []
    if risky_tld:  flags.append(f"⚠️ High-risk TLD `{tld}`")
    if has_sus_kw: flags.append(f"⚠️ Suspicious keywords: `{', '.join(kw_hits[:4])}`")
    if gs:         flags.append("⚠️ Google Safe Browsing threat match")
    if vt["malicious"] > 0:
        flags.append(f"⚠️ VirusTotal: {vt['malicious']} engines flagged")

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
        f"🔗 *URL:* `{full_url[:55]}`\n"
        f"🌐 *Domain:* `{domain}`\n"
        f"📌 *Identity:* {'✅ Verified Infrastructure' if trusted else '⚠️ Unverified Web'}\n\n"
        f"🏁 *VERDICT:* {verdict}\n"
        f"📊 *Risk:* `{risk}%`  `[{bar}]`\n\n"
        f"🧪 *Engine Results:*\n"
        f"  • VirusTotal:  `{vt['malicious']} malicious / {vt['suspicious']} suspicious`\n"
        f"  • Google SB:   `{'⚠️ THREAT DETECTED' if gs else '✅ Clean'}`\n"
        f"  • Sandbox:     `{us}/100 risk score`\n"
    )
    if vt["categories"]:
        report += f"  • Categories:  `{', '.join(vt['categories'])}`\n"

    if flags:
        report += f"\n🚩 *Risk Flags:*\n"
        for f_ in flags:
            report += f"  {f_}\n"

    report += (
        f"\n🤖 *AI Insight:*\n_{insight}_\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ CyberGuard Pro · {ts}"
    )

    try: await status.delete()
    except: pass

    # Screenshot: URLScan এর shot (risky site হলে) অথবা thum.io shot (সবসময়)
    final_shot = (us_shot if (us_shot and risk >= 21) else None) or shot

    if final_shot:
        try:
            await u.message.reply_photo(
                photo=final_shot, caption=report,
                parse_mode=constants.ParseMode.MARKDOWN,
            )
            return
        except:
            pass

    await u.message.reply_text(report, parse_mode="Markdown")


async def cmd_dns(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await u.message.reply_text("❗ Usage: `/dns <domain>`", parse_mode="Markdown"); return
    domain = ctx.args[0].lower().strip()
    msg    = await u.message.reply_text(f"🔍 `Resolving {domain}...`", parse_mode="Markdown")
    d      = await dns_lookup(domain)
    def fmt(lst): return "".join(f"  `{x}`\n" for x in lst) or "  `—`\n"
    await msg.edit_text(
        f"🌐 *DNS — {domain}*\n━━━━━━━━━━━━━━━━━━━━━\n"
        f"📍 *A:*\n{fmt(d['A'])}📬 *MX:*\n{fmt(d['MX'])}🗂️ *NS:*\n{fmt(d['NS'])}"
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
    await msg.edit_text(
        f"🖥️ *IP — {ip}*\n━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔀 *Hostname:* `{hostname}`\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n⚡ CyberGuard IP",
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
        f"❓ _{q}_\n\n💬 {ans}\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n⚡ Gemini 1.5 Flash",
        parse_mode="Markdown",
    )


async def handle_text(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not u.message or not u.message.text: return

    text      = u.message.text.strip()
    chat_type = u.message.chat.type
    is_group  = chat_type in (
        constants.ChatType.GROUP,
        constants.ChatType.SUPERGROUP,
    )
    is_private = chat_type == constants.ChatType.PRIVATE

    # ── Group: শুধু link থাকলেই scan, normal text সম্পূর্ণ ignore ──
    if is_group:
        # Telegram নিজেই entity হিসেবে link mark করে — সবচেয়ে accurate
        found_url = None
        for ent in (u.message.entities or []):
            if ent.type == "url":
                found_url = text[ent.offset : ent.offset + ent.length]
                break
            elif ent.type == "text_link":
                found_url = ent.url
                break

        # Entity তে না পেলে regex fallback
        if not found_url:
            m = URL_RE.search(text)
            found_url = m.group(0) if m else None

        # Link নেই → চুপ থাকো, কিছু করো না
        if not found_url:
            return

        u.message.text = "/check " + found_url
        await cmd_check(u, ctx)
        return

    # ── Private: link → scan, বাকি সব → AI expert ──
    if is_private:
        if URL_RE.search(text):
            u.message.text = "/check " + text
            await cmd_check(u, ctx)
        else:
            u.message.text = "/ask " + text
            await cmd_ask(u, ctx)

# ═══════════════════════════════════════════════════
#  FLASK  (webhook receiver)
# ═══════════════════════════════════════════════════

flask_app   = Flask(__name__)
_ptb_app    = None
_event_loop = asyncio.new_event_loop()


def _run_loop():
    asyncio.set_event_loop(_event_loop)
    _event_loop.run_forever()


async def _boot():
    global _ptb_app
    _ptb_app = ApplicationBuilder().token(BOT_TOKEN).build()

    _ptb_app.add_handler(CommandHandler("start",  cmd_start))
    _ptb_app.add_handler(CommandHandler("help",   cmd_help))
    _ptb_app.add_handler(CommandHandler("check",  cmd_check))
    _ptb_app.add_handler(CommandHandler("dns",    cmd_dns))
    _ptb_app.add_handler(CommandHandler("whois",  cmd_whois))
    _ptb_app.add_handler(CommandHandler("ip",     cmd_ip))
    _ptb_app.add_handler(CommandHandler("ask",    cmd_ask))
    _ptb_app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    await _ptb_app.initialize()
    await _ptb_app.start()

    if WORKER_URL:
        wh = f"{WORKER_URL.rstrip('/')}/telegram"
        await _ptb_app.bot.set_webhook(url=wh, secret_token=WORKER_SECRET)
        logger.info(f"Webhook registered → {wh}")

    await _ptb_app.bot.set_my_commands([
        BotCommand("start",  "Welcome & commands"),
        BotCommand("check",  "Full URL threat scan"),
        BotCommand("dns",    "DNS record lookup"),
        BotCommand("whois",  "Domain WHOIS info"),
        BotCommand("ip",     "IP reputation check"),
        BotCommand("ask",    "Ask AI security expert"),
        BotCommand("help",   "Help menu"),
    ])
    logger.info("CyberGuard Pro ready ✅")


@flask_app.route("/", methods=["GET"])
def health():
    return Response("🛡️ CyberGuard Pro — Online", status=200)


@flask_app.route("/telegram", methods=["POST"])
def tg_webhook():
    # Verify origin — only accept from our Cloudflare Worker
    if request.headers.get("X-Worker-Secret", "") != WORKER_SECRET:
        logger.warning("Rejected webhook — invalid secret")
        return Response("Forbidden", status=403)

    data   = request.get_json(force=True, silent=True)
    if not data:
        return Response("Bad Request", status=400)

    update = Update.de_json(data, _ptb_app.bot)
    asyncio.run_coroutine_threadsafe(_ptb_app.process_update(update), _event_loop)
    return Response("ok", status=200)

# ═══════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════

if __name__ == "__main__":
    threading.Thread(target=_run_loop, daemon=True).start()
    asyncio.run_coroutine_threadsafe(_boot(), _event_loop).result(timeout=30)
    logger.info(f"Flask on :{PORT}")
    flask_app.run(host="0.0.0.0", port=PORT, use_reloader=False, threaded=True)
