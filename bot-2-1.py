from __future__ import annotations

"""
╔══════════════════════════════════════════════════════════╗
║            CyberGuard Pro  —  Telegram Bot               ║
║  Render + Cloudflare Worker  |  RAM Optimized            ║
║  Multi-API Rotation  |  Concurrent Users  |  Group Scan  ║
╚══════════════════════════════════════════════════════════╝
"""

import io, os, re, asyncio, base64, logging, socket, threading, time
from datetime import datetime, timezone
from collections import defaultdict

import httpx
from flask import Flask, request, Response
from telegram import (
    Update, BotCommand, constants,
    InlineKeyboardButton, InlineKeyboardMarkup,
)
from telegram.constants import MessageEntityType
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    CallbackQueryHandler, filters, ContextTypes,
)

import zbot  #

# ══════════════════════════════════════════════════════════
#  LOGGING
# ══════════════════════════════════════════════════════════
logging.basicConfig(
    format="%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("CyberGuard")

# ══════════════════════════════════════════════════════════
#  CONFIG  —  সব Render env vars দিয়ে override করা যাবে
# ══════════════════════════════════════════════════════════
BOT_TOKEN     = os.environ.get("BOT_TOKEN",     "")
VT_KEY        = os.environ.get("VT_KEY",        "")
WORKER_SECRET = os.environ.get("WORKER_SECRET", "")
WORKER_URL    = os.environ.get("WORKER_URL",    "")
PORT          = int(os.environ.get("PORT",       8080))
OPENAI_KEY    = os.environ.get("OPENAI_KEY",    "")

# Google Safe Browsing — 2 keys rotation
# Google Safe Browsing keys (rotate to spread quota)
GOOGLE_KEYS = [
    os.environ.get("GOOGLE_KEY1", ""),
    os.environ.get("GOOGLE_KEY2", ""),
]

# URLScan.io keys (rotate to spread quota)
URLSCAN_KEYS = [
    os.environ.get("URLSCAN_KEY1", ""),
    os.environ.get("URLSCAN_KEY2", ""),
]


# ══════════════════════════════════════════════════════════
#  THREAT INTELLIGENCE LISTS
# ══════════════════════════════════════════════════════════
TRUSTED_DOMAINS = {
    "youtube.com","youtu.be","google.com","facebook.com","instagram.com",
    "github.com","render.com","cloudflare.com","netflix.com","microsoft.com",
    "apple.com","amazon.com","twitter.com","x.com","linkedin.com","wikipedia.org",
    "stackoverflow.com","reddit.com","discord.com","telegram.org","tiktok.com",
    "whatsapp.com","zoom.us","dropbox.com","drive.google.com","docs.google.com",
}

# এই domain গুলোর link group এ আসলে scan করবে না (internal/messaging links)
SKIP_SCAN_DOMAINS = {
    "t.me","telegram.me","telegram.org",
    "wa.me","whatsapp.com",
    "discord.gg","discord.com",
    "instagram.com","facebook.com",
    "youtube.com","youtu.be",
    "twitter.com","x.com",
}

# TLDs historically associated with phishing / spam
RISKY_TLDS = {
    ".site",".xyz",".top",".online",".club",".icu",".pw",".tk",".ml",
    ".cf",".ga",".gq",".info",".biz",".vip",".work",".rest",".fun",
    ".live",".world",".uno",".click",".loan",".win",".download",".stream",
}

# Keywords that boost risk score when present in URL
SUSPICIOUS_KW = {
    "girl","sex","xxx","porn","adult","nude","naked","escort","paid",
    "onlyfan","leak","free-money","win-prize","login-verify","verify-now",
    "account-suspend","limited-offer","claim-now","lucky-winner",
}

URL_RE = re.compile(
    r"(?:"
    r"https?://[^\s<>\"']+|"
    r"(?<!\w)[a-zA-Z0-9\-]+\.[a-zA-Z]{2,15}(?:/[^\s]*)?"
    r")"
)

# Domain validation regex
DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$"
)

# Telegram message length limit
TG_MSG_LIMIT = 4096

# ══════════════════════════════════════════════════════════
#  STATE
# ══════════════════════════════════════════════════════════
_stats   = {"scans": 0, "threats": 0, "started": datetime.now(timezone.utc)}
_rate    = defaultdict(list)
_gi = _ui = 0                # API key rotation counters

# Locks for Flask threaded mode (race-condition safe)
_stats_lock = threading.Lock()
_rate_lock  = threading.Lock()
_key_lock   = threading.Lock()

RATE_LIMIT = 5               # requests per user per 60s

def _check_rate(uid: int) -> bool:
    """Sliding-window rate limiter — returns False if user is over limit."""
    now = time.time()
    with _rate_lock:
        _rate[uid] = [t for t in _rate[uid] if now - t < 60]
        if len(_rate[uid]) >= RATE_LIMIT:
            return False
        _rate[uid].append(now)
        return True

async def _rate_cleanup():
    """Drop idle users from _rate every 5 min to prevent unbounded growth."""
    while True:
        await asyncio.sleep(300)
        now = time.time()
        with _rate_lock:
            stale = [uid for uid, ts in _rate.items() if not ts or now - ts[-1] > 300]
            for uid in stale:
                del _rate[uid]
            if stale:
                logger.info(f"Rate dict cleanup: removed {len(stale)} stale users")

def _escape_md(text: str) -> str:
    """Escape Markdown special characters for legacy Markdown."""
    return re.sub(r'([_*`\[])', r'\\\1', text)

def _split_message(text: str, limit: int = TG_MSG_LIMIT - 100) -> list[str]:
    """Split text into chunks that fit Telegram's 4096-char message limit."""
    if len(text) <= limit:
        return [text]
    chunks = []
    while text:
        if len(text) <= limit:
            chunks.append(text)
            break
        cut = text.rfind("\n", 0, limit)
        if cut == -1 or cut < limit // 2:
            cut = limit
        
        chunk = text[:cut]
        if chunk.count("```") % 2 != 0:
            last_fence = chunk.rfind("```")
            if last_fence > 0:
                cut = last_fence
                chunk = text[:cut]
        
        chunks.append(chunk)
        text = text[cut:].lstrip("\n")
    return chunks

def _gkey() -> str | None:
    keys = [k for k in GOOGLE_KEYS if k]
    if not keys: return None
    global _gi
    with _key_lock:
        k = keys[_gi % len(keys)]
        _gi += 1
    return k

def _ukey() -> str | None:
    keys = [k for k in URLSCAN_KEYS if k]
    if not keys: return None
    global _ui
    with _key_lock:
        k = keys[_ui % len(keys)]
        _ui += 1
    return k

# ══════════════════════════════════════════════════════════
#  URL PARSING  —  entities ব্যবহার নেই, pure regex
# ══════════════════════════════════════════════════════════
VALID_TLDS = {
    "com","net","org","io","co","app","dev","ai","me","info","biz","edu","gov",
    "uk","us","ca","au","de","fr","jp","cn","in","br","ru","it","es","nl","se",
    "xyz","site","top","online","club","icu","pw","tk","ml","cf","ga","gq",
    "live","fun","vip","work","click","win","download","stream","pro","store",
    "shop","tech","cloud","digital","media","news","blog","web","host","link",
    "ly","gg","gl","is","to","cc","tv","fm","am","id","my","sg","ph","ng",
    "ke","gh","za","bd","pk","lk","np","mm","kh","vn","th",
}

def _parse_url(text: str) -> tuple[str, str] | None:
    """Extract first URL from text. Returns (full_url, domain) or None."""
    m = URL_RE.search(text.strip())
    if not m:
        return None
    raw = m.group(0).strip()
    # Normalize accidental triple slashes (https:/// → https://)
    raw = re.sub(r"^(https?:)/{2,}", r"\1//", raw)
    full = raw if raw.startswith("http") else "https://" + raw
    domain = re.sub(r"^https?://", "", full).split("/")[0].split("?")[0].lower().strip(".")
    if not domain or "." not in domain:
        return None
    tld = domain.rsplit(".", 1)[-1].lower()
    if tld not in VALID_TLDS:
        return None
    return full, domain

def _extract_url_from_message(text: str, entities=None) -> str | None:
    """Extract URL — prefer Telegram entities, fall back to regex."""
    for ent in (entities or []):
        if ent.type == MessageEntityType.URL:
            return text[ent.offset: ent.offset + ent.length]
        if ent.type == MessageEntityType.TEXT_LINK:
            return ent.url
    m = URL_RE.search(text)
    return m.group(0) if m else None

# ══════════════════════════════════════════════════════════
#  SCAN ENGINE 1 — VirusTotal
# ══════════════════════════════════════════════════════════
async def vt_scan(url: str, _retry: int = 0) -> dict:
    out = {"malicious": 0, "suspicious": 0, "categories": [], "link": ""}
    if not VT_KEY:
        logger.warning("VT: no key configured")
        return out
    try:
        uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(
                f"https://www.virustotal.com/api/v3/urls/{uid}",
                headers={"x-apikey": VT_KEY},
            )
            if r.status_code == 429 and _retry < 1:
                logger.warning("VT rate limited — backing off 60s")
                await asyncio.sleep(60)
                return await vt_scan(url, _retry=_retry + 1)
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

# ══════════════════════════════════════════════════════════
#  SCAN ENGINE 2 — Google Safe Browsing
# ══════════════════════════════════════════════════════════
async def google_sb(url: str) -> bool:
    key = _gkey()
    if not key:
        logger.warning("GSB: no key configured")
        return False
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
                json={
                    "client": {"clientId": "cyberguard", "clientVersion": "2.0"},
                    "threatInfo": {
                        "threatTypes": [
                            "MALWARE", "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
                        ],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}],
                    },
                },
            )
            return bool(r.json().get("matches"))
    except Exception as e:
        logger.warning(f"GSB: {e}")
        return False

# ══════════════════════════════════════════════════════════
#  SCAN ENGINE 3 — URLScan.io
# ══════════════════════════════════════════════════════════
async def urlscan(url: str) -> tuple:
    key = _ukey()
    if not key:
        logger.warning("URLScan: no key configured")
        return None, 0
    try:
        # 60s timeout covers the 20s sandbox wait + 2 API calls
        async with httpx.AsyncClient(timeout=60) as c:
            r = await c.post(
                "https://urlscan.io/api/v1/scan/",
                headers={"API-Key": key, "Content-Type": "application/json"},
                json={"url": url, "visibility": "public"},
            )
            uuid = r.json().get("uuid")
            if not uuid:
                return None, 0
            await asyncio.sleep(20)
            res   = await c.get(f"https://urlscan.io/api/v1/result/{uuid}/")
            score = res.json().get("verdicts", {}).get("overall", {}).get("score", 0)
            return f"https://urlscan.io/screenshots/{uuid}.png", score
    except Exception as e:
        logger.warning(f"URLScan: {e}")
        return None, 0

# ══════════════════════════════════════════════════════════
#  SCREENSHOT — Microlink (free, no key) + thum.io fallback
# ══════════════════════════════════════════════════════════
async def take_screenshot(url: str) -> str | None:

    # Provider 1: Microlink
    try:
        async with httpx.AsyncClient(timeout=45, follow_redirects=True) as c:
            r = await c.get(
                "https://api.microlink.io/",
                params={
                    "url":                  url,
                    "screenshot":           "true",
                    "screenshot.fullPage":  "true",
                    "waitUntil":            "networkidle2",
                    "waitForTimeout":       "3000",
                    "meta":                 "false",
                },
            )
            if r.status_code == 200:
                shot_url = r.json().get("data", {}).get("screenshot", {}).get("url")
                if shot_url:
                    logger.info("Screenshot ✅ Microlink fullPage")
                    return shot_url
    except Exception as e:
        logger.warning(f"Microlink: {e}")

    # Provider 2: thum.io (free fallback)
    try:
        thum = f"https://image.thum.io/get/width/1280/crop/800/noanimate/{url}"
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
            r = await c.get(thum)
            if r.status_code == 200 and "image" in r.headers.get("content-type", ""):
                logger.info("Screenshot ✅ thum.io fallback")
                return thum
    except Exception as e:
        logger.warning(f"thum.io: {e}")

    logger.warning("Screenshot ❌ all providers failed")
    return None

# ══════════════════════════════════════════════════════════
#  HTTP SECURITY HEADERS
# ══════════════════════════════════════════════════════════
async def check_headers(url: str) -> dict:
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
    except Exception:
        pass
    return checks

# ══════════════════════════════════════════════════════════
#  DNS  &  WHOIS
# ══════════════════════════════════════════════════════════
async def dns_lookup(domain: str) -> dict:
    info = {"A": [], "MX": [], "NS": [], "TXT": []}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            for rt in ("A", "MX", "NS", "TXT"):
                r = await c.get(
                    "https://dns.google/resolve",
                    params={"name": domain, "type": rt},
                )
                info[rt] = [a["data"] for a in r.json().get("Answer", [])[:3]]
    except Exception:
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
    except Exception:
        pass
    return info

# ══════════════════════════════════════════════════════════
#  AI ENGINE — OpenAI / ChatAnywhere
# ══════════════════════════════════════════════════════════
_SYSTEM = (
    "You are CyberGuard AI — elite cybersecurity analyst. "
    "Give concise 2-3 sentence technically precise actionable assessments. "
    "No greetings. No disclaimers. Pure signal only."
)

OPENAI_BASE  = os.environ.get("OPENAI_BASE",  "https://openrouter.ai/api/v1")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "openai/gpt-oss-120b:free")

async def _ai(prompt: str, max_tokens: int = 350) -> str | None:
    if not OPENAI_KEY:
        logger.warning("OPENAI_KEY not set — AI disabled")
        return None
    try:
        async with httpx.AsyncClient(timeout=25) as c:
            r = await c.post(
                f"{OPENAI_BASE}/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENAI_KEY}",
                    "Content-Type":  "application/json",
                    "HTTP-Referer":  "https://cyberguard-bot.onrender.com",
                    "X-Title":       "CyberGuard Pro",
                },
                json={
                    "model":       OPENAI_MODEL,
                    "messages":    [
                        {"role": "system", "content": _SYSTEM},
                        {"role": "user",   "content": prompt},
                    ],
                    "max_tokens":  max_tokens,
                    "temperature": 0.2,
                },
            )
            data = r.json()
            if "choices" in data:
                logger.info(f"AI ✅ model={OPENAI_MODEL}")
                return data["choices"][0]["message"]["content"].strip()
            else:
                logger.warning(f"AI no choices: {data}")
    except Exception as e:
        logger.warning(f"AI error: {e}")
    return None

async def ai_url_insight(domain, vt, gs, us_score, risk) -> str:
    r = await _ai(
        f"Domain: {domain}\n"
        f"VirusTotal: {vt['malicious']} malicious / {vt['suspicious']} suspicious\n"
        f"Google Safe Browsing: {'THREAT DETECTED' if gs else 'clean'}\n"
        f"Sandbox score: {us_score}/100  |  Aggregate risk: {risk}%\n"
        f"Categories: {', '.join(vt['categories']) or 'unknown'}\n"
        f"Write a 2-3 sentence technical security assessment. Always complete your sentences fully.",
        max_tokens=300,
    )
    if r: return r
    if risk >= 60: return "High-confidence threat across multiple intelligence feeds. Avoid and escalate immediately."
    if risk >= 21: return "Suspicious indicators present. Use isolated environment before proceeding."
    return "No active threats detected. Maintain standard security hygiene."

async def ai_qa(question: str) -> str:
    r = await _ai(question, max_tokens=450)
    return r or "⚠️ AI engine temporarily unavailable."

# ══════════════════════════════════════════════════════════
#  RISK SCORING
# ══════════════════════════════════════════════════════════
def calc_risk(vt, gs, us_score, domain, full_url) -> tuple[int, list]:
    """Aggregate risk score (0-100). Trusted domains always score 0."""
    # Use exact match + subdomain suffix to avoid "evil-google.com" bypassing trust
    if any(domain == d or domain.endswith("." + d) for d in TRUSTED_DOMAINS):
        return 0, []

    tld      = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
    kw_hits  = [k for k in SUSPICIOUS_KW if k in full_url.lower()]

    risk = min(100,
        (50 if vt["malicious"] > 2 else 20 if vt["malicious"] > 0 else 0)
        + (50 if gs else 0)
        + int(us_score / 5)
        + (20 if tld in RISKY_TLDS else 0)
        + (25 if kw_hits else 0)
    )

    flags = []
    if tld in RISKY_TLDS:    flags.append(f"⚠️ High-risk TLD `{tld}`")
    if kw_hits:              flags.append(f"⚠️ Suspicious keywords: `{', '.join(kw_hits[:4])}`")
    if gs:                   flags.append("⚠️ Google Safe Browsing threat match")
    if vt["malicious"] > 0: flags.append(f"⚠️ {vt['malicious']} AV engines flagged")

    return risk, flags

# ══════════════════════════════════════════════════════════
#  SCAN ANIMATION
# ══════════════════════════════════════════════════════════
_STEPS = [
    ("🔍", "Resolving Infrastructure..."),
    ("🧬", "VirusTotal Multi-Engine Scan..."),
    ("🛰️", "Google Safe Browsing Check..."),
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
        except Exception:
            break

# ══════════════════════════════════════════════════════════
#  CORE SCAN — সব কিছু এখানে
# ══════════════════════════════════════════════════════════
async def _scan_core(u: Update, url_input: str):
    """Main scan pipeline — invoked by /check command and group text handler."""
    if not _check_rate(u.effective_user.id):
        await u.message.reply_text("⏳ Too many requests! Wait 60 seconds.")
        return

    parsed = _parse_url(url_input)
    if not parsed:
        await u.message.reply_text("❗ Valid URL খুঁজে পাইনি।")
        return

    full_url, domain = parsed

    # Skip scan for verified platforms (messaging, social, video)
    base = domain.replace("www.", "")
    if any(base == s or base.endswith("." + s) for s in SKIP_SCAN_DOMAINS):
        await u.message.reply_text(
            f"ℹ️ *Scan Skipped — Domain Verified*\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"🔗 `{full_url[:60]}`\n"
            f"🌐 Domain: `{base}`\n\n"
            f"✅ This is an official & verified platform domain. No threat scan needed.\n\n"
            f"⚠️ However, always be cautious about the *content* you open.\n\n"
            f"⚡ CyberGuard Pro",
            parse_mode="Markdown",
        )
        return

    status = await u.message.reply_text("📡 *Initialising CyberGuard...*", parse_mode="Markdown")
    anim   = asyncio.create_task(_animate(status))

    # সব engine একসাথে — concurrent
    vt, gs, (us_shot, us_score), shot = await asyncio.gather(
        vt_scan(full_url),
        google_sb(full_url),
        urlscan(full_url),
        take_screenshot(full_url),
    )
    anim.cancel()

    risk, flags = calc_risk(vt, gs, us_score, domain, full_url)

    with _stats_lock:
        _stats["scans"] += 1
        if risk >= 60:
            _stats["threats"] += 1

    insight = await ai_url_insight(domain, vt, gs, us_score, risk)

    verdict = (
        "🔴 *HIGH RISK*"  if risk >= 60 else
        "🟡 *SUSPICIOUS*" if risk >= 21 else
        "🟢 *SAFE*"
    )
    filled  = risk // 10
    bar     = ("#" * filled) + ("-" * (10 - filled))
    ts      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    report = (
        f"🛡️ *CyberGuard Threat Report*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔗 `{full_url[:60]}`\n"
        f"🌐 *Domain:* `{domain}`\n\n"
        f"🏁 *VERDICT:* {verdict}\n"
        f"📊 `[{bar}]` `{risk}%`\n\n"
        f"🧪 *Scan Results:*\n"
        f"  • VirusTotal   `{vt['malicious']}M / {vt['suspicious']}S`\n"
        f"  • Google SB    `{'⚠️ THREAT' if gs else '✅ Clean'}`\n"
        f"  • Sandbox      `{us_score}/100`\n"
    )
    if vt["categories"]:
        report += f"  • Category     `{', '.join(vt['categories'])}`\n"
    if flags:
        report += "\n🚩 *Risk Flags:*\n" + "".join(f"  {f}\n" for f in flags)
    insight_clean = _escape_md(insight.strip())
    report += (
        f"\n🤖 *AI Insight:*\n{insight_clean}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ CyberGuard Pro · {ts}"
    )

    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton("🔗 VT Report", url=vt["link"])
    ]]) if vt["link"] else None

    try:
        await status.delete()
    except Exception:
        pass

    final_shot = (us_shot if us_shot and risk >= 21 else None) or shot

    if final_shot:
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
                img_r = await c.get(final_shot)
            if img_r.status_code == 200 and "image" in img_r.headers.get("content-type", ""):
                short_caption = (
                    f"🛡️ *CyberGuard Report*\n"
                    f"🌐 `{domain}`\n"
                    f"🏁 {verdict} · `{risk}%`\n"
                )
                await u.message.reply_photo(
                    photo=io.BytesIO(img_r.content),
                    caption=short_caption,
                    parse_mode=constants.ParseMode.MARKDOWN,
                )
                
                chunks = _split_message(report)
                for i, chunk in enumerate(chunks):
                    is_last = (i == len(chunks) - 1)
                    await u.message.reply_text(
                        chunk, 
                        parse_mode="Markdown", 
                        reply_markup=kb if is_last else None
                    )
                return
        except Exception as e:
            logger.warning(f"Photo send failed: {e}")

    # Split long reports to fit Telegram's 4096-char limit
    chunks = _split_message(report)
    for i, chunk in enumerate(chunks):
        is_last = (i == len(chunks) - 1)
        await u.message.reply_text(
            chunk, 
            parse_mode="Markdown", 
            reply_markup=kb if is_last else None
        )

# ══════════════════════════════════════════════════════════
#  COMMAND HANDLERS
# ══════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════
#  GITHUB REPO COMMAND
# ══════════════════════════════════════════════════════════
async def cmd_github(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/github — Show CyberGuard Pro source code repository."""
    await u.message.reply_text(
        "🛡️ *CyberGuard Pro — Source Code*\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "📦 *Repository:* `cyberguard-bot`\n"
        "👨‍💻 *Developer:* `shihab81x`\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "📂 *Main Files*\n\n"
        "[🤖 bot\\-2\\-1\\.py](https://github.com/shihab81x/cyberguard-bot/blob/main/bot-2-1.py)      "
        "[🛡️ zbot\\.py](https://github.com/shihab81x/cyberguard-bot/blob/main/zbot.py)\n\n"
        "[📋 requirements\\.txt](https://github.com/shihab81x/cyberguard-bot/blob/main/requirements.txt)      "
        "[⚙️ Procfile](https://github.com/shihab81x/cyberguard-bot/blob/main/Procfile)\n\n"
        "[📖 README\\.md](https://github.com/shihab81x/cyberguard-bot/blob/main/README.md)\n\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "[🔗 View Full Repository](https://github.com/shihab81x/cyberguard-bot/tree/main)\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "⚡ CyberGuard Pro",
        parse_mode="MarkdownV2",
    )

async def cmd_start(u: Update, _):
    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton("📖 Help",  callback_data="help"),
        InlineKeyboardButton("📊 Stats", callback_data="stats"),
    ]])
    await u.message.reply_text(
        "🛡️ *CyberGuard Pro*\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "Elite threat intelligence for your group.\n\n"
        "📌 *Commands:*\n"
        "• `/check <url>` — Full threat scan\n"
        "• `/dns <domain>` — DNS records\n"
        "• `/whois <domain>` — WHOIS info\n"
        "• `/ip <address>` — IP check\n"
        "• `/headers <url>` — Security headers\n"
        "• `/github` — View source code repo\n"
        "• `/ask <question>` — AI expert\n"
        "• `/setrules <text>` — Admin: edit group rules\n"
        "• `/ping` — Latency check\n"
        "• `/stats` — Scan statistics\n\n"
        "💡 *Group এ যেকোনো link পাঠালে auto-scan হবে!*\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "⚡ VT · Google SB · URLScan · OpenAI",
        parse_mode="Markdown",
        reply_markup=kb,
    )

async def cmd_help(u: Update, _):
    await u.message.reply_text(
        "🛡️ *CyberGuard Pro — Help*\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "🔍 `/check <url>`\n"
        "VirusTotal + Google SB + Sandbox + AI\n\n"
        "🌐 `/dns <domain>`\n"
        "A, MX, NS, TXT records\n\n"
        "📋 `/whois <domain>`\n"
        "Registrar · dates · country\n\n"
        "🖥️ `/ip <address>`\n"
        "Hostname + PTR record\n\n"
        "🔒 `/headers <url>`\n"
        "HTTP security headers audit (A–F grade)\n\n"
        "🐙 `/github`\n"
        "Get this bot's source from GitHub\n\n"
        "📋 `/rules`\n"
        "Show group rules (custom or default)\n\n"
        "✏️ `/setrules <text>`\n"
        "Admin: set custom group rules via Telegram\n\n"
        "🔄 `/resetrules`\n"
        "Admin: reset rules to default\n\n"
        "🤖 `/ask <question>`\n"
        "AI cybersecurity Q&A\n\n"
        "🏓 `/ping` — Response latency\n"
        "📊 `/stats` — Total scans & threats\n\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "💡 Group এ link paste করলে auto scan হয়!",
        parse_mode="Markdown",
    )

async def cmd_ping(u: Update, _):
    msg = await u.message.reply_text("🏓 Pinging...")
    t   = time.time()
    await msg.edit_text(
        "🏓 *Pong!*\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "⚡ Latency: `measuring...`\n"
        "🟢 Status:  `Online`\n"
        "━━━━━━━━━━━━━━━━━━━━━",
        parse_mode="Markdown",
    )
    ms = int((time.time() - t) * 1000)
    await msg.edit_text(
        f"🏓 *Pong!*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ Latency: `{ms}ms`\n"
        f"🟢 Status:  `Online`\n"
        f"━━━━━━━━━━━━━━━━━━━━━",
        parse_mode="Markdown",
    )

async def cmd_stats(u: Update, _):
    with _stats_lock:
        scans   = _stats["scans"]
        threats = _stats["threats"]
        started = _stats["started"]
    up = int((datetime.now(timezone.utc) - started).total_seconds() // 3600)
    await u.message.reply_text(
        f"📊 *CyberGuard Stats*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔍 Total Scans:   `{scans}`\n"
        f"🚨 Threats Found: `{threats}`\n"
        f"⏱️ Uptime:        `{up}h`\n"
        f"━━━━━━━━━━━━━━━━━━━━━",
        parse_mode="Markdown",
    )

async def cmd_check(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    raw = re.sub(r"^/(check|scan)\s*", "", u.message.text or "").strip()
    if not raw:
        await u.message.reply_text("❗ Usage: `/check <url>`", parse_mode="Markdown")
        return
    await _scan_core(u, raw)

async def cmd_dns(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await u.message.reply_text("❗ Usage: `/dns <domain>`", parse_mode="Markdown"); return
    domain = ctx.args[0].lower().strip()
    if not DOMAIN_RE.match(domain):
        await u.message.reply_text("❌ Invalid domain format", parse_mode="Markdown"); return
    msg    = await u.message.reply_text(f"🔍 `Resolving {domain}...`", parse_mode="Markdown")
    d      = await dns_lookup(domain)
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
    if not DOMAIN_RE.match(domain):
        await u.message.reply_text("❌ Invalid domain format", parse_mode="Markdown"); return
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
    ip = ctx.args[0].strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        await u.message.reply_text("❌ Invalid IP address", parse_mode="Markdown"); return
    
    msg = await u.message.reply_text(f"🔍 `Analysing {ip}...`", parse_mode="Markdown")
    
    ptr = "N/A"
    try:
        ptr = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass
    
    ip_info = {"country": "N/A", "org": "N/A"}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"https://ipinfo.io/{ip}/json")
            if r.status_code == 200:
                d = r.json()
                ip_info = {
                    "country": d.get("country", "N/A"),
                    "org": d.get("org", "N/A"),
                }
    except Exception:
        pass
    
    await msg.edit_text(
        f"🖥️ *IP — {ip}*\n━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔀 *Hostname:* `{ptr}`\n"
        f"🌍 *Country:*  `{ip_info['country']}`\n"
        f"🏢 *Org:*      `{ip_info['org']}`\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n⚡ CyberGuard IP",
        parse_mode="Markdown",
    )

async def cmd_headers(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await u.message.reply_text("❗ Usage: `/headers <url>`", parse_mode="Markdown"); return
    url = ctx.args[0].strip()
    if not url.startswith("http"): url = "https://" + url
    msg   = await u.message.reply_text("🔒 `Checking security headers...`", parse_mode="Markdown")
    hdrs  = await check_headers(url)
    score = sum(1 for v in hdrs.values() if v == "✅")
    grade = ["F","D","C","B","A"][score]
    await msg.edit_text(
        f"🔒 *HTTP Headers — {url[:45]}*\n━━━━━━━━━━━━━━━━━━━━━\n"
        + "".join(f"  {v} `{h}`\n" for h, v in hdrs.items())
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
        f"━━━━━━━━━━━━━━━━━━━━━\n⚡ CyberGuard AI",
        parse_mode="Markdown",
    )

# ══════════════════════════════════════════════════════════
#  MESSAGE HANDLER — group link detect + private chat
# ══════════════════════════════════════════════════════════
async def handle_text(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not u.message or not u.message.text:
        return

    text       = u.message.text.strip()
    chat_type  = u.message.chat.type
    is_group   = chat_type in (constants.ChatType.GROUP, constants.ChatType.SUPERGROUP)
    is_private = chat_type == constants.ChatType.PRIVATE

    if is_group:
        found = _extract_url_from_message(text, u.message.entities)
        if not found:
            return
        parsed = _parse_url(found)
        if parsed:
            _, domain = parsed
            base = domain.replace("www.", "")
            if any(base == s or base.endswith("." + s) for s in SKIP_SCAN_DOMAINS):
                await u.message.reply_text(
                    f"ℹ️ *Scan Skipped — Domain Verified*\n"
                    f"━━━━━━━━━━━━━━━━━━━━━\n"
                    f"🔗 `{found[:60]}`\n"
                    f"🌐 Domain: `{base}`\n\n"
                    f"✅ This is an official & verified platform domain. No threat scan needed.\n\n"
                    f"⚠️ However, always be cautious about the *content* you open.\n\n"
                    f"⚡ CyberGuard Pro",
                    parse_mode="Markdown",
                )
                return
        await _scan_core(u, found)

    elif is_private:
        if URL_RE.search(text):
            await _scan_core(u, text)
        else:
            # Plain text in private chat → treat as AI question
            await cmd_ask(u, ctx)

async def handle_callback(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = u.callback_query
    await q.answer()
    if q.data == "help":
        await q.message.reply_text(
            "🛡️ *CyberGuard Pro — Help*\n"
            "━━━━━━━━━━━━━━━━━━━━━\n\n"
            "🔍 `/check <url>`\n"
            "VirusTotal + Google SB + Sandbox + AI\n\n"
            "🌐 `/dns <domain>`\n"
            "A, MX, NS, TXT records\n\n"
            "📋 `/whois <domain>`\n"
            "Registrar · dates · country\n\n"
            "🖥️ `/ip <address>`\n"
            "Hostname + PTR record\n\n"
            "🔒 `/headers <url>`\n"
            "HTTP security headers audit (A–F grade)\n\n"
            "🐙 `/github`\n"
            "Get this bot's source from GitHub\n\n"
            "📋 `/rules`\n"
            "Show group rules\n\n"
            "✏️ `/setrules <text>`\n"
            "Admin: edit rules\n\n"
            "🔄 `/resetrules`\n"
            "Admin: reset rules\n\n"
            "🤖 `/ask <question>`\n"
            "AI cybersecurity Q&A\n\n"
            "🏓 `/ping` — Response latency\n"
            "📊 `/stats` — Total scans & threats\n\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "💡 Group এ link paste করলে auto scan হয়!",
            parse_mode="Markdown",
        )
    elif q.data == "stats":
        with _stats_lock:
            scans   = _stats["scans"]
            threats = _stats["threats"]
            started = _stats["started"]
        up = int((datetime.now(timezone.utc) - started).total_seconds() // 3600)
        await q.message.reply_text(
            f"📊 *CyberGuard Stats*\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"🔍 Total Scans:   `{scans}`\n"
            f"🚨 Threats Found: `{threats}`\n"
            f"⏱️ Uptime:        `{up}h`\n"
            f"━━━━━━━━━━━━━━━━━━━━━",
            parse_mode="Markdown",
        )

# ══════════════════════════════════════════════════════════
#  BOT SETUP
# ══════════════════════════════════════════════════════════
_COMMANDS = [
    BotCommand("start",   "Welcome & command list"),
    BotCommand("check",   "Full URL threat scan"),
    BotCommand("scan",    "Full URL threat scan"),
    BotCommand("dns",     "DNS record lookup"),
    BotCommand("whois",   "Domain WHOIS info"),
    BotCommand("ip",      "IP reputation check"),
    BotCommand("headers", "HTTP security headers"),
    BotCommand("ask",     "Ask AI security expert"),
    BotCommand("github",  "View source code repository"),
    BotCommand("setrules",    "Admin: set group rules via Telegram"),
    BotCommand("resetrules",  "Admin: reset rules to default"),
    BotCommand("ping",    "Bot latency check"),
    BotCommand("stats",   "Scan statistics"),
    BotCommand("help",    "Help menu"),
]

def _register(app):
    app.add_handler(CommandHandler("start",   cmd_start))
    app.add_handler(CommandHandler("help",    cmd_help))
    app.add_handler(CommandHandler("check",   cmd_check))
    app.add_handler(CommandHandler("scan",    cmd_check))
    app.add_handler(CommandHandler("dns",     cmd_dns))
    app.add_handler(CommandHandler("whois",   cmd_whois))
    app.add_handler(CommandHandler("ip",      cmd_ip))
    app.add_handler(CommandHandler("headers", cmd_headers))
    app.add_handler(CommandHandler("ask",     cmd_ask))
    app.add_handler(CommandHandler("github",  cmd_github))
    app.add_handler(CommandHandler("ping",    cmd_ping))
    app.add_handler(CommandHandler("stats",   cmd_stats))
    app.add_handler(CallbackQueryHandler(handle_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    zbot.register_handlers(app)

# ══════════════════════════════════════════════════════════
#  FLASK  (webhook receiver + health check)
# ══════════════════════════════════════════════════════════
flask_app   = Flask(__name__)
_ptb_app    = None
_event_loop = asyncio.new_event_loop()

def _run_loop():
    asyncio.set_event_loop(_event_loop)
    _event_loop.run_forever()

async def _boot_webhook():
    global _ptb_app
    try:
        _ptb_app = ApplicationBuilder().token(BOT_TOKEN).build()
        zbot.init_db()
        _register(_ptb_app)
        await _ptb_app.initialize()
        await _ptb_app.start()
        wh = f"{WORKER_URL.rstrip('/')}/telegram"
        await _ptb_app.bot.set_webhook(url=wh, secret_token=WORKER_SECRET)
        await _ptb_app.bot.set_my_commands(_COMMANDS)
        logger.info(f"Webhook → {wh}")
        logger.info("CyberGuard Pro ready ✅")
        asyncio.create_task(_rate_cleanup())
    except Exception as e:
        logger.error(f"Boot failed: {e}")
        raise

@flask_app.route("/", methods=["GET"])
def health():
    return Response("🛡️ CyberGuard Pro — Online", status=200)

@flask_app.route("/telegram", methods=["POST"])
def tg_webhook():
    if request.headers.get("X-Worker-Secret", "") != WORKER_SECRET:
        return Response("Forbidden", status=403)
    if _ptb_app is None or _ptb_app.bot is None:
        return Response("Bot initializing, retry later", status=503)
    data = request.get_json(force=True, silent=True)
    if not data:
        return Response("Bad Request", status=400)
    try:
        update = Update.de_json(data, _ptb_app.bot)
        asyncio.run_coroutine_threadsafe(_ptb_app.process_update(update), _event_loop)
    except Exception as e:
        logger.error(f"Webhook processing failed: {e}")
        return Response("Internal error", status=500)
    return Response("ok", status=200)

# ══════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════
if __name__ == "__main__":
    if WORKER_URL:
        # Webhook mode requires WORKER_SECRET to verify incoming requests
        if not WORKER_SECRET:
            logger.error("❌ WORKER_SECRET env var must be set in webhook mode! Exiting.")
            raise SystemExit(1)

        logger.info("Starting webhook mode...")
        threading.Thread(target=_run_loop, daemon=True).start()
        asyncio.run_coroutine_threadsafe(_boot_webhook(), _event_loop).result(timeout=30)
        flask_app.run(host="0.0.0.0", port=PORT, use_reloader=False, threaded=True)
    else:
        # ── Polling mode (Cloudflare ছাড়া) ──
        logger.info("Starting polling mode...")

        async def _post_init(app):
            await app.bot.set_my_commands(_COMMANDS)
            asyncio.create_task(_rate_cleanup())

        poll = ApplicationBuilder().token(BOT_TOKEN).build()
        poll.post_init = _post_init
        _register(poll)

        threading.Thread(
            target=lambda: flask_app.run(
                host="0.0.0.0", port=PORT, use_reloader=False
            ),
            daemon=True,
        ).start()

        poll.run_polling(allowed_updates=Update.ALL_TYPES)
