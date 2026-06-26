from __future__ import annotations

"""
╔══════════════════════════════════════════════════════════╗
║                   Z Bot — Moderation v1.0                ║
║  Anti-Spam  |  Anti-Bypass  |  Group Management          ║
║  Module: bot-2-1.py দ্বারা import হয়                     ║
╚══════════════════════════════════════════════════════════╝
"""

import os, re, sqlite3, logging, unicodedata, threading
from datetime import datetime, timezone
from telegram import Update, ChatPermissions
from telegram.constants import ChatType
from telegram.ext import (
    CommandHandler, MessageHandler, filters, ContextTypes,
)

logger = logging.getLogger("ZBot")

# ══════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════
CREATOR_ID   = int(os.environ.get("CREATOR_ID", "0"))
DB_PATH      = os.environ.get("ZBOT_DB", "zbot.db")
WARN_LIMIT   = int(os.environ.get("WARN_LIMIT", "3"))   # auto-ban after N warnings
_maintenance = False

# ══════════════════════════════════════════════════════════
#  DATABASE — Phase 10
# ══════════════════════════════════════════════════════════
_db_lock = threading.Lock()

def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    """Tables তৈরি + default blacklist seed।"""
    with _db_lock:
        db = _conn()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS warnings (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                reason  TEXT,
                ts      TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS muted_users (
                chat_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                PRIMARY KEY (chat_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS banned_users (
                chat_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                PRIMARY KEY (chat_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS spam_history (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                msg     TEXT,
                score   INTEGER,
                action  TEXT,
                ts      TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS blacklisted_domains (
                domain   TEXT PRIMARY KEY,
                added_by INTEGER,
                ts       TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS whitelisted_domains (
                domain   TEXT PRIMARY KEY,
                added_by INTEGER,
                ts       TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS group_settings (
                chat_id            INTEGER PRIMARY KEY,
                rules              TEXT,
                owner_id           INTEGER,
                owner_username     TEXT,
                moderation_enabled INTEGER DEFAULT 1
            );
        """)
        # Default blacklisted domains seed
        for d in [
            "paidgirls.site", "adultads.xyz", "escortservice.top",
            "hookup.club", "sexads.online", "adultservice.pw",
            "nudegirls.tk", "girlsservice.online", "escortbd.site",
            "adultchat.icu", "paidservice.xyz", "escortdhaka.top",
        ]:
            db.execute(
                "INSERT OR IGNORE INTO blacklisted_domains (domain) VALUES (?)", (d,)
            )
        db.commit()
        db.close()
    logger.info("ZBot DB ready ✅")

# ── DB Helpers ──────────────────────────────────────────
def _warn_add(chat_id: int, user_id: int, reason: str) -> int:
    with _db_lock:
        db = _conn()
        db.execute(
            "INSERT INTO warnings (chat_id, user_id, reason) VALUES (?,?,?)",
            (chat_id, user_id, reason),
        )
        count = db.execute(
            "SELECT COUNT(*) FROM warnings WHERE chat_id=? AND user_id=?",
            (chat_id, user_id),
        ).fetchone()[0]
        db.commit()
        db.close()
    return count

def _warn_count(chat_id: int, user_id: int) -> int:
    with _db_lock:
        db = _conn()
        n = db.execute(
            "SELECT COUNT(*) FROM warnings WHERE chat_id=? AND user_id=?",
            (chat_id, user_id),
        ).fetchone()[0]
        db.close()
    return n

def _warn_clear(chat_id: int, user_id: int):
    with _db_lock:
        db = _conn()
        db.execute(
            "DELETE FROM warnings WHERE chat_id=? AND user_id=?", (chat_id, user_id)
        )
        db.commit()
        db.close()

def _warn_list(chat_id: int, user_id: int) -> list:
    with _db_lock:
        db = _conn()
        rows = db.execute(
            "SELECT reason, ts FROM warnings WHERE chat_id=? AND user_id=? ORDER BY ts",
            (chat_id, user_id),
        ).fetchall()
        db.close()
    return rows

def _spam_log(chat_id: int, user_id: int, msg: str, score: int, action: str):
    with _db_lock:
        db = _conn()
        db.execute(
            "INSERT INTO spam_history (chat_id, user_id, msg, score, action) VALUES (?,?,?,?,?)",
            (chat_id, user_id, msg[:500], score, action),
        )
        db.commit()
        db.close()

def _get_settings(chat_id: int) -> dict:
    with _db_lock:
        db = _conn()
        row = db.execute(
            "SELECT * FROM group_settings WHERE chat_id=?", (chat_id,)
        ).fetchone()
        db.close()
    return dict(row) if row else {}

def _set_settings(chat_id: int, **kwargs):
    with _db_lock:
        db = _conn()
        existing = db.execute(
            "SELECT chat_id FROM group_settings WHERE chat_id=?", (chat_id,)
        ).fetchone()
        if existing:
            sets = ", ".join(f"{k}=?" for k in kwargs)
            db.execute(
                f"UPDATE group_settings SET {sets} WHERE chat_id=?",
                (*kwargs.values(), chat_id),
            )
        else:
            kwargs["chat_id"] = chat_id
            cols = ", ".join(kwargs.keys())
            vals = ", ".join("?" * len(kwargs))
            db.execute(
                f"INSERT INTO group_settings ({cols}) VALUES ({vals})",
                tuple(kwargs.values()),
            )
        db.commit()
        db.close()

def _get_blacklist() -> list[str]:
    with _db_lock:
        db = _conn()
        rows = db.execute(
            "SELECT domain FROM blacklisted_domains ORDER BY domain"
        ).fetchall()
        db.close()
    return [r[0] for r in rows]

def _get_whitelist() -> list[str]:
    with _db_lock:
        db = _conn()
        rows = db.execute(
            "SELECT domain FROM whitelisted_domains ORDER BY domain"
        ).fetchall()
        db.close()
    return [r[0] for r in rows]

def _bl_add(domain: str, added_by: int):
    with _db_lock:
        db = _conn()
        db.execute(
            "INSERT OR IGNORE INTO blacklisted_domains (domain, added_by) VALUES (?,?)",
            (domain, added_by),
        )
        db.commit()
        db.close()

def _bl_remove(domain: str):
    with _db_lock:
        db = _conn()
        db.execute("DELETE FROM blacklisted_domains WHERE domain=?", (domain,))
        db.commit()
        db.close()

def _wl_add(domain: str, added_by: int):
    with _db_lock:
        db = _conn()
        db.execute(
            "INSERT OR IGNORE INTO whitelisted_domains (domain, added_by) VALUES (?,?)",
            (domain, added_by),
        )
        db.commit()
        db.close()

def _wl_remove(domain: str):
    with _db_lock:
        db = _conn()
        db.execute("DELETE FROM whitelisted_domains WHERE domain=?", (domain,))
        db.commit()
        db.close()

# ══════════════════════════════════════════════════════════
#  UNICODE NORMALIZER — Phase 3 + 11
#  Strips: fancy fonts, Cyrillic/Greek lookalikes, invisible
#  chars, zero-width spaces, emoji flags, fullwidth chars.
# ══════════════════════════════════════════════════════════

# Confusable character map → plain ASCII
_CONFUSABLE = str.maketrans({
    # Cyrillic lookalikes
    'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x',
    'і':'i','ѕ':'s','ԁ':'d','ν':'n','ω':'w','η':'n','τ':'t',
    # Small caps / phonetic
    'ʟ':'l','ᴍ':'m','ɴ':'n','ʙ':'b','ʜ':'h','ᴋ':'k','ᴛ':'t',
    'ᴜ':'u','ᴠ':'v','ᴡ':'w','ʏ':'y','ᴢ':'z','ᴄ':'c','ᴀ':'a',
    'ᴇ':'e','ɪ':'i','ᴏ':'o','ᴘ':'p','ꜰ':'f','ꜱ':'s','ʀ':'r',
    'ɡ':'g','ɢ':'g','ʟ':'l','ɴ':'n','ʀ':'r',
    # Blackboard bold / script
    'ℂ':'c','ℍ':'h','ℕ':'n','ℙ':'p','ℚ':'q','ℝ':'r','ℤ':'z',
    'ℰ':'e','ℱ':'f','ℋ':'h','ℐ':'i','ℒ':'l','ℳ':'m','ℬ':'b',
    'ℭ':'c','ℊ':'g','ℴ':'o',
    # Greek lookalikes
    'α':'a','β':'b','ε':'e','ι':'i','κ':'k','ο':'o',
    'ρ':'p','τ':'t','υ':'u','χ':'x','ϲ':'c',
    # Misc
    'ɛ':'e','ꞃ':'r',
})

# Invisible / zero-width characters
_INVISIBLE = re.compile(
    r'[\u200b\u200c\u200d\u2060\ufeff\u00ad\u034f'
    r'\u180e\u2028\u2029\u115f\u1160\u3164\uffa0]'
)

def _flags_to_ascii(text: str) -> str:
    """🇻🇮🇩🇪🇴  →  video"""
    out = []
    for ch in text:
        cp = ord(ch)
        if 0x1F1E6 <= cp <= 0x1F1FF:
            out.append(chr(cp - 0x1F1E6 + ord('a')))
        else:
            out.append(ch)
    return ''.join(out)

def normalize(text: str) -> str:
    """
    Full bypass-proof normalization pipeline:
      🇻🇮🇩🇪🇴  →  ѕer_vi_ℂɛ  →  𝗔𝗩𝗔𝗜𝗟𝗔𝗕𝗟𝗘  →  all become plain lowercase ASCII.
    """
    text = _flags_to_ascii(text)                      # emoji flags → letters
    text = _INVISIBLE.sub('', text)                    # invisible chars removed
    text = unicodedata.normalize('NFKD', text)         # math bold/italic, fullwidth, etc.
    text = ''.join(
        c for c in text if unicodedata.category(c) != 'Mn'
    )                                                  # strip combining/accent marks
    text = text.translate(_CONFUSABLE)                 # lookalike chars → ASCII
    text = text.lower()
    text = re.sub(r'(?<=[a-z0-9])[-_.](?=[a-z0-9])', '', text)  # a_b → ab
    text = re.sub(r'[^a-z0-9\s]', ' ', text)          # non-alnum → space
    text = re.sub(r'\s+', ' ', text).strip()
    return text

# ══════════════════════════════════════════════════════════
#  KEYWORD SCORING — Phase 4 + 6
# ══════════════════════════════════════════════════════════
# Sorted longest-first so phrases score before substrings
_KEYWORDS: list[tuple[str, int]] = sorted([
    # ── Phrases (high confidence) ──
    ("video call",  40),
    ("voice call",  40),
    ("phone sex",   60),
    ("dirty talk",  50),
    ("video chat",  35),
    ("live show",   35),
    # ── Adult keywords ──
    ("sex",         50),
    ("nude",        50),
    ("naked",       50),
    ("porn",        60),
    ("xxx",         60),
    ("escort",      50),
    ("onlyfans",    60),
    ("onlyfan",     55),
    ("adult",       40),
    ("18+",         40),
    # ── Advertisement signals ──
    ("available",   30),
    ("service",     30),
    ("payment",     20),
    ("demo",        15),
    ("girls",       20),
    ("video",       20),
    ("call",        20),
    ("paid",        20),
    ("rate",        15),
    ("booking",     20),
    ("contact",     10),
    ("whatsapp",    10),
], key=lambda x: -len(x[0]))

def score_message(text: str) -> tuple[int, list[str]]:
    """
    Returns (total_score, matched_keywords) for raw input.
    Normalizes internally — bypass-proof.
    """
    norm  = normalize(text)
    total = 0
    hits  = []
    seen  = set()
    for kw, pts in _KEYWORDS:
        if kw in norm and kw not in seen:
            total += pts
            hits.append(kw)
            seen.add(kw)
    return min(total, 250), hits  # cap at 250

# ══════════════════════════════════════════════════════════
#  BLACKLISTED DOMAIN DETECTION — Phase 5
#  Bot শুধু text-এ domain চেক করে।
#  Website visit / content scan করে না।
# ══════════════════════════════════════════════════════════
_DOMAIN_RE = re.compile(
    r'(?:https?://|www\.)?'
    r'([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'
    r'\.[a-zA-Z]{2,15})'
    r'(?:/[^\s]*)?',
    re.IGNORECASE,
)

def _extract_domains(text: str) -> list[str]:
    return [m.group(1).lower() for m in _DOMAIN_RE.finditer(text)]

def check_blacklisted_domains(text: str) -> list[str]:
    """
    text-এ blacklisted domain আছে কিনা শুধু check করে।
    Website open করে না, content scan করে না।
    """
    found = _extract_domains(text)
    if not found:
        return []
    bl = set(_get_blacklist())
    wl = set(_get_whitelist())
    hits = []
    for d in found:
        if d in wl or any(d.endswith('.' + w) for w in wl):
            continue
        if d in bl or any(d.endswith('.' + b) for b in bl):
            hits.append(d)
    return hits

# ══════════════════════════════════════════════════════════
#  RISK VERDICT — Phase 6
# ══════════════════════════════════════════════════════════
def get_verdict(score: int) -> tuple[str, str]:
    """(label, level)"""
    if score >= 100: return "🔴 DANGER",     "danger"
    if score >= 70:  return "🟠 HIGH RISK",  "high_risk"
    if score >= 40:  return "🟡 SUSPICIOUS", "suspicious"
    return               "🟢 SAFE",          "safe"

# ══════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════
async def _is_admin(ctx, chat_id: int, user_id: int) -> bool:
    try:
        m = await ctx.bot.get_chat_member(chat_id, user_id)
        return m.status in ("administrator", "creator")
    except Exception:
        return False

async def _get_owner(ctx, chat_id: int) -> tuple[int | None, str | None]:
    """Group creator এর (id, username) return করে।"""
    try:
        admins = await ctx.bot.get_chat_administrators(chat_id)
        for a in admins:
            if a.status == "creator":
                return a.user.id, a.user.username
    except Exception:
        pass
    return None, None

def _is_bot_creator(user_id: int) -> bool:
    return CREATOR_ID != 0 and user_id == CREATOR_ID

def _mention(user_id: int, name: str) -> str:
    safe = name.replace('[', '').replace(']', '').replace('`', '')
    return f"[{safe}](tg://user?id={user_id})"

async def _get_target(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Reply করা user অথবা argument থেকে target বের করে।"""
    if u.message.reply_to_message:
        t = u.message.reply_to_message.from_user
        return t.id, t.full_name, t.username
    if ctx.args:
        try:
            uid    = int(ctx.args[0])
            member = await ctx.bot.get_chat_member(u.effective_chat.id, uid)
            return member.user.id, member.user.full_name, member.user.username
        except Exception:
            pass
    return None, None, None

# ══════════════════════════════════════════════════════════
#  PHASE 1 — MODERATION COMMANDS
# ══════════════════════════════════════════════════════════

async def cmd_zban(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/zban — User ban করো। Admin only।"""
    chat_id = u.effective_chat.id
    caller  = u.effective_user.id
    if not await _is_admin(ctx, chat_id, caller):
        await u.message.reply_text("❌ Admin permission required.")
        return
    uid, name, _ = await _get_target(u, ctx)
    if not uid:
        await u.message.reply_text("❗ কোনো user কে reply করো অথবা user ID দাও।")
        return
    reason = " ".join(ctx.args[1:]) if ctx.args and len(ctx.args) > 1 else "Admin action"
    try:
        await ctx.bot.ban_chat_member(chat_id, uid)
        await u.message.reply_text(
            f"🔨 *User Banned*\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"👤 *User:* {_mention(uid, name or str(uid))}\n"
            f"📝 *Reason:* {reason}\n"
            f"👮 *By:* {_mention(caller, u.effective_user.full_name)}\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"⚡ Z Bot",
            parse_mode="Markdown",
        )
    except Exception as e:
        await u.message.reply_text(f"❌ Ban failed: `{e}`", parse_mode="Markdown")

async def cmd_zunban(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/zunban — User unban করো। Admin only।"""
    chat_id = u.effective_chat.id
    if not await _is_admin(ctx, chat_id, u.effective_user.id):
        await u.message.reply_text("❌ Admin permission required.")
        return
    uid, name, _ = await _get_target(u, ctx)
    if not uid:
        await u.message.reply_text("❗ User ID বা reply দাও।")
        return
    try:
        await ctx.bot.unban_chat_member(chat_id, uid, only_if_banned=True)
        await u.message.reply_text(
            f"✅ *User Unbanned*\n"
            f"👤 {_mention(uid, name or str(uid))} unbanned হয়েছে।\n"
            f"⚡ Z Bot",
            parse_mode="Markdown",
        )
    except Exception as e:
        await u.message.reply_text(f"❌ Unban failed: `{e}`", parse_mode="Markdown")

async def cmd_zmute(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/zmute — User mute করো। Admin only।"""
    chat_id = u.effective_chat.id
    caller  = u.effective_user.id
    if not await _is_admin(ctx, chat_id, caller):
        await u.message.reply_text("❌ Admin permission required.")
        return
    uid, name, _ = await _get_target(u, ctx)
    if not uid:
        await u.message.reply_text("❗ User ID বা reply দাও।")
        return
    reason = " ".join(ctx.args[1:]) if ctx.args and len(ctx.args) > 1 else "Admin action"
    try:
        perms = ChatPermissions(
            can_send_messages=False,
            can_send_polls=False,
            can_send_other_messages=False,
            can_add_web_page_previews=False,
        )
        await ctx.bot.restrict_chat_member(chat_id, uid, perms)
        with _db_lock:
            db = _conn()
            db.execute("INSERT OR IGNORE INTO muted_users VALUES (?,?)", (chat_id, uid))
            db.commit()
            db.close()
        await u.message.reply_text(
            f"🔇 *User Muted*\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"👤 *User:* {_mention(uid, name or str(uid))}\n"
            f"📝 *Reason:* {reason}\n"
            f"👮 *By:* {_mention(caller, u.effective_user.full_name)}\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"⚡ Z Bot",
            parse_mode="Markdown",
        )
    except Exception as e:
        await u.message.reply_text(f"❌ Mute failed: `{e}`", parse_mode="Markdown")

async def cmd_zunmute(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/zunmute — User unmute করো। Admin only।"""
    chat_id = u.effective_chat.id
    if not await _is_admin(ctx, chat_id, u.effective_user.id):
        await u.message.reply_text("❌ Admin permission required.")
        return
    uid, name, _ = await _get_target(u, ctx)
    if not uid:
        await u.message.reply_text("❗ User ID বা reply দাও।")
        return
    try:
        perms = ChatPermissions(
            can_send_messages=True,
            can_send_polls=True,
            can_send_other_messages=True,
            can_add_web_page_previews=True,
        )
        await ctx.bot.restrict_chat_member(chat_id, uid, perms)
        with _db_lock:
            db = _conn()
            db.execute(
                "DELETE FROM muted_users WHERE chat_id=? AND user_id=?", (chat_id, uid)
            )
            db.commit()
            db.close()
        await u.message.reply_text(
            f"🔊 *User Unmuted*\n"
            f"👤 {_mention(uid, name or str(uid))} আবার কথা বলতে পারবে।\n"
            f"⚡ Z Bot",
            parse_mode="Markdown",
        )
    except Exception as e:
        await u.message.reply_text(f"❌ Unmute failed: `{e}`", parse_mode="Markdown")

async def cmd_zwarn(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/zwarn — User কে warn করো। Admin only।"""
    chat_id = u.effective_chat.id
    caller  = u.effective_user.id
    if not await _is_admin(ctx, chat_id, caller):
        await u.message.reply_text("❌ Admin permission required.")
        return
    uid, name, _ = await _get_target(u, ctx)
    if not uid:
        await u.message.reply_text("❗ User ID বা reply দাও।")
        return
    reason = " ".join(ctx.args[1:]) if ctx.args and len(ctx.args) > 1 else "Admin warning"
    count  = _warn_add(chat_id, uid, reason)

    msg = (
        f"⚠️ *Warning Issued*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"👤 *User:* {_mention(uid, name or str(uid))}\n"
        f"📝 *Reason:* {reason}\n"
        f"🔢 *Warnings:* `{count}/{WARN_LIMIT}`\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
    )
    if count >= WARN_LIMIT:
        msg += f"🔨 *Auto-ban! ({WARN_LIMIT} warnings reached)*\n"
        try:
            await ctx.bot.ban_chat_member(chat_id, uid)
            msg += "✅ User banned.\n"
        except Exception as e:
            msg += f"❌ Auto-ban failed: `{e}`\n"
    msg += "⚡ Z Bot"
    await u.message.reply_text(msg, parse_mode="Markdown")

async def cmd_warnings(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/warnings — User এর সব warning দেখো।"""
    chat_id = u.effective_chat.id
    uid, name, _ = await _get_target(u, ctx)
    if not uid:
        uid  = u.effective_user.id
        name = u.effective_user.full_name
    rows = _warn_list(chat_id, uid)
    if not rows:
        await u.message.reply_text(
            f"✅ {_mention(uid, name or str(uid))} এর কোনো warning নেই।",
            parse_mode="Markdown",
        )
        return
    lines = "\n".join(
        f"  `{i+1}.` {r['reason']} — _{r['ts']}_" for i, r in enumerate(rows)
    )
    await u.message.reply_text(
        f"⚠️ *Warnings — {name or uid}*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"{lines}\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"Total: `{len(rows)}/{WARN_LIMIT}`\n"
        f"⚡ Z Bot",
        parse_mode="Markdown",
    )

async def cmd_clearwarnings(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/clearwarnings — সব warning মুছে দাও। Admin only।"""
    chat_id = u.effective_chat.id
    if not await _is_admin(ctx, chat_id, u.effective_user.id):
        await u.message.reply_text("❌ Admin permission required.")
        return
    uid, name, _ = await _get_target(u, ctx)
    if not uid:
        await u.message.reply_text("❗ User ID বা reply দাও।")
        return
    _warn_clear(chat_id, uid)
    await u.message.reply_text(
        f"🗑️ *Warnings Cleared*\n"
        f"👤 {_mention(uid, name or str(uid))} এর সব warning মুছে গেছে।\n"
        f"⚡ Z Bot",
        parse_mode="Markdown",
    )

# ══════════════════════════════════════════════════════════
#  PHASE 2 — RULES SYSTEM
# ══════════════════════════════════════════════════════════
_DEFAULT_RULES = (
    "📋 *Group Rules*\n"
    "━━━━━━━━━━━━━━━━━━━━━\n"
    "• Be respectful to everyone.\n"
    "• Stay on topic.\n"
    "• No spam or advertisements.\n"
    "• No offensive or adult content.\n"
    "• No scam links.\n"
    "• Need help? Contact: {owner}\n"
    "• Enjoy the community 🎉\n"
    "━━━━━━━━━━━━━━━━━━━━━\n"
    "⚡ Z Bot"
)

async def cmd_rules(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/rules — Group rules দেখাও। Owner username auto-fetch হয়।"""
    chat_id  = u.effective_chat.id
    settings = _get_settings(chat_id)

    # Owner username cache না থাকলে auto-fetch করো
    owner_username = settings.get("owner_username")
    if not owner_username:
        _, owner_username = await _get_owner(ctx, chat_id)
        if owner_username:
            _set_settings(chat_id, owner_username=owner_username)

    owner_mention = f"@{owner_username}" if owner_username else "Admin"
    custom_rules  = settings.get("rules")
    text = custom_rules if custom_rules else _DEFAULT_RULES.format(owner=owner_mention)
    await u.message.reply_text(text, parse_mode="Markdown")

# ══════════════════════════════════════════════════════════
#  PHASE 7 + 8 — AUTO ACTION + NOTIFICATION
# ══════════════════════════════════════════════════════════
async def _notify_owner_and_creator(
    ctx, chat_id: int, chat_title: str,
    user, score: int, verdict_label: str, reasons: list[str],
):
    """Group owner + bot creator কে DM notification পাঠাও।"""
    ts    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    uname = f"@{user.username}" if user.username else "None"
    text  = (
        f"⚠️ *Suspicious Message Detected*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"👤 *User:*\n"
        f"  Display Name: `{user.full_name}`\n"
        f"  Username: `{uname}`\n"
        f"  ID: `{user.id}`\n\n"
        f"🏠 *Group:* `{chat_title}` (`{chat_id}`)\n\n"
        f"📊 *Score:* `{score}` — {verdict_label}\n\n"
        f"🚩 *Reasons:*\n"
        + "".join(f"  • {r}\n" for r in reasons)
        + f"\n🗑️ Message deleted.\n"
        f"Owner has been notified.\n"
        f"Creator has been notified.\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ {ts}"
    )
    # Group owner notify
    owner_id, _ = await _get_owner(ctx, chat_id)
    if owner_id and owner_id != user.id:
        try:
            await ctx.bot.send_message(owner_id, text, parse_mode="Markdown")
        except Exception as e:
            logger.warning(f"Owner notify failed: {e}")
    # Bot creator notify
    if CREATOR_ID and CREATOR_ID != user.id:
        try:
            await ctx.bot.send_message(CREATOR_ID, text, parse_mode="Markdown")
        except Exception as e:
            logger.warning(f"Creator notify failed: {e}")

async def handle_group_message(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """
    Group message spam detection handler.
    Phase 3-8: normalize → score → domain check → verdict → action.
    """
    global _maintenance
    if _maintenance and not _is_bot_creator(u.effective_user.id):
        return

    msg = u.message
    if not msg or not msg.text:
        return

    chat    = u.effective_chat
    user    = u.effective_user
    text    = msg.text
    chat_id = chat.id

    # Admin ও bot creator কে skip করো
    if _is_bot_creator(user.id) or await _is_admin(ctx, chat_id, user.id):
        return

    # Group moderation enabled কিনা চেক
    settings = _get_settings(chat_id)
    if settings.get("moderation_enabled", 1) == 0:
        return

    # ── Score calculation ──
    score, kw_hits = score_message(text)
    bl_domains     = check_blacklisted_domains(text)

    # Blacklisted domain = +100 per domain
    if bl_domains:
        score += 100 * len(bl_domains)
    score = min(score, 300)

    verdict_label, level = get_verdict(score)

    if level == "safe":
        return  # কিছু করার নেই

    # ── Reason বানাও ──
    reasons = []
    if bl_domains:
        reasons.append(f"Blacklisted Domain: `{', '.join(bl_domains)}`")
    if kw_hits:
        _adult_kw = {
            "sex","nude","naked","porn","xxx","escort","onlyfans",
            "onlyfan","adult","dirty talk","phone sex","live show",
        }
        _adv_kw = {
            "available","service","payment","demo","booking",
            "rate","girls","video call","voice call","video chat",
        }
        adult_hits = [k for k in kw_hits if k in _adult_kw]
        adv_hits   = [k for k in kw_hits if k in _adv_kw]
        if adult_hits:
            reasons.append(f"Adult Keywords: `{', '.join(adult_hits[:4])}`")
        if adv_hits:
            reasons.append(f"Adult Advertisement: `{', '.join(adv_hits[:4])}`")
        # Unicode bypass detect
        orig_lower = text.lower()
        norm_text  = normalize(text)
        if any(kw in norm_text and kw not in orig_lower for kw in kw_hits):
            reasons.append("Unicode Bypass Detected")
    if not reasons:
        reasons.append(f"Suspicion score: {score}")

    # ── Action: danger/high_risk → delete ──
    action = "warn"
    if level in ("danger", "high_risk"):
        action = "delete+warn"
        try:
            await msg.delete()
        except Exception as e:
            logger.warning(f"Delete failed: {e}")

    # Warning যোগ করো
    warn_count = _warn_add(chat_id, user.id, " | ".join(reasons))

    # Spam log save
    _spam_log(chat_id, user.id, text, score, action)

    # ── Group notification (Phase 8) ──
    uname        = f"@{user.username}" if user.username else "None"
    group_notice = (
        f"⚠️ *Suspicious Message Detected*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"👤 *User:*\n"
        f"  Display Name: `{user.full_name}`\n"
        f"  Username: `{uname}`\n\n"
        f"🚩 *Reason:*\n"
        + "".join(f"  • {r}\n" for r in reasons)
        + f"\n📊 Score: `{score}` — {verdict_label}\n"
        f"⚠️ Warnings: `{warn_count}/{WARN_LIMIT}`\n"
        + ("🗑️ Message deleted.\n" if "delete" in action else "")
        + "Owner has been notified.\n"
        f"Creator has been notified.\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ Z Bot"
    )
    try:
        await chat.send_message(group_notice, parse_mode="Markdown")
    except Exception as e:
        logger.warning(f"Group notice failed: {e}")

    # Auto-ban on warn limit
    if warn_count >= WARN_LIMIT:
        try:
            await ctx.bot.ban_chat_member(chat_id, user.id)
            await chat.send_message(
                f"🔨 *Auto-ban:* {_mention(user.id, user.full_name)} — "
                f"{WARN_LIMIT}টি warning পূর্ণ হয়েছে।\n⚡ Z Bot",
                parse_mode="Markdown",
            )
        except Exception as e:
            logger.warning(f"Auto-ban failed: {e}")

    # Owner + Creator DM notification
    await _notify_owner_and_creator(
        ctx, chat_id, chat.title or "Unknown",
        user, score, verdict_label, reasons,
    )

# ══════════════════════════════════════════════════════════
#  PHASE 9 — CREATOR-ONLY COMMANDS
# ══════════════════════════════════════════════════════════
def _creator_only(func):
    """Decorator: শুধু bot creator রান করতে পারবে।"""
    async def wrapper(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if not _is_bot_creator(u.effective_user.id):
            await u.message.reply_text("🔒 Creator only command.")
            return
        return await func(u, ctx)
    wrapper.__name__ = func.__name__
    return wrapper

@_creator_only
async def cmd_zlogs(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/zlogs — Last 10 spam log দেখাও।"""
    with _db_lock:
        db   = _conn()
        rows = db.execute(
            "SELECT chat_id, user_id, score, action, ts "
            "FROM spam_history ORDER BY ts DESC LIMIT 10"
        ).fetchall()
        db.close()
    if not rows:
        await u.message.reply_text("📭 কোনো spam log নেই।")
        return
    lines = "\n".join(
        f"`{r['ts'][:16]}` | chat:`{r['chat_id']}` | "
        f"user:`{r['user_id']}` | score:`{r['score']}` | `{r['action']}`"
        for r in rows
    )
    await u.message.reply_text(
        f"📋 *Recent Spam Logs*\n━━━━━━━━━━━━━━━━━━━━━\n{lines}\n⚡ Z Bot",
        parse_mode="Markdown",
    )

@_creator_only
async def cmd_zdebug(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/zdebug <text> — Normalizer + scorer test করো।"""
    text = re.sub(r"^/zdebug\s*", "", u.message.text or "").strip()
    if not text:
        await u.message.reply_text("❗ Usage: `/zdebug <text>`", parse_mode="Markdown")
        return
    norm        = normalize(text)
    score, hits = score_message(text)
    bl          = check_blacklisted_domains(text)
    total_score = min(score + (100 * len(bl) if bl else 0), 300)
    v_label, _  = get_verdict(total_score)
    await u.message.reply_text(
        f"🔬 *Z Bot Debug*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"📥 *Input:*      `{text[:100]}`\n"
        f"🔄 *Normalized:* `{norm[:100]}`\n"
        f"🎯 *Score:*      `{total_score}`\n"
        f"🔑 *Keywords:*   `{', '.join(hits) or 'none'}`\n"
        f"🚫 *BL Domains:* `{', '.join(bl) or 'none'}`\n"
        f"🏁 *Verdict:*    {v_label}\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ Z Bot",
        parse_mode="Markdown",
    )

@_creator_only
async def cmd_zstats(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/zstats — Global statistics।"""
    with _db_lock:
        db           = _conn()
        total_spam   = db.execute("SELECT COUNT(*) FROM spam_history").fetchone()[0]
        total_warn   = db.execute("SELECT COUNT(*) FROM warnings").fetchone()[0]
        total_bl     = db.execute("SELECT COUNT(*) FROM blacklisted_domains").fetchone()[0]
        total_groups = db.execute("SELECT COUNT(*) FROM group_settings").fetchone()[0]
        db.close()
    await u.message.reply_text(
        f"📊 *Z Bot Global Stats*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"🚨 Spam Detected:    `{total_spam}`\n"
        f"⚠️ Warnings Issued:  `{total_warn}`\n"
        f"🚫 Blacklist Size:   `{total_bl}`\n"
        f"🏠 Groups Tracked:   `{total_groups}`\n"
        f"🔧 Maintenance Mode: `{'ON 🔴' if _maintenance else 'OFF 🟢'}`\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ Z Bot",
        parse_mode="Markdown",
    )

@_creator_only
async def cmd_zblacklist(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/zblacklist [add/remove] <domain> — Blacklist manage করো।"""
    if not ctx.args:
        bl   = _get_blacklist()
        text = "\n".join(f"  `{d}`" for d in bl) or "  _empty_"
        await u.message.reply_text(
            f"🚫 *Blacklisted Domains* ({len(bl)})\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n{text}\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"Usage: `/zblacklist add <domain>`\n"
            f"       `/zblacklist remove <domain>`\n"
            f"⚡ Z Bot",
            parse_mode="Markdown",
        )
        return
    op = ctx.args[0].lower()
    if op not in ("add", "remove") or len(ctx.args) < 2:
        await u.message.reply_text(
            "❗ Usage: `/zblacklist add/remove <domain>`", parse_mode="Markdown"
        )
        return
    domain = ctx.args[1].lower().strip()
    if op == "add":
        _bl_add(domain, u.effective_user.id)
        await u.message.reply_text(
            f"✅ `{domain}` blacklist এ যোগ হলো।", parse_mode="Markdown"
        )
    else:
        _bl_remove(domain)
        await u.message.reply_text(
            f"🗑️ `{domain}` blacklist থেকে সরানো হলো।", parse_mode="Markdown"
        )

@_creator_only
async def cmd_zwhitelist(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/zwhitelist [add/remove] <domain> — Whitelist manage করো।"""
    if not ctx.args:
        wl   = _get_whitelist()
        text = "\n".join(f"  `{d}`" for d in wl) or "  _empty_"
        await u.message.reply_text(
            f"✅ *Whitelisted Domains* ({len(wl)})\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n{text}\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"Usage: `/zwhitelist add <domain>`\n"
            f"       `/zwhitelist remove <domain>`\n"
            f"⚡ Z Bot",
            parse_mode="Markdown",
        )
        return
    op = ctx.args[0].lower()
    if op not in ("add", "remove") or len(ctx.args) < 2:
        await u.message.reply_text(
            "❗ Usage: `/zwhitelist add/remove <domain>`", parse_mode="Markdown"
        )
        return
    domain = ctx.args[1].lower().strip()
    if op == "add":
        _wl_add(domain, u.effective_user.id)
        await u.message.reply_text(
            f"✅ `{domain}` whitelist এ যোগ হলো।", parse_mode="Markdown"
        )
    else:
        _wl_remove(domain)
        await u.message.reply_text(
            f"🗑️ `{domain}` whitelist থেকে সরানো হলো।", parse_mode="Markdown"
        )

@_creator_only
async def cmd_zmaintenance(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/zmaintenance — Maintenance mode toggle করো।"""
    global _maintenance
    _maintenance = not _maintenance
    status = "🔴 ON" if _maintenance else "🟢 OFF"
    await u.message.reply_text(
        f"🔧 *Maintenance Mode:* {status}\n"
        + (
            "Z Bot এখন সব non-creator user এর জন্য pause।"
            if _maintenance
            else "Z Bot সম্পূর্ণ চালু।"
        )
        + "\n⚡ Z Bot",
        parse_mode="Markdown",
    )

@_creator_only
async def cmd_zupdate(u: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/zupdate — Version info দেখাও।"""
    await u.message.reply_text(
        f"🔄 *Z Bot Version*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"📦 Version: `1.0.0`\n"
        f"📅 Build:   `{datetime.now(timezone.utc).strftime('%Y-%m-%d')}`\n"
        f"✅ All systems operational\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ Z Bot",
        parse_mode="Markdown",
    )

# ══════════════════════════════════════════════════════════
#  REGISTER — bot-2-1.py এ call করো
# ══════════════════════════════════════════════════════════
def register_handlers(app) -> None:
    """
    Z Bot handlers PTB Application এ register করো।
    bot-2-1.py থেকে call হয়:

        import zbot
        zbot.init_db()
        zbot.register_handlers(app)
    """
    # ── Moderation ──
    app.add_handler(CommandHandler("zban",          cmd_zban))
    app.add_handler(CommandHandler("zunban",        cmd_zunban))
    app.add_handler(CommandHandler("zmute",         cmd_zmute))
    app.add_handler(CommandHandler("zunmute",       cmd_zunmute))
    app.add_handler(CommandHandler("zwarn",         cmd_zwarn))
    app.add_handler(CommandHandler("warnings",      cmd_warnings))
    app.add_handler(CommandHandler("clearwarnings", cmd_clearwarnings))
    app.add_handler(CommandHandler("rules",         cmd_rules))
    # ── Creator only ──
    app.add_handler(CommandHandler("zlogs",         cmd_zlogs))
    app.add_handler(CommandHandler("zdebug",        cmd_zdebug))
    app.add_handler(CommandHandler("zstats",        cmd_zstats))
    app.add_handler(CommandHandler("zblacklist",    cmd_zblacklist))
    app.add_handler(CommandHandler("zwhitelist",    cmd_zwhitelist))
    app.add_handler(CommandHandler("zmaintenance",  cmd_zmaintenance))
    app.add_handler(CommandHandler("zupdate",       cmd_zupdate))
    # ── Group spam detection — group=1 যাতে CyberGuard এর handler ও চলে ──
    app.add_handler(
        MessageHandler(
            filters.TEXT
            & ~filters.COMMAND
            & (filters.ChatType.GROUP | filters.ChatType.SUPERGROUP),
            handle_group_message,
        ),
        group=1,
    )
    logger.info("Z Bot handlers registered ✅")
