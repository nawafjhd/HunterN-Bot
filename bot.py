import os
import requests
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

# ------------------ Commands ------------------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🐺 HunterN IOC Bot\n\n"
        "استخدم:\n"
        "/ioc <IP Address>\n\n"
        "مثال:\n"
        "/ioc 206.119.191.106"
    )

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "/ioc <IP> - IOC Summary\n"
        "/help - Help"
    )

# ------------------ IOC Logic ------------------

def vt_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return None
    return r.json()

def abuse_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSE_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    r = requests.get(url, headers=headers, params=params)
    if r.status_code != 200:
        return None
    return r.json()

def otx_ip(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return None
    return r.json()

# ------------------ /ioc Command ------------------

async def ioc(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ استخدم: /ioc <IP>")
        return

    ip = context.args[0]

    vt = vt_ip(ip)
    abuse = abuse_ip(ip)
    otx = otx_ip(ip)

    risk = "Low"
    reasons = []

    if abuse and abuse["data"]["abuseConfidenceScore"] >= 50:
        risk = "⚠️ Medium – High"
        reasons.append("Reported for abusive activity")

    if vt:
        stats = vt["data"]["attributes"]["last_analysis_stats"]
        if stats["malicious"] > 0:
            risk = "🚨 High"
            reasons.append("Flagged by VirusTotal engines")

    if otx and otx.get("pulse_info", {}).get("count", 0) > 0:
        reasons.append("Seen in OTX threat pulses")

    summary = f"""🔎 IoC Summary – {ip}

Indicator Type: IP Address
Risk Level: {risk}
Category: Suspicious / Malicious

🧠 Why it’s flagged
"""
    if reasons:
        for r in reasons:
            summary += f"- {r}\n"
    else:
        summary += "- No strong malicious indicators found\n"

    summary += f"""
🔗 External Reports
VirusTotal:
https://www.virustotal.com/gui/ip-address/{ip}

AbuseIPDB:
https://www.abuseipdb.com/check/{ip}

OTX:
https://otx.alienvault.com/indicator/ip/{ip}
"""

    await update.message.reply_text(summary)

# ------------------ App ------------------

app = ApplicationBuilder().token(BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("help", help_cmd))
app.add_handler(CommandHandler("ioc", ioc))

app.run_polling()
