import os
import requests
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes
)

# ========= ENV =========
BOT_TOKEN = os.getenv("BOT_TOKEN")
OTX_API_KEY = os.getenv("OTX_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")

# ========= COMMANDS =========
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🧠 HunterN IOC Bot جاهز\n\n"
        "الأوامر:\n"
        "/ioc <IP | Domain | Hash>\n"
        "/help"
    )

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📌 الاستخدام:\n"
        "/ioc 8.8.8.8\n"
        "/ioc example.com\n"
        "/ioc <hash>"
    )

async def ioc(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ استخدم: /ioc <indicator>")
        return

    indicator = context.args[0]

    message = f"🔎 IoC Summary – {indicator}\n\n"

    # ===== AbuseIPDB =====
    try:
        abuse_resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSE_API_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress": indicator,
                "maxAgeInDays": 90
            },
            timeout=10
        ).json()

        data = abuse_resp.get("data", {})
        score = data.get("abuseConfidenceScore", "N/A")
        country = data.get("countryCode", "Unknown")

        message += (
            "🚩 AbuseIPDB\n"
            f"- Score: {score}%\n"
            f"- Country: {country}\n"
            f"- https://abuseipdb.com/check/{indicator}\n\n"
        )
    except Exception:
        message += "⚠️ AbuseIPDB: no data\n\n"

    # ===== VirusTotal =====
    try:
        vt_resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
            headers={"x-apikey": VT_API_KEY},
            timeout=10
        ).json()

        stats = vt_resp["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)

        message += (
            "🧪 VirusTotal\n"
            f"- Malicious detections: {malicious}\n"
            f"- https://www.virustotal.com/gui/ip-address/{indicator}\n\n"
        )
    except Exception:
        message += "⚠️ VirusTotal: no data\n\n"

    # ===== OTX =====
    try:
        otx_resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=10
        ).json()

        pulse_count = otx_resp.get("pulse_info", {}).get("count", 0)

        message += (
            "🧠 AlienVault OTX\n"
            f"- Pulses: {pulse_count}\n"
            f"- https://otx.alienvault.com/indicator/ip/{indicator}\n"
        )
    except Exception:
        message += "⚠️ OTX: no data\n"

    await update.message.reply_text(message)

# ========= MAIN =========
def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("ioc", ioc))

    print("✅ HunterN Bot is running")
    app.run_polling()

if __name__ == "__main__":
    main()
