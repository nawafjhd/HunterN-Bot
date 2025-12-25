import os
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
)

BOT_TOKEN = os.getenv("BOT_TOKEN")

# ===== Commands =====
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 HunterN Bot is running!\n\nCommands:\n/start\n/status"
    )

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("✅ Bot status: ONLINE")

# ===== Main =====
def main():
    if not BOT_TOKEN:
        raise RuntimeError("❌ BOT_TOKEN is not set in environment variables")

    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("status", status))

    print("🚀 HunterN Bot started successfully")
    app.run_polling()

if __name__ == "__main__":
    main()
