import os
import json
import asyncio
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CallbackQueryHandler, ContextTypes
from pathlib import Path

# Cấu hình đường dẫn (Khớp với analyzer.py của bạn)
BLOCKED_IPS_FILE = Path("/home/imsupershy/monitoring-project/langchain_pipeline/logs/blocked_ips.json")
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") # Đảm bảo bạn đã export token này
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")   # ID của bạn hoặc Group

async def send_interactive_alert(ip, severity, category, reason):
    """Gửi tin nhắn kèm nút bấm Block IP."""
    text = (
        f"🚨 *AI SECURITY ALERT*\n"
        f"━━━━━━━━━━━━━━━\n"
        f"📍 *IP:* `{ip}`\n"
        f"📊 *Severity:* {severity}\n"
        f"🔍 *Type:* {category}\n"
        f"📝 *Behavior:* {reason}\n"
        f"━━━━━━━━━━━━━━━\n"
        f"Bạn có muốn chặn IP này không?"
    )
    
    # Tạo nút bấm
    keyboard = [
        [
            InlineKeyboardButton("🚫 BLOCK IP", callback_data=f"block:{ip}"),
            InlineKeyboardButton("✅ IGNORE", callback_data="ignore")
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    app = Application.builder().token(TOKEN).build()
    await app.bot.send_message(chat_id=CHAT_ID, text=text, parse_mode='Markdown', reply_markup=reply_markup)

async def handle_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Xử lý khi người dùng nhấn nút trên điện thoại."""
    query = update.callback_query
    await query.answer()
    
    if query.data.startswith("block:"):
        ip = query.data.split(":")[1]
        
        # Ghi vào file blocked_ips.json
        blocked_data = {}
        if BLOCKED_IPS_FILE.exists():
            blocked_data = json.loads(BLOCKED_IPS_FILE.read_text())
        
        blocked_data[ip] = {"blocked_at": "Manual via Telegram", "reason": "Confirmed by Admin"}
        BLOCKED_IPS_FILE.write_text(json.dumps(blocked_data, indent=2))
        
        await query.edit_message_text(text=f"✅ Đã chặn IP: `{ip}` thành công!")
    else:
        await query.edit_message_text(text="👌 Đã bỏ qua cảnh báo.")

if __name__ == "__main__":
    # Chạy bot để lắng nghe phản hồi từ nút bấm
    print("[BOT] Đang lắng nghe lệnh phản hồi...")
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CallbackQueryHandler(handle_button))
    app.run_polling()