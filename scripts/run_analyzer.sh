#!/bin/bash

# ====== ENV ======
export OPENAI_API_KEY="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"
export OPENAI_BASE_URL="https://openrouter.ai/api/v1"
export ABUSEIPDB_API_KEY="d7e13c6422ba0b3d9405bcfba3d28edb576f6856bc15545b094aa6fee6b6edb67e066125812e6624"
export TELEGRAM_BOT_TOKEN="8601519829:AAF_PjU06fxN8g_D6JQ9iPxhhAY75p1f9Ks"
export TELEGRAM_CHAT_ID="6236677517"

# ====== PATHS ======
PROJECT_DIR="/home/imsupershy/monitoring-project/langchain_pipeline"
VENV_PYTHON="$PROJECT_DIR/venv/bin/python"
ANALYZER="$PROJECT_DIR/src/analyzer.py"
LOGFILE="$PROJECT_DIR/logs/analyzer-cron.log"

# ====== RUN ======
echo "[$(date)] Analyzer started" >> $LOGFILE
$VENV_PYTHON $ANALYZER >> $LOGFILE 2>&1
echo "[$(date)] Analyzer finished" >> $LOGFILE
echo "--------------------------------" >> $LOGFILE
