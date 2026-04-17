#!/bin/bash

# ====== ENV ======
export OPENAI_API_KEY=""
export OPENAI_BASE_URL="https://openrouter.ai/api/v1"
export ABUSEIPDB_API_KEY=""
export TELEGRAM_BOT_TOKEN=""
export TELEGRAM_CHAT_ID=""

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
