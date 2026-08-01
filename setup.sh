#!/bin/bash
# One-time setup after cloning this repo.
# Run this once, then fill in real values in .env

echo "Creating .env from template..."
cp .env.example .env

echo ""
echo "Now edit .env and fill in your real values:"
echo "  nano .env"
echo ""
echo "You need:"
echo "  TELEGRAM_BOT_TOKEN  - from @BotFather on Telegram"
echo "  TELEGRAM_CHAT_ID    - your numeric chat ID"
echo "  VT_API_KEY          - from virustotal.com (optional)"
echo ""
echo "Then run:"
echo "  docker compose up --build -d"
