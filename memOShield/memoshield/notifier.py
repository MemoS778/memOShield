import os
import logging
import requests

TELEGRAM_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT = os.getenv('TELEGRAM_CHAT_ID')
SLACK_WEBHOOK = os.getenv('SLACK_WEBHOOK')


class Notifier:
    def __init__(self):
        self.token = TELEGRAM_TOKEN
        self.chat_id = TELEGRAM_CHAT
        self.slack = SLACK_WEBHOOK

    def send_telegram(self, text: str) -> bool:
        if not (self.token and self.chat_id):
            logging.debug('Telegram creds not set; skipping notification')
            return False
        url = f'https://api.telegram.org/bot{self.token}/sendMessage'
        payload = {'chat_id': self.chat_id, 'text': text}
        try:
            r = requests.post(url, json=payload, timeout=5)
            return r.ok
        except Exception as e:
            logging.warning('Failed to send telegram: %s', e)
            return False

    def send_slack(self, text: str) -> bool:
        if not self.slack:
            logging.debug('Slack webhook not set; skipping')
            return False
        try:
            r = requests.post(self.slack, json={'text': text}, timeout=5)
            return r.ok
        except Exception as e:
            logging.warning('Failed to send slack message: %s', e)
            return False

    def notify_critical(self, event: dict) -> None:
        """Send critical alert to configured channels. Non-blocking best-effort."""
        text = f"[CRITICAL] {event.get('type')} from {event.get('ip')} reason={event.get('reason')}"
        try:
            # best-effort, ignore failures
            self.send_telegram(text)
            self.send_slack(text)
        except Exception:
            logging.exception('Notifier failed')
