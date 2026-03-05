package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/MemoS778/memOShield/internal/config"
)

// Notifier sends alerts to Telegram and Slack.
type Notifier struct {
	token   string
	chatID  string
	slack   string
	client  *http.Client
}

// New creates a Notifier.
func New() *Notifier {
	return &Notifier{
		token:  config.TelegramBotToken,
		chatID: config.TelegramChatID,
		slack:  config.SlackWebhook,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// SendTelegram sends a message via Telegram Bot API.
func (n *Notifier) SendTelegram(text string) bool {
	if n.token == "" || n.chatID == "" {
		log.Println("Telegram creds not set; skipping notification")
		return false
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.token)
	payload, _ := json.Marshal(map[string]string{
		"chat_id": n.chatID,
		"text":    text,
	})
	resp, err := n.client.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("Failed to send telegram: %v", err)
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// SendSlack sends a message via Slack webhook.
func (n *Notifier) SendSlack(text string) bool {
	if n.slack == "" {
		log.Println("Slack webhook not set; skipping")
		return false
	}
	payload, _ := json.Marshal(map[string]string{"text": text})
	resp, err := n.client.Post(n.slack, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("Failed to send slack message: %v", err)
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// NotifyCritical sends alerts to all configured channels (best-effort).
func (n *Notifier) NotifyCritical(eventType, ip, reason string) {
	text := fmt.Sprintf("[CRITICAL] %s from %s reason=%s", eventType, ip, reason)
	go n.SendTelegram(text)
	go n.SendSlack(text)
}
