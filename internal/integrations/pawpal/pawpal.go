package pawpal

import (
	"crypto/subtle"
	"fmt"
	"math"
)

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
)

const maxSafeInt float64 = 9_007_199_254_740_991

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

func VerifyWebhook(payload any, expected, provided string) WebhookVerification {
	if !webhookKeysMatch(expected, provided) {
		return WebhookVerification{Outcome: WebhookUnauthorized}
	}
	return verifyPayload(payload)
}

func webhookKeysMatch(expected, provided string) bool {
	expectedByte := []byte(expected)
	providedByte := []byte(provided)
	return len(expectedByte) == len(providedByte) && subtle.ConstantTimeCompare(expectedByte, providedByte) == 1
}

func verifyPayload(payload any) WebhookVerification {
	payloadRecord, ok := payload.(map[string]any)
	if !ok || payloadRecord["status"] != "approved" {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	orderID, ok := payloadRecord["orderId"].(float64)
	if !ok || orderID != math.Trunc(orderID) || orderID < 1 || orderID > maxSafeInt {
		return WebhookVerification{Outcome: WebhookMalformed, OrderID: 0}
	}
	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(orderID)}
}
