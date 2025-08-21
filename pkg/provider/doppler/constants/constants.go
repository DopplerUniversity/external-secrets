package constants

import "time"

const (
	// DefaultRetryAmount is the default that's used if the user doesn't specify one
	DefaultRetryAmount = 3

	// DefaultRetryDuration is the default that's used if the user doesn't supply
	DefaultRetryDuration = 5 * time.Second

	// MaxBackoffMultiplier caps exponential growth at 8x base delay
	MaxBackoffMultiplier = 8

	// JitterMultiplier sets the percentage we vary sleeps by to avoid thundering herd issues
	JitterMultiplier = 0.1

	// MaxAllowedRetries is the maximum number of retries we allow the user to specify
	MaxAllowedRetries = 10

	// MinAllowedDelay is the lowest delay we allow the user to specify
	MinAllowedDelay = time.Second

	// MaxAllowedDelay is the highest delay we allow the user to specify
	MaxAllowedDelay = 10 * time.Second
)
