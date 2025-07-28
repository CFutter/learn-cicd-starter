package auth

import (
	"net/http"
	"testing"
)

func TestAuth(t *testing.T) {
	saulAccessToken := "someValidAccessToken123" // Define a dummy access token for testing

	// --- Test Case 1: Correct API Key format ---
	headerOne := make(http.Header)
	headerOne.Set("Authorization", "ApiKey "+saulAccessToken) // Correct way to set
	if _, err := GetAPIKey(headerOne); err != nil {
		t.Fatalf("Test Case 1 failed: expected an API key, got error: %v", err)
	}

	// --- Test Case 2: Incorrect header name ("Authoron") ---
	headerTwo := make(http.Header)
	headerTwo.Set("Authoron", "ApiKey "+saulAccessToken) // Incorrect header name
	if _, err := GetAPIKey(headerTwo); err == nil {
		t.Fatalf("Test Case 2 failed: expected an error due to wrong header name, got none")
	}

	// --- Test Case 3: Incorrect scheme ("ApiTey") ---
	headerThree := make(http.Header)
	headerThree.Set("Authorization", "ApiTey "+saulAccessToken) // Incorrect scheme
	if _, err := GetAPIKey(headerThree); err == nil {
		t.Fatalf("Test Case 3 failed: expected an error due to wrong scheme, got none")
	}

	// --- Test Case 4: Missing API Key value ---
	headerFour := make(http.Header)
	headerFour.Set("Authorization", "ApiKey") // Missing key
	if _, err := GetAPIKey(headerFour); err == nil {
		t.Fatalf("Test Case 4 failed: expected an error due to missing API key, got none")
	}

	// --- Test Case 5: No Authorization header at all ---
	headerFive := make(http.Header)
	// Do not set any authorization header
	if _, err := GetAPIKey(headerFive); err == nil {
		t.Fatalf("Test Case 5 failed: expected an error when no Authorization header is present, got none")
	}
}
