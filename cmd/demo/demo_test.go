package main

import (
	"testing"

	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/webauthn"
)

func testIdentities() []identities.CredentialSource {
	return []identities.CredentialSource{
		{
			ID:           []byte{0x1A, 0x2B, 0x3C, 0x4D, 0x01},
			RelyingParty: &webauthn.PublicKeyCredentialRPEntity{ID: "github.com", Name: "GitHub"},
			User:         &webauthn.PublicKeyCrendentialUserEntity{ID: []byte{1}, Name: "alice@example.com", DisplayName: "Alice"},
		},
		{
			ID:           []byte{0x1A, 0x2B, 0x3C, 0x4D, 0x02},
			RelyingParty: &webauthn.PublicKeyCredentialRPEntity{ID: "github.com", Name: "GitHub"},
			User:         &webauthn.PublicKeyCrendentialUserEntity{ID: []byte{2}, Name: "bob@example.com", DisplayName: "Bob"},
		},
		{
			ID:           []byte{0xAA, 0xBB, 0xCC, 0xDD, 0x01},
			RelyingParty: &webauthn.PublicKeyCredentialRPEntity{ID: "gitlab.com", Name: "GitLab"},
			User:         &webauthn.PublicKeyCrendentialUserEntity{ID: []byte{3}, Name: "alice@example.com", DisplayName: "Alice"},
		},
	}
}

func TestFilterIdentities(t *testing.T) {
	sources := testIdentities()
	tests := []struct {
		name   string
		filter credentialFilter
		want   int
	}{
		// Fail-safe: an empty filter must never select everything.
		{"empty filter matches nothing", credentialFilter{}, 0},
		{"id prefix", credentialFilter{identityPrefix: "1a2b"}, 2},
		{"id prefix is case-insensitive", credentialFilter{identityPrefix: "1A2B"}, 2},
		{"website by id", credentialFilter{website: "github.com"}, 2},
		{"website by name is case-insensitive", credentialFilter{website: "gitlab"}, 1},
		{"website and user", credentialFilter{website: "github.com", user: "alice@example.com"}, 1},
		{"user across websites", credentialFilter{user: "alice@example.com"}, 2},
		{"user by display name", credentialFilter{user: "BOB"}, 1},
		{"no match", credentialFilter{website: "example.org"}, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := len(filterIdentities(sources, test.filter)); got != test.want {
				t.Fatalf("filterIdentities(%v) matched %d credentials, want %d", test.filter, got, test.want)
			}
		})
	}
}

func TestCredentialFilterMatchDetails(t *testing.T) {
	sources := testIdentities()

	got := filterIdentities(sources, credentialFilter{website: "github.com", user: "alice@example.com"})
	if len(got) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(got))
	}
	if got[0].User.Name != "alice@example.com" || got[0].RelyingParty.ID != "github.com" {
		t.Fatalf("matched the wrong credential: %+v", got[0])
	}
	// The matched value must not alias the range variable / original slice
	// element's identity in a way that makes later comparisons wrong.
	if got[0].ID[1] != 0x2B {
		t.Fatalf("credential ID was altered: %x", got[0].ID)
	}
}

func TestNormalizeWebsite(t *testing.T) {
	tests := map[string]string{
		"github.com":             "github.com",
		"  github.com  ":         "github.com",
		"https://github.com":     "github.com",
		"HTTPS://GitHub.com/":    "GitHub.com",
		"http://a.example.com//": "a.example.com",
	}
	for input, want := range tests {
		if got := normalizeWebsite(input); got != want {
			t.Fatalf("normalizeWebsite(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCredentialFilterIsEmptyAndIsBulk(t *testing.T) {
	if !(credentialFilter{}).isEmpty() {
		t.Fatalf("zero filter should be empty")
	}
	if (credentialFilter{identityPrefix: "ab"}).isEmpty() {
		t.Fatalf("filter with an ID prefix should not be empty")
	}
	if (credentialFilter{identityPrefix: "ab"}).isBulk() {
		t.Fatalf("a bare ID prefix should not be a bulk filter")
	}
	if !(credentialFilter{website: "github.com"}).isBulk() {
		t.Fatalf("a website filter should be a bulk filter")
	}
	if !(credentialFilter{user: "alice"}).isBulk() {
		t.Fatalf("a user filter should be a bulk filter")
	}
}
