package identities

import (
	"testing"

	"github.com/bulwarkid/virtual-fido/webauthn"
)

// TestImportKeepsDistinctRelyingParties ensures that importing a vault with
// multiple credentials keeps each credential's relying party and user
// distinct. A classic Go bug is capturing the loop variable's address in
// Import (e.g. &source.RelyingParty), which makes every imported source
// point at the LAST source's data, silently corrupting all existing keys.
func TestImportKeepsDistinctRelyingParties(t *testing.T) {
	vault := NewIdentityVault()
	vault.NewIdentity(
		&webauthn.PublicKeyCredentialRPEntity{ID: "a.example.com", Name: "Site A"},
		&webauthn.PublicKeyCrendentialUserEntity{ID: []byte{1}, Name: "Alice"})
	vault.NewIdentity(
		&webauthn.PublicKeyCredentialRPEntity{ID: "b.example.com", Name: "Site B"},
		&webauthn.PublicKeyCrendentialUserEntity{ID: []byte{2}, Name: "Bob"})

	exported := vault.Export()

	imported := NewIdentityVault()
	if err := imported.Import(exported); err != nil {
		t.Fatalf("Import failed: %v", err)
	}
	if len(imported.CredentialSources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(imported.CredentialSources))
	}

	if got := imported.CredentialSources[0].RelyingParty.ID; got != "a.example.com" {
		t.Fatalf("source[0] relying party corrupted: got %q, want %q", got, "a.example.com")
	}
	if got := imported.CredentialSources[1].RelyingParty.ID; got != "b.example.com" {
		t.Fatalf("source[1] relying party corrupted: got %q, want %q", got, "b.example.com")
	}
	if got := imported.CredentialSources[0].User.Name; got != "Alice" {
		t.Fatalf("source[0] user corrupted: got %q, want %q", got, "Alice")
	}
	if got := imported.CredentialSources[1].User.Name; got != "Bob" {
		t.Fatalf("source[1] user corrupted: got %q, want %q", got, "Bob")
	}
}

// TestDeleteIdentityRemovesOnlyMatching ensures DeleteIdentity removes
// exactly the credential with the matching ID and leaves others untouched.
func TestDeleteIdentityRemovesOnlyMatching(t *testing.T) {
	vault := NewIdentityVault()
	first := vault.NewIdentity(
		&webauthn.PublicKeyCredentialRPEntity{ID: "a.example.com", Name: "Site A"},
		&webauthn.PublicKeyCrendentialUserEntity{ID: []byte{1}, Name: "Alice"})
	second := vault.NewIdentity(
		&webauthn.PublicKeyCredentialRPEntity{ID: "b.example.com", Name: "Site B"},
		&webauthn.PublicKeyCrendentialUserEntity{ID: []byte{2}, Name: "Bob"})

	if !vault.DeleteIdentity(first.ID) {
		t.Fatalf("DeleteIdentity returned false for existing ID")
	}
	if len(vault.CredentialSources) != 1 {
		t.Fatalf("expected 1 source after delete, got %d", len(vault.CredentialSources))
	}
	if got := vault.CredentialSources[0].ID; !bytesEqual(got, second.ID) {
		t.Fatalf("wrong source remains after delete")
	}
}

// TestDeleteIdentitiesRemovesAllMatching ensures a batch delete removes every
// requested credential (and only those), even though DeleteIdentity reorders
// the vault as it goes.
func TestDeleteIdentitiesRemovesAllMatching(t *testing.T) {
	vault := NewIdentityVault()
	kept := vault.NewIdentity(
		&webauthn.PublicKeyCredentialRPEntity{ID: "c.example.com", Name: "Site C"},
		&webauthn.PublicKeyCrendentialUserEntity{ID: []byte{3}, Name: "Carol"})
	first := vault.NewIdentity(
		&webauthn.PublicKeyCredentialRPEntity{ID: "a.example.com", Name: "Site A"},
		&webauthn.PublicKeyCrendentialUserEntity{ID: []byte{1}, Name: "Alice"})
	second := vault.NewIdentity(
		&webauthn.PublicKeyCredentialRPEntity{ID: "b.example.com", Name: "Site B"},
		&webauthn.PublicKeyCrendentialUserEntity{ID: []byte{2}, Name: "Bob"})

	deleted := vault.DeleteIdentities([][]byte{first.ID, second.ID})
	if deleted != 2 {
		t.Fatalf("expected 2 credentials deleted, got %d", deleted)
	}
	if len(vault.CredentialSources) != 1 {
		t.Fatalf("expected 1 source left, got %d", len(vault.CredentialSources))
	}
	if got := vault.CredentialSources[0].ID; !bytesEqual(got, kept.ID) {
		t.Fatalf("wrong source remains after batch delete")
	}

	// Deleting the same IDs twice must be a no-op.
	if deleted := vault.DeleteIdentities([][]byte{first.ID, second.ID}); deleted != 0 {
		t.Fatalf("expected 0 credentials deleted on the second pass, got %d", deleted)
	}
	if len(vault.CredentialSources) != 1 {
		t.Fatalf("expected 1 source still left, got %d", len(vault.CredentialSources))
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
