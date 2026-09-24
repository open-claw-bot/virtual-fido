package ctap

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/test"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/bulwarkid/virtual-fido/webauthn"
	"github.com/fxamacker/cbor/v2"
)

type dummyCTAPClient struct {
	vault identities.IdentityVault
}
func (client *dummyCTAPClient) SupportsResidentKey() bool {
	return true
}
func (client *dummyCTAPClient) SupportsPIN() bool {
	return false
}

func (client *dummyCTAPClient) NewCredentialSource(
	PubKeyCredParams []webauthn.PublicKeyCredentialParams,
	ExcludeList []webauthn.PublicKeyCredentialDescriptor,
	relyingParty *webauthn.PublicKeyCredentialRPEntity,
	user *webauthn.PublicKeyCrendentialUserEntity) *identities.CredentialSource {
	return client.vault.NewIdentity(relyingParty, user)
}
func (client *dummyCTAPClient) GetAssertionSource(
	relyingPartyID string, 
	allowList []webauthn.PublicKeyCredentialDescriptor) *identities.CredentialSource {
	sources := client.vault.GetMatchingCredentialSources(relyingPartyID, allowList)
	if len(sources) > 0 {
		return sources[0]
	} else {
		return nil
	}
}
func (client *dummyCTAPClient) CreateAttestationCertificiate(privateKey *cose.SupportedCOSEPrivateKey) []byte {
	return nil
}

func (client *dummyCTAPClient) PINHash() []byte {
	return nil
}
func (client *dummyCTAPClient) SetPINHash(pin []byte) {}
func (client *dummyCTAPClient) PINRetries() int32 {
	return 0
}
func (client *dummyCTAPClient) SetPINRetries(retries int32) {}
func (client *dummyCTAPClient) PINKeyAgreement() *crypto.ECDHKey {
	return nil
}
func (client *dummyCTAPClient) PINToken() []byte {
	return nil
}

func (client *dummyCTAPClient) ApproveAccountCreation(relyingParty string) bool {
	return true
}
func (client *dummyCTAPClient) ApproveAccountLogin(credentialSource *identities.CredentialSource) bool {
	return true
}

func TestMakeCredential(t *testing.T) {
	client := &dummyCTAPClient{}
	ctap := NewCTAPServer(client)

	args := makeCredentialArgs{
		ClientDataHash: []byte{},
		RP: &webauthn.PublicKeyCredentialRPEntity{
			ID: "example.com",
			Name: "Example",
		},
		User: &webauthn.PublicKeyCrendentialUserEntity{
			ID: []byte{0,1,2,3,4},
			DisplayName: "DisplayAlice",
			Name: "Alice",
		},
		PubKeyCredParams: []webauthn.PublicKeyCredentialParams{
			{
				Type: "public-key",
				Algorithm: cose.COSE_ALGORITHM_ID_ES256,
			},
		},
		ExcludeList: []webauthn.PublicKeyCredentialDescriptor{},
		Extensions: map[string]interface{}{},
		Options: &makeCredentialOptions{
			ResidentKey: true,
		},
		PINUVAuthParam: nil,
		PINUVAuthProtocol: 0,
	}
	argBytes, err := cbor.Marshal(&args)
	util.CheckErr(err, "Cant create makeCredentialArgs")
	message := util.Concat([]byte{byte(ctapCommandMakeCredential)}, argBytes)

	responseBytes := ctap.HandleMessage(message)
	test.AssertNotNil(t, responseBytes, "Response is nil")
	code := ctapStatusCode(responseBytes[0])
	test.AssertEqual(t, code, ctap1ErrSuccess, "Response code is not success")
	var response makeCredentialResponse
	err = cbor.Unmarshal(responseBytes[1:], &response)
	util.CheckErr(err, "Invalid response")
	test.AssertNotNil(t, response.AuthData, "AuthData is nil")
	test.AssertNotEqual(t, response.FormatIdentifer, "", "Format is empty")
	test.AssertNotNil(t, response.AttestationStatement.Sig, "Attestation signature is nil")
	test.AssertNotNil(t, response.AttestationStatement.X5c, "Attestation cert is nil")
}

// TestMakeCredentialAuthDataFlags verifies the authenticator data flags byte
// is standards-conformant. This is a regression test ensuring the AT bit is
// set at bit 6 (0x40) and ED at bit 7 (0x80), per WebAuthn L2 §6.1 / CTAP2.
// (Emitting AT at bit 5 / 0x20 -- which is RFU2/reserved -- makes browsers
// such as Firefox and the Windows WebAuthn API skip the attested credential
// data, so a packed-attestation MakeCredential response yields an empty
// credential ID / rawId, which relying parties like OpenRouter/Clerk reject.)
func TestMakeCredentialAuthDataFlags(t *testing.T) {
	client := &dummyCTAPClient{}
	ctap := NewCTAPServer(client)

	args := makeCredentialArgs{
		ClientDataHash: []byte{},
		RP: &webauthn.PublicKeyCredentialRPEntity{
			ID:   "example.com",
			Name: "Example",
		},
		User: &webauthn.PublicKeyCrendentialUserEntity{
			ID:          []byte{0, 1, 2, 3, 4},
			DisplayName: "DisplayAlice",
			Name:        "Alice",
		},
		PubKeyCredParams: []webauthn.PublicKeyCredentialParams{
			{
				Type:      "public-key",
				Algorithm: cose.COSE_ALGORITHM_ID_ES256,
			},
		},
		ExcludeList:      []webauthn.PublicKeyCredentialDescriptor{},
		Extensions:       map[string]interface{}{},
		Options:          &makeCredentialOptions{ResidentKey: true},
		PINUVAuthParam:   nil,
		PINUVAuthProtocol: 0,
	}
	argBytes := util.Concat([]byte{byte(ctapCommandMakeCredential)}, util.MarshalCBOR(args))
	responseBytes := ctap.HandleMessage(argBytes)
	test.AssertEqual(t, ctapStatusCode(responseBytes[0]), ctap1ErrSuccess, "Response is not success")
	var response makeCredentialResponse
	err := cbor.Unmarshal(responseBytes[1:], &response)
	util.CheckErr(err, "Invalid response")

	authData := response.AuthData
	test.Assert(t, len(authData) >= 37, "AuthData too short")
	flags := authData[32]
	test.Assert(t, flags&byte(authDataFlagUserPresent) != 0, "UP flag not set")
	test.Assert(t, flags&byte(authDataFlagAttestedDataIncluded) != 0,
		fmt.Sprintf("AT flag (0x40) not set (got 0x%02x): attested credential data present but flag says otherwise", flags))
	test.Assert(t, flags&byte(authDataFlagExtensionDataIncluded) == 0,
		fmt.Sprintf("ED flag (0x80) set on a response with no extension data (got 0x%02x)", flags))

	// Validate the attested-credential-data layout consumes exactly the rest
	// of the buffer, so the structure agrees with the AT flag.
	rest := authData[37:]
	test.Assert(t, len(rest) >= 18, "No room for AAGUID + credential ID length")
	credIDLen := int(rest[16])<<8 | int(rest[17])
	test.Assert(t, len(rest) == 18+credIDLen+len(cose.MarshalCOSEPublicKey(client.vault.CredentialSources[0].PrivateKey.Public())),
		"AuthData trailing bytes do not match AT structure")
}

// TestMakeCredentialAttestationSignatureIsDER verifies the "packed" attestation
// signature uses the ASN.1 DER encoding required by WebAuthn/CTAP2 (RFC 9053
// §8.1, WebAuthn L2 §6.5.6 "Signature Attestation Types"). A raw r||s
// signature is rejected by relying parties: @simplewebauthn/server (used by
// Clerk/OpenRouter) parses the signature with an ASN.1 parser, so a raw 64-byte
// signature throws and registration fails with "Passkey registration failed".
func TestMakeCredentialAttestationSignatureIsDER(t *testing.T) {
	client := &dummyCTAPClient{}
	server := NewCTAPServer(client)

	clientDataHash := crypto.HashSHA256([]byte("client data"))
	args := makeCredentialArgs{
		ClientDataHash: clientDataHash,
		RP: &webauthn.PublicKeyCredentialRPEntity{
			ID:   "example.com",
			Name: "Example",
		},
		User: &webauthn.PublicKeyCrendentialUserEntity{
			ID:          []byte{0, 1, 2, 3, 4},
			DisplayName: "DisplayAlice",
			Name:        "Alice",
		},
		PubKeyCredParams: []webauthn.PublicKeyCredentialParams{
			{Type: "public-key", Algorithm: cose.COSE_ALGORITHM_ID_ES256},
		},
		Options: &makeCredentialOptions{ResidentKey: true},
	}
	message := util.Concat([]byte{byte(ctapCommandMakeCredential)}, util.MarshalCBOR(args))
	responseBytes := server.HandleMessage(message)
	test.AssertEqual(t, ctapStatusCode(responseBytes[0]), ctap1ErrSuccess, "Response is not success")

	var response makeCredentialResponse
	err := cbor.Unmarshal(responseBytes[1:], &response)
	util.CheckErr(err, "Invalid response")

	publicKey := client.vault.CredentialSources[0].PrivateKey.Public().ECDSA
	signed := util.Concat(response.AuthData, clientDataHash)
	signature := response.AttestationStatement.Sig

	test.Assert(t, crypto.VerifyECDSADER(publicKey, signed, signature),
		fmt.Sprintf("attestation signature is not a valid DER-encoded ECDSA signature (len=%d)", len(signature)))
}

func TestGetAssertion(t *testing.T) {
	client := &dummyCTAPClient{}
	ctap := NewCTAPServer(client)
	identity := client.vault.NewIdentity(&webauthn.PublicKeyCredentialRPEntity{
		ID: "rp",
		Name: "rp",
	}, &webauthn.PublicKeyCrendentialUserEntity{
		ID: []byte{0,1,2,3,4},
		DisplayName: "Alice",
		Name: "Alice",
	})

	clientDataHash := crypto.HashSHA256([]byte{0,1,2,3,4})
	args := getAssertionArgs{
		RPID: "rp",
		ClientDataHash: clientDataHash,
		AllowList: []webauthn.PublicKeyCredentialDescriptor{
			{
				Type: "public-key",
				ID: identity.ID,
				Transports: []string{"USB"},
			},
		},
		Options: getAssertionOptions{},
		PINUVAuthParam: nil,
		PINUVAuthProtocol: 0,
	}
	argBytes := util.Concat([]byte{byte(ctapCommandGetAssertion)}, util.MarshalCBOR(args))
	responseBytes := ctap.HandleMessage(argBytes)
	test.AssertNotNil(t, responseBytes, "Response is nil")
	test.AssertEqual(t, ctapStatusCode(responseBytes[0]), ctap1ErrSuccess, "Response is not success")
	var response getAssertionResponse
	err := cbor.Unmarshal(responseBytes[1:], &response)
	util.CheckErr(err, "Could not decode response")
	test.Assert(t, bytes.Equal(response.Credential.ID, identity.ID), "Did not return correct identity")
}

func TestGetInfo(t *testing.T) {
	client := &dummyCTAPClient{}
	ctap := NewCTAPServer(client)
	argBytes := util.Concat([]byte{byte(ctapCommandGetInfo)})
	responseBytes := ctap.HandleMessage(argBytes)
	test.AssertNotNil(t, responseBytes, "Response is nil")
	test.AssertEqual(t, ctapStatusCode(responseBytes[0]), ctap1ErrSuccess, "Response is not success")
	var response getInfoResponse
	err := cbor.Unmarshal(responseBytes[1:], &response)
	util.CheckErr(err, "Could not decode response")
	test.AssertContains(t, response.Versions, "U2F_V2", "U2F not supported")
	test.AssertContains(t, response.Versions, "FIDO_2_0", "FIDO2.0 not supported")
	test.Assert(t, !bytes.Equal(make([]byte,16), response.AAGUID[:]), "AAGUID is empty")
	test.Assert(t, response.Options.CanResidentKey, "Cant use resident keys")
	test.Assert(t, !response.Options.IsPlatform, "Is not marked a non-platform auth")
}