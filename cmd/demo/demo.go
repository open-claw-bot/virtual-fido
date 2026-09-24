package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	virtual_fido "github.com/bulwarkid/virtual-fido"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/spf13/cobra"
)

var vaultFilename string
var vaultPassphrase string
var identityID string
var deleteWebsite string
var deleteUser string
var deleteForce bool
var verbose bool

func checkErr(err error, message string) {
	if err != nil {
		panic(fmt.Sprintf("Error: %s - %s", err, message))
	}
}

func listIdentities(cmd *cobra.Command, args []string) {
	client := createClient()
	fmt.Printf("------- Identities in file '%s' -------\n", vaultFilename)
	sources := client.Identities()
	for _, source := range sources {
		fmt.Printf("(%s): '%s' for website '%s'\n", hex.EncodeToString(source.ID[:4]), source.User.Name, source.RelyingParty.Name)
	}
}

// credentialFilter selects the stored credentials a command operates on. Empty
// fields are ignored; when several fields are set they are combined with AND.
type credentialFilter struct {
	// identityPrefix matches the beginning of the hex-encoded credential ID.
	identityPrefix string
	// website matches the relying party ID or name (case-insensitive).
	website string
	// user matches the account name or display name (case-insensitive).
	user string
}

func (filter credentialFilter) isEmpty() bool {
	return filter.identityPrefix == "" && filter.website == "" && filter.user == ""
}

// isBulk reports whether the filter may match several credentials. A bare
// --identity intentionally keeps its original "abort when ambiguous" behavior.
func (filter credentialFilter) isBulk() bool {
	return filter.website != "" || filter.user != ""
}

func (filter credentialFilter) String() string {
	parts := make([]string, 0, 3)
	if filter.identityPrefix != "" {
		parts = append(parts, fmt.Sprintf("ID prefix '%s'", filter.identityPrefix))
	}
	if filter.website != "" {
		parts = append(parts, fmt.Sprintf("website '%s'", filter.website))
	}
	if filter.user != "" {
		parts = append(parts, fmt.Sprintf("account '%s'", filter.user))
	}
	return strings.Join(parts, " and ")
}

// normalizeWebsite tolerates the way a site is usually pasted (for example
// "https://example.com/") by dropping the scheme and any trailing slashes.
// The stored relying party ID never has either.
func normalizeWebsite(website string) string {
	normalized := strings.TrimSpace(website)
	for _, scheme := range []string{"https://", "http://"} {
		if len(normalized) >= len(scheme) && strings.EqualFold(normalized[:len(scheme)], scheme) {
			normalized = normalized[len(scheme):]
			break
		}
	}
	return strings.TrimRight(normalized, "/")
}

func (filter credentialFilter) matches(source identities.CredentialSource) bool {
	// An empty filter matches nothing. Every field is optional and ignored
	// when blank, so without this guard a caller that forgot to validate the
	// filter would select (and could delete) the entire vault.
	if filter.isEmpty() {
		return false
	}
	if filter.identityPrefix != "" {
		hexString := hex.EncodeToString(source.ID)
		if !strings.HasPrefix(strings.ToLower(hexString), strings.ToLower(filter.identityPrefix)) {
			return false
		}
	}
	if filter.website != "" {
		if source.RelyingParty == nil {
			return false
		}
		if !strings.EqualFold(source.RelyingParty.ID, filter.website) && !strings.EqualFold(source.RelyingParty.Name, filter.website) {
			return false
		}
	}
	if filter.user != "" {
		if source.User == nil {
			return false
		}
		if !strings.EqualFold(source.User.Name, filter.user) && !strings.EqualFold(source.User.DisplayName, filter.user) {
			return false
		}
	}
	return true
}

// filterIdentities returns copies of the credentials matching filter. The
// values are copied out of client.Identities(), so holding them is safe.
func filterIdentities(sources []identities.CredentialSource, filter credentialFilter) []identities.CredentialSource {
	matches := make([]identities.CredentialSource, 0)
	for _, source := range sources {
		if filter.matches(source) {
			matches = append(matches, source)
		}
	}
	return matches
}

func shortID(id []byte) string {
	if len(id) > 4 {
		id = id[:4]
	}
	return hex.EncodeToString(id)
}

func describeIdentity(source identities.CredentialSource) string {
	name := ""
	if source.User != nil {
		name = source.User.Name
	}
	website := ""
	if source.RelyingParty != nil {
		website = source.RelyingParty.Name
	}
	return fmt.Sprintf("(%s): '%s' for website '%s'", shortID(source.ID), name, website)
}

func identityWord(count int) string {
	if count == 1 {
		return "identity"
	}
	return "identities"
}

// confirmDeletion asks the user before destroying several credentials at once.
func confirmDeletion(cmd *cobra.Command, count int) bool {
	fmt.Printf("Delete these %d %s? [y/N] ", count, identityWord(count))
	answer, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil && strings.TrimSpace(answer) == "" {
		fmt.Println()
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}

func deleteIdentity(cmd *cobra.Command, args []string) error {
	filter := credentialFilter{
		identityPrefix: identityID,
		website:        normalizeWebsite(deleteWebsite),
		user:           deleteUser,
	}
	if filter.isEmpty() {
		return fmt.Errorf("no credentials selected: pass --identity, --website and/or --user (see 'demo delete --help')")
	}

	client := createClient()
	targets := filterIdentities(client.Identities(), filter)
	if len(targets) == 0 {
		fmt.Printf("No identity found matching %s\n", filter)
		return nil
	}

	// A bare --identity keeps the original behavior: refuse to guess when the
	// prefix matches more than one credential.
	if !filter.isBulk() {
		if len(targets) > 1 {
			fmt.Printf("Multiple identities with prefix (%s):\n", identityID)
			for _, source := range targets {
				fmt.Printf("- (%s)\n", hex.EncodeToString(source.ID))
			}
			return nil
		}
		fmt.Printf("Deleting identity (%s)\n...", hex.EncodeToString(targets[0].ID))
		if client.DeleteIdentity(targets[0].ID) {
			fmt.Printf("Done.\n")
		} else {
			fmt.Printf("Could not find (%s).\n", hex.EncodeToString(targets[0].ID))
		}
		return nil
	}

	// Bulk delete: every credential of a website and/or an account.
	fmt.Printf("%d %s match %s:\n", len(targets), identityWord(len(targets)), filter)
	for _, source := range targets {
		fmt.Printf("- %s\n", describeIdentity(source))
	}
	if !deleteForce && !confirmDeletion(cmd, len(targets)) {
		cmd.Println("Aborted: no identities deleted")
		return nil
	}

	ids := make([][]byte, 0, len(targets))
	for _, source := range targets {
		// Append the value's own ID slice, NOT a pointer to the loop variable.
		ids = append(ids, source.ID)
	}
	deleted := client.DeleteIdentities(ids)
	fmt.Printf("Deleted %d %s\n", deleted, identityWord(deleted))
	return nil
}

func enablePIN(cmd *cobra.Command, args []string) {
	client := createClient()
	client.EnablePIN()
	cmd.Println("PIN enabled")
}

func disablePIN(cmd *cobra.Command, args []string) {
	client := createClient()
	client.DisablePIN()
	cmd.Println("PIN disabled")
}

var newPIN int

func setPIN(cmd *cobra.Command, args []string) {
	if newPIN < 0 {
		cmd.PrintErr("Invalid PIN: PIN must be positive")
		return
	}
	newPINString := strconv.Itoa(newPIN)
	if len(newPINString) < 4 {
		cmd.PrintErr("Invalid PIN: PIN must be 4 digits")
		return
	}
	client := createClient()
	client.SetPIN([]byte(newPINString))
	cmd.Println("PIN set")
}

func start(cmd *cobra.Command, args []string) {
	client := createClient()
	runServer(client)
}

func createClient() *fido_client.DefaultFIDOClient {
	// ALL OF THIS IS INSECURE, FOR TESTING PURPOSES ONLY
	caPrivateKey, err := identities.CreateCAPrivateKey()
	checkErr(err, "Could not generate attestation CA private key")
	certificateAuthority, err := identities.CreateSelfSignedCA(caPrivateKey)
	encryptionKey := sha256.Sum256([]byte("test"))

	virtual_fido.SetLogOutput(os.Stdout)
	if verbose {
		virtual_fido.SetLogLevel(util.LogLevelTrace)
	} else {
		virtual_fido.SetLogLevel(util.LogLevelDebug)
	}
	support := ClientSupport{vaultFilename: vaultFilename, vaultPassphrase: vaultPassphrase}
	return fido_client.NewDefaultClient(certificateAuthority, caPrivateKey, encryptionKey, false, &support, &support)
}

var rootCmd = &cobra.Command{
	Use:   "demo",
	Short: "Run Virtual FIDO demo",
	Long:  `demo attaches a virtual FIDO2 device for logging in with WebAuthN`,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&vaultFilename, "vault", "", "vault.json", "Identity vault filename")
	rootCmd.PersistentFlags().StringVarP(&vaultPassphrase, "passphrase", "", "passphrase", "Identity vault passphrase")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.MarkFlagRequired("vault")
	rootCmd.MarkFlagRequired("passphrase")
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	start := &cobra.Command{
		Use:   "start",
		Short: "Attach virtual FIDO device",
		Run:   start,
	}
	rootCmd.AddCommand(start)

	list := &cobra.Command{
		Use:   "list",
		Short: "List identities in vault",
		Run:   listIdentities,
	}
	rootCmd.AddCommand(list)

	delete := &cobra.Command{
		Use:   "delete",
		Short: "Delete identity(ies) in vault",
		Long: `Delete credentials from the vault.

Select what to delete with --identity (hex credential ID prefix), --website
(relying party) and/or --user (account name). Selectors are combined with AND,
and --website/--user delete every matching credential after confirmation.

Examples:
  demo delete --identity 1a2b3c4d
  demo delete --website github.com
  demo delete --website github.com --user alice@example.com
  demo delete --user alice@example.com`,
		RunE:          deleteIdentity,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	delete.Flags().StringVar(&identityID, "identity", "", "Credential ID prefix (hex) to delete")
	delete.Flags().StringVar(&deleteWebsite, "website", "", "Delete every credential of this website (relying party ID or name)")
	delete.Flags().StringVar(&deleteUser, "user", "", "Delete every credential of this account (user name or display name)")
	delete.Flags().BoolVarP(&deleteForce, "force", "f", false, "Skip the confirmation prompt when deleting multiple credentials")
	rootCmd.AddCommand(delete)

	pinCommand := &cobra.Command{
		Use:   "pin",
		Short: "Modify PIN Behavior",
	}
	enablePINCommand := &cobra.Command{
		Use:   "enable",
		Short: "Enables PIN protection",
		Run:   enablePIN,
	}
	pinCommand.AddCommand(enablePINCommand)
	disablePINCommand := &cobra.Command{
		Use:   "disable",
		Short: "Disables PIN protection",
		Run:   disablePIN,
	}
	pinCommand.AddCommand(disablePINCommand)
	setPINCommand := &cobra.Command{
		Use:   "set",
		Short: "Sets the PIN",
		Run:   setPIN,
	}
	setPINCommand.Flags().IntVar(&newPIN, "pin", -1, "New PIN")
	setPINCommand.MarkFlagRequired("pin")
	pinCommand.AddCommand(setPINCommand)
	rootCmd.AddCommand(pinCommand)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
