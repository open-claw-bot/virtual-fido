package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	virtual_fido "github.com/bulwarkid/virtual-fido"
	"github.com/bulwarkid/virtual-fido/fido_client"
)

func prompt(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println(prompt)
	fmt.Print("--> ")
	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Could not read user input: %s - %s\n", response, err)
		panic(err)
	}
	response = strings.ToLower(strings.TrimSpace(response))
	if response == "y" || response == "yes" {
		return true
	}
	return false
}

type ClientSupport struct {
	vaultFilename   string
	vaultPassphrase string
}

func (support *ClientSupport) ApproveClientAction(action fido_client.ClientAction, params fido_client.ClientActionRequestParams) bool {
	switch action {
	case fido_client.ClientActionFIDOGetAssertion:
		return prompt(fmt.Sprintf("Approve login for \"%s\" with identity \"%s\" (Y/n)?", params.RelyingParty, params.UserName))
	case fido_client.ClientActionFIDOMakeCredential:
		return prompt(fmt.Sprintf("Approve account creation for \"%s\" (Y/n)?", params.RelyingParty))
	case fido_client.ClientActionU2FAuthenticate:
		return prompt("Approve registration of U2F device (Y/n)?")
	case fido_client.ClientActionU2FRegister:
		return prompt("Approve use of U2F device (Y/n)?")
	}
	fmt.Printf("Unknown client action for approval: %d\n", action)
	return false
}

func (support *ClientSupport) SaveData(data []byte) {
	// Write atomically: write to a temporary file, then rename.
	// This prevents vault corruption if the process is killed mid-write.
	tmpFilename := support.vaultFilename + ".tmp"
	f, err := os.OpenFile(tmpFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	checkErr(err, "Could not open vault temp file")
	_, err = f.Write(data)
	f.Close()
	checkErr(err, "Could not write vault data")
	err = os.Rename(tmpFilename, support.vaultFilename)
	checkErr(err, "Could not finalize vault write")
}

func (support *ClientSupport) RetrieveData() []byte {
	f, err := os.Open(support.vaultFilename)
	if os.IsNotExist(err) {
		return nil
	}
	checkErr(err, "Could not open vault")
	data, err := io.ReadAll(f)
	checkErr(err, "Could not read vault data")
	return data
}

func (support *ClientSupport) Passphrase() string {
	return support.vaultPassphrase
}

func runServer(client virtual_fido.FIDOClient) {
	// Handle Ctrl+C (SIGINT) and SIGTERM for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the virtual FIDO server first so it's listening before the
	// usbip.exe client tries to connect.
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		virtual_fido.Start(client)
		wg.Done()
	}()

	// Start the usbip.exe child process (if any) with Start/Wait
	// so we can kill it on shutdown. Sleep first to let the server bind.
	time.Sleep(500 * time.Millisecond)
	var usbipCmd *exec.Cmd
	prog := platformUSBIPExec()
	if prog != nil {
		prog.Stdin = os.Stdin
		prog.Stdout = os.Stdout
		prog.Stderr = os.Stderr
		err := prog.Start()
		if err != nil {
			fmt.Printf("Error starting USBIP: %s\n", err)
		} else {
			usbipCmd = prog
		}
	}
	if usbipCmd != nil {
		wg.Add(1)
		go func() {
			_ = usbipCmd.Wait()
			wg.Done()
		}()
	}

	// Wait for either a signal or both goroutines to finish
	select {
	case sig := <-sigChan:
		fmt.Printf("\nReceived %v, shutting down gracefully...\n", sig)
		if usbipCmd != nil && usbipCmd.Process != nil {
			usbipCmd.Process.Kill()
		}
		virtual_fido.Stop()
	case <-waitAll(wg):
	}

	wg.Wait()
	signal.Stop(sigChan)
}

// waitAll returns a channel that closes when all WaitGroup items are done.
func waitAll(wg *sync.WaitGroup) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	return done
}
