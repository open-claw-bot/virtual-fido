//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
)

// usbipWin2Exe is the default install location of the usbip-win2 client
// (https://github.com/vadimgrn/usbip-win2). Its UDE driver (usbip2_ude.sys) is
// WHLK-signed, so it works on Windows 10/11 without enabling test signing.
const usbipWin2Exe = `C:\Program Files\USBip\usbip.exe`

// Execute USB IP attach for Windows.
//
// The repo bundles a legacy usbip.exe from cezanne/usbip-win in
// cmd/demo/usbip/bin. That binary only recognizes the old usbip-win VHCI driver
// (hardware IDs "usbipwin\vhci"/"root\vhci_ude" and device interface GUID
// {D35F7840-...}). The usbip-win2 driver (usbip2_ude.sys) uses different
// hardware IDs (ROOT\USBIP_WIN2\UDE) and a different interface GUID
// ({B4030C06-...}), so the bundled binary reports "vhci driver is not loaded"
// even when usbip-win2 is installed.
//
// We therefore prefer the usbip-win2 usbip.exe and only fall back to the
// bundled binary if it is missing. Set the USBIP_EXE environment variable to
// use a usbip.exe installed in a custom location.
func platformUSBIPExec() *exec.Cmd {
	exe := os.Getenv("USBIP_EXE")
	if exe == "" {
		exe = usbipWin2Exe
		if _, err := os.Stat(exe); err != nil {
			exe = filepath.Join("cmd", "demo", "usbip", "bin", "usbip.exe")
		}
	}
	command := exec.Command(exe, "attach", "-r", "127.0.0.1", "-b", "2-2")
	command.Dir = filepath.Dir(exe)
	return command
}
