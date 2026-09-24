# Virtual FIDO

> Also check out [Bulwark Passkey](https://bulwark.id), a passkey manager based on VirtualFIDO that is currently in beta!

Virtual FIDO is a virtual USB device that implements the FIDO2/U2F protocol (like a YubiKey) to support 2FA and WebAuthN. Please note that this software is still in beta and under active development, so APIs may be subject to change.

## Features

-   Support for both Windows and Linux through USB/IP (Mac support coming later)
-   Connect using both U2F and FIDO2 protocols for both normal 2FA and WebAuthN
-   Store credentials in an encrypted format with a passphrase
-   Store credential data anywhere (example provided: a local file)
-   Generic approval mechanism for credential creation and login (example provided: terminal-based)

## How it works

Virtual FIDO creates a USB/IP server over local TCP to attach a virtual USB device. This USB device then emulates the USB/CTAP protocols to provide U2F/FIDO services to the host computer. In the demo, credentials created by the virtual device are stored in a local file, and approvals are done using the terminal.

## Demo Usage

Go to the [YubiKey test page](https://demo.yubico.com/webauthn-technical/registration) in order to test WebAuthN.

### Windows

1. Install the [usbip-win2](https://github.com/vadimgrn/usbip-win2) USB/IP client. Its UDE driver (`usbip2_ude.sys`) is WHLK-signed, so it works on Windows 10/11 without enabling test signing (`bcdedit /set TESTSIGNING ON` is not required). The demo automatically uses the `usbip.exe` it installs at `C:\Program Files\USBip\usbip.exe`.
   - If `usbip.exe` is installed somewhere else, point the demo at it with the `USBIP_EXE` environment variable, e.g. `$env:USBIP_EXE = "C:\path\to\usbip.exe"`.
   - The demo only falls back to the legacy `usbip.exe` bundled in `cmd/demo/usbip/bin` if no usbip-win2 install is found. That legacy binary requires the old [cezanne/usbip-win](https://github.com/cezanne/usbip-win) driver and test signing, and is not recommended.
2. Open an **Administrator** terminal (attaching a virtual USB device requires elevation).
3. Run `go run ./cmd/demo start` to attach the USB device. Run `go run ./cmd/demo --help` to see more commands, such as to list or delete credentials from the file.

You can sanity-check the driver separately while the server is running:
`"C:\Program Files\USBip\usbip.exe" list -r 127.0.0.1` should show the `2-2` device, and `"C:\Program Files\USBip\usbip.exe" attach -r 127.0.0.1 -b 2-2` should print `succesfully attached to port N`.

### Linux

Note that this tool requires elevated permissions.

1. Run `sudo modprobe vhci-hcd` to load the necessary drivers.
2. Run `sudo go run ./cmd/demo start` to start up the USB device server. Authenticate when `sudo` prompts you; this is necessary to attach the device.
