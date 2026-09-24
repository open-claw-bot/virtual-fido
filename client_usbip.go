//go:build linux || windows

package virtual_fido

import (
	"github.com/bulwarkid/virtual-fido/ctap"
	"github.com/bulwarkid/virtual-fido/ctap_hid"
	"github.com/bulwarkid/virtual-fido/u2f"
	"github.com/bulwarkid/virtual-fido/usb"
	"github.com/bulwarkid/virtual-fido/usbip"
)

var usbipServer *usbip.USBIPServer

func startClient(client FIDOClient) {
	ctapServer := ctap.NewCTAPServer(client)
	u2fServer := u2f.NewU2FServer(client)
	ctapHIDServer := ctap_hid.NewCTAPHIDServer(ctapServer, u2fServer)
	usbDevice := usb.NewUSBDevice(ctapHIDServer)
	usbipServer = usbip.NewUSBIPServer([]usbip.USBIPDevice{usbDevice})
	usbipServer.Start()
}

func stopClient() {
	if usbipServer != nil {
		usbipServer.Stop()
	}
}
