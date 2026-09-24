package usbip

import (
	"net"
	"strings"
	"sync"
	"syscall"

	"github.com/bulwarkid/virtual-fido/util"
)

var usbipLogger = util.NewLogger("[USBIP] ", util.LogLevelTrace)
var errLogger = util.NewLogger("[ERR] ", util.LogLevelEnabled)

type USBIPServer struct {
	devices     []USBIPDevice
	listener    net.Listener
	stopChan    chan struct{}
	connections []net.Conn
	connMutex   sync.Mutex
}

func NewUSBIPServer(devices []USBIPDevice) *USBIPServer {
	server := new(USBIPServer)
	server.devices = devices
	return server
}

func (server *USBIPServer) Start() {
	usbipLogger.Println("Starting USBIP server...")
	server.stopChan = make(chan struct{})
	listener, err := net.Listen("tcp", "127.0.0.1:3240")
	util.CheckErr(err, "Could not create listener")
	server.listener = listener
	for {
		select {
		case <-server.stopChan:
			return
		default:
		}
		connection, err := listener.Accept()
		if err != nil {
			select {
			case <-server.stopChan:
				return
			default:
			}
			usbipLogger.Printf("Connection accept error: %v", err)
			continue
		}
		if !strings.HasPrefix(connection.RemoteAddr().String(), "127.0.0.1") {
			usbipLogger.Printf("Connection attempted from non-local address: %s", connection.RemoteAddr().String())
			connection.Close()
			continue
		}
		server.trackConnection(connection)
		usbipConn := newUSBIPConnection(server, connection)
		util.Try(func() {
			usbipConn.handle()
		}, func(err interface{}) {
			logPanicUnlessShutdown(err)
		})
		server.untrackConnection(connection)
		connection.Close()
	}
}

func (server *USBIPServer) Stop() {
	select {
	case <-server.stopChan:
		// already stopped
		return
	default:
	}
	close(server.stopChan)
	if server.listener != nil {
		server.listener.Close()
	}
	// Close all active connections to unblock any in-progress handles
	server.connMutex.Lock()
	for _, conn := range server.connections {
		conn.Close()
	}
	server.connections = nil
	server.connMutex.Unlock()
}

func (server *USBIPServer) trackConnection(conn net.Conn) {
	server.connMutex.Lock()
	server.connections = append(server.connections, conn)
	server.connMutex.Unlock()
}

func (server *USBIPServer) untrackConnection(conn net.Conn) {
	server.connMutex.Lock()
	for i, c := range server.connections {
		if c == conn {
			server.connections[i] = server.connections[len(server.connections)-1]
			server.connections = server.connections[:len(server.connections)-1]
			break
		}
	}
	server.connMutex.Unlock()
}

func logPanicUnlessShutdown(err interface{}) {
	// Suppress noisy stack traces when the connection is deliberately
	// closed during server shutdown.
	if s, ok := err.(string); ok && strings.Contains(s, "use of closed network connection") {
		return
	}
	errLogger.Printf("%v", err)
}

func (server *USBIPServer) getDevice(busID string) USBIPDevice {
	var device USBIPDevice = nil
	for _, other := range server.devices {
		if other.BusID() == busID {
			device = other
			break
		}
	}
	return device
}

type usbipConnection struct {
	responseMutex *sync.Mutex
	conn          net.Conn
	server        *USBIPServer
}

func newUSBIPConnection(server *USBIPServer, conn net.Conn) *usbipConnection {
	usbipConn := new(usbipConnection)
	usbipConn.responseMutex = &sync.Mutex{}
	usbipConn.conn = conn
	usbipConn.server = server
	return usbipConn
}

func (conn *usbipConnection) handle() {
	for {
		// Stop handling this connection once the client disconnects or a
		// protocol error occurs, instead of spinning on read errors.
		var header usbipControlHeader
		shouldContinue := true
		util.Try(func() {
			header = util.ReadBE[usbipControlHeader](conn.conn)
		}, func(err interface{}) {
			logPanicUnlessShutdown(err)
			shouldContinue = false
		})
		if !shouldContinue {
			return
		}
		usbipLogger.Printf("[CONTROL MESSAGE] %#v\n\n", header)
		if header.Command == usbipCommandOpReqDevlist {
			reply := newOpRepDevlist(conn.server.devices)
			usbipLogger.Printf("[OP_REP_DEVLIST] %#v\n\n", reply)
			conn.writeResponse(util.ToBE(reply))
		} else if header.Command == usbipCommandOpReqImport {
			busIDData := util.Read(conn.conn, 32)
			busID := util.CStringToString(busIDData)
			device := conn.server.getDevice(busID)
			if device == nil {
				// Device not found
				reply := opRepImportError(1)
				conn.writeResponse(util.ToBE(reply))
				continue
			}
			reply := newOpRepImport(device)
			usbipLogger.Printf("[OP_REP_IMPORT] %s\n\n", reply)
			conn.writeResponse(util.ToBE(reply))
			conn.handleCommands(device)
		} else {
			usbipLogger.Printf("Unknown Command Code: %d", header.Command)
		}
	}
}

func (conn *usbipConnection) handleCommands(device USBIPDevice) {
	for {
		// A read failure means the client disconnected or the connection is
		// broken. Log it once and stop handling this connection, otherwise we
		// would spin here forever printing the same error.
		shouldContinue := true
		util.Try(func() {
			header := util.ReadBE[usbipMessageHeader](conn.conn)
			usbipLogger.Printf("[MESSAGE HEADER] %s\n\n", header)
			if header.Command == usbipCmdSubmit {
				conn.handleCommandSubmit(device, header)
			} else if header.Command == usbipCmdUnlink {
				conn.handleCommandUnlink(device, header)
			} else {
				usbipLogger.Printf("Unsupported Command: %#v\n\n", header)
			}
		}, func(err interface{}) {
			logPanicUnlessShutdown(err)
			shouldContinue = false
		})
		if !shouldContinue {
			return
		}
	}
}

func (conn *usbipConnection) handleCommandSubmit(device USBIPDevice, header usbipMessageHeader) {
	command := util.ReadBE[usbipCommandSubmitBody](conn.conn)
	usbipLogger.Printf("[COMMAND SUBMIT] %s\n\n", command)
	transferBuffer := make([]byte, command.TransferBufferLength)
	if header.Direction == usbipDirOut && command.TransferBufferLength > 0 {
		_, err := conn.conn.Read(transferBuffer)
		util.CheckErr(err, "Could not read transfer buffer")
	}
	// Getting the reponse may not be immediate, so we need a callback
	onReturnSubmit := func(response []byte) {
		if response != nil {
			copy(transferBuffer, response)
		}
		replyHeader := header.replyHeader()
		replyBody := usbipReturnSubmitBody{
			Status:          0,
			ActualLength:    uint32(len(transferBuffer)),
			StartFrame:      0,
			NumberOfPackets: 0,
			ErrorCount:      0,
			Padding:         0,
		}
		usbipLogger.Printf("[RETURN SUBMIT] %v %#v\n\n", replyHeader, replyBody)
		reply := util.Concat(util.ToBE(replyHeader), util.ToBE(replyBody))
		if header.Direction == usbipDirIn {
			usbipLogger.Printf("[RETURN SUBMIT] DATA: %#v\n\n", transferBuffer)
			reply = append(reply, transferBuffer...)
		}
		conn.writeResponse(reply)
	}
	device.HandleMessage(header.SequenceNumber, onReturnSubmit, header.Endpoint, command.SetupBytes[:], transferBuffer)
}

func (conn *usbipConnection) handleCommandUnlink(device USBIPDevice, header usbipMessageHeader) {
	unlink := util.ReadBE[usbipCommandUnlinkBody](conn.conn)
	usbipLogger.Printf("[COMMAND UNLINK] %#v\n\n", unlink)
	var status int32
	if device.RemoveWaitingRequest(unlink.UnlinkSequenceNumber) {
		status = -int32(syscall.ECONNRESET)
	} else {
		status = -int32(syscall.ENOENT)
	}
	replyHeader := header.replyHeader()
	replyBody := usbipReturnUnlinkBody{
		Status:  status,
		Padding: [24]byte{},
	}
	reply := util.Concat(
		util.ToBE(replyHeader),
		util.ToBE(replyBody),
	)
	conn.writeResponse(reply)
}

func (conn *usbipConnection) writeResponse(data []byte) {
	conn.responseMutex.Lock()
	util.Write(conn.conn, data)
	conn.responseMutex.Unlock()
}
