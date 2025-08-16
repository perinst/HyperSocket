package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	guid                       = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	maxPayloadSize       int64 = 1024 * 1024 // 1 MB
	smallBufferThreshold       = 4096
	opcodeContinuation         = 0x0 // Continuation Frame
	opcodeText                 = 0x1 // Text Frame
	opcodeBinary               = 0x2 // Binary Frame
	opcodeClose                = 0x8 // Close Frame
	opcodePing                 = 0x9 // Ping Frame
	opcodePong                 = 0xA // Pong Frame
)

var (
	regMu       sync.Mutex
	conns       = make(map[*wsConn]struct{})
	payloadPool = sync.Pool{New: func() interface{} { b := make([]byte, smallBufferThreshold); return &b }}
)

type wsConn struct {
	mu       sync.Mutex
	conn     net.Conn
	br       *bufio.Reader
	bw       *bufio.Writer
	closed   bool
	lastPong time.Time
}

func registerConn(c *wsConn)   { regMu.Lock(); conns[c] = struct{}{}; regMu.Unlock() }
func unregisterConn(c *wsConn) { regMu.Lock(); delete(conns, c); regMu.Unlock() }
func Active() int              { regMu.Lock(); n := len(conns); regMu.Unlock(); return n }
func Shutdown() {
	regMu.Lock()
	list := make([]*wsConn, 0, len(conns))
	for c := range conns {
		list = append(list, c)
	}
	regMu.Unlock()
	for _, c := range list {
		c.close()
	}
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Connection"), "Upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "Upgrade required", http.StatusUpgradeRequired)
		return
	}

	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "Unsupported WebSocket Version", http.StatusBadRequest)
		return
	}

	key := r.Header.Get("Sec-WebSocket-Key")

	if strings.TrimSpace(key) == "" {
		http.Error(w, "Missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}

	hj, ok := w.(http.Hijacker)

	if !ok {
		http.Error(w, "Hijack not supported", http.StatusBadRequest)
		return
	}

	conn, rw, err := hj.Hijack()

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	accept := computeAccept(key)

	response := fmt.Sprintf(
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n"+
			"Sec-WebSocket-Protocol: chat\r\n"+
			"\r\n", accept)

	if _, err := rw.WriteString(response); err != nil {
		conn.Close()
		return
	}

	if err := rw.Flush(); err != nil {
		conn.Close()
		return
	}

	c := &wsConn{
		conn:     conn,
		br:       rw.Reader,
		bw:       rw.Writer,
		lastPong: time.Now(),
	}

	registerConn(c)
	log.Printf("Client connected. Total active connections: %d", Active())

	go c.readLoop()
	go c.keepAlive()

}

func computeAccept(key string) string {
	h := sha1.Sum([]byte(key + guid))
	return base64.StdEncoding.EncodeToString(h[:])
}

func (ws *wsConn) readLoop() {
	defer ws.close()
	for {
		opcode, payload, fin, masked, err := ws.readFrame()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("read error: %v", err)
			}
			return
		}
		if masked {
			// Masking should only be set on frames from client; we already unmasked in readFrame
		}

		switch opcode {
		case opcodeContinuation:
			// This example doesn't assemble fragmented messages beyond single frame.
			log.Printf("ignore continuation frame (FIN=%v, %d bytes)", fin, len(payload))

		case opcodeText:
			msg := string(payload)
			log.Printf("<- text: %q", msg)
			// Broadcast to all connected clients
			ws.broadcast(msg)

		case opcodeBinary:
			log.Printf("<- %d bytes binary", len(payload))
			// Echo binary length message
			if err := ws.writeFrame(opcodeText, true, []byte(fmt.Sprintf("received %d bytes", len(payload)))); err != nil {
				return
			}

		case opcodePing:
			// Reply with Pong with same payload
			if err := ws.writeFrame(opcodePong, true, payload); err != nil {
				return
			}
			log.Printf("<- ping, -> pong (%d bytes)", len(payload))

		case opcodePong:
			ws.lastPong = time.Now()
			log.Printf("<- pong (%d bytes)", len(payload))

		case opcodeClose:
			log.Printf("<- close")
			// Echo close back per spec
			_ = ws.writeFrame(opcodeClose, true, payload)
			return

		default:
			log.Printf("unknown opcode: %x", opcode)
			return
		}
	}
}

func (ws *wsConn) keepAlive() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	idleTimeout := 60 * time.Second
	for range ticker.C {
		if err := ws.writeFrame(opcodePing, true, []byte("heartbeat")); err != nil {
			return
		}
		if time.Since(ws.lastPong) > idleTimeout {
			log.Printf("idle timeout, closing")
			ws.close()
			return
		}
	}
}

func (ws *wsConn) readExactly(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(ws.br, buf)
	return buf, err
}

func (ws *wsConn) readFrame() (opcode byte, payload []byte, fin bool, masked bool, err error) {
	// Read first 2 bytes: FIN/RSV/opcode + MASK/PayloadLen7
	b, err := ws.readExactly(2)
	if err != nil {
		return
	}

	fin = (b[0] & 0x80) != 0          // FIN bit
	opcode = b[0] & 0x0F              // Opcode bits
	masked = b[1]&0x80 != 0           // Mask bit
	payloadLen7 := int64(b[1] & 0x7F) // Payload length (7 bits)

	var length int64
	switch payloadLen7 {
	case 126:
		// next 2 bytes uint16
		ext, e := ws.readExactly(2)
		if e != nil {
			err = e
			return
		}
		length = int64(uint16(ext[0])<<8 | uint16(ext[1])) // 16-bit extended payload length
	case 127:
		// next 8 bytes uint64
		ext, e := ws.readExactly(8)
		if e != nil {
			err = e
			return
		}
		var v uint64
		// Read each byte and shift it into the correct position
		for i := 0; i < 8; i++ {
			v = (v << 8) | uint64(ext[i])
		}

		length = int64(v)

	default:
		length = payloadLen7 // No extension, use 7-bit length directly

	}

	if length < 0 || length > maxPayloadSize {
		err = fmt.Errorf("payload too large: %d", length)
		return
	}

	var maskKey [4]byte

	if masked {
		mk, e := ws.readExactly(4)
		if e != nil {
			err = e
			return
		}

		copy(maskKey[:], mk)
	}

	if length > 0 {
		payload, err = ws.readExactly(int(length))

		if err != nil {
			return
		}

		// Unmask the payload if it was masked
		if masked {
			// Apply the mask to the payload
			for i := int64(0); i < length; i++ {
				payload[i] ^= maskKey[i%4] // Unmask the payload
			}
		}
	}

	return
}

func (ws *wsConn) writeFrame(opcode byte, fin bool, payload []byte) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	if ws.closed {
		return io.ErrClosedPipe
	}

	var b0 byte

	if fin {
		b0 |= 0x80 // Set FIN bit
	}

	b0 |= (opcode & 0x0F) // Set opcode bits

	length := len(payload)
	var header []byte

	if length < 126 {
		header = []byte{b0, byte(length)}
	} else if length < 65535 { //0xFFFF
		header = []byte{b0, 126, byte(length >> 8), byte(length)}
	} else {
		header = make([]byte, 10)
		header[0] = b0
		header[1] = 127
		l := uint64(length)

		for i := 0; i < 8; i++ {
			header[9-i] = byte(l & 0xFF)
			l >>= 8
		}
	}

	if _, err := ws.bw.Write(header); err != nil {
		return err
	}

	if length > 0 {
		if _, err := ws.bw.Write(payload); err != nil {
			return err
		}
	}

	return ws.bw.Flush()

}

func (ws *wsConn) close() {
	ws.mu.Lock()
	if ws.closed {
		ws.mu.Unlock()
		return
	}

	ws.closed = true
	ws.mu.Unlock()
	_ = ws.conn.Close()
	unregisterConn(ws)
	log.Printf("Client disconnected. Total active connections: %d", Active())
}

// broadcast sends a message to all connected clients
func (ws *wsConn) broadcast(msg string) {
	regMu.Lock()
	clients := make([]*wsConn, 0, len(conns))
	for conn := range conns {
		clients = append(clients, conn)
	}
	regMu.Unlock()

	payload := []byte(msg)
	for _, client := range clients {
		if err := client.writeFrame(opcodeText, true, payload); err != nil {
			log.Printf("Failed to send message to client: %v", err)
			// Don't close the connection here, let it fail naturally
		}
	}
}
