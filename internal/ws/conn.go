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
	opcodeContinuation         = 0x0
	opcodeText                 = 0x1
	opcodeBinary               = 0x2
	opcodeClose                = 0x8
	opcodePing                 = 0x9
	opcodePong                 = 0xA
)

var (
	regMu       sync.Mutex
	conns       = make(map[*Conn]struct{})
	payloadPool = sync.Pool{New: func() interface{} { b := make([]byte, smallBufferThreshold); return &b }}
)

type Conn struct {
	mu       sync.Mutex
	conn     net.Conn
	br       *bufio.Reader
	bw       *bufio.Writer
	closed   bool
	lastPong time.Time
}

func registerConn(c *Conn)   { regMu.Lock(); conns[c] = struct{}{}; regMu.Unlock() }
func unregisterConn(c *Conn) { regMu.Lock(); delete(conns, c); regMu.Unlock() }
func Active() int            { regMu.Lock(); n := len(conns); regMu.Unlock(); return n }
func Shutdown() {
	regMu.Lock()
	list := make([]*Conn, 0, len(conns))
	for c := range conns {
		list = append(list, c)
	}
	regMu.Unlock()
	for _, c := range list {
		c.Close()
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
	resp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: chat\r\n\r\n", accept)
	if _, err := rw.WriteString(resp); err != nil {
		_ = conn.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return
	}
	c := &Conn{conn: conn, br: rw.Reader, bw: rw.Writer, lastPong: time.Now()}
	registerConn(c)
	go c.readLoop()
	go c.keepAlive()
}

func computeAccept(key string) string {
	h := sha1.Sum([]byte(key + guid))
	return base64.StdEncoding.EncodeToString(h[:])
}

func (c *Conn) readLoop() {
	defer c.Close()
	for {
		opcode, payload, fin, _, err := c.readFrame()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("read error: %v", err)
			}
			return
		}
		switch opcode {
		case opcodeContinuation:
			log.Printf("ignore continuation frame (FIN=%v, %d bytes)", fin, len(payload))
		case opcodeText:
			msg := string(payload)
			log.Printf("<- text: %q", msg)
			if err := c.writeFrame(opcodeText, true, []byte("echo: "+msg)); err != nil {
				return
			}
		case opcodeBinary:
			log.Printf("<- %d bytes binary", len(payload))
			if err := c.writeFrame(opcodeText, true, []byte(fmt.Sprintf("received %d bytes", len(payload)))); err != nil {
				return
			}
		case opcodePing:
			if err := c.writeFrame(opcodePong, true, payload); err != nil {
				return
			}
			log.Printf("<- ping, -> pong (%d bytes)", len(payload))
		case opcodePong:
			c.lastPong = time.Now()
			log.Printf("<- pong (%d bytes)", len(payload))
		case opcodeClose:
			log.Printf("<- close")
			_ = c.writeFrame(opcodeClose, true, payload)
			return
		default:
			log.Printf("unknown opcode: %x", opcode)
			return
		}
		if cap(payload) == smallBufferThreshold {
			payloadPool.Put(&payload)
		}
	}
}

func (c *Conn) keepAlive() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	idle := 60 * time.Second
	for range t.C {
		if err := c.writeFrame(opcodePing, true, []byte("heartbeat")); err != nil {
			return
		}
		if time.Since(c.lastPong) > idle {
			log.Printf("idle timeout, closing")
			c.Close()
			return
		}
	}
}

func (c *Conn) readExactly(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(c.br, b)
	return b, err
}

func (c *Conn) readFrame() (opcode byte, payload []byte, fin bool, masked bool, err error) {
	b, err := c.readExactly(2)
	if err != nil {
		return
	}
	fin = b[0]&0x80 != 0
	opcode = b[0] & 0x0F
	masked = b[1]&0x80 != 0
	payloadLen7 := int64(b[1] & 0x7F)
	var length int64
	switch payloadLen7 {
	case 126:
		ext, e := c.readExactly(2)
		if e != nil {
			err = e
			return
		}
		length = int64(uint16(ext[0])<<8 | uint16(ext[1]))
	case 127:
		ext, e := c.readExactly(8)
		if e != nil {
			err = e
			return
		}
		var v uint64
		for i := 0; i < 8; i++ {
			v = (v << 8) | uint64(ext[i])
		}
		length = int64(v)
	default:
		length = payloadLen7
	}
	if length < 0 || length > maxPayloadSize {
		err = fmt.Errorf("payload too large: %d", length)
		return
	}
	var maskKey [4]byte
	if masked {
		mk, e := c.readExactly(4)
		if e != nil {
			err = e
			return
		}
		copy(maskKey[:], mk)
	}
	if length > 0 {
		if length <= smallBufferThreshold {
			rawPtr := payloadPool.Get().(*[]byte)
			raw := *rawPtr
			payload = raw[:length]
			_, err = io.ReadFull(c.br, payload)
			if err != nil {
				return
			}
			// Return to pool after use (copy to new slice if caller keeps beyond loop; here payload reused only inside loop)
			payloadPool.Put(rawPtr)
		} else {
			payload, err = c.readExactly(int(length))
			if err != nil {
				return
			}
		}
		if masked {
			for i := int64(0); i < length; i++ {
				payload[i] ^= maskKey[i%4]
			}
		}
	}
	return
}

func (c *Conn) writeFrame(opcode byte, fin bool, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return io.ErrClosedPipe
	}
	var b0 byte
	if fin {
		b0 |= 0x80
	}
	b0 |= opcode & 0x0F
	length := len(payload)
	var hdr [10]byte
	header := hdr[:0]
	if length < 126 {
		header = append(header, b0, byte(length))
	} else if length < 65535 {
		header = append(header, b0, 126, byte(length>>8), byte(length))
	} else {
		header = hdr[:10]
		header[0] = b0
		header[1] = 127
		l := uint64(length)
		for i := 0; i < 8; i++ {
			header[9-i] = byte(l & 0xFF)
			l >>= 8
		}
	}
	if _, err := c.bw.Write(header); err != nil {
		return err
	}
	if length > 0 {
		if _, err := c.bw.Write(payload); err != nil {
			return err
		}
	}
	return c.bw.Flush()
}

// Close terminates the connection (idempotent) and unregisters it.
func (c *Conn) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	_ = c.conn.Close()
	unregisterConn(c)
}
