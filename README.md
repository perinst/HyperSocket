# HyperSocket

Minimal from-scratch WebSocket server in Go focused on clarity first, with guidance for evolving toward high throughput and low latency.

## Overview

This project implements the WebSocket RFC 6455 handshake and basic frame processing without third‑party libraries. It shows how to:

- Perform manual HTTP upgrade & compute `Sec-WebSocket-Accept`.
- Parse frame headers (FIN, opcode, masking, extended lengths).
- Unmask client payloads and write frames back (echo, ping/pong, close).
- Maintain a lightweight keep‑alive (ping → pong tracking & idle timeout).

The code lives in `main/main.go` and runs a server on `:8080` exposing `/ws`.

## Quick Start

```bash
# Build
go build ./...

# Run
./HyperSocket   # (Windows: HyperSocket.exe)
```

Connect with a browser or a tool:

```javascript
const ws = new WebSocket("ws://localhost:8080/ws", "chat");
ws.onopen = () => ws.send("hello");
ws.onmessage = (e) => console.log("server:", e.data);
```

## Current Behavior

Message types handled:

- Text frames: echoed back with `echo: <msg>`
- Binary frames: server replies with a text summary of byte length
- Ping: answered with Pong (same payload)
- Pong: updates last activity timestamp
- Close: echoed then connection closed

Fragmented messages (`opcodeContinuation`) are logged & ignored (no reassembly yet).

## Code Walkthrough

High‑level flow:

1. `wsHandler` validates headers, hijacks the HTTP connection, returns 101 response.
2. `wsConn` wraps raw `net.Conn` with buffered reader/writer and starts:
   - `readLoop()` – sequential frame parsing & dispatch
   - `keepAlive()` – periodic ping + idle timeout enforcement
3. `readFrame()` reads minimal bytes needed per RFC (2 + optional extended length + mask + payload) using `readExactly` to avoid partial frame issues.
4. `writeFrame()` constructs a server frame (server frames are never masked per spec) and flushes.
5. `close()` idempotently closes the underlying connection.

## Design Choices (Baseline)

- Simplicity over completeness: no fragmentation reassembly, no compression (permessage-deflate), no per-connection goroutine pools.
- Backpressure left to OS socket buffers (writes flush synchronously).
- Single read goroutine per connection; write path serialized via mutex.

## Moving Toward High Throughput / Low Latency

Below are staged improvements you can apply.

### Reduce Allocations

- Reuse payload buffers (sync.Pool keyed by size bucket) instead of `make([]byte, n)` each frame.
- Maintain a reusable header scratch array (10 bytes) per connection.
- Avoid converting `[]byte` → `string` unless needed (e.g., for logging). Consider structured logging or sampling.

### Faster Frame Parsing

- Inline small helpers (e.g., merge `readExactly` logic) only after profiling.
- Use a single read buffer and slice it instead of allocating a new payload slice each frame.

### Concurrency & Parallelism

- Offload application message handling to a worker pool so the read goroutine returns to reading ASAP (reduces head‑of‑line blocking when handlers are slow).
- Consider batching writes: queue outbound frames and have a dedicated writer goroutine per connection; this removes lock contention around `writeFrame` and enables coalescing multiple small frames before a flush.

### Minimize Syscalls / Flushes

- Avoid calling `Flush()` for every small frame; use corking / delayed flush: schedule a flush via timer (e.g., up to 1ms delay) or flush when outbound buffer exceeds threshold.
- Tune `bufio.NewWriterSize` / `bufio.NewReaderSize` to align with typical frame sizes (e.g., 16–64KB).

### Event Loop Style (Advanced)

For very high connection counts:

- Evaluate using a library (e.g., gnet) or implement an internal poller to reduce goroutine count. The standard library is fine for tens of thousands on modern machines; only push lower if profiling indicates scheduler overhead.

### Memory & GC

- Pre-size slices for common frame sizes (e.g., 125 bytes small text frame bucket).
- Recycle large buffers promptly; keep them in pool only if reused soon to avoid heap growth.

### Compression (Optional)

- Add permessage-deflate negotiation for large text frames; measure latency impact (may increase CPU and tail latency).

### Monitoring & Instrumentation

- Expose metrics: active conns, messages/sec, bytes in/out, ping RTT (track time between ping and pong), error counts.
- Add pprof endpoints behind admin-only listener for CPU/heap profiling.

### Error Handling & Robustness

- Validate opcodes and close on protocol violations (unexpected continuation, reserved bits set, control frame fragmentation or >125 bytes payload).
- Enforce rate limits for malicious flood of control frames.

## Example: Buffer Pool Sketch

```go
var smallBufPool = sync.Pool{New: func() any { return make([]byte, 2048) }}
// Acquire
b := smallBufPool.Get().([]byte)
// Use a slice of b[:n]
// Release
smallBufPool.Put(b)
```

(Integrate carefully: ensure no references after return, avoid retaining mega buffers.)

## Benchmarking Ideas

Use a load generator (e.g., `github.com/gobwas/ws` client or `wrk` + a shim) to send frames:

- Measure latency distribution (p50/p90/p99) and throughput (msgs/sec) under varying concurrency.
- Toggle optimization flags to validate impact (A/B tests). Always profile before/after (CPU & heap).

## Production Hardening Checklist

- TLS termination (wss://) via reverse proxy or `net/http` + certs.
- Graceful shutdown: track connections, send Close frames, wait for drain.
- Per-connection / global write deadlines to prevent stuck writes.
- Authentication & authorization (token in query/header → validate before upgrade).
- Origin checks / subprotocol negotiation (currently hardcoded to `chat`).
- Structured logging with levels; optional sampling for high volume.

## Running on Windows

```powershell
go build -o HyperSocket.exe .
./HyperSocket.exe
```

Navigate to `http://localhost:8080` (you can embed a test page) and attach a WebSocket client to `ws://localhost:8080/ws`.

## Next Steps (Suggested PRs)

1. Implement fragmented message reassembly.
2. Add simple outbound queue + writer goroutine.
3. Introduce sync.Pool for small payload buffers.
4. Add metrics + basic Prometheus exposition.
5. Graceful shutdown & context cancellation.

## License

Add a LICENSE file (MIT / Apache-2.0 recommended) before distribution.

---

Contributions: open issues or PRs describing performance targets and profiling evidence.
