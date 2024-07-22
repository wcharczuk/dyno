package dyno

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"
)

// A conn represents the server side of an HTTP connection.
type conn struct {
	// server is the server on which the connection arrived.
	// Immutable; never nil.
	server *Server

	// cancelCtx cancels the connection-level context.
	cancelCtx context.CancelFunc

	// rwc is the underlying network connection.
	// This is never wrapped by other types and is the value given out
	// to CloseNotifier callers. It is usually of type *net.TCPConn.
	rwc net.Conn

	// remoteAddr is rwc.RemoteAddr().String(). It is not populated synchronously
	// inside the Listener's Accept goroutine, as some implementations block.
	// It is populated immediately inside the (*conn).serve goroutine.
	// This is the value of a Handler's (*Request).RemoteAddr.
	remoteAddr string

	// werr is set to the first write error to rwc.
	// It is set via checkConnErrorWriter{w}, where bufw writes.
	werr error

	// r is bufr's read source. It's a wrapper around rwc that provides
	// io.LimitedReader-style limiting (while reading request headers)
	// and functionality to support CloseNotifier. See *connReader docs.
	r *connReader

	// bufr reads from r.
	bufr *bufio.Reader

	// bufw writes to checkConnErrorWriter{c}, which populates werr on error.
	bufw *bufio.Writer

	// lastMethod is the method of the most recent request
	// on this connection, if any.
	lastMethod string

	curReq atomic.Pointer[response] // (which has a Request in it)

	curState atomic.Uint64 // packed (unixtime<<8|uint8(ConnState))

	// mu guards hijackedv
	mu sync.Mutex
}

// Read next request from connection.
func (c *conn) readRequest(ctx context.Context) (w *response, err error) {
	var (
		wholeReqDeadline time.Time // or zero if none
		hdrDeadline      time.Time // or zero if none
	)
	t0 := time.Now()
	if d := c.server.readHeaderTimeout(); d > 0 {
		hdrDeadline = t0.Add(d)
	}
	if d := c.server.ReadTimeout; d > 0 {
		wholeReqDeadline = t0.Add(d)
	}
	c.rwc.SetReadDeadline(hdrDeadline)
	if d := c.server.WriteTimeout; d > 0 {
		defer func() {
			c.rwc.SetWriteDeadline(time.Now().Add(d))
		}()
	}

	c.r.setReadLimit(c.server.initialReadLimitSize())
	if c.lastMethod == "POST" {
		// RFC 7230 section 3 tolerance for old buggy clients.
		peek, _ := c.bufr.Peek(4) // ReadRequest will get err below
		c.bufr.Discard(numLeadingCRorLF(peek))
	}
	req, err := readRequest(c.bufr)
	if err != nil {
		if c.r.hitReadLimit() {
			return nil, errTooLarge
		}
		return nil, err
	}

	if !http1ServerSupportsRequest(req) {
		return nil, statusError{http.StatusHTTPVersionNotSupported, "unsupported protocol version"}
	}

	c.lastMethod = req.Method
	c.r.setInfiniteReadLimit()

	hosts, haveHost := req.Header["Host"]
	if req.ProtoAtLeast(1, 1) && (!haveHost || len(hosts) == 0) && req.Method != "CONNECT" {
		return nil, badRequestError("missing required Host header")
	}
	if len(hosts) == 1 && !httpguts.ValidHostHeader(hosts[0]) {
		return nil, badRequestError("malformed Host header")
	}
	for k, vv := range req.Header {
		if !httpguts.ValidHeaderFieldName(k) {
			return nil, badRequestError("invalid header name")
		}
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				return nil, badRequestError("invalid header value")
			}
		}
	}
	delete(req.Header, "Host")

	ctx, cancelCtx := context.WithCancel(ctx)
	req = req.WithContext(ctx)
	req.RemoteAddr = c.remoteAddr
	if body, ok := req.Body.(*body); ok {
		body.doEarlyClose = true
	}

	// Adjust the read deadline if necessary.
	if !hdrDeadline.Equal(wholeReqDeadline) {
		c.rwc.SetReadDeadline(wholeReqDeadline)
	}

	w = &response{
		conn:          c,
		cancelCtx:     cancelCtx,
		req:           req,
		reqBody:       req.Body,
		handlerHeader: make(http.Header),
		contentLength: -1,
		closeNotifyCh: make(chan bool, 1),

		// We populate these ahead of time so we're not
		// reading from req.Header after their Handler starts
		// and maybe mutates it (Issue 14940)
		wants10KeepAlive: wantsHttp10KeepAlive(req),
		wantsClose:       wantsClose(req),
	}
	w.cw.res = w
	w.w = newBufioWriterSize(&w.cw, bufferBeforeChunkingSize)
	return w, nil
}

// Serve a new connection.
func (c *conn) serve(ctx context.Context) {
	if ra := c.rwc.RemoteAddr(); ra != nil {
		c.remoteAddr = ra.String()
	}
	ctx = context.WithValue(ctx, http.LocalAddrContextKey, c.rwc.LocalAddr())
	var inFlightResponse *response
	defer func() {
		if err := recover(); err != nil && err != http.ErrAbortHandler {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
		}
		if inFlightResponse != nil {
			inFlightResponse.cancelCtx()
			inFlightResponse.disableWriteContinue()
		}
		if inFlightResponse != nil {
			inFlightResponse.conn.r.abortPendingRead()
			inFlightResponse.reqBody.Close()
		}
		c.close()
		c.setState(c.rwc, http.StateClosed, true /*runHooks ~= true */)
		// release the semaphore on the server for this connection.
		if c.server.connSem != nil {
			<-c.server.connSem
		}
	}()

	ctx, cancelCtx := context.WithCancel(ctx)
	c.cancelCtx = cancelCtx
	defer cancelCtx()

	c.r = &connReader{conn: c}
	c.bufr = newBufioReader(c.r)
	c.bufw = newBufioWriterSize(checkConnErrorWriter{c}, 4<<10)

	for {
		w, err := c.readRequest(ctx)
		if c.r.remain != c.server.initialReadLimitSize() {
			c.setState(c.rwc, http.StateActive, true /*runHooks ~= true*/)
		}
		if err != nil {
			const errorHeaders = "\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"

			switch {
			case err == errTooLarge:
				// Their HTTP client may or may not be
				// able to read this if we're
				// responding to them and hanging up
				// while they're still writing their
				// request. Undefined behavior.
				const publicErr = "431 Request Header Fields Too Large"
				fmt.Fprintf(c.rwc, "HTTP/1.1 "+publicErr+errorHeaders+publicErr)
				c.closeWriteAndWait()
				return

			case isUnsupportedTEError(err):
				// Respond as per RFC 7230 Section 3.3.1 which says,
				//      A server that receives a request message with a
				//      transfer coding it does not understand SHOULD
				//      respond with 501 (Unimplemented).
				code := http.StatusNotImplemented

				// We purposefully aren't echoing back the transfer-encoding's value,
				// so as to mitigate the risk of cross side scripting by an attacker.
				fmt.Fprintf(c.rwc, "HTTP/1.1 %d %s%sUnsupported transfer encoding", code, http.StatusText(code), errorHeaders)
				return

			case isCommonNetReadError(err):
				return // don't reply

			default:
				if v, ok := err.(statusError); ok {
					fmt.Fprintf(c.rwc, "HTTP/1.1 %d %s: %s%s%d %s: %s", v.code, http.StatusText(v.code), v.text, errorHeaders, v.code, http.StatusText(v.code), v.text)
					return
				}
				const publicErr = "400 Bad Request"
				fmt.Fprintf(c.rwc, "HTTP/1.1 "+publicErr+errorHeaders+publicErr)
				return
			}
		}

		// Expect 100 Continue support
		req := w.req
		if expectsContinue(req) {
			if req.ProtoAtLeast(1, 1) && req.ContentLength != 0 {
				// Wrap the Body reader with one that replies on the connection
				req.Body = &expectContinueReader{readCloser: req.Body, resp: w}
				w.canWriteContinue.Store(true)
			}
		} else if getHeader(req.Header, "Expect") != "" {
			w.sendExpectationFailed()
			return
		}

		c.curReq.Store(w)

		if requestBodyRemains(req.Body) {
			registerOnHitEOF(req.Body, w.conn.r.startBackgroundRead)
		} else {
			w.conn.r.startBackgroundRead()
		}

		// HTTP cannot have multiple simultaneous active requests.[*]
		// Until the server replies to this request, it can't read another,
		// so we might as well run the handler in this goroutine.
		// [*] Not strictly true: HTTP pipelining. We could let them all process
		// in parallel even if their responses need to be serialized.
		// But we're not going to implement HTTP pipelining because it
		// was never deployed in the wild and the answer is HTTP/2.
		inFlightResponse = w
		if c.server.Handler == nil {
			http.DefaultServeMux.ServeHTTP(w, req)
		} else if !c.server.DisableGeneralOptionsHandler && req.RequestURI == "*" && req.Method == "OPTIONS" {
			globalOptionsHandler{}.ServeHTTP(w, req)
		} else {
			c.server.Handler.ServeHTTP(w, req)
		}
		inFlightResponse = nil
		w.cancelCtx()
		w.finishRequest()
		c.rwc.SetWriteDeadline(time.Time{})

		// call the out-of-band handler
		if c.server.Handler != nil {
			c.server.Handler.OutOfBand(req)
		}
		if !w.shouldReuseConnection() {
			if w.requestBodyLimitHit || w.closedRequestBodyEarly() {
				c.closeWriteAndWait()
			}
			return
		}
		c.setState(c.rwc, http.StateIdle, true /*runHooks ~= true*/)
		c.curReq.Store(nil)

		if !w.conn.server.doKeepAlives() {
			// We're in shutdown mode. We might've replied
			// to the user without "Connection: close" and
			// they might think they can send another
			// request, but such is life with HTTP/1.1.
			return
		}

		if d := c.server.idleTimeout(); d > 0 {
			c.rwc.SetReadDeadline(time.Now().Add(d))
		} else {
			c.rwc.SetReadDeadline(time.Time{})
		}

		// Wait for the connection to become readable again before trying to
		// read the next request. This prevents a ReadHeaderTimeout or
		// ReadTimeout from starting until the first bytes of the next request
		// have been received.
		if _, err := c.bufr.Peek(4); err != nil {
			return
		}

		c.rwc.SetReadDeadline(time.Time{})
	}
}

// closeWriteAndWait flushes any outstanding data and sends a FIN packet (if
// client is connected via TCP), signaling that we're done. We then
// pause for a bit, hoping the client processes it before any
// subsequent RST.
//
// See https://golang.org/issue/3595
func (c *conn) closeWriteAndWait() {
	c.finalFlush()
	if tcp, ok := c.rwc.(closeWriter); ok {
		tcp.CloseWrite()
	}

	// When we return from closeWriteAndWait, the caller will fully close the
	// connection. If client is still writing to the connection, this will cause
	// the write to fail with ECONNRESET or similar. Unfortunately, many TCP
	// implementations will also drop unread packets from the client's read buffer
	// when a write fails, causing our final response to be truncated away too.
	//
	// As a result, https://www.rfc-editor.org/rfc/rfc7230#section-6.6 recommends
	// that “[t]he server … continues to read from the connection until it
	// receives a corresponding close by the client, or until the server is
	// reasonably certain that its own TCP stack has received the client's
	// acknowledgement of the packet(s) containing the server's last response.”
	//
	// Unfortunately, we have no straightforward way to be “reasonably certain”
	// that we have received the client's ACK, and at any rate we don't want to
	// allow a misbehaving client to soak up server connections indefinitely by
	// withholding an ACK, nor do we want to go through the complexity or overhead
	// of using low-level APIs to figure out when a TCP round-trip has completed.
	//
	// Instead, we declare that we are “reasonably certain” that we received the
	// ACK if maxRSTAvoidanceDelay has elapsed.
	time.Sleep(rstAvoidanceDelay)
}

func (c *conn) finalFlush() {
	if c.bufr != nil {
		// Steal the bufio.Reader (~4KB worth of memory) and its associated
		// reader for a future connection.
		putBufioReader(c.bufr)
		c.bufr = nil
	}

	if c.bufw != nil {
		c.bufw.Flush()
		// Steal the bufio.Writer (~4KB worth of memory) and its associated
		// writer for a future connection.
		putBufioWriter(c.bufw)
		c.bufw = nil
	}
}

// Close the connection.
func (c *conn) close() {
	c.finalFlush()
	c.rwc.Close()
}

func (c *conn) setState(nc net.Conn, state http.ConnState, runHook bool) {
	srv := c.server
	switch state {
	case http.StateNew:
		srv.trackConn(c, true)
	case http.StateHijacked, http.StateClosed:
		srv.trackConn(c, false)
	}
	if state > 0xff || state < 0 {
		panic("internal error")
	}
	packedState := uint64(time.Now().Unix()<<8) | uint64(state)
	c.curState.Store(packedState)
	if !runHook {
		return
	}
	if hook := srv.ConnState; hook != nil {
		hook(nc, state)
	}
}

func (c *conn) getState() (state http.ConnState, unixSec int64) {
	packedState := c.curState.Load()
	return http.ConnState(packedState & 0xff), int64(packedState >> 8)
}

// checkConnErrorWriter writes to c.rwc and records any write errors to c.werr.
// It only contains one field (and a pointer field at that), so it
// fits in an interface value without an extra allocation.
type checkConnErrorWriter struct {
	c *conn
}

func (w checkConnErrorWriter) Write(p []byte) (n int, err error) {
	n, err = w.c.rwc.Write(p)
	if err != nil && w.c.werr == nil {
		w.c.werr = err
		w.c.cancelCtx()
	}
	return
}
