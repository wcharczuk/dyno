package dyno

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"
)

// A response represents the server side of an HTTP response.
type response struct {
	conn             *conn
	req              *http.Request // request for this response
	reqBody          io.ReadCloser
	cancelCtx        context.CancelFunc // when ServeHTTP exits
	wroteHeader      bool               // a non-1xx header has been (logically) written
	wants10KeepAlive bool               // HTTP/1.0 w/ Connection "keep-alive"
	wantsClose       bool               // HTTP request has Connection "close"

	// canWriteContinue is an atomic boolean that says whether or
	// not a 100 Continue header can be written to the
	// connection.
	// writeContinueMu must be held while writing the header.
	// These two fields together synchronize the body reader (the
	// expectContinueReader, which wants to write 100 Continue)
	// against the main writer.
	writeContinueMu  sync.Mutex
	canWriteContinue atomic.Bool

	w  *bufio.Writer // buffers output in chunks to chunkWriter
	cw chunkWriter

	// handlerHeader is the Header that Handlers get access to,
	// which may be retained and mutated even after WriteHeader.
	// handlerHeader is copied into cw.header at WriteHeader
	// time, and privately mutated thereafter.
	handlerHeader http.Header
	calledHeader  bool // handler accessed handlerHeader via Header

	written       int64 // number of bytes written in body
	contentLength int64 // explicitly-declared Content-Length; or -1
	status        int   // status code passed to WriteHeader

	// close connection after this reply.  set on request and
	// updated after response from handler if there's a
	// "Connection: keep-alive" response header and a
	// Content-Length.
	closeAfterReply bool

	// When fullDuplex is false (the default), we consume any remaining
	// request body before starting to write a response.
	fullDuplex bool

	// requestBodyLimitHit is set by requestTooLarge when
	// maxBytesReader hits its max size. It is checked in
	// WriteHeader, to make sure we don't consume the
	// remaining request body to try to advance to the next HTTP
	// request. Instead, when this is set, we stop reading
	// subsequent requests on this connection and stop reading
	// input from it.
	requestBodyLimitHit bool

	// trailers are the headers to be sent after the handler
	// finishes writing the body. This field is initialized from
	// the Trailer response header when the response header is
	// written.
	trailers []string

	handlerDone atomic.Bool // set true when the handler exits

	// Buffers for Date, Content-Length, and status code
	dateBuf   [len(TimeFormat)]byte
	clenBuf   [10]byte
	statusBuf [3]byte

	// closeNotifyCh is the channel returned by CloseNotify.
	// TODO(bradfitz): this is currently (for Go 1.8) always
	// non-nil. Make this lazily-created again as it used to be?
	closeNotifyCh  chan bool
	didCloseNotify atomic.Bool // atomic (only false->true winner should send)
}

func (c *response) SetReadDeadline(deadline time.Time) error {
	return c.conn.rwc.SetReadDeadline(deadline)
}

func (c *response) SetWriteDeadline(deadline time.Time) error {
	return c.conn.rwc.SetWriteDeadline(deadline)
}

func (c *response) EnableFullDuplex() error {
	c.fullDuplex = true
	return nil
}

// finalTrailers is called after the Handler exits and returns a non-nil
// value if the Handler set any trailers.
func (w *response) finalTrailers() http.Header {
	var t http.Header
	for k, vv := range w.handlerHeader {
		if kk, found := strings.CutPrefix(k, http.TrailerPrefix); found {
			if t == nil {
				t = make(http.Header)
			}
			t[kk] = vv
		}
	}
	for _, k := range w.trailers {
		if t == nil {
			t = make(http.Header)
		}
		for _, v := range w.handlerHeader[k] {
			t.Add(k, v)
		}
	}
	return t
}

// declareTrailer is called for each Trailer header when the
// response header is written. It notes that a header will need to be
// written in the trailers at the end of the response.
func (w *response) declareTrailer(k string) {
	k = http.CanonicalHeaderKey(k)
	if !httpguts.ValidTrailerHeader(k) {
		// Forbidden by RFC 7230, section 4.1.2
		return
	}
	w.trailers = append(w.trailers, k)
}

func (w *response) sendExpectationFailed() {
	// TODO(bradfitz): let ServeHTTP handlers handle
	// requests with non-standard expectation[s]? Seems
	// theoretical at best, and doesn't fit into the
	// current ServeHTTP model anyway. We'd need to
	// make the ResponseWriter an optional
	// "ExpectReplier" interface or something.
	//
	// For now we'll just obey RFC 7231 5.1.1 which says
	// "A server that receives an Expect field-value other
	// than 100-continue MAY respond with a 417 (Expectation
	// Failed) status code to indicate that the unexpected
	// expectation cannot be met."
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusExpectationFailed)
	w.finishRequest()
}

// requestTooLarge is called by maxBytesReader when too much input has
// been read from the client.
func (w *response) requestTooLarge() {
	w.closeAfterReply = true
	w.requestBodyLimitHit = true
	if !w.wroteHeader {
		w.Header().Set("Connection", "close")
	}
}

// disableWriteContinue stops Request.Body.Read from sending an automatic 100-Continue.
// If a 100-Continue is being written, it waits for it to complete before continuing.
func (w *response) disableWriteContinue() {
	w.writeContinueMu.Lock()
	w.canWriteContinue.Store(false)
	w.writeContinueMu.Unlock()
}

// bodyAllowed reports whether a Write is allowed for this response type.
// It's illegal to call this before the header has been flushed.
func (w *response) bodyAllowed() bool {
	if !w.wroteHeader {
		panic("")
	}
	return bodyAllowedForStatus(w.status)
}

func (w *response) Header() http.Header {
	if w.cw.header == nil && w.wroteHeader && !w.cw.wroteHeader {
		// Accessing the header between logically writing it
		// and physically writing it means we need to allocate
		// a clone to snapshot the logically written state.
		w.cw.header = w.handlerHeader.Clone()
	}
	w.calledHeader = true
	return w.handlerHeader
}

func (w *response) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	checkWriteHeaderCode(code)

	if code < 101 || code > 199 {
		// Sending a 100 Continue or any non-1xx header disables the
		// automatically-sent 100 Continue from Request.Body.Read.
		w.disableWriteContinue()
	}

	// Handle informational headers.
	//
	// We shouldn't send any further headers after 101 Switching Protocols,
	// so it takes the non-informational path.
	if code >= 100 && code <= 199 && code != http.StatusSwitchingProtocols {
		writeStatusLine(w.conn.bufw, w.req.ProtoAtLeast(1, 1), code, w.statusBuf[:])

		// Per RFC 8297 we must not clear the current header map
		w.handlerHeader.WriteSubset(w.conn.bufw, excludedHeadersNoBody)
		w.conn.bufw.Write(crlf)
		w.conn.bufw.Flush()

		return
	}

	w.wroteHeader = true
	w.status = code

	if w.calledHeader && w.cw.header == nil {
		w.cw.header = w.handlerHeader.Clone()
	}

	if cl := getHeader(w.handlerHeader, "Content-Length"); cl != "" {
		v, err := strconv.ParseInt(cl, 10, 64)
		if err == nil && v >= 0 {
			w.contentLength = v
		} else {
			w.handlerHeader.Del("Content-Length")
		}
	}
}

func checkWriteHeaderCode(code int) {
	// Issue 22880: require valid WriteHeader status codes.
	// For now we only enforce that it's three digits.
	// In the future we might block things over 599 (600 and above aren't defined
	// at https://httpwg.org/specs/rfc7231.html#status.codes).
	// But for now any three digits.
	//
	// We used to send "HTTP/1.1 000 0" on the wire in responses but there's
	// no equivalent bogus thing we can realistically send in HTTP/2,
	// so we'll consistently panic instead and help people find their bugs
	// early. (We can't return an error from WriteHeader even if we wanted to.)
	if code < 100 || code > 999 {
		panic(fmt.Sprintf("invalid WriteHeader code %v", code))
	}
}

// ReadFrom is here to optimize copying from an [*os.File] regular file
// to a [*net.TCPConn] with sendfile, or from a supported src type such
// as a *net.TCPConn on Linux with splice.
func (w *response) ReadFrom(src io.Reader) (n int64, err error) {
	buf := getCopyBuf()
	defer putCopyBuf(buf)

	// Our underlying w.conn.rwc is usually a *TCPConn (with its
	// own ReadFrom method). If not, just fall back to the normal
	// copy method.
	rf, ok := w.conn.rwc.(io.ReaderFrom)
	if !ok {
		return io.CopyBuffer(writerOnly{w}, src, buf)
	}

	// Copy the first sniffLen bytes before switching to ReadFrom.
	// This ensures we don't start writing the response before the
	// source is available (see golang.org/issue/5660) and provides
	// enough bytes to perform Content-Type sniffing when required.
	if !w.cw.wroteHeader {
		n0, err := io.CopyBuffer(writerOnly{w}, io.LimitReader(src, sniffLen), buf)
		n += n0
		if err != nil || n0 < sniffLen {
			return n, err
		}
	}

	w.w.Flush()  // get rid of any previous writes
	w.cw.flush() // make sure Header is written; flush data to rwc

	// Now that cw has been flushed, its chunking field is guaranteed initialized.
	if !w.cw.chunking && w.bodyAllowed() {
		n0, err := rf.ReadFrom(src)
		n += n0
		w.written += n0
		return n, err
	}

	n0, err := io.CopyBuffer(writerOnly{w}, src, buf)
	n += n0
	return n, err
}

// The Life Of A Write is like this:
//
// Handler starts. No header has been sent. The handler can either
// write a header, or just start writing. Writing before sending a header
// sends an implicitly empty 200 OK header.
//
// If the handler didn't declare a Content-Length up front, we either
// go into chunking mode or, if the handler finishes running before
// the chunking buffer size, we compute a Content-Length and send that
// in the header instead.
//
// Likewise, if the handler didn't set a Content-Type, we sniff that
// from the initial chunk of output.
//
// The Writers are wired together like:
//
//  1. *response (the ResponseWriter) ->
//  2. (*response).w, a [*bufio.Writer] of bufferBeforeChunkingSize bytes ->
//  3. chunkWriter.Writer (whose writeHeader finalizes Content-Length/Type)
//     and which writes the chunk headers, if needed ->
//  4. conn.bufw, a *bufio.Writer of default (4kB) bytes, writing to ->
//  5. checkConnErrorWriter{c}, which notes any non-nil error on Write
//     and populates c.werr with it if so, but otherwise writes to ->
//  6. the rwc, the [net.Conn].
//
// TODO(bradfitz): short-circuit some of the buffering when the
// initial header contains both a Content-Type and Content-Length.
// Also short-circuit in (1) when the header's been sent and not in
// chunking mode, writing directly to (4) instead, if (2) has no
// buffered data. More generally, we could short-circuit from (1) to
// (3) even in chunking mode if the write size from (1) is over some
// threshold and nothing is in (2).  The answer might be mostly making
// bufferBeforeChunkingSize smaller and having bufio's fast-paths deal
// with this instead.
func (w *response) Write(data []byte) (n int, err error) {
	return w.write(len(data), data, "")
}

func (w *response) WriteString(data string) (n int, err error) {
	return w.write(len(data), nil, data)
}

// either dataB or dataS is non-zero.
func (w *response) write(lenData int, dataB []byte, dataS string) (n int, err error) {
	if w.canWriteContinue.Load() {
		// Body reader wants to write 100 Continue but hasn't yet. Tell it not to.
		w.disableWriteContinue()
	}

	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if lenData == 0 {
		return 0, nil
	}
	if !w.bodyAllowed() {
		return 0, http.ErrBodyNotAllowed
	}

	w.written += int64(lenData) // ignoring errors, for errorKludge
	if w.contentLength != -1 && w.written > w.contentLength {
		return 0, http.ErrContentLength
	}
	if dataB != nil {
		return w.w.Write(dataB)
	} else {
		return w.w.WriteString(dataS)
	}
}

func (w *response) finishRequest() {
	w.handlerDone.Store(true)

	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	w.w.Flush()
	putBufioWriter(w.w)
	w.cw.close()
	w.conn.bufw.Flush()

	w.conn.r.abortPendingRead()

	// Close the body (regardless of w.closeAfterReply) so we can
	// re-use its bufio.Reader later safely.
	w.reqBody.Close()

	if w.req.MultipartForm != nil {
		w.req.MultipartForm.RemoveAll()
	}
}

// shouldReuseConnection reports whether the underlying TCP connection can be reused.
// It must only be called after the handler is done executing.
func (w *response) shouldReuseConnection() bool {
	if w.closeAfterReply {
		// The request or something set while executing the
		// handler indicated we shouldn't reuse this
		// connection.
		return false
	}

	if w.req.Method != "HEAD" && w.contentLength != -1 && w.bodyAllowed() && w.contentLength != w.written {
		// Did not write enough. Avoid getting out of sync.
		return false
	}

	// There was some error writing to the underlying connection
	// during the request, so don't re-use this conn.
	if w.conn.werr != nil {
		return false
	}

	if w.closedRequestBodyEarly() {
		return false
	}

	return true
}

func (w *response) closedRequestBodyEarly() bool {
	body, ok := w.req.Body.(*body)
	return ok && body.didEarlyClose()
}

func (w *response) Flush() {
	w.FlushError()
}

func (w *response) FlushError() error {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	err := w.w.Flush()
	e2 := w.cw.flush()
	if err == nil {
		err = e2
	}
	return err
}
