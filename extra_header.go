package dyno

import "bufio"

// extraHeader is the set of headers sometimes added by chunkWriter.writeHeader.
// This type is used to avoid extra allocations from cloning and/or populating
// the response Header map and all its 1-element slices.
type extraHeader struct {
	contentType      string
	connection       string
	transferEncoding string
	date             []byte // written if not nil
	contentLength    []byte // written if not nil
}

// Write writes the headers described in h to w.
//
// This method has a value receiver, despite the somewhat large size
// of h, because it prevents an allocation. The escape analysis isn't
// smart enough to realize this function doesn't mutate h.
func (h extraHeader) Write(w *bufio.Writer) {
	if h.date != nil {
		w.Write(headerDate)
		w.Write(h.date)
		w.Write(crlf)
	}
	if h.contentLength != nil {
		w.Write(headerContentLength)
		w.Write(h.contentLength)
		w.Write(crlf)
	}
	for i, v := range []string{h.contentType, h.connection, h.transferEncoding} {
		if v != "" {
			w.Write(extraHeaderKeys[i])
			w.Write(colonSpace)
			w.WriteString(v)
			w.Write(crlf)
		}
	}
}

// Sorted the same as extraHeader.Write's loop.
var extraHeaderKeys = [][]byte{
	[]byte("Content-Type"),
	[]byte("Connection"),
	[]byte("Transfer-Encoding"),
}
