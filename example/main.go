package main

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"sync/atomic"

	"github.com/wcharczuk/dyno"
)

func main() {
	slog.Info("setting gc percent -1")
	debug.SetGCPercent(-1)
	srv := dyno.Server{
		Addr:                     "127.0.0.1:8081",
		Handler:                  new(handler),
		MaxConcurrentConnections: 8,
		OnListen: func(l net.Listener) {
			slog.Info("listening", "addr", l.Addr().String())
		},
	}
	if err := srv.Listen(); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}

type handler struct{}

func (h handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "ok!\n")
}

var reqTotal = new(atomic.Uint64)

const gcEvery = 1024 << 4

func (h handler) OutOfBand(req *http.Request) {
	if reqTotal.Add(1)%(gcEvery) == 0 {
		slog.Info("running outofband compaction")
		runtime.GC()
	}
}
