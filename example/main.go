package main

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/wcharczuk/dyno"
)

func main() {
	debug.SetGCPercent(-1)
	srv := dyno.Server{
		Addr:                     "127.0.0.1:8081",
		Handler:                  new(handler),
		MaxConcurrentConnections: 1,
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

func (h handler) OutOfBand(req *http.Request) {
	runtime.GC()
	// slog.Info("request", "method", req.Method, "url", req.URL.String())
}
