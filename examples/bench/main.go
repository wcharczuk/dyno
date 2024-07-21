package main

import (
	"flag"
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

var disableGC = flag.Bool("disable-gc", true, "disable automatic gc")
var variant = flag.String("variant", "dyno", "the server variant to use (dyno|stdlib)")
var addr = flag.String("addr", "127.0.0.1:8081", "the server listen addr")

var dynoDisableOOBGC = flag.Bool("dyno-disable-oob-gc", true, "disable out of band gc")
var dynoMaxConns = flag.Int("dyno-max-conns", 32, "the dyno maximum current connections (set to -1 to disable conn semaphore)")

func main() {
	flag.Parse()
	if *disableGC {
		slog.Info("disabling automatic gc")
		debug.SetGCPercent(-1)
	}
	if err := server().ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}

type Server interface {
	ListenAndServe() error
}

func server() Server {
	switch *variant {
	case "dyno":
		return &dyno.Server{
			Addr:                     *addr,
			Handler:                  new(handler),
			MaxConcurrentConnections: *dynoMaxConns,
			OnListen: func(l net.Listener) {
				slog.Info("listening", "addr", l.Addr().String())
			},
		}
	case "stdlib":
		return &http.Server{
			Addr:    *addr,
			Handler: new(handler),
		}
	default:
		panic(fmt.Sprintf("invalid variant: %s", *variant))
	}
}

type handler struct{}

func (h handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "ok!\n")
}

var reqTotal = new(atomic.Uint64)

const gcEvery = 1024 << 6

func (h handler) OutOfBand(req *http.Request) {
	if !*dynoDisableOOBGC {
		if reqTotal.Add(1)%(gcEvery) == 0 {
			slog.Info("running outofband compaction")
			runtime.GC()
		}
	}
}
