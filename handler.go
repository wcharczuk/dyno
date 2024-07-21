package dyno

import "net/http"

type Handler interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
	OutOfBand(req *http.Request)
}

type NoOutOfBandHandler struct {
	http.Handler
}

func (_ NoOutOfBandHandler) OutOfBand(_ *http.Request) {}
