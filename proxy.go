package main

import (
	"net/http"
	"net/http/httputil"
)

type proxy struct {
	h             http.Handler
	secureBackend bool
	backendHost   string
	transport     *http.Transport
}

func (p proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	director := func(r *http.Request) {
		r.Header.Add("X-Forwarded-Host", r.Host)
		r.Header.Add("X-Real-IP", r.RemoteAddr)

		if p.secureBackend {
			r.URL.Scheme = "https"
		} else {
			r.URL.Scheme = "http"
		}

		r.URL.Host = p.backendHost
	}

	proxy := &httputil.ReverseProxy{
		Director:  director,
		Transport: p.transport,
	}

	proxy.ServeHTTP(w, r)
}
