package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"os"
)

// Trap ServeHTTP's ResponseWriter so that response headers and body can be
// written to Stdout.
type responseWriterTrap struct {
	status int
	writer http.ResponseWriter
}

func (w responseWriterTrap) Header() http.Header {
	return w.writer.Header()
}

func (w responseWriterTrap) Write(p []byte) (int, error) {
	if w.status != http.StatusOK {
		os.Stdout.Write(p)
	}
	return w.writer.Write(p)
}

func (w *responseWriterTrap) WriteHeader(i int) {
	fmt.Printf("\n---------------------------\n")
	fmt.Printf("RESPONSE STATUS: %d %s\n", i, http.StatusText(i))
	w.writer.Header().Write(os.Stdout)
	fmt.Println()
	w.status = i
	w.writer.WriteHeader(i)
}

// To log the request headers and body to Stdout.
type tracer struct {
	h http.Handler
}

func (l tracer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqBytes, err := httputil.DumpRequest(r, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Printf("\n---------------------------\n")
	fmt.Printf("REQUEST ")
	io.Copy(os.Stdout, bytes.NewReader(reqBytes))

	fmt.Println()
	l.h.ServeHTTP(&responseWriterTrap{0, w}, r)
	fmt.Printf("\n--------------------------\n")
}
