package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorGrey   = "\033[90m"
	colorCyan   = "\033[36m"
	colorYellow = "\033[33m"
	colorWhite  = "\033[97m"

	colorGreen   = "\033[32m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorRed     = "\033[31m"
)

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	if lrw.statusCode == 0 {
		lrw.statusCode = http.StatusOK
	}
	n, err := lrw.ResponseWriter.Write(b)
	lrw.size += n
	return n, err
}

// Forward the Hijacker interface
func (lrw *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := lrw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
	}
	return hj.Hijack()
}

// Forward the Flusher interface
func (lrw *loggingResponseWriter) Flush() {
	if f, ok := lrw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Forward the Pusher interface
func (lrw *loggingResponseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := lrw.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func colorStatus(code int) string {
	switch {
	case code >= 100 && code < 200:
		return colorBlue + strconv.Itoa(code) + colorReset
	case code >= 200 && code < 300:
		return colorGreen + strconv.Itoa(code) + colorReset
	case code >= 300 && code < 400:
		return colorMagenta + strconv.Itoa(code) + colorReset
	case code >= 400 && code < 500:
		return colorYellow + strconv.Itoa(code) + colorReset
	default:
		return colorRed + strconv.Itoa(code) + colorReset
	}
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w}
		next.ServeHTTP(lrw, r)
		duration := time.Since(start)

		ip := colorCyan + r.RemoteAddr + colorReset
		timestamp := colorGrey + start.Format("02/Jan/2006:15:04:05 -0700") + colorReset
		method := r.Method
		path := colorYellow + r.URL.RequestURI() + colorReset
		proto := r.Proto
		status := colorStatus(lrw.statusCode)
		size := colorWhite + strconv.Itoa(lrw.size) + colorReset

		log.Printf(`%s - - [%s] "%s %s %s" %s %s (%v)`,
			ip, timestamp, method, path, proto, status, size, duration)
	})
}
