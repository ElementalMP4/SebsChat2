package main

import (
	"bufio"
	"embed"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

//go:embed static/*.*
var staticFS embed.FS

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

func ShowTheBanner() {
	data, err := staticFS.ReadFile("static/banner.txt")
	if err != nil {
		LogFatalError(err)
	}

	lines := strings.Split(string(data), "\n")
	printGradientBanner(lines)
}

func printGradientBanner(lines []string) {
	total := 0
	for _, line := range lines {
		total += len(line)
	}

	index := 0
	for _, line := range lines {
		for _, char := range line {
			r, g := gradientColor(index, total)
			fmt.Printf("\033[38;2;%d;%d;0m%c", r, g, char)
			index++
		}
		fmt.Println()
	}
	fmt.Print("\033[0m")
}

func gradientColor(position, max int) (int, int) {
	if max == 0 {
		return 255, 0
	}

	r := 255
	g := int(float64(position) / float64(max) * 230)
	if g > 230 {
		g = 230
	}
	return r, g
}

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
		if r.Header.Get("Upgrade") == "websocket" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w}
		next.ServeHTTP(lrw, r)
		duration := time.Since(start)

		ip := r.Header.Get("X-Real-IP")
		if ip == "" {
			ip = r.RemoteAddr
		}
		ip = colorCyan + ip + colorReset

		method := r.Method
		path := colorYellow + r.URL.RequestURI() + colorReset
		proto := r.Proto
		status := colorStatus(lrw.statusCode)
		size := colorWhite + strconv.Itoa(lrw.size) + colorReset

		LogInfo(fmt.Sprintf(`%s - "%s %s %s" %s %s (%v)`,
			ip, method, path, proto, status, size, duration))
	})
}

func logStyled(message string, color string) {
	timestamp := time.Now().Format("2006/01/02 15:04:05")
	fmt.Printf("%s%s%s %s%s%s\n", colorGrey, timestamp, colorReset, color, message, colorReset)
}

func LogInfo(msg string)    { logStyled(msg, colorCyan) }
func LogWarn(msg string)    { logStyled(msg, colorYellow) }
func LogError(msg string)   { logStyled(msg, colorRed) }
func LogSuccess(msg string) { logStyled(msg, colorGreen) }

func LogFatal(msg string) {
	logStyled(msg, colorRed)
	os.Exit(1)
}

func LogFatalError(err error) {
	logStyled(fmt.Sprintf("%v", err), colorRed)
	os.Exit(1)
}

func LogTask(taskName string, taskFunc func() error) {
	start := time.Now()

	timestamp := time.Now().Format("2006/01/02 15:04:05")
	fmt.Printf("%s%s %s%-50s%s", colorGrey, timestamp, colorCyan, taskName+"...", colorReset)

	err := taskFunc()
	elapsed := time.Since(start)

	if err != nil {
		fmt.Printf("[%sFAIL%s] %s(%v)%s\n", colorRed, colorReset, colorGrey, elapsed, colorReset)
		LogFatal(fmt.Sprintf("↳ Error: %v", err))
	} else {
		fmt.Printf("[ %sOK%s ] %s(%v)%s\n", colorGreen, colorReset, colorGrey, elapsed, colorReset)
	}
}
