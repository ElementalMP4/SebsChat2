package log

import (
	"fmt"
	"os"
	"time"
)

const (
	colorReset = "\033[0m"
	colorGrey  = "\033[90m"
	colorCyan  = "\033[36m"
	colorWhite = "\033[97m"

	colorGreen = "\033[32m"
	colorBlue  = "\033[34m"
	colorRed   = "\033[31m"
)

func logStyled(message string, color string) {
	timestamp := time.Now().Format("2006/01/02 15:04:05")
	fmt.Printf("%s%s%s %s%s%s\n", colorGrey, timestamp, colorReset, color, message, colorReset)
}

func LogError(msg string)   { logStyled(msg, colorRed) }
func LogSuccess(msg string) { logStyled(msg, colorGreen) }
func LogFatalError(err error) {
	logStyled(fmt.Sprintf("%v", err), colorRed)
	os.Exit(1)
}

func TimedTask(taskName string, taskFunc func() error) error {
	start := time.Now()

	timestamp := time.Now().Format("2000/01/01 12:00:00")
	fmt.Printf("%s%s %s%-50s%s", colorGrey, timestamp, colorCyan, taskName+"...", colorReset)
	err := taskFunc()
	elapsed := time.Since(start)

	if err != nil {
		fmt.Printf("[%sFAIL%s] %s(%v)%s\n", colorRed, colorReset, colorGrey, elapsed, colorReset)
		LogError(fmt.Sprintf("↳ Error: %v", err))
		return err
	}

	fmt.Printf("[ %sOK%s ] %s(%v)%s\n", colorGreen, colorReset, colorGrey, elapsed, colorReset)
	return nil
}
