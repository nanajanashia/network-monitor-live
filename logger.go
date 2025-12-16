package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

type Logger struct {
	file *os.File
	mu   sync.Mutex
}

var logger *Logger

func initLogger(logPath string) error {
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	logger = &Logger{file: file}
	return nil
}

func closeLogger() {
	if logger != nil && logger.file != nil {
		logger.file.Close()
	}
}

func logWrite(level string, message string) {
	if logger == nil {
		return
	}
	logger.mu.Lock()
	defer logger.mu.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("%s [%s] %s\n", timestamp, level, message)
	logger.file.WriteString(line)
}

func logInfo(message string) {
	logWrite("INFO", message)
}

func logError(message string) {
	logWrite("ERROR", message)
}

func logAlert(message string) {
	logWrite("ALERT", message)
}
