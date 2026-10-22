package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/winapi"
	"gopkg.in/natefinch/lumberjack.v2"
)

type bestEffort struct {
	w io.Writer
}

func (b bestEffort) Write(p []byte) (int, error) {
	_, _ = b.w.Write(p)
	return len(p), nil
}

type Supervisor struct {
	logger *slog.Logger
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

func NewSupervisor(logger *slog.Logger) *Supervisor {
	ctx, cancel := context.WithCancel(context.Background())
	return &Supervisor{
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (s *Supervisor) Context() context.Context {
	return s.ctx
}

func (s *Supervisor) Stop(timeout time.Duration) bool {
	s.cancel()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (s *Supervisor) Run(name string, fn func(ctx context.Context) error) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		backoff := 1 * time.Second
		maxBackoff := 30 * time.Second

		for {
			select {
			case <-s.ctx.Done():
				return
			default:
			}

			start := time.Now()
			err := func() (retErr error) {
				defer func() {
					if r := recover(); r != nil {
						s.logger.Error("component panicked", "component", name, "panic", r)
						retErr = fmt.Errorf("panic: %v", r)
					}
				}()
				return fn(s.ctx)
			}()

			select {
			case <-s.ctx.Done():
				return
			default:
			}

			if err != nil {
				if time.Since(start) > maxBackoff {
					backoff = 1 * time.Second
				}
				s.logger.Warn("component failed, restarting with backoff", "component", name, "error", err, "backoff", backoff)
				select {
				case <-s.ctx.Done():
					return
				case <-time.After(backoff):
				}
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			} else {
				return
			}
		}
	}()
}

func SetupLogger(headless bool) (*slog.Logger, io.Closer) {
	if _, err := config.EnsureDataDir(); err != nil {
		l := slog.New(slog.NewJSONHandler(os.Stderr, nil))
		l.Error("cannot create data dir, logging to stderr only", "error", err)
		slog.SetDefault(l)
		return l, io.NopCloser(nil)
	}

	logPath := config.AppLogPath()

	lumLog := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    10,
		MaxBackups: 3,
		MaxAge:     7,
		Compress:   true,
	}

	var writer io.Writer
	if headless {
		writer = io.MultiWriter(lumLog, bestEffort{w: os.Stdout})
	} else {
		writer = lumLog
	}

	handler := slog.NewJSONHandler(writer, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	return logger, lumLog
}

func HandleExistingInstance(logger *slog.Logger) bool {
	portData, err := os.ReadFile(config.PortPath())
	if errors.Is(err, os.ErrNotExist) {
		// The running instance has its dashboard turned off, so there is
		// nothing to open.
		logger.Info("another instance is running with the web UI disabled")
		return true
	}
	if err != nil {
		logger.Error("another instance is running, but port file could not be read", "error", err)
		return false
	}

	portStr := strings.TrimSpace(string(portData))
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		logger.Error("invalid port in port file", "port", portStr)
		return false
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
	if err == nil {
		defer resp.Body.Close()
		var body struct {
			App string `json:"app"`
		}
		ok := resp.StatusCode == http.StatusOK &&
			json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&body) == nil &&
			body.App == "netscan"
		if ok {
			targetURL := fmt.Sprintf("http://127.0.0.1:%d", port)
			if err := winapi.OpenDashboard(targetURL); err != nil {
				logger.Error("failed to open dashboard", "error", err)
			}
			return true
		}
	}

	logger.Error("existing instance did not answer /healthz", "port", port)
	return false
}
