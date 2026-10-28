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
	"github.com/aaronburt/netscan/internal/platform"
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

// UnderSystemd reports whether the process was started by a systemd unit.
// systemd sets INVOCATION_ID for every service it starts.
func UnderSystemd(getenv func(string) string) bool {
	return getenv("INVOCATION_ID") != ""
}

// ShouldRunHeadless decides whether to skip the system tray: always under
// systemd, and on Linux whenever there is no display server to draw it on.
func ShouldRunHeadless(goos string, getenv func(string) string) bool {
	if UnderSystemd(getenv) {
		return true
	}
	return goos == "linux" && getenv("DISPLAY") == "" && getenv("WAYLAND_DISPLAY") == ""
}

// InContainer reports whether NetScan runs inside a container. There the binary
// cannot replace itself, and updates come from pulling a new image. The image
// sets NETSCAN_CONTAINER, and setting it to 0 turns detection off. Otherwise
// the marker files that Docker and Podman create decide.
func InContainer(getenv func(string) string, exists func(string) bool) bool {
	if on, err := strconv.ParseBool(getenv("NETSCAN_CONTAINER")); err == nil {
		return on
	}
	return exists("/.dockerenv") || exists("/run/.containerenv")
}

// SetupLogger returns the app logger. Under a service manager the journal
// owns log storage and rotation, so logs go to stdout only.
func SetupLogger(headless, service bool) (*slog.Logger, io.Closer) {
	if service {
		l := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
		slog.SetDefault(l)
		return l, io.NopCloser(nil)
	}
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
			if err := platform.OpenDashboard(targetURL); err != nil {
				logger.Error("failed to open dashboard", "error", err)
			}
			return true
		}
	}

	logger.Error("existing instance did not answer /healthz", "port", port)
	return false
}
