package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/drone/drone/core"
	"github.com/rs/zerolog"

	"github.com/spritsail/drone-notify/config"
)

// https://github.com/drone/drone/blob/4f85961434061d8a36be9d7528e5a0171a07d3ba/plugin/webhook/webhook.go#L45C1-L48C2
type WebhookData struct {
	core.WebhookData
	System *core.System `json:"system"`
}

type NotifyFunc func(ctx context.Context, data WebhookData) error

func NewServer(cfg config.Main, notify NotifyFunc) *Server {
	var secret []byte
	if cfg.Secret != "" {
		secret = []byte(cfg.Secret)
	}
	return &Server{
		hostport: net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		secret:   secret,
		notify:   notify,
	}
}

type Server struct {
	log      *zerolog.Logger
	hostport string
	secret   []byte
	notify   NotifyFunc
}

func (s *Server) Run(ctx context.Context) error {
	s.log = zerolog.Ctx(ctx)

	router := http.NewServeMux()
	router.HandleFunc("/hook", s.hook)

	// Always verify the Digest header
	var handler http.Handler = &DigestVerifier{log: s.log, handler: router}

	// Verify the Signature header to verify request authenticity if the config
	// specifies a signing secret
	if s.secret != nil {
		handler = &SignatureVerifier{
			log:     s.log,
			secret:  s.secret,
			handler: handler,
		}
	}

	srv := http.Server{
		Addr:    s.hostport,
		Handler: handler,
		// TLSConfig: nil,
		ErrorLog:    stdlog.New(s.log, "", 0),
		BaseContext: func(listener net.Listener) context.Context { return ctx },
	}

	var err error
	var stopped = make(chan struct{})
	go func() {
		s.log.Info().Str("addr", s.hostport).Msg("Starting HTTP server")
		err = srv.ListenAndServe()
		close(stopped)
	}()

	select {
	case <-ctx.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		shutdownErr := srv.Shutdown(ctx)
		if shutdownErr != nil {
			s.log.Error().Err(shutdownErr).Msg("Error stopping HTTP server")
		}
		cancel()
	case <-stopped:
	}

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) hook(resp http.ResponseWriter, req *http.Request) {
	s.log.Debug().
		Str("method", req.Method).
		Str("content-type", req.Header.Get("Content-Type")).
		Str("length", req.Header.Get("Content-Length")).
		Str("user-agent", req.Header.Get("User-Agent")).
		Str("from", req.RemoteAddr).
		Msg("Hook request received")

	// Decode the webhook request body
	var payload WebhookData
	decoder := json.NewDecoder(req.Body)
	decoder.DisallowUnknownFields()
	// In case we need to error
	buffer := decoder.Buffered()
	err := decoder.Decode(&payload)

	if err != nil {
		body, _ := io.ReadAll(buffer)
		s.log.Debug().
			Err(err).
			Str("request", string(body)).
			Msg("Error parsing payload")
		respond(resp, http.StatusBadRequest, fmt.Sprintf("parse error: %s\n", err))
		return
	}

	// Basic sanity check to ensure we have all the required data
	if payload.Event == "" || payload.Action == "" ||
		payload.Repo == nil || payload.Build == nil || payload.System == nil {
		body, _ := io.ReadAll(buffer)
		s.log.Debug().
			Str("request", string(body)).
			Msg("Invalid hook payload")
		respond(resp, http.StatusBadRequest, "invalid payload\n")
		return
	}

	if payload.Event == core.WebhookEventBuild {
		notifLog := s.log.With().
			Str("drone", payload.System.Host).
			Str("remote", req.RemoteAddr).
			Str("repo", payload.Repo.Slug).
			Int64("build", payload.Build.Number).
			Str("status", payload.Build.Status).
			Logger()
		if !payload.Build.IsDone() {
			notifLog.Debug().Msg("Build running")
		} else {
			notifLog.Info().Msg("Build finished")

			ctx := notifLog.WithContext(req.Context())
			err = s.notify(ctx, payload)
			if err != nil {
				s.log.Error().Err(err).Msg("Error sending notification(s)")
			}
		}
	}
	resp.WriteHeader(http.StatusOK)
}

func respond(writer http.ResponseWriter, status int, data string) {
	headers := writer.Header()
	headers.Set("Content-Length", strconv.Itoa(len(data)))
	headers.Set("Content-Type", "text/plain")
	writer.WriteHeader(status)
	_, _ = writer.Write([]byte(data))
}
