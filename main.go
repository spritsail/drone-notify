package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exzerolog"

	"github.com/spritsail/drone-notify/config"
	"github.com/spritsail/drone-notify/notify"
	"github.com/spritsail/drone-notify/webhook"

	// Anonymous imports to register the types
	_ "github.com/spritsail/drone-notify/notify/matrix"
)

func main() {
	log := zerolog.New(&zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		Level(zerolog.InfoLevel).
		With().Timestamp().Caller().
		Logger()
	exzerolog.SetupDefaults(&log)

	ctx, cancel := context.WithCancel(log.WithContext(context.Background()))

	sigs := make(chan os.Signal)
	defer close(sigs)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-sigs:
			if sig != nil {
				log.Info().Stringer("signal", sig).Msg("Received signal, shutting down")
				cancel()
			}
		}
	}()

	configfile := "notify.toml"
	if len(os.Args) > 1 {
		configfile = os.Args[1]
	}
	cfg, err := config.LoadTOMLFile(configfile)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}
	if cfg.Main.Debug {
		log = log.Level(zerolog.DebugLevel)
		ctx = log.WithContext(ctx)
	}
	log.Info().Interface("path", configfile).Msg("Loaded config file")

	var (
		bots      notify.BotManager
		notifiers notify.Notificator
	)

	defer func(bots *notify.BotManager) {
		err := bots.Stop(ctx)
		if err != nil {
			zerolog.Ctx(ctx).Error().Err(err).Msg("Error stopping bots")
		}
	}(&bots)

	err = bots.Init(ctx, cfg.Bots)
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialise bots")
		return
	}

	err = notifiers.Init(ctx, cfg.Notifiers, bots)
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialise notifiers")
		return
	}

	srv := webhook.NewServer(cfg.Main, notifiers.Notify)

	group := notify.ErrorGroup(ctx)
	group.RunCtx(bots.Run)
	group.RunCtx(srv.Run)
	err = group.Error()
	if err != nil {
		log.Error().Err(err).Msg("Uh-oh")
	}
	_ = group.Wait()
	return
}
