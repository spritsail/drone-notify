package notify

import (
	"context"
	"fmt"

	"github.com/puzpuzpuz/xsync"
	"github.com/rs/zerolog"

	"github.com/spritsail/drone-notify/config"
	"github.com/spritsail/drone-notify/webhook"
)

type Notificator struct {
	notifs *xsync.MapOf[string, Notifier]
}

func (n *Notificator) Init(ctx context.Context, configs map[string]config.Notifier, bots BotManager) error {
	n.notifs = xsync.NewMapOf[Notifier]()

	log := zerolog.Ctx(ctx)
	doer := ErrorGroup(ctx)

	for name, cfg := range configs {
		botname := cfg.Bot().Name()
		kind := cfg.Bot().Kind()

		bot, ok := bots.Get(botname)
		if !ok || bot == nil {
			// We should never get here as the config should catch this mismatch early
			panic(fmt.Sprintf("bot %s not found for %s notifier %s", botname, kind, name))
		}

		notiflog := log.With().
			Str("name", name).
			Str("bot", botname).
			Str("kind", kind).
			Logger()

		doer.RunCtx(func(ctx context.Context) error {
			notiflog.Debug().Msg("Starting notifier")

			notifier, err := Registry.Get(kind).Notifier(notiflog.WithContext(ctx), cfg, bot)
			if err != nil {
				notiflog.Error().Err(err).Msg("Failed to initialise notifier")
				return err
			}

			n.notifs.Store(name, notifier)
			notiflog.Info().Msg("Started notifier")
			return nil
		})
	}

	return doer.Wait()
}

func (n *Notificator) Notify(ctx context.Context, event webhook.WebhookData) error {
	var matched []Notifier
	for _, notifier := range n.notifs.Range {
		if notifier.ShouldNotifyFor(event.Build, event.Repo) {
			matched = append(matched, notifier)
		}
	}

	if len(matched) == 0 {
		// Nothing to do
		return nil
	}

	// RenderNotification the message template
	message, err := RenderNotification(event)
	if err != nil {
		return err
	}

	group := ErrorGroup(ctx)
	for _, notifier := range matched {
		group.RunCtx(func(ctx context.Context) error {
			err := notifier.Send(ctx, message)
			if err == nil {
				log := zerolog.Ctx(ctx)
				cfg := notifier.Config()
				log.Info().
					Str("name", cfg.Name()).
					Str("kind", cfg.Bot().Kind()).
					Str("bot", cfg.Bot().Name()).
					Msg("Notification sent")
			}
			return err
		})
	}
	return group.Wait()
}
