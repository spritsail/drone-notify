package notify

import (
	"context"

	"github.com/puzpuzpuz/xsync"
	"github.com/rs/zerolog"

	"github.com/spritsail/drone-notify/config"
)

type BotManager struct {
	bots *xsync.MapOf[string, Bot]
}

func (t *BotManager) Init(ctx context.Context, configs map[string]config.Bot) error {
	t.bots = xsync.NewMapOf[Bot]()

	log := zerolog.Ctx(ctx)
	group := ErrorGroup(ctx)

	for name, cfg := range configs {
		kind := cfg.Kind()
		botlog := log.With().Str("name", name).Str("kind", kind).Logger()

		group.RunCtx(func(ctx context.Context) error {
			botlog.Debug().Msg("Starting bot")
			bot, err := Registry.Get(kind).Bot(botlog.WithContext(ctx), cfg)
			if err != nil {
				botlog.Error().Err(err).Msg("Failed to initialise bot")
				return err
			}

			t.bots.Store(name, bot)
			botlog.Info().Msg("Started bot")
			return nil
		})
	}

	return group.Wait()
}

func (t *BotManager) Run(ctx context.Context) error {
	group := ErrorGroup(ctx)
	for _, bot := range t.bots.Range {
		group.RunCtx(bot.Run)
	}
	return group.Wait()
}

func (t *BotManager) Stop(ctx context.Context) error {
	log := zerolog.Ctx(ctx)
	group := ErrorGroup(ctx)
	for name, bot := range t.bots.Range {
		log.Debug().Str("bot", name).Msg("Stopping bot")
		group.Run(bot.Stop)
	}
	return group.Wait()
}

func (t *BotManager) Get(bot string) (Bot, bool) {
	return t.bots.Load(bot)
}
