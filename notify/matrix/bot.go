package matrix

import (
	"context"
	"errors"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/cryptohelper"

	"github.com/spritsail/drone-notify/config"
	"github.com/spritsail/drone-notify/notify"
)

const (
	pickleKey = "dronenotify"
)

type matrixBot struct {
	Config *BotConfig
	Client *mautrix.Client
	crypto *cryptohelper.CryptoHelper

	stopSync func() error
}

func Bot(ctx context.Context, botcfg config.Bot) (notify.Bot, error) {
	cfg := *botcfg.(*BotConfig)
	localpart, homeserver, err := cfg.Mxid.Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse mxid: %w", err)
	}
	wellKnown, err := mautrix.DiscoverClientAPI(ctx, homeserver)
	if err != nil {
		return nil, err
	}

	client, err := mautrix.NewClient(wellKnown.Homeserver.BaseURL, cfg.Mxid, cfg.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("error creating Client: %w", err)
	}

	client.Log = *zerolog.Ctx(ctx)

	whoiam, err := client.Whoami(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to ask whoami: %w", err)
	}
	client.UserID = whoiam.UserID
	client.DeviceID = whoiam.DeviceID
	client.AccessToken = cfg.AccessToken

	crypto, err := cryptohelper.NewCryptoHelper(client, []byte(pickleKey), cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create cryptohelper: %w", err)
	}
	err = crypto.Init(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialise cryptohelper: %w", err)
	}
	client.Crypto = crypto

	bot := matrixBot{
		Config: &cfg,
		Client: client,
		crypto: crypto,
	}

	// Manually trigger crypto initialisation instead of waiting for sync to do
	// it. This triggers a crypto account upload to the server if this is the
	// first time this device has been used and crypto has never been set up.
	err = crypto.Machine().ShareKeys(ctx, -1)
	if err != nil {
		return nil, fmt.Errorf("failed to initialise crypto: %w", err)
	}
	err = bot.trustDevice(ctx, cfg.RecoveryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to trust device: %w", err)
	}

	client.Log.Info().Msgf("Connected to %s as %s (%s)", homeserver, localpart, client.DeviceID)

	syncer := client.Syncer.(*mautrix.DefaultSyncer)
	syncer.OnEvent(bot.sendReceipts)

	return &bot, nil
}

func (b *matrixBot) Run(ctx context.Context) (err error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(err) // be sure to cancel the context to stop the goroutine
	b.stopSync = func() error {
		cancel(nil) // no error
		<-ctx.Done()
		return context.Cause(ctx)
	}
	return b.Client.SyncWithContext(ctx)
}

func (b *matrixBot) Stop() error {
	stopSync := b.stopSync
	if stopSync != nil {
		err := stopSync()
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	}
	return b.crypto.Close()
}
