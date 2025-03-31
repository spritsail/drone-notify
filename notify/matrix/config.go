package matrix

import (
	"maunium.net/go/mautrix/id"

	"github.com/spritsail/drone-notify/config"
)

func NewBotConfig(name string) config.Bot {
	return &BotConfig{name: name}
}

func NewNotifierConfig(name string, bot config.Bot) config.Notifier {
	return &NotifierConfig{name: name, bot: bot}
}

type BotConfig struct {
	name string

	Mxid        id.UserID `toml:"mxid"`
	AccessToken string    `toml:"access_token"`
	RecoveryKey string    `toml:"recovery_key"`
	DBPath      string    `toml:"db_path"`
}

func (b BotConfig) Name() string {
	return b.name
}

func (b BotConfig) Kind() string {
	return "matrix"
}

type NotifierConfig struct {
	config.BaseNotifier

	name string
	bot  config.Bot

	Room id.RoomID `toml:"room_id"`
}

func (n NotifierConfig) Name() string {
	return n.name
}

func (n NotifierConfig) Bot() config.Bot {
	return n.bot
}
