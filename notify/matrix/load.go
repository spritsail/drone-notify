package matrix

import (
	"github.com/spritsail/drone-notify/config"
	"github.com/spritsail/drone-notify/notify"
)

func init() {
	config.Registry.Register("matrix", config.Pair{Bot: NewBotConfig, Notifier: NewNotifierConfig})
	notify.Registry.Register("matrix", notify.Pair{Bot: Bot, Notifier: Notifier})
}
