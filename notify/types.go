package notify

import (
	"context"

	"github.com/drone/drone/core"

	"github.com/spritsail/drone-notify/config"
	"github.com/spritsail/drone-notify/registry"
)

type Bot interface {
	Run(context.Context) error
	Stop() error
}

type Notifier interface {
	Config() config.Notifier
	Send(context.Context, string) error

	ShouldNotifyFor(build *core.Build, repo *core.Repository) bool
}

type BotInit func(context.Context, config.Bot) (Bot, error)
type NotifierInit func(context.Context, config.Notifier, Bot) (Notifier, error)

type Pair struct {
	Bot      BotInit
	Notifier NotifierInit
}

var Registry = registry.New[Pair]()
