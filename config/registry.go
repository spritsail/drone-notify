package config

import (
	"github.com/spritsail/drone-notify/registry"
)

type BotLoader func(name string) Bot
type NotifierLoader func(name string, bot Bot) Notifier

type Pair struct {
	Bot      BotLoader
	Notifier NotifierLoader
}

var Registry = registry.New[Pair]()
