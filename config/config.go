package config

import (
	"fmt"
	"io"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Main      Main
	Bots      map[string]Bot
	Notifiers map[string]Notifier
}

func LoadTOMLFile(name string) (Config, error) {
	f, err := os.Open(name)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	return LoadTOML(f)
}

func LoadTOML(in io.Reader) (Config, error) {
	var tmp = struct {
		Main     Main
		Bot      map[string]toml.Primitive
		Notifier map[string]toml.Primitive
	}{}

	meta, err := toml.NewDecoder(in).Decode(&tmp)
	if err != nil {
		return Config{}, err
	}

	var bots = make(map[string]Bot, len(tmp.Bot))
	for name, data := range tmp.Bot {
		bot, err := loadBot(meta, data, name)
		if err != nil {
			return Config{}, err
		}
		bots[name] = bot
	}

	var notifiers = make(map[string]Notifier, len(tmp.Notifier))
	for name, data := range tmp.Notifier {
		notifier, err := loadNotifiers(meta, data, bots, name)
		if err != nil {
			return Config{}, err
		}
		notifiers[name] = notifier
	}

	return Config{
		Main:      tmp.Main,
		Bots:      bots,
		Notifiers: notifiers,
	}, nil
}

func loadBot(meta toml.MetaData, data toml.Primitive, name string) (Bot, error) {
	var tmp = struct{ Kind string }{}
	err := meta.PrimitiveDecode(data, &tmp)
	if err != nil {
		return nil, err
	}

	init, ok := Registry.Find(tmp.Kind)
	if !ok {
		return nil, fmt.Errorf("unknown bot kind: %s", tmp.Kind)
	}

	bot := init.Bot(name)
	return bot, meta.PrimitiveDecode(data, bot)
}

func loadNotifiers(meta toml.MetaData, data toml.Primitive, bots map[string]Bot, name string) (Notifier, error) {
	var tmp = struct{ Bot string }{}
	err := meta.PrimitiveDecode(data, &tmp)
	if err != nil {
		return nil, err
	}

	// We need to reference the bot (config) to work out what kind the notifier
	// should be
	bot, ok := bots[tmp.Bot]
	if !ok {
		return nil, fmt.Errorf("unknown bot: %s", tmp.Bot)
	}

	// Given that we already loaded the bot from the registry, there's no reason
	// that accessing the same key a second time should fail, so don't check it.
	kind := bot.Kind()
	init, ok := Registry.Find(kind)
	if !ok {
		panic(fmt.Sprintf("unknown registry kind: %s", kind))
	}
	notifier := init.Notifier(name, bot)
	return notifier, meta.PrimitiveDecode(data, notifier)
}

type Main struct {
	Host   string `toml:"host,omitempty"`
	Port   int    `toml:"port,omitempty"`
	Secret string `toml:"secret,omitempty"`
	Debug  bool   `toml:"debug,omitempty"`
}

type Bot interface {
	Name() string
	Kind() string
}

type Notifier interface {
	Name() string
	Bot() Bot
}

type BaseNotifier struct {
	Status []string
	Repos  []string
}
