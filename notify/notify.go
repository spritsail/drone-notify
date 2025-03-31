package notify

import (
	"bytes"
	_ "embed"
	"html/template"
	"path"
	"slices"
	"strings"

	"github.com/Masterminds/sprig/v3"
	"github.com/drone/drone/core"
	"github.com/rs/zerolog"

	"github.com/spritsail/drone-notify/config"
	"github.com/spritsail/drone-notify/webhook"
)

var (
	//go:embed default.tmpl
	defaultTemplate string
	DefaultTemplate = template.Must(template.New("default").Funcs(sprig.FuncMap()).Parse(defaultTemplate))
)

func RenderNotification(event webhook.WebhookData) (string, error) {
	var buffer bytes.Buffer
	err := DefaultTemplate.Execute(&buffer, event)
	if err != nil {
		return "", err
	}

	// Remove all newlines for consistent rendering
	return strings.ReplaceAll(buffer.String(), "\n", ""), nil
}

func ShouldNotifyFor(log *zerolog.Logger, cfg config.BaseNotifier, build *core.Build, repo *core.Repository) bool {
	return (len(cfg.Status) == 0 || slices.Contains(cfg.Status, build.Status)) &&
		RepoMatch(log, cfg.Repos, repo.Slug)
}

func RepoMatch(log *zerolog.Logger, repos []string, slug string) bool {
	// If no repos are defined, we match everything by default
	if len(repos) == 0 {
		return true
	}

	var accept, reject []string
	for _, repo := range repos {
		if strings.HasPrefix(repo, "!") {
			reject = append(reject, repo[1:])
		} else {
			accept = append(accept, repo)
		}
	}

	pathMustMatch := func(pattern string) bool {
		matched, err := path.Match(pattern, slug)
		if err != nil {
			panic(err)
		}
		return matched
	}

	// Skip this repo if there are any explicit rejections
	idx := slices.IndexFunc(reject, pathMustMatch)
	if idx >= 0 {
		log.Debug().Str("repo", slug).Str("rule", reject[idx]).Msg("Repo rejected by exclude rule")
		return false
	}

	// Skip this repo if there are explicit matches but non match
	idx = slices.IndexFunc(accept, pathMustMatch)
	if len(accept) > 0 && idx < 0 {
		log.Debug().Str("repo", slug).Msg("Repo rejected by lack of include rule")
		return false
	}

	log.Debug().Str("repo", slug).Msg("Repo accepted")
	return true
}
