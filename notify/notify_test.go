package notify

import (
	"testing"

	"github.com/drone/drone/core"
	"github.com/rs/zerolog"

	"github.com/spritsail/drone-notify/config"
	"github.com/spritsail/drone-notify/webhook"
)

func TestRenderNotification(t *testing.T) {
	type args struct {
	}
	system := &core.System{Link: "https://drone"}
	repo := &core.Repository{
		Slug: "user/repo",
		Link: "https://git/user/repo.git",
	}
	tests := []struct {
		name  string
		event webhook.WebhookData
		want  string
	}{
		{
			name: "Simple successful build",
			event: webhook.WebhookData{
				WebhookData: core.WebhookData{
					Repo: repo,
					Build: &core.Build{
						Status:   core.StatusPassing,
						Target:   "master",
						Link:     "https://git/user/repo/pull/12345",
						After:    "abcd1234defg5678",
						Author:   "steve",
						Message:  "I did a cool thing\n",
						Stages:   []*core.Stage{},
						Number:   123,
						Started:  946728000,
						Finished: 946728083,
					},
				},
				System: system,
			},
			want: `✅ <b>user/repo [master]</b> #123: <b>SUCCESS</b> in 1m23s<br/>` +
				`<a href="https://drone/user/repo/123">https://drone/user/repo/123</a><br/>` +
				`<a href="https://git/user/repo/pull/12345">#abcd123</a> (steve): <i>I did a cool thing</i>`,
		},
		{
			name: "Simple failed build",
			event: webhook.WebhookData{
				WebhookData: core.WebhookData{
					Repo: repo,
					Build: &core.Build{
						Status:   core.StatusFailing,
						Target:   "master",
						Link:     "https://git/user/repo/pull/12346",
						After:    "abcd1234defg5678",
						Author:   "steve",
						Message:  "yolo probably won't work",
						Stages:   []*core.Stage{},
						Number:   124,
						Started:  946728000,
						Finished: 946728032,
					},
				},
				System: system,
			},
			want: `❌ <b>user/repo [master]</b> #124: <b>FAILURE</b> in 32s<br/>` +
				`<a href="https://drone/user/repo/124">https://drone/user/repo/124</a><br/>` +
				`<a href="https://git/user/repo/pull/12346">#abcd123</a> (steve): <i>yolo probably won&#39;t work</i>`,
		},
		{
			name: "Multi-stage build",
			event: webhook.WebhookData{
				WebhookData: core.WebhookData{
					Repo: repo,
					Build: &core.Build{
						Status: core.StatusPassing,
						Target: "master",
						Link:   "https://git/user/repo/pull/12346",
						After:  "abcd1234defg5678",
						Author: "steve",
						// Lots of newlines get chomped
						Message: "This does lots of things\n\n\n\n\nand even has a longer commit message\n" +
							"because why not\n\nSigned-off-by: Steve <steve@drone>",
						Stages: []*core.Stage{
							{
								Number:  1,
								Name:    core.StatusPassing,
								Status:  core.StatusPassing,
								Started: 946728000,
								Stopped: 946728153,
							},
							{
								Number:  2,
								Name:    core.StatusError,
								Status:  core.StatusError,
								Started: 946728000,
								Stopped: 946728153,
							},
							{
								Number:  3,
								Name:    core.StatusKilled,
								Status:  core.StatusKilled,
								Started: 946728000,
								Stopped: 946728153,
							},
							{
								Number:  4,
								Name:    core.StatusKilled,
								Status:  core.StatusKilled,
								Started: 946728000,
								Stopped: 946728153,
							},
							{
								Number:  5,
								Name:    core.StatusSkipped,
								Status:  core.StatusSkipped,
								Started: 946728000,
								Stopped: 946728153,
							},
							{
								Number:  6,
								Name:    core.StatusPending,
								Status:  core.StatusPending,
								Started: 946728000,
								Stopped: 946728153,
							},
						},
						Number:   124,
						Started:  946728000,
						Finished: 946728032,
					},
				},
				System: system,
			},
			want: `✅ <b>user/repo [master]</b> #124: <b>SUCCESS</b> in 32s<br/>` +
				`<a href="https://drone/user/repo/124">https://drone/user/repo/124</a><br/><br/>` +
				`• <a href="https://drone/user/repo/124/1">success</a> <b>success</b> in 2m33s ✅<br/>` +
				`• <a href="https://drone/user/repo/124/2">error</a> <b>error</b> in 2m33s 💢<br/>` +
				`• <a href="https://drone/user/repo/124/3">killed</a> <b>killed</b> in 2m33s ☠️<br/>` +
				`• <a href="https://drone/user/repo/124/4">killed</a> <b>killed</b> in 2m33s ☠️<br/>` +
				`• <a href="https://drone/user/repo/124/5">skipped</a> <b>skipped</b> in 2m33s 🚫<br/>` +
				`• <a href="https://drone/user/repo/124/6">pending</a> <b>pending</b> in 2m33s ⏳<br/>` +
				`<br/><a href="https://git/user/repo/pull/12346">#abcd123</a> (steve): <i>This does lots of things</i>` +
				`<br/>-----<br/>and even has a longer commit message<br/>because why not<br/><br/>` +
				`Signed-off-by: Steve &lt;steve@drone&gt;<br/>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RenderNotification(tt.event)
			if err != nil {
				t.Errorf("RenderNotification() failed %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("RenderNotification() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRepoMatch(t *testing.T) {
	tests := []struct {
		name  string
		repos []string
		slug  string
		want  bool
	}{
		{
			name:  "no config defined",
			repos: nil,
			slug:  "my/repo",
			want:  true,
		},
		{
			name:  "empty repo list",
			repos: []string{},
			slug:  "my/repo",
			want:  true,
		},
		{
			name:  "allowlist only",
			repos: []string{"my/repo", "other/repo"},
			slug:  "my/repo",
			want:  true,
		},
		{
			name:  "denylist only",
			repos: []string{"!some/repo", "!other/repo"},
			slug:  "my/repo",
			want:  true,
		},
		{
			name:  "explicitly allowed",
			repos: []string{"my/repo"},
			slug:  "my/repo",
			want:  true,
		},
		{
			name:  "explicitly denied",
			repos: []string{"!my/repo"},
			slug:  "my/repo",
			want:  false,
		},
		{
			name:  "neither accepted nor denied",
			repos: []string{"some/repo", "!other/repo"},
			slug:  "my/repo",
			want:  false,
		},
		{
			name:  "accepted glob",
			repos: []string{"my/*"},
			slug:  "my/repo",
			want:  true,
		},
		{
			name:  "denied glob",
			repos: []string{"!my/*"},
			slug:  "my/repo",
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zerolog.New(zerolog.NewTestWriter(t))
			if got := RepoMatch(&log, tt.repos, tt.slug); got != tt.want {
				t.Errorf("RepoMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldNotifyFor(t *testing.T) {
	type args struct {
	}
	tests := []struct {
		name  string
		cfg   config.BaseNotifier
		build *core.Build
		repo  *core.Repository
		want  bool
	}{
		{
			name:  "default config",
			cfg:   config.BaseNotifier{},
			build: &core.Build{Status: core.StatusPassing},
			repo:  &core.Repository{Slug: "my/repo"},
			want:  true,
		},
		{
			name:  "only passing builds",
			cfg:   config.BaseNotifier{Status: []string{core.StatusPassing}},
			build: &core.Build{Status: core.StatusPassing},
			repo:  &core.Repository{Slug: "my/repo"},
			want:  true,
		},
		{
			name:  "only failing builds",
			cfg:   config.BaseNotifier{Status: []string{core.StatusFailing, core.StatusKilled}},
			build: &core.Build{Status: core.StatusFailing},
			repo:  &core.Repository{Slug: "my/repo"},
			want:  true,
		},
		{
			name:  "skip to due failure",
			cfg:   config.BaseNotifier{Status: []string{core.StatusPassing}},
			build: &core.Build{Status: core.StatusFailing},
			repo:  &core.Repository{Slug: "my/repo"},
			want:  false,
		},
		{
			name: "only passing builds for my/repo",
			cfg: config.BaseNotifier{
				Status: []string{core.StatusPassing},
				Repos:  []string{"my/repo"},
			},
			build: &core.Build{Status: core.StatusPassing},
			repo:  &core.Repository{Slug: "my/repo"},
			want:  true,
		},
		// You can picture the rest, as RepoMatch() is tested separately above
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zerolog.New(zerolog.NewTestWriter(t))
			if got := ShouldNotifyFor(&log, tt.cfg, tt.build, tt.repo); got != tt.want {
				t.Errorf("ShouldNotifyFor() = %v, want %v", got, tt.want)
			}
		})
	}
}
