package matrix

import (
	"context"
	"fmt"
	"slices"

	"github.com/drone/drone/core"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"

	"github.com/spritsail/drone-notify/config"
	"github.com/spritsail/drone-notify/notify"
)

type matrixNotifier struct {
	config NotifierConfig
	log    *zerolog.Logger
	bot    *matrixBot
}

func Notifier(ctx context.Context, anycfg config.Notifier, anybot notify.Bot) (notify.Notifier, error) {
	log := zerolog.Ctx(ctx)
	cfg := anycfg.(*NotifierConfig)
	bot, ok := anybot.(*matrixBot)
	if !ok {
		return nil, fmt.Errorf("bot must be a Matrix bot")
	}

	notifier := matrixNotifier{
		config: *cfg,
		log:    log,
		bot:    bot,
	}

	// Check if we're in the notification room and attempt to join if not
	resp, err := bot.Client.JoinedRooms(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list joined rooms: %w", err)
	}
	if !slices.Contains(resp.JoinedRooms, notifier.config.Room) {
		roomlog := log.With().Stringer("room", notifier.config.Room).Logger()
		// Attempt to join the room as we're not in it
		_, err = bot.Client.JoinRoomByID(ctx, notifier.config.Room)
		if err == nil {
			roomlog.Info().Msg("Joined notification room")
		} else {
			// It could fail if the join rule doesn't permit the bot joining
			// This is not fatal as the bot will autojoin if invited to the room later
			roomlog.Warn().Err(err).Msg("Failed to join notification room")
		}
	}

	// Attempt to self-manage room membership like accepting room invites or rejoining when kicked/unbanned
	syncer := bot.Client.Syncer.(*mautrix.DefaultSyncer)
	syncer.OnEventType(event.StateMember, notifier.onMemberEvent)

	return &notifier, nil
}

func (n *matrixNotifier) Config() config.Notifier {
	return n.config
}

func (n *matrixNotifier) Send(ctx context.Context, message string) error {
	content := format.RenderMarkdown(message, true, true)
	_, err := n.bot.Client.SendMessageEvent(ctx, n.config.Room, event.EventMessage, content)
	return err
}

func (n *matrixNotifier) ShouldNotifyFor(build *core.Build, repo *core.Repository) bool {
	return notify.ShouldNotifyFor(n.log, n.config.BaseNotifier, build, repo)
}

func (n *matrixNotifier) onMemberEvent(ctx context.Context, evt *event.Event) {
	client := n.bot.Client
	if evt.GetStateKey() != client.UserID.String() {
		return
	}

	var err error
	membership := evt.Content.AsMember().Membership
	switch membership {
	default: // case event.MembershipJoin, event.MembershipBan, event.MembershipKnock:
		// Not much we can do with these membership states
		// Maybe we could have a config option that leaves unrecognised rooms(?)
		previous := evt.Unsigned.PrevContent.AsMember().Membership
		if previous == "" {
			previous = "unknown"
		}
		n.log.Info().Msgf("Room membership changed from %s to %s in room %s", previous, membership, evt.RoomID)
		break

	case event.MembershipInvite, event.MembershipLeave:
		// Attempt to accept the invite and/or join the room if we should be in there
		// This includes attempting to rejoin the notification room if we've just been kicked.
		if evt.RoomID == n.config.Room {
			n.log.Info().Msgf("Joining room %s after %s from %s", evt.RoomID, membership, evt.Sender)
			_, err = client.JoinRoomByID(ctx, evt.RoomID)
		} else if membership == event.MembershipInvite {
			n.log.Info().Msgf("Declining invite to join room %s from %s", evt.RoomID, evt.Sender)
			_, err = client.LeaveRoom(ctx, evt.RoomID)
		}
	}

	if err != nil {
		n.log.Info().
			Err(err).
			Stringer("room", evt.RoomID).
			Stringer("sender", evt.Sender).
			Msgf("Error joining room")
	}
}
