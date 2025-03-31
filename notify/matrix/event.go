package matrix

import (
	"context"

	"maunium.net/go/mautrix/event"
)

func (b *matrixBot) sendReceipts(ctx context.Context, evt *event.Event) {
	if evt.Type.Class != event.MessageEventType && evt.Type.Class != event.StateEventType {
		return
	}

	err := b.Client.SendReceipt(ctx, evt.RoomID, evt.ID, event.ReceiptTypeRead, nil)
	if err != nil {
		b.Client.Log.Error().
			Err(err).
			Stringer("event", evt.ID).
			Stringer("room", evt.RoomID).
			Msg("failed to send receipt")
	}
}

func (b *matrixBot) onMessage(ctx context.Context, evt *event.Event) {
	log := b.Client.Log
	if evt.Sender != b.Client.UserID {
		log.Info().Msgf("Received message in %s from %s: %s", evt.RoomID, evt.Sender, evt.Content.AsMessage().Body)

		// Echo it back
		_, err := b.Client.SendMessageEvent(ctx, evt.RoomID, evt.Type, evt.Content.AsMessage())
		if err != nil {
			log.Info().Err(err).Stringer("sender", evt.Sender).Msgf("Failed to echo message")
		}
	}
}
