package matrix

import (
	"context"
	"fmt"
)

func (b *matrixBot) generateRecoveryKey(ctx context.Context) error {
	log := b.Client.Log
	machine := b.crypto.Machine()

	recoveryKey, keys, err := machine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
	if err != nil {
		return fmt.Errorf("failed to generate and upload cross-signing keys: %w", err)
	}
	log.Warn().
		Str("recovery-key", recoveryKey).
		Msg("Generated recovery key. Write this down, it is important")
	machine.CrossSigningKeys = keys

	// Whilst we're here, we may as well sign this device as we have the signing
	// keys loaded already
	err = machine.SignOwnDevice(ctx, machine.OwnIdentity())
	if err != nil {
		return fmt.Errorf("failed to sign own device: %w", err)
	}
	err = machine.SignOwnMasterKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to sign own master key: %w", err)
	}
	return nil
}

func (b *matrixBot) trustDevice(ctx context.Context, recoveryKey string) error {
	log := b.Client.Log
	machine := b.crypto.Machine()

	pubkeys := machine.GetOwnCrossSigningPublicKeys(ctx)
	if pubkeys == nil {
		log.Info().Msg("No cross-signing public keys found; Generating a new recovery key")
		// User has no recovery key so generate one and sign the device that way
		err := b.generateRecoveryKey(ctx)
		if err != nil {
			return fmt.Errorf("failed to generate recovery key: %w", err)
		}
		return nil
	}

	isVerified, err := machine.CryptoStore.IsKeySignedBy(
		ctx, machine.Client.UserID, machine.GetAccount().SigningKey(),
		machine.Client.UserID, pubkeys.SelfSigningKey,
	)
	if err != nil {
		err = fmt.Errorf("failed to check if current device is signed by own self-signing key: %w", err)
	} else if isVerified {
		log.Debug().Msg("Device is already trusted")
		return nil
	}

	if recoveryKey == "" {
		log.Warn().Msg("Skipping signing device as trusted as no recovery key supplied")
		return nil
	}

	// Continue with signing using the supplied recovery key
	device := machine.OwnIdentity()
	log.Info().
		Stringer("device", device.DeviceID).
		Msg("Device is untrusted. Signing using the recovery key")
	keyid, keydata, err := machine.SSSS.GetDefaultKeyData(ctx)
	if err != nil {
		return err
	}
	verified, err := keydata.VerifyRecoveryKey(keyid, recoveryKey)
	if err != nil {
		return err
	}
	err = machine.FetchCrossSigningKeysFromSSSS(ctx, verified)
	if err != nil {
		return err
	}
	err = machine.SignOwnDevice(ctx, device)
	if err != nil {
		return err
	}
	log.Info().Stringer("device", device.DeviceID).Msg("Device trusted")
	return nil
}
