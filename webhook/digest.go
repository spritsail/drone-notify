package webhook

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
)

type DigestVerifier struct {
	log     *zerolog.Logger
	handler http.Handler
}

func (d DigestVerifier) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	// Wrap the body in a TeeReader so we can consume it now, but also allow
	// later handlers to also consume it
	body, err := io.ReadAll(req.Body)
	if err != nil {
		d.log.Error().Err(err).Msg("Failed to read body")
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	// https://github.com/drone/drone/blob/4f85961434061d8a36be9d7528e5a0171a07d3ba/plugin/webhook/webhook.go#L134C1-L138C2
	h := sha256.Sum256(body)
	expected := base64.StdEncoding.EncodeToString(h[:])

	digest := strings.SplitN(req.Header.Get("digest"), "=", 2)
	if len(digest) != 2 || digest[0] != "SHA-256" || digest[1] != expected {
		digestLog := d.log.Error().Str("expected", expected)
		if len(digest) < 2 {
			digestLog.Str("digest", digest[0])
		} else {
			digestLog.Str("algorithm", digest[0]).Str("digest", digest[1])
		}
		digestLog.Msg("Invalid Digest header")
		respond(resp, http.StatusBadRequest, "invalid or missing digest\n")
		return
	}

	req.Body = io.NopCloser(bytes.NewReader(body))
	d.handler.ServeHTTP(resp, req)
}
