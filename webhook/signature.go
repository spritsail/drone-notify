package webhook

import (
	"net/http"

	"github.com/go-fed/httpsig"
	"github.com/rs/zerolog"
)

type SignatureVerifier struct {
	log     *zerolog.Logger
	secret  []byte
	handler http.Handler
}

func (s SignatureVerifier) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	verifier, err := httpsig.NewVerifier(req)
	if err == nil {
		err = verifier.Verify(s.secret, httpsig.HMAC_SHA256)
	}
	if err != nil {
		s.log.Error().Err(err).Msg("Error verifying signature")
		respond(resp, http.StatusUnauthorized, "invalid signature\n")
		return
	}

	s.handler.ServeHTTP(resp, req)
}
