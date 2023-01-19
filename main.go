package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	errMalformedHeader   = errors.New("malformed authorization header")
	errInvalidSigningKey = errors.New("invalid signing key")
	errInvalidToken      = errors.New("unable to validate JWT")

	envJWKSURI = "JWKS_URI"
	envAddr    = "ADDR"
)

type echoHandler struct {
	jwks *jose.JSONWebKeySet
}

func (h *echoHandler) getJWKS(kid string) *jose.JSONWebKey {
	keys := h.jwks.Key(kid)

	if len(keys) == 0 {
		return nil
	}

	return &keys[0]
}

func (h *echoHandler) verifyToken(header string) (map[string]any, error) {
	expectedAuthHeaderParts := 2

	authHeaderParts := strings.SplitN(header, " ", expectedAuthHeaderParts)

	if !(len(authHeaderParts) == expectedAuthHeaderParts && strings.ToLower(authHeaderParts[0]) == "bearer") {
		return nil, errMalformedHeader
	}

	rawToken := authHeaderParts[1]

	tok, err := jwt.ParseSigned(rawToken)
	if err != nil {
		return nil, errMalformedHeader
	}

	if tok.Headers[0].KeyID == "" {
		return nil, errMalformedHeader
	}

	key := h.getJWKS(tok.Headers[0].KeyID)
	if key == nil {
		return nil, errInvalidSigningKey
	}

	out := make(map[string]any)

	if err := tok.Claims(key, &out); err != nil {
		return nil, errInvalidToken
	}

	return out, nil
}

func (h *echoHandler) writeError(rw http.ResponseWriter, statusCode int, err error) {
	var out struct {
		Error error `json:"error"`
	}

	out.Error = err

	bytes, err := json.Marshal(out)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(`{"error": "error writing error"}`))
		return
	}

	rw.WriteHeader(statusCode)
	rw.Write(bytes)
}

func (h *echoHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Authorization")

	claims, err := h.verifyToken(header)
	if err != nil {
		h.writeError(rw, http.StatusBadRequest, err)
		return
	}

	bytes, err := json.Marshal(claims)
	if err != nil {
		h.writeError(rw, http.StatusInternalServerError, err)
		return
	}

	rw.Write(bytes)
}

func getJWKS(uri string) (*jose.JSONWebKeySet, error) {
	log.Printf("getting JWKS from %s", uri)

	resp, err := http.Get(uri)
	if err != nil {
		return nil, err
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var out jose.JSONWebKeySet

	err = json.Unmarshal(bytes, &out)
	if err != nil {
		return nil, err
	}

	return &out, nil
}

func main() {
	jwksURI := os.Getenv(envJWKSURI)

	if jwksURI == "" {
		log.Fatalf("JWKS URI not defined (did you remember to set %s?)", envJWKSURI)
	}

	addr := os.Getenv(envAddr)
	if addr == "" {
		addr = ":8000"
	}

	jwks, err := getJWKS(jwksURI)
	if err != nil {
		log.Fatalf("error getting JWKS: %s", err)
	}

	handler := echoHandler{
		jwks: jwks,
	}

	log.Printf("starting jwt-inspector on %s", addr)

	http.Handle("/", &handler)
	http.ListenAndServe(addr, nil)

	log.Fatal("shutting down jwt-inspector")
}
