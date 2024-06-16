package api

import (
	"github.com/gorilla/mux"
	"go.lumeweb.com/portal/middleware"
	"net/http"
)

const (
	authCookieName = "s5-auth-token"
	authQueryParam = "auth_token"
)

func findToken(r *http.Request) string {
	return middleware.FindAuthToken(r, authCookieName, authQueryParam)
}

func authMiddleware(options middleware.AuthMiddlewareOptions) mux.MiddlewareFunc {
	options.FindToken = findToken
	return middleware.AuthMiddleware(options)
}
