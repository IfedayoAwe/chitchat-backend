package main

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func (app *application) routes() http.Handler {
	router := httprouter.New()
	router.NotFound = http.HandlerFunc(app.notFoundResponse)
	router.MethodNotAllowed = http.HandlerFunc(app.methodNotAllowedResponse)
	router.HandlerFunc(http.MethodGet, "/v1/healthcheck", app.healthcheckHandler)
	router.HandlerFunc(http.MethodPost, "/v1/movies", app.createPostHandler)
	router.HandlerFunc(http.MethodGet, "/v1/movies/:id", app.showPostHandler)
	router.HandlerFunc(http.MethodPost, "/v1/users", app.registerUserHandler)
	// router.HandlerFunc(http.MethodPut, "/v1/users/activated", app.validateOTP(ScopeActivation, app.activateUserHandler))
	return app.metrics(app.recoverPanic(app.enableCORS(app.rateLimit(router))))
}
