package main

import (
	"fmt"
	"net/http"
)

func (app *application) createPostHandler(w http.ResponseWriter, r *http.Request) {
	app.writeJSON(w, http.StatusCreated, envelope{"movies": "Create a new post"}, nil)
}

func (app *application) showPostHandler(w http.ResponseWriter, r *http.Request) {
	id, err := app.readIDParam(r)
	if err != nil {
		app.notFoundResponse(w, r)
		return
	}
	app.writeJSON(w, http.StatusOK, envelope{"movies": fmt.Sprintf("show the details of post %d", id)}, nil)
}
