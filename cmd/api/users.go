package main

import (
	"errors"
	"net/http"

	"github.com/IfedayoAwe/chitchat-backend/internal/data"
	"github.com/IfedayoAwe/chitchat-backend/internal/validator"
)

func (app *application) registerUserHandler(w http.ResponseWriter, r *http.Request) {
	var input struct {
		FullName        string `json:"full_name"`
		Username        string `json:"username"`
		Email           string `json:"email"`
		PhoneNo         string `json:"phone_no"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirm_password"`
	}

	err := app.readJSON(w, r, &input)
	if err != nil {
		app.badRequestResponse(w, r, err)
		return
	}

	user := &data.User{
		FullName:        input.FullName,
		Username:        input.Username,
		Email:           input.Email,
		PhoneNo:         input.PhoneNo,
		Activated:       false,
		Admin:           false,
		PhoneNoVerified: false,
	}

	err = user.Password.Set(input.Password, input.ConfirmPassword)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	v := validator.New()

	if data.ValidateUser(v, user); !v.Valid() {
		app.failedValidationResponse(w, r, v.Errors)
		return
	}

	err = app.models.Users.Insert(user)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrDuplicateEmail):
			v.AddError("email", "a user with this email address already exists")
			app.failedValidationResponse(w, r, v.Errors)
		case errors.Is(err, data.ErrDuplicatePhoneNo):
			v.AddError("phone_no", "a user with this phone number already exists")
			app.failedValidationResponse(w, r, v.Errors)
		default:
			app.serverErrorResponse(w, r, err)
		}
		return
	}

	// app.background(func() {
	// 	err := app.models.UsersProfile.InsertProfilePic(user.ID)
	// 	if err != nil {
	// 		switch {
	// 		case errors.Is(err, data.ErrDuplicateProfile):
	// 			app.duplicateProfiledResponse(w, r)
	// 		default:
	// 			app.serverErrorResponse(w, r, err)
	// 		}
	// 		return
	// 	}
	// })

	otp, err := app.generateOTP(user.ID, ScopeActivation)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	data := map[string]interface{}{
		"activationToken": otp,
		"fullName":        user.FullName,
		"username":        user.Username,
	}

	app.background(func() {
		err := app.mailer.Send(user.Email, "user_welcome.html", data)
		if err != nil {
			app.logger.PrintError(err, nil)
		}
	})

	err = app.writeJSON(w, http.StatusAccepted, envelope{"user": user}, nil)
	if err != nil {
		app.serverErrorResponse(w, r, err)
	}
}

// func (app *application) activateUserHandler(w http.ResponseWriter, r *http.Request) {
// 	w.Write([]byte("User Activated"))
// }
