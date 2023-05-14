package data

import (
	"database/sql"
	"errors"
)

var (
	ErrRecordNotFound     = errors.New("record not found")
	ErrEditConflict       = errors.New("edit conflict")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type Models struct {
	Users interface {
		Insert(user *User) error
		// GetByEmail(email string) (*User, error)
		// GetByID(ID int64) (*User, error)
		// Update(user *User) error
		// GetForToken(tokenScope, tokenPlaintext string) (*User, error)
		// ChangePassword(id int64, newPassword string) error
		// Delete(id int64) error
	}
}

func NewModels(db *sql.DB) Models {
	return Models{
		Users: UserModel{DB: db},
	}
}
