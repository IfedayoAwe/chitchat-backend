package data

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/IfedayoAwe/chitchat-backend/internal/validator"
	"github.com/ttacon/libphonenumber"
	"golang.org/x/crypto/bcrypt"
)

type Password struct {
	Plaintext *string
	Confirm   string
	Hash      []byte
}

type User struct {
	ID              int64     `json:"id"`
	CreatedAt       time.Time `json:"created_at"`
	FullName        string    `json:"full_name"`
	Username        string    `json:"username"`
	Email           string    `json:"email"`
	PhoneNo         string    `json:"phone_no"`
	Password        Password  `json:"-"`
	Activated       bool      `json:"activated"`
	Admin           bool      `json:"admin"`
	PhoneNoVerified bool      `json:"phone_no_verified"`
	Version         int       `json:"-"`
}

var AnonymousUser = &User{}

func (u *User) IsAnonymous() bool {
	return u == AnonymousUser
}

func (p *Password) Set(plaintextPassword, confirmPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintextPassword), 12)
	if err != nil {
		return err
	}
	p.Plaintext = &plaintextPassword
	p.Confirm = confirmPassword
	p.Hash = hash
	return nil
}

func (p *Password) Matches(plaintextPassword string) (bool, error) {
	err := bcrypt.CompareHashAndPassword(p.Hash, []byte(plaintextPassword))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, nil
		default:
			return false, err
		}
	}
	return true, nil
}

func ValidateEmail(v *validator.Validator, email string) {
	v.Check(email != "", "email", "must be provided")
	v.Check(validator.Matches(email, validator.EmailRX), "email", "must be a valid email address")
}

func ValidatePhoneNo(v *validator.Validator, phoneNo string) {
	v.Check(phoneNo != "" && strings.TrimSpace(phoneNo) != "", "phone_no", "must be provided")
	number, err := libphonenumber.Parse(phoneNo, "NG")
	if err != nil {
		v.AddError("phone_no", err.Error())
	}
	if !libphonenumber.IsValidNumber(number) {
		v.AddError("phone_no", "invalid phone number")
	}
}

func ValidatePasswordPlaintext(v *validator.Validator, password string) {
	v.Check(password != "" && strings.TrimSpace(password) != "", "password", "must be provided")
	v.Check(len(password) >= 10, "password", "must be at least 10 bytes long")
	v.Check(len(password) <= 72, "password", "must not be more than 72 bytes long")
}

func ValidateChangePassword(v *validator.Validator, currentpassword, newpassword, confirmpassword string) {
	ValidatePasswordPlaintext(v, newpassword)
	v.Check(currentpassword != "", "currentpassword", "current Password field cannot be empty")
	v.Check(confirmpassword != "", "confirmpassword", "confirm password field cannot be empty")
	v.Check(newpassword == confirmpassword, "password mismatch", "new password and password confirmation do not match")
}

func ValidateUser(v *validator.Validator, user *User) {
	v.Check(user.FullName != "" && strings.TrimSpace(user.FullName) != "", "full_name", "must be provided")
	v.Check(len(user.FullName) <= 50, "full_name", "must not be more than 50 bytes long")
	v.Check(user.Username != "" && strings.TrimSpace(user.Username) != "", "username", "must be provided")
	v.Check(len(user.Username) <= 50, "username", "must not be more than 50 bytes long")
	ValidateEmail(v, user.Email)
	ValidatePhoneNo(v, user.PhoneNo)
	if user.Password.Plaintext != nil {
		ValidatePasswordPlaintext(v, *user.Password.Plaintext)
		v.Check(user.Password.Confirm != "" && strings.TrimSpace(user.Password.Confirm) != "", "confirm_password", "must be provided")
		v.Check(user.Password.Confirm == *user.Password.Plaintext, "password_mismatch", "password and confirm_password do not match")
	}
	if user.Password.Hash == nil {
		panic("missing password hash for user")
	}
}

var (
	ErrDuplicateEmail   = errors.New("duplicate email")
	ErrDuplicatePhoneNo = errors.New("duplicate phone number")
)

type UserModel struct {
	DB *sql.DB
}

func (m UserModel) Insert(user *User) error {
	query := `
	INSERT INTO users (full_name, username, email, phone_no, password_hash, activated, admin, phone_no_verified)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	RETURNING id, created_at, version`
	args := []interface{}{user.FullName,
		user.Username,
		user.Email,
		user.PhoneNo,
		user.Password.Hash,
		user.Activated,
		user.Admin,
		user.PhoneNoVerified}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := m.DB.QueryRowContext(ctx, query, args...).Scan(&user.ID, &user.CreatedAt, &user.Version)
	if err != nil {
		switch {
		case err.Error() == `pq: duplicate key value violates unique constraint "users_email_key"`:
			return ErrDuplicateEmail
		case err.Error() == `pq: duplicate key value violates unique constraint "users_phone_no_key"`:
			return ErrDuplicatePhoneNo
		default:
			return err
		}
	}
	return nil
}

// func (m UserModel) GetByEmail(email string) (*User, error) {
// 	query := `
// 	SELECT id, created_at, full_name, username, email, phone_no, password_hash, activated, admin, phone_no_verified, version
// 	FROM users
// 	WHERE email = $1`
// 	var user User
// 	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
// 	defer cancel()
// 	err := m.DB.QueryRowContext(ctx, query, email).Scan(
// 		&user.ID,
// 		&user.CreatedAt,
// 		&user.FullName,
// 		&user.Username,
// 		&user.Email,
// 		&user.PhoneNo,
// 		&user.Password.Hash,
// 		&user.Activated,
// 		&user.Admin,
// 		&user.PhoneNoVerified,
// 		&user.Version,
// 	)
// 	if err != nil {
// 		switch {
// 		case errors.Is(err, sql.ErrNoRows):
// 			return nil, ErrRecordNotFound
// 		default:
// 			return nil, err
// 		}
// 	}
// 	return &user, nil
// }

// func (m UserModel) GetByID(ID int64) (*User, error) {
// 	query := `
// 	SELECT id, created_at, full_name, username, email, phone_no, password_hash, activated, admin, phone_no_verified, version
// 	FROM users
// 	WHERE id = $1`
// 	var user User
// 	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
// 	defer cancel()
// 	err := m.DB.QueryRowContext(ctx, query, ID).Scan(
// 		&user.ID,
// 		&user.CreatedAt,
// 		&user.FullName,
// 		&user.Username,
// 		&user.Email,
// 		&user.PhoneNo,
// 		&user.Password.Hash,
// 		&user.Activated,
// 		&user.Admin,
// 		&user.PhoneNoVerified,
// 		&user.Version,
// 	)
// 	if err != nil {
// 		switch {
// 		case errors.Is(err, sql.ErrNoRows):
// 			return nil, ErrRecordNotFound
// 		default:
// 			return nil, err
// 		}
// 	}
// 	return &user, nil
// }

// func (m UserModel) Update(user *User) error {
// 	query := `
// 	UPDATE users
// 	SET full_name = $1, username = $2, email = $3, phone_no = $4, password_hash = $5, activated = $6, admin = $7, phone_no_verified = $8, version = version + 1
// 	WHERE id = $9 AND version = $10
// 	RETURNING version`
// 	args := []interface{}{
// 		user.FullName,
// 		user.Username,
// 		user.Email,
// 		user.PhoneNo,
// 		user.Password.Hash,
// 		user.Activated,
// 		user.Admin,
// 		user.PhoneNoVerified,
// 		user.ID,
// 		user.Version,
// 	}
// 	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
// 	defer cancel()
// 	err := m.DB.QueryRowContext(ctx, query, args...).Scan(&user.Version)
// 	if err != nil {
// 		switch {
// 		case err.Error() == `pq: duplicate key value violates unique constraint "users_email_key"`:
// 			return ErrDuplicateEmail
// 		case err.Error() == `pq: duplicate key value violates unique constraint "users_phone_no_key"`:
// 			return ErrDuplicatePhoneNo
// 		case errors.Is(err, sql.ErrNoRows):
// 			return ErrEditConflict
// 		default:
// 			return err
// 		}
// 	}
// 	return nil
// }

// func (m UserModel) GetForToken(tokenScope, tokenPlaintext string) (*User, error) {
// 	var user User
// 	return &user, nil
// }

// func (m UserModel) ChangePassword(id int64, newPassword string) error {
// 	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
// 	if err != nil {
// 		return err
// 	}
// 	query := "UPDATE users SET password_hash = $1 WHERE id = $2"
// 	_, err = m.DB.Exec(query, newHashedPassword, id)
// 	return err

// }

// func (m UserModel) Delete(id int64) error {
// 	if id < 1 {
// 		return ErrRecordNotFound
// 	}

// 	query := `
// 	DELETE FROM users
// 	WHERE id = $1`

// 	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
// 	defer cancel()

// 	result, err := m.DB.ExecContext(ctx, query, id)
// 	if err != nil {
// 		return err
// 	}

// 	rowsAffected, err := result.RowsAffected()
// 	if err != nil {
// 		return err
// 	}

// 	if rowsAffected == 0 {
// 		return ErrRecordNotFound
// 	}
// 	return nil
// }
