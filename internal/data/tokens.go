package data

// const (
// 	ScopeAuthentication = "authentication"
// )

// func GenerateToken(userID int64, expires time.Time, scope, secret string) (string, error) {
// 	var claims struct {
// 		jwt.Claims
// 		Scope string `json:"scope"`
// 	}
// 	claims.Subject = strconv.FormatInt(int64(userID), 10)
// 	claims.Issued = jwt.NewNumericTime(time.Now())
// 	claims.NotBefore = jwt.NewNumericTime(time.Now())
// 	claims.Expires = jwt.NewNumericTime(expires)
// 	claims.Issuer = "github.com/IfedayoAwe/chitchat-backend"
// 	claims.Audiences = []string{"github.com/IfedayoAwe/chitchat-backend"}
// 	claims.Scope = scope
// 	jwtBytes, err := claims.HMACSign(jwt.HS256, []byte(secret))
// 	if err != nil {
// 		return "", err
// 	}
// 	return string(jwtBytes), nil
// }
