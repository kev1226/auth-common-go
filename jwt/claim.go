// jwt/claims.go
package jwt

import "github.com/golang-jwt/jwt/v5"

type CustomClaims struct {
	ID    int      `json:"id"`
	Email string   `json:"email"`
	Roles []string `json:"roles"`
	jwt.RegisteredClaims
}
