// jwt/jwt_utils.go
package jwt

import (
	"errors"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var JwtSecret = []byte("kalemat2025") // Pon una más segura en prod

func ParseToken(tokenHeader string) (*CustomClaims, error) {
	if !strings.HasPrefix(tokenHeader, "Bearer ") {
		return nil, errors.New("token inválido: falta Bearer")
	}
	tokenStr := strings.TrimPrefix(tokenHeader, "Bearer ")

	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		return JwtSecret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, errors.New("token inválido o expirado")
	}
	return claims, nil
}
