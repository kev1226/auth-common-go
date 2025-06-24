// jwt/auth_guard.go
package jwt

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func AuthGuard(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		claims, err := ParseToken(authHeader)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token inválido"})
			return
		}

		if !hasRole(claims.Roles, roles) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "No tienes permisos"})
			return
		}

		// Guarda el ID o correo si luego quieres usarlo en el handler
		c.Set("userID", claims.ID)
		c.Set("email", claims.Email)
		c.Next()
	}
}

func hasRole(userRoles, requiredRoles []string) bool {
	for _, required := range requiredRoles {
		for _, user := range userRoles {
			if strings.EqualFold(user, required) {
				return true
			}
		}
	}
	return false
}
