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

		c.Set("claims", claims)
		c.Set("userID", claims.ID)
		c.Set("email", claims.Email)

		c.Next()
	}
}

func hasRole(userRoles, requiredRoles []string) bool {
	for _, required := range requiredRoles {
		for _, user := range userRoles {
			// Si el rol requerido es "admin", solo "admin" puede pasar
			if strings.EqualFold(required, "admin") {
				if strings.EqualFold(user, "admin") {
					return true
				}
			} else {
				// Para cualquier otro rol, también se permite "admin" por jerarquía
				if strings.EqualFold(user, required) || strings.EqualFold(user, "admin") {
					return true
				}
			}
		}
	}
	return false
}
