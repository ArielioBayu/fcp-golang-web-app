package middleware

import (
	"a21hc3NpZ25tZW50/model"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

func Auth() gin.HandlerFunc {
	return gin.HandlerFunc(func(ctx *gin.Context) {
		// Mengambil cookie
		sessionToken, err := ctx.Cookie("session_token")
		if err != nil {
			// Jika cookie sessionToken tidak ada
			if ctx.GetHeader("Content-Type") == "application/json" {
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			} else {
				ctx.Redirect(http.StatusSeeOther, "/client/login")
				return
			}
		}

		// Parsing JWT
		tokenClaims := &model.Claims{}
		token, err := jwt.ParseWithClaims(sessionToken, tokenClaims, func(token *jwt.Token) (any, error) {
			return model.JwtKey, nil
		})

		if err != nil {
			// Jika parsing token gagal
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Bad Request"})
			return
		}

		if !token.Valid {
			// Jika token tidak valid
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		ctx.Status(http.StatusOK)
		ctx.Set("email", tokenClaims.Email)
		ctx.Next()
	})
}
