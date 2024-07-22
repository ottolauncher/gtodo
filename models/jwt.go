package models

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/ottolauncher/gtodo/config"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"log"
	"net/http"
	"strings"
)

var userCtxKey = &contextKey{"user"}

type contextKey struct {
	name string
}

func init() {
	lcfg, err := config.Read(".env")
	if err != nil {
		log.Fatalln("unable to load env files: ", err)
	}
	cfg = lcfg
}

type JWTCustomClaims struct {
	UserID      string   `json:"userID"`
	Roles       []string `json:"role"`
	RefreshUUID *string  `json:"refresh_uuid"`
	AccessUUID  *string  `json:"access_uuid"`
	Authorized  bool     `json:"authorized"`
	jwt.RegisteredClaims
}

func NewAccessToken(claims JWTCustomClaims) (string, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return accessToken.SignedString([]byte(cfg.TokenSecretKey))
}

func NewRefreshToken(claims JWTCustomClaims) (string, error) {
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return refreshToken.SignedString([]byte(cfg.RefreshSecretKey))
}

func ParseAccessToken(accessToken string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(
		accessToken, &JWTCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.TokenSecretKey), nil
		},
	)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func ParseRefreshToken(refreshToken string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(
		refreshToken, &JWTCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.RefreshSecretKey), nil
		},
	)
	if err != nil {
		return nil, err
	}
	return token, nil
}

// TokenFromCookie tries to retrieve the token string from a cookie named
// "jwt".
func TokenFromCookie(req *http.Request) string {
	cookie, err := req.Cookie("jwt")
	if err != nil {
		return ""
	}
	return cookie.Value
}

// TokenFromHeader tries to retrieve the token string from the
// "Authorization" request header: "Authorization: BEARER T".
func TokenFromHeader(req *http.Request) string {
	// Get token from authorization header.
	bearer := req.Header.Get("Authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}
	return ""
}

// TokenFromQuery tries to retrieve the token string from the "jwt" URI
// query parameter.
func TokenFromQuery(req *http.Request) string {
	// Get token from query param named "jwt".
	return req.URL.Query().Get("jwt")
}

func AuthMiddleware(client *mongo.Client) gin.HandlerFunc {
	col := client.Database(cfg.MongodbDatabase).Collection(cfg.DbUserName)
	return func(c *gin.Context) {
		token := TokenFromHeader(c.Request)

		if len(token) == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "You are not logged in"})
			return
		}
		res, err := ParseAccessToken(token)

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": err.Error()})
			return
		}
		claims, ok := res.Claims.(*JWTCustomClaims)
		if ok && res.Valid {
			filter := bson.M{"_id": claims.UserID}
			var user User
			if err := col.FindOne(context.TODO(), filter).Decode(&user); err != nil {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"status": "fail", "message": "the user belonging to this token no longer exists"})
				return
			}
			c.Set(userCtxKey.name, user)
			c.Next()
		}
	}
}

// ForContext finds the user from the context. REQUIRES Middleware to have run.
func ForContext(ctx context.Context) *User {
	raw, _ := ctx.Value(userCtxKey).(*User)
	return raw
}
