package models

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"log"
	"os"
	"time"
)

type AccessDetails struct {
	AccessUuid *string
	UserID     string
}

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	Role         string
	AtExpires    time.Time
	RtExpires    time.Time
}

func DeleteAuth(client *redis.Client, givenUUID string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.TODO(), 2*time.Second)
	defer cancel()

	_, exErr := client.Exists(ctx, givenUUID).Result()
	if exErr == nil {
		deleted, err := client.Del(ctx, givenUUID).Result()
		if err != nil {
			return 0, err
		}
		return deleted, nil
	}
	return 0, exErr
}
func DeleteTokens(client *redis.Client, authD *AccessDetails) error {
	ctx, cancel := context.WithTimeout(context.TODO(), 2*time.Second)
	defer cancel()
	//get the refresh uuid
	refreshUuid := fmt.Sprintf("%s++%s", *authD.AccessUuid, authD.UserID)
	_, exErr := client.Exists(ctx, *authD.AccessUuid, refreshUuid).Result()

	if exErr == nil {
		//delete access token
		deletedAt, err := client.Del(ctx, *authD.AccessUuid).Result()
		if err != nil {
			log.Println("DeletedAt: ", err.Error())
			return err
		}
		//delete refresh token
		deletedRt, err := client.Del(ctx, refreshUuid).Result()
		if err != nil {
			log.Println("DeletedRt: ", err.Error())
			return err
		}
		//When the record is deleted, the return value is 1
		if deletedAt != 1 || deletedRt != 1 {
			return fmt.Errorf("something went wrong")
		}
	}

	return nil
}

func CreateToken(user User) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 15)
	td.AccessUuid = uuid.NewString()

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7)
	td.RefreshUuid = td.AccessUuid + "++" + fmt.Sprintf("%v", user.ID)

	var err error
	//Creating Access Token
	atClaims := JWTCustomClaims{
		Authorized:  true,
		UserID:      user.ID.String(),
		Roles:       user.Roles,
		RefreshUUID: nil,
		AccessUUID:  &td.AccessUuid,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(td.AtExpires),
		},
	}

	at := jwt.NewWithClaims(jwt.SigningMethodES384, atClaims)
	td.AccessToken, err = at.SignedString([]byte(os.Getenv("TOKEN_SECRET")))
	if err != nil {
		return nil, err
	}

	//Creating Refresh Token
	rtClaims := JWTCustomClaims{
		Authorized:  true,
		UserID:      user.ID.String(),
		Roles:       user.Roles,
		RefreshUUID: &td.RefreshUuid,
		AccessUUID:  nil,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(td.RtExpires),
		},
	}
	rt := jwt.NewWithClaims(jwt.SigningMethodES384, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_TOKEN_SECRET")))
	if err != nil {
		return nil, err
	}
	return td, nil
}

func CreateAuth(redisClient *redis.Client, userID string, td *TokenDetails) error {
	ctx, cancel := context.WithTimeout(context.TODO(), 500*time.Millisecond)
	defer cancel()

	at := time.Unix(td.AtExpires.Unix(), 0)
	rt := time.Unix(td.RtExpires.Unix(), 0)
	now := time.Now()

	errAccess := redisClient.Set(ctx, td.AccessUuid, userID, at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	errRefresh := redisClient.Set(ctx, td.RefreshUuid, userID, rt.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}
