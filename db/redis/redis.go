package db

import (
	"context"
	"github.com/ottolauncher/gtodo/config"
	"github.com/redis/go-redis/v9"
	"log"
	"time"
)

func InitRedisDB(ctx context.Context, cfg *config.Config) *redis.Client {
	ctx, cancel := context.WithTimeout(ctx, 350*time.Millisecond)
	defer cancel()
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisDBUri,
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	err := client.Ping(ctx).Err()
	if err != nil {
		log.Fatalln(err)
	}
	return client
}
