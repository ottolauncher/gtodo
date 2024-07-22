package db

import (
	"context"
	"fmt"
	"github.com/ottolauncher/gtodo/config"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"log"
)

func Connect(ctx context.Context, cfg *config.Config) *mongo.Client {
	uri := fmt.Sprintf("mongodb://%s:%s/%s?timeoutMS=15000", cfg.MongodbHostName, cfg.MongodbPort, cfg.MongodbDatabase)
	serverApi := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(uri).SetServerAPIOptions(serverApi)

	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		log.Fatalln(err)
	}
	if err = client.Ping(ctx, readpref.Primary()); err != nil {
		log.Fatalln(err)
	}
	return client
}
