package main

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/credentials"
	"gtodo/config"
	db "gtodo/db/mongo"
	rdb "gtodo/db/redis"
	"gtodo/interceptor"
	"gtodo/models"
	"gtodo/pb"
	"gtodo/server"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/mongo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"
)

// run is the main entry point for the gRPC server.
// It sets up the server, initializes the necessary dependencies, and starts the server
// to listen for incoming requests.
func runGRPC(logger *log.Logger) error {
	log.Println("main: initializing gRPC server")
	defer logger.Println("main: Completed")
	const envFilePath = ".env"
	cfg, err := config.Read(envFilePath)
	if err != nil {
		return errors.Wrap(err, "reading config")
	}
	var (
		client      *mongo.Client
		redisClient *redis.Client
		once        sync.Once
	)
	once.Do(func() {
		client = db.Connect(context.Background(), cfg)
		redisClient = rdb.InitRedisDB(context.Background(), cfg)
	})

	port := cfg.GrpcServerPort
	creds, err := credentials.NewServerTLSFromFile(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		log.Fatalf("Failed to generate credentials %v", err)
	}
	roleSeq := strings.Split(cfg.Roles, " ")
	todoServicePath := "TodoService."
	log.Printf("listening on port :%s", port)
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return errors.Wrap(err, "tcp listening")
	}
	roles := map[string][]string{
		todoServicePath + "CreateTodo": {roleSeq[0]},
		todoServicePath + "DeleteTodo": {roleSeq[0]},
		todoServicePath + "ListTodo":   {roleSeq[0], roleSeq[1]},
		todoServicePath + "SearchTodo": {roleSeq[0], roleSeq[1]},
		todoServicePath + "BulkTodo":   {roleSeq[0]},
		todoServicePath + "GetTodo":    {roleSeq[0], roleSeq[1]},
		todoServicePath + "UpdateTodo": {roleSeq[0]},
	}

	tm := models.NewTodoManger(client)
	um := models.NewUserManger(client, redisClient)
	guard := interceptor.NewInterceptor(um, roles)
	srv := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(guard.Unary()),
		grpc.StreamInterceptor(guard.Stream()),
	)
	ctl := server.NewTodoServer(tm)
	uctl := server.NewUserServer(um)

	pb.RegisterTodoServiceServer(srv, ctl)
	pb.RegisterUserServiceServer(srv, uctl)

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	// Make a channel to listen for errors coming from the listener. Use a
	// buffered channel so the goroutine can exit if we don't collect this error.
	serverErrors := make(chan error, 1)

	// Start the service listening for requests.
	go func() {
		logger.Printf("main: gRPC server listening on %s", port)
		serverErrors <- ctl.GrpcSrv.Serve(lis)
	}()
	// Shutdown
	select {
	case err := <-serverErrors:
		return fmt.Errorf("server error: %w", err)
	case sig := <-shutdown:
		log.Println("main: received signal for shutdown: ", sig)
		ctl.GrpcSrv.Stop()
	}
	return nil
}

func main() {
	logFile, err := os.OpenFile("./logs/grpc.log.txt", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		log.Fatalln("file not found: ", err)
	}
	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)

	grpclog.SetLoggerV2(grpclog.NewLoggerV2(mw, mw, mw))

	logger := log.New(os.Stdout, "GRPC SERVER: ", log.LstdFlags|log.Lmicroseconds|log.Lshortfile)
	logger.SetOutput(mw)

	if err := runGRPC(logger); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
