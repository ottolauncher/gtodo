package main

import (
	"context"
	"fmt"
	"google.golang.org/grpc/credentials"
	"gtodo/config"
	db "gtodo/db/mongo"
	"gtodo/docs"
	"gtodo/handlers"
	"gtodo/middleware"
	"gtodo/pb"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/quangdangfit/gocommon/errors"
	"go.mongodb.org/mongo-driver/mongo"
	"google.golang.org/grpc"
)

// @title Gingo Todo API
// @version 0.0.1
// @Description A todo management server API in Go using GRPC and Gin framework
// @contact.name Nguionza Siegfried
// @contact.url https://github.com/ottolauncher
// @contact.email nnguionza@gmail.com

// @host localhost:8082
// @BasePath /api/v1
// @licence.name Apache 2.0
// @licence.url https://www.apcahe.org/licences/LICENSE-2.0.html

func runApp() error {
	var (
		client *mongo.Client
		once   sync.Once
		conn   *grpc.ClientConn
	)

	const envFilePath = ".env"
	cfg, err := config.Read(envFilePath)
	if err != nil {
		return errors.Wrap(err, "reading config")
	}
	once.Do(func() {
		client = db.Connect(context.Background(), cfg)
		//conn, err = grpc.NewClient(cfg.GrpcServerPort, grpc.WithTransportCredentials(insecure.NewCredentials()))
		conn, err = grpc.NewClient(cfg.GrpcServerPort, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")))
		if err != nil {
			log.Fatalln("cannot bind grpc server: ", err)
		}
	})

	logFile, err := os.OpenFile("./logs/log.txt", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		log.Fatalln("file not found: ", err)
	}
	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)

	defer func() {
		if err := client.Disconnect(context.TODO()); err != nil {
			panic(err)
		}
	}()
	bookClient := pb.NewTodoServiceClient(conn)
	srv := handlers.NewResolver(bookClient)
	//gin.SetMode(gin.DebugMode)
	router := gin.Default()
	docs.SwaggerInfo.BasePath = "/api/v1"
	router.Use(gin.Recovery())
	gin.DefaultWriter = mw
	router.Use(middleware.ErrorHandlerMiddleware())
	router.Use(cors.New(cors.Config{
		AllowOrigins:              []string{"http://localhost:3000", "http://localhost:5173"},
		AllowMethods:              []string{"*"},
		AllowHeaders:              []string{"*"},
		AllowCredentials:          true,
		ExposeHeaders:             []string{"Content-Length"},
		MaxAge:                    12 * time.Hour,
		AllowWebSockets:           true,
		AllowFiles:                true,
		OptionsResponseStatusCode: 0,
	}))
	// PingExample godoc
	// @Summary ping example
	// @Schemes
	// @Description do ping
	// @Tags example
	// @Accept json
	// @Produce json
	// @Success 200 {string} Helloworld
	// @Router /health-checker [get]

	router.GET("/health-checker", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"status": "success", "message": "OK"})
	})
	api := router.Group("/api")
	{
		v1 := api.Group("/v1")
		{
			todos := v1.Group("/todos")
			{
				todos.GET("/list", srv.AllTodos)
				todos.GET("/search", srv.SearchTodo)
				todos.POST("/bulk", srv.BulkTodo)
				todos.DELETE("", srv.DeleteTodo)
				todos.GET("", srv.GetTodo)
				todos.PUT("", srv.UpdateTodo)
				todos.POST("", srv.CreateTodo)
			}
		}
	}
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	server := &http.Server{
		Addr:    ":" + cfg.AppServerPort,
		Handler: router,
	}

	go func() {
		// service connections
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server with
	// a timeout of 5 seconds.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	<-quit
	log.Println("Shutdown Server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return errors.Wrap(err, "while shutting down:")
	}
	log.Println("Server exiting")
	return nil
}
func main() {
	if err := runApp(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
