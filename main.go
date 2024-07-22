package main

import (
	"context"
	"fmt"
	"github.com/ottolauncher/gtodo/config"
	db "github.com/ottolauncher/gtodo/db/mongo"
	dbr "github.com/ottolauncher/gtodo/db/redis"
	"github.com/ottolauncher/gtodo/docs"
	"github.com/ottolauncher/gtodo/handlers"
	"github.com/ottolauncher/gtodo/interceptor"
	"github.com/ottolauncher/gtodo/middleware"
	"github.com/ottolauncher/gtodo/models"
	"github.com/ottolauncher/gtodo/pb"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/credentials"
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

func authMethods() map[string]bool {
	const todoServicePath = "TodoService."

	return map[string]bool{
		todoServicePath + "ListTodo":   true,
		todoServicePath + "SearchTodo": true,
		todoServicePath + "GetTodo":    true,
	}
}

func runApp() error {
	var (
		client      *mongo.Client
		redisClient *redis.Client
		once        sync.Once
		conn        *grpc.ClientConn
	)

	const envFilePath = ".env"
	cfg, err := config.Read(envFilePath)
	if err != nil {
		return errors.Wrap(err, "reading config")
	}
	once.Do(func() {
		client = db.Connect(context.Background(), cfg)
		var methods map[string]bool

		um := models.NewUserManger(client, redisClient)
		redisClient = dbr.InitRedisDB(context.Background(), cfg)
		guard, err := interceptor.NewAuthInterceptor(um, methods, time.Duration(cfg.RefreshTokenTimer))
		//conn, err = grpc.NewClient(cfg.GrpcServerPort, grpc.WithTransportCredentials(insecure.NewCredentials()))
		conn, err = grpc.NewClient(
			cfg.GrpcServerPort,
			grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")),
			grpc.WithUnaryInterceptor(guard.Unary()),
			grpc.WithStreamInterceptor(guard.Stream()),
		)
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

	userClient := pb.NewUserServiceClient(conn)
	bookClient := pb.NewTodoServiceClient(conn)
	srv := handlers.NewResolver(bookClient, userClient)
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
		msg := "Welcome to GRPC Todo API"
		ctx.JSON(http.StatusOK, gin.H{"status": "success", "message": msg})
	})
	api := router.Group("/api")
	{
		v1 := api.Group("/v1")
		{
			todos := v1.Group("/todos")
			{
				todos.GET("/list", srv.AllTodos)
				todos.GET("/search", srv.SearchTodo)
				todos.POST("/bulk", models.AuthMiddleware(client), srv.BulkTodo)
				todos.DELETE("", models.AuthMiddleware(client), srv.DeleteTodo)
				todos.GET("", srv.GetTodo)
				todos.PUT("", models.AuthMiddleware(client), srv.UpdateTodo)
				todos.POST("", models.AuthMiddleware(client), srv.CreateTodo)
			}
			users := v1.Group("/users")
			{
				users.GET("/list", srv.AllUser)
				users.GET("/search", srv.SearchUser)
				users.POST("/bulk", models.AuthMiddleware(client), srv.BulkUser)
				users.DELETE("", srv.DeleteUser)
				users.GET("", srv.GetUser)
				users.PUT("", models.AuthMiddleware(client), srv.UpdateUser)
			}
			auth := v1.Group("/auth")
			{
				auth.POST("/login", srv.Login)
				auth.POST("/register", srv.CreateUser)
				auth.POST("/logout", models.AuthMiddleware(client), srv.Logout)
				auth.GET("/verify-email/:verificationCode", srv.VerifyEmail)
				auth.POST("/forgot-password", srv.ForgotPassword)
				auth.PATCH("/reset-password", srv.ResetPassword)
				auth.POST("/change-password", srv.ChangePassword)
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
