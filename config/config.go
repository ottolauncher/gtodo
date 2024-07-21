package config

import (
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"os"
)

// Config holds all the configuration needed by the application.
type Config struct {
	RedisDBUri          string `envconfig:"REDIS_URI" required:"true"`
	MongodbDatabase     string `envconfig:"MONGODB_DATABASE" required:"true"`
	MongodbHostName     string `envconfig:"MONGODB_HOST_NAME" required:"true"`
	MongodbPort         string `envconfig:"MONGODB_PORT" required:"true"`
	GrpcServerPort      string `envconfig:"GRPC_SERVER_PORT" required:"true"`
	AppServerPort       string `envconfig:"APP_SERVER_PORT" required:"true"`
	DbTodoName          string `envconfig:"DB_TODO_NAME" required:"true"`
	DbUserName          string `envconfig:"DB_USER_NAME" required:"true"`
	LogPath             string `envconfig:"LOG_PATH" required:"true"`
	MongodbTestPath     string `envconfig:"MONGODB_PATH" required:"true"`
	GinMode             string `envconfig:"GIN_MODE" required:"true"`
	MongodbTestDatabase string `envconfig:"MONGODB_TEST_DATABASE" required:"true"`
	MongodbTestHostName string `envconfig:"MONGODB_TEST_HOST_NAME" required:"true"`
	MongodbTestDBPath   string `envconfig:"MONGODB_TEST_PATH" required:"true"`
	MongodbTestPort     string `envconfig:"MONGODB_TEST_PORT" required:"true"`
	TokenSecretKey      string `envconfig:"TOKEN_SECRET" required:"true"`
	RefreshSecretKey    string `envconfig:"REFRESH_SECRET" required:"true"`
	CertFile            string `envconfig:"CERT_FILE" required:"true"`
	KeyFile             string `envconfig:"KEY_FILE" required:"true"`
	Roles               string `envconfig:"ROLES" required:"true"`
}

// For ease of unit testing.
var (
	godotenvLoad     = godotenv.Load
	envconfigProcess = envconfig.Process
)

const (
	DEV   = "dev"
	STAGE = "staging"
	BUILD = "release"
)

// Read the environment variables fo the given file and returns a Config.
func Read(envFilePath string) (*Config, error) {
	curEnv, ok := os.LookupEnv("APP_MODE")
	if ok == true {
		path := os.ExpandEnv("gtodo/.env." + curEnv)
		if err := godotenvLoad(path); err != nil {
			return nil, errors.Wrap(err, "loading env vars")
		}
	} else {
		if err := godotenvLoad(envFilePath); err != nil {
			return nil, errors.Wrap(err, "loading env vars")
		}
	}

	config := new(Config)
	if err := envconfigProcess("", config); err != nil {
		return nil, errors.Wrap(err, "processing env vars")
	}
	return config, nil
}
