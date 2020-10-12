package config

import (
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"log"
)

type EnvConfig struct {
	ValidToken string `required:"true"`
	Subject string `required:"true"`
	APIDomain string `required:"true"`
	Audience string `required:"true"`
	Issuer string `required:"true"`
	Azp string `required:"true"`
	Alg string `required:"true"`
	//User string `default:"waaaay"`
}

var (
	EnvConf EnvConfig
)

func init() {
	if err := godotenv.Load("config/.env"); err != nil {
		log.Fatal(err)
	}
	if err := envconfig.Process("", &EnvConf); err != nil {
		log.Fatal(err)
	}
}
