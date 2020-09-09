package middleware

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/kkmmttdd/golang-auth0-server/config"
	"net/http"
	"strings"
)

type AuthInfo struct{
	Subject string
}

type Jwk struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

type Jwks struct {
	Keys []Jwk `json:"keys"`
}


func HandleFunc() func(*gin.Context) {
  return func(ctx *gin.Context) {
  	token, err := parseTokenFromRequest(ctx)
  	if err != nil {
		_ = ctx.AbortWithError(http.StatusForbidden, fmt.Errorf("error parsing token from request [%w]", err))
	}
  	authInfo, err := ValidateToken(token)
  	if err != nil {
  		_ = ctx.AbortWithError(http.StatusForbidden, fmt.Errorf("error validating token [%w]", err))
  	}
  	keys := ctx.Keys
  	if keys == nil { keys = make(map[string]interface{}) }
	keys["authInfo"] = authInfo
	ctx.Keys = keys
  }
}

func parseTokenFromRequest(ctx *gin.Context) (token string, err error) {
	//token = jwt.Token{}
	tokenStr := ctx.Request.Header.Get("Authorization")
	splitted := strings.Split(tokenStr, " ")
	if len(splitted) != 2 || strings.ToLower(splitted[0]) != "bearer" {
		err = fmt.Errorf("invalid format")
		return
	}
	token = splitted[1]
	return
}

func getPublicKeyPem(token *jwt.Token) (interface{}, error) {
	var pubKey *rsa.PublicKey
	var err error
	resp, err := http.Get(config.EnvConf.APIDomain + "/oauth/.well-known/jwks.json")
	if err != nil { return pubKey, fmt.Errorf("http error [%w]", err) }
	jwks := Jwks{Keys: []Jwk{}}
	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil { return pubKey, err }
	pem := ""
	for _, key := range jwks.Keys {
		if token.Header["kid"] == key.Kid {
			// reference about JWKS format https://auth0.com/docs/tokens/json-web-tokens/json-web-key-set-properties
			pem = "-----BEGIN CERTIFICATE-----\n" + key.X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}
	pubKey, err = jwt.ParseRSAPublicKeyFromPEM([]byte(pem))
	if err != nil {return pubKey, fmt.Errorf("parse pem error [%w]", err) }
	return pubKey, nil
}

func ValidateToken(tokenStr string) (authInfo AuthInfo, err error) {
	var token *jwt.Token
	token, err = jwt.Parse(tokenStr, getPublicKeyPem)
	if err != nil { err = fmt.Errorf("err when parsing [%w]", err); return }
	if !token.Valid { err = fmt.Errorf("err when validating [%w]", err); return }
	payload := token.Claims.(jwt.MapClaims)
	authInfo.Subject =  payload["sub"].(string)
	return
}
