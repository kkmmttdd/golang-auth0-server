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

type CustomClaims struct {
	jwt.MapClaims
	issuer string
	audience string
	azp string
}

func (cc CustomClaims) CustomValid() error {
	var valid bool
	err := cc.MapClaims.Valid()
	if err != nil {
		return fmt.Errorf("default claim retuned erorr [%w]", err)
	}
	valid = cc.MapClaims.VerifyAudience(cc.audience, true)
	if valid != true {
		return fmt.Errorf("invalid audience")
	}
	valid = cc.MapClaims.VerifyIssuer(cc.issuer, true)
	if valid != true {
		return fmt.Errorf("invalid issuer")
	}
	if cc.azp != cc.MapClaims["azp"] {
		return fmt.Errorf("invalid azp")
	}
	return nil
}


func HandleFunc(ctx *gin.Context) {
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
	customClaims := CustomClaims{
		MapClaims: jwt.MapClaims{},
		issuer: config.EnvConf.Issuer,
		audience: config.EnvConf.Audience,
		azp: config.EnvConf.Azp,
	}
	// parse token from string
	parser := jwt.Parser{SkipClaimsValidation: true}
	token, err = parser.ParseWithClaims(tokenStr, customClaims.MapClaims, getPublicKeyPem)
	if err != nil { err = fmt.Errorf("err when parsing [%w]", err); return }
	// check if token is valid
	if token.Valid != true { err = fmt.Errorf("err when validating [%w]", err); return }
	// check is claims are valid
	err = customClaims.CustomValid()
	if err != nil { err = fmt.Errorf("err when validating customClaims [%w]", err); return}
	payload := token.Claims.(jwt.MapClaims)
	authInfo.Subject = payload["sub"].(string)
	return
}
