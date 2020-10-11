package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/kkmmttdd/golang-auth0-server/config"
	"net/http/httptest"
	"testing"
)

func TestMiddleware(t *testing.T) {
	req := httptest.NewRequest("GET", "http://localhost:8080/hoge", nil)
	req.Header.Add("Authorization", config.EnvConf.ValidToken)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = req
	HandleFunc()(ctx)
	if ctx.Errors != nil {
		t.Errorf("authentication failed [%v]", ctx.Errors)
	}
	authInfo, ok := ctx.Keys["authInfo"].(AuthInfo); if !ok {
		t.Errorf("type assertion failed")
	}
	if authInfo.Subject != config.EnvConf.Subject {
		t.Errorf("subject name mismatch \n subject from token is %s but from config is %s", authInfo.Subject, config.EnvConf.Subject)
	}
	return
}

