package main

import (
	"fmt"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/kkmmttdd/golang-auth0-server/middleware"
)

func main() {
	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowMethods: []string{
			"POST",
			"GET",
			"OPTIONS",
			"PUT",
			"DELETE",
		},
		AllowHeaders: []string{
			"Access-Control-Allow-Headers",
			"Content-Type",
			"Content-Length",
			"Accept-Encoding",
			"X-CSRF-Token",
			"Authorization",
		},
		AllowOrigins: []string{
			"http://localhost:3000",
		},
	}))
	r.Use(middleware.HandleFunc())
	r.GET("/hoge", func(c *gin.Context) {
		c.Writer.Header().Set("Content-Type", "application/json")
		c.JSON(200, gin.H{
			"You are login as ": c.Keys["authInfo"].(middleware.AuthInfo).Subject,
		})
		if c.Errors != nil {
			fmt.Println(c.Errors)
		}
	})
	_ = r.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}
