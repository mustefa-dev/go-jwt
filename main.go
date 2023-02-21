package main

import (
	"gin-jwt/controllers"
	"gin-jwt/middleware"
	"gin-jwt/models"
	"github.com/gin-gonic/gin"
)

func main() {
	models.ConnectDatabase()
	r := gin.Default()
	r.POST("/signUp", controllers.SignUp)
	r.POST("/login", controllers.Login)
	r.GET("/validate", middleware.RequireAuth(), controllers.Validate)

	r.Run(":8080")

}
