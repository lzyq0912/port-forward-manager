package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/lzyq0912/port-forward-manager/config"
	"github.com/lzyq0912/port-forward-manager/handlers"
	"github.com/lzyq0912/port-forward-manager/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	// 初始化数据库
	db, err := gorm.Open(postgres.Open(config.GetPostgresConnStr()), &gorm.Config{})
	if err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}

	// 初始化handlers包中的数据库连接
	handlers.InitDB(db)

	// 自动迁移数据库结构
	if err := db.AutoMigrate(
		&models.Server{},
		&models.Port{},
		&models.User{},
		&models.UserServerPermission{},
		&models.UserPortPermission{},
	); err != nil {
		log.Fatalf("数据库迁移失败: %v", err)
	}

	// 设置路由
	r := gin.Default()

	// 服务器管理路由
	r.POST("/api/servers", handlers.AddServer)
	r.GET("/api/servers", handlers.GetServers)
	r.PUT("/api/servers/:id", handlers.UpdateServer)
	r.DELETE("/api/servers/:id", handlers.DeleteServer)

	// 端口管理路由
	r.POST("/api/ports", handlers.AddPort)
	r.GET("/api/servers/:id/ports", handlers.GetServerPorts)

	// 用户管理路由
	r.POST("/api/register", handlers.Register)
	r.POST("/api/login", handlers.Login)

	// 需要管理员权限的路由
	r.GET("/api/users", handlers.GetUsers)
	r.POST("/api/users", handlers.CreateUser)
	r.PUT("/api/users/:id", handlers.UpdateUser)
	r.DELETE("/api/users/:id", handlers.DeleteUser)
	r.GET("/api/users/:id/permissions", handlers.GetUserPermissions)

	// 权限管理路由
	r.POST("/api/permissions/server", handlers.GrantServerAccess)
	r.POST("/api/permissions/port", handlers.GrantPortAccess)
	r.DELETE("/api/permissions/server/:user_id/:server_id", handlers.RevokeServerAccess)
	r.DELETE("/api/permissions/port/:user_id/:port_id", handlers.RevokePortAccess)

	// 启动服务器
	log.Println("服务器启动在 :8080 端口")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
}
