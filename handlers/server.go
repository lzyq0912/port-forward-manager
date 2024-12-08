package handlers

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lzyq0912/port-forward-manager/models"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

var db *gorm.DB

// InitDB 初始化数据库连接
func InitDB(database *gorm.DB) {
	db = database
}

type AddServerRequest struct {
	Name            string `json:"name" binding:"required"`
	Address         string `json:"address" binding:"required"`
	AnsibleAlias    string `json:"ansible_alias" binding:"required"`
	SSHUsername     string `json:"ssh_username" binding:"required"`
	SSHHost         string `json:"ssh_host" binding:"required"`
	SSHPort         int    `json:"ssh_port" binding:"required"`
	SSHPassword     string `json:"ssh_password"`
	RequireSSHPass  bool   `json:"require_ssh_pass"`
	SudoPassword    string `json:"sudo_password"`
	RequireSudoPass bool   `json:"require_sudo_pass"`
}

func AddServer(c *gin.Context) {
	var req AddServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	// 检查是否存在相同IP的服务器
	var existingServer models.Server
	if err := db.Where("ssh_host = ?", req.SSHHost).First(&existingServer).Error; err == nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "该IP地址的服务器已存在",
		})
		return
	}

	// 验证SSH连接
	config := &ssh.ClientConfig{
		User: req.SSHUsername,
		Auth: []ssh.AuthMethod{
			ssh.Password(req.SSHPassword),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	// 尝试SSH连接
	addr := fmt.Sprintf("%s:%d", req.SSHHost, req.SSHPort)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "SSH连接失败: " + err.Error(),
		})
		return
	}
	defer client.Close()

	// 创建服务器记录
	server := models.Server{
		Name:            req.Name,
		Address:         req.Address,
		AnsibleAlias:    req.AnsibleAlias,
		SSHUsername:     req.SSHUsername,
		SSHHost:         req.SSHHost,
		SSHPort:         req.SSHPort,
		SSHPassword:     req.SSHPassword,
		RequireSSHPass:  req.RequireSSHPass,
		SudoPassword:    req.SudoPassword,
		RequireSudoPass: req.RequireSudoPass,
	}

	if err := db.Create(&server).Error; err != nil {
		c.JSON(500, gin.H{
			"success": false,
			"message": "保存服务器信息失败: " + err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"success": true,
		"message": "服务器添加成功",
		"data":    server,
	})
}

// GetServers 获取服务器列表
func GetServers(c *gin.Context) {
	// TODO: 从JWT中获取用户信息
	userID := uint(1) // 临时使用固定值，后续需要从JWT中获取
	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		c.JSON(401, gin.H{
			"success": false,
			"message": "用户未找到",
		})
		return
	}

	var servers []models.Server
	if user.IsAdmin {
		// 管理员可以看到所有服务器
		if err := db.Find(&servers).Error; err != nil {
			c.JSON(500, gin.H{
				"success": false,
				"message": "获取服务器列表失败: " + err.Error(),
			})
			return
		}
	} else {
		// 普通用户只能看到有权限的服务器
		if err := db.Joins("JOIN user_server_permissions ON servers.id = user_server_permissions.server_id").
			Where("user_server_permissions.user_id = ?", userID).
			Find(&servers).Error; err != nil {
			c.JSON(500, gin.H{
				"success": false,
				"message": "获取服务器列表失败: " + err.Error(),
			})
			return
		}
	}

	c.JSON(200, gin.H{
		"success": true,
		"data":    servers,
	})
}

// UpdateServer 更新服务器信息
func UpdateServer(c *gin.Context) {
	serverID := c.Param("id")
	var req AddServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	// 验证SSH连接
	config := &ssh.ClientConfig{
		User: req.SSHUsername,
		Auth: []ssh.AuthMethod{
			ssh.Password(req.SSHPassword),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", req.SSHHost, req.SSHPort)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "SSH连接失败: " + err.Error(),
		})
		return
	}
	defer client.Close()

	// 更新服务器信息
	server := models.Server{
		Name:            req.Name,
		Address:         req.Address,
		AnsibleAlias:    req.AnsibleAlias,
		SSHUsername:     req.SSHUsername,
		SSHHost:         req.SSHHost,
		SSHPort:         req.SSHPort,
		SSHPassword:     req.SSHPassword,
		RequireSSHPass:  req.RequireSSHPass,
		SudoPassword:    req.SudoPassword,
		RequireSudoPass: req.RequireSudoPass,
	}

	if err := db.Where("id = ?", serverID).Updates(&server).Error; err != nil {
		c.JSON(500, gin.H{
			"success": false,
			"message": "更新服务器信息失败: " + err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"success": true,
		"message": "服务器信息更新成功",
	})
}

// DeleteServer 删除服务器
func DeleteServer(c *gin.Context) {
	serverID := c.Param("id")

	// 删除服务器及其关联的端口
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("server_id = ?", serverID).Delete(&models.Port{}).Error; err != nil {
			return err
		}
		if err := tx.Delete(&models.Server{}, serverID).Error; err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		c.JSON(500, gin.H{
			"success": false,
			"message": "删除服务器失败: " + err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"success": true,
		"message": "服务器删除成功",
	})
}
