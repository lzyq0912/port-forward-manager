package handlers

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lzyq0912/port-forward-manager/models"
	"golang.org/x/crypto/ssh"
)

// AddPortRequest 添加端口请求
type AddPortRequest struct {
	ServerID   uint   `json:"server_id" binding:"required"`
	PortRange  string `json:"port_range" binding:"required"` // 格式：单端口"8000"或端口范围"8000-8010"
	PublicPort *int   `json:"public_port"`
}

// 检查端口是否被占用
func isPortInUse(port int) bool {
	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return true
	}
	listener.Close()
	return false
}

// AddPort 添加端口
func AddPort(c *gin.Context) {
	var req AddPortRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	// 首先验证服务器是否存在
	var server models.Server
	if err := db.First(&server, req.ServerID).Error; err != nil {
		c.JSON(404, gin.H{
			"success": false,
			"message": "服务器不存在或已被删除",
		})
		return
	}

	// 验证SSH连接是否可用
	config := &ssh.ClientConfig{
		User: server.SSHUsername,
		Auth: []ssh.AuthMethod{
			ssh.Password(server.SSHPassword),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", server.SSHHost, server.SSHPort)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "服务器SSH连接失败，无法添加端口: " + err.Error(),
		})
		return
	}
	defer client.Close()

	// 解析端口范围
	var ports []int
	if strings.Contains(req.PortRange, "-") {
		// 处理端口范围
		rangeParts := strings.Split(req.PortRange, "-")
		if len(rangeParts) != 2 {
			c.JSON(400, gin.H{
				"success": false,
				"message": "端口范围格式错误",
			})
			return
		}

		start, err1 := strconv.Atoi(rangeParts[0])
		end, err2 := strconv.Atoi(rangeParts[1])
		if err1 != nil || err2 != nil || start > end {
			c.JSON(400, gin.H{
				"success": false,
				"message": "端口范围无效",
			})
			return
		}

		for i := start; i <= end; i++ {
			ports = append(ports, i)
		}
	} else {
		// 处理单个端口
		port, err := strconv.Atoi(req.PortRange)
		if err != nil {
			c.JSON(400, gin.H{
				"success": false,
				"message": "端口格式错误",
			})
			return
		}
		ports = append(ports, port)
	}

	// 批量添加端口
	var addedPorts []models.Port
	for _, port := range ports {
		// 检查端口是否已经存在
		var existingPort models.Port
		if err := db.Where("server_id = ? AND local_port = ?", req.ServerID, port).First(&existingPort).Error; err == nil {
			c.JSON(400, gin.H{
				"success": false,
				"message": fmt.Sprintf("端口 %d 已经存在", port),
			})
			return
		}

		status := "未使用"
		if isPortInUse(port) {
			status = "已占用"
		}

		newPort := models.Port{
			ServerID:   req.ServerID,
			LocalPort:  port,
			PublicPort: req.PublicPort,
			Status:     status,
		}

		if err := db.Create(&newPort).Error; err != nil {
			c.JSON(500, gin.H{
				"success": false,
				"message": fmt.Sprintf("添加端口 %d 失败: %s", port, err.Error()),
			})
			return
		}
		addedPorts = append(addedPorts, newPort)
	}

	c.JSON(200, gin.H{
		"success": true,
		"message": "端口添加成功",
		"data":    addedPorts,
	})
}

// GetServerPorts 获取服务器的端口列表
func GetServerPorts(c *gin.Context) {
	serverID := c.Param("id")
	// TODO: 从JWT中获取用户信息
	userID := uint(1) // 临时使用固定值，后续需要从JWT中获取

	// 检查用户是否有权限访问该服务器
	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		c.JSON(401, gin.H{
			"success": false,
			"message": "用户未找到",
		})
		return
	}

	// 如果不是管理员，检查是否有服务器访问权限
	if !user.IsAdmin {
		var permission models.UserServerPermission
		if err := db.Where("user_id = ? AND server_id = ?", userID, serverID).First(&permission).Error; err != nil {
			c.JSON(403, gin.H{
				"success": false,
				"message": "没有权限访问该服务器",
			})
			return
		}
	}

	var ports []models.Port
	if err := db.Where("server_id = ?", serverID).Find(&ports).Error; err != nil {
		c.JSON(500, gin.H{
			"success": false,
			"message": "获取端口列表失败: " + err.Error(),
		})
		return
	}

	// 如果不是管理员，只返回有权限的端口
	if !user.IsAdmin {
		var authorizedPorts []models.Port
		for _, port := range ports {
			var permission models.UserPortPermission
			if err := db.Where("user_id = ? AND port_id = ?", userID, port.ID).First(&permission).Error; err == nil {
				authorizedPorts = append(authorizedPorts, port)
			}
		}
		ports = authorizedPorts
	}

	// 更新端口状态
	for i := range ports {
		if isPortInUse(ports[i].LocalPort) {
			ports[i].Status = "已占用"
		} else {
			ports[i].Status = "未使用"
		}
		db.Save(&ports[i])
	}

	c.JSON(200, gin.H{
		"success": true,
		"data":    ports,
	})
}
