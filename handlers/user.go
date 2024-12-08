package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lzyq0912/port-forward-manager/models"
	"gorm.io/gorm"
)

// RegisterRequest 注册请求
type RegisterRequest struct {
	Email           string `json:"email" binding:"required,email"`
	Password        string `json:"password" binding:"required,min=8"`
	ConfirmPassword string `json:"confirm_password" binding:"required"`
}

// 密码加密
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// 验证密码强度
func validatePassword(password string) bool {
	hasLetter := regexp.MustCompile(`[a-zA-Z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	return len(password) >= 8 && hasLetter && hasNumber
}

// Register 用户注册
func Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	// 验证密码
	if req.Password != req.ConfirmPassword {
		c.JSON(400, gin.H{
			"success": false,
			"message": "两次输入的密码不一致",
		})
		return
	}

	if !validatePassword(req.Password) {
		c.JSON(400, gin.H{
			"success": false,
			"message": "密码必须至少包含8个字符，并且包含字母和数字",
		})
		return
	}

	// 检查邮箱是否已存在
	var existingUser models.User
	if err := db.Where("email = ?", strings.ToLower(req.Email)).First(&existingUser).Error; err == nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "该邮箱已被注册",
		})
		return
	}

	// 检查是否是第一个用户（设置为管理员）
	var count int64
	db.Model(&models.User{}).Count(&count)
	isFirstUser := count == 0

	// 创建用户
	user := models.User{
		Email:    strings.ToLower(req.Email),
		Password: hashPassword(req.Password),
		IsAdmin:  isFirstUser,
	}

	if err := db.Create(&user).Error; err != nil {
		c.JSON(500, gin.H{
			"success": false,
			"message": "创建用户失败: " + err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"success": true,
		"message": "注册成功",
		"data": gin.H{
			"id":       user.ID,
			"email":    user.Email,
			"is_admin": user.IsAdmin,
		},
	})
}

// LoginRequest 登录请求
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// Login 用户登录
func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	var user models.User
	if err := db.Where("email = ?", strings.ToLower(req.Email)).First(&user).Error; err != nil {
		c.JSON(401, gin.H{
			"success": false,
			"message": "用户不存在或密码错误",
		})
		return
	}

	if user.Password != hashPassword(req.Password) {
		c.JSON(401, gin.H{
			"success": false,
			"message": "用户不存在或密码错误",
		})
		return
	}

	// TODO: 生成JWT token
	// 这里先返回简单的登录成功信息
	c.JSON(200, gin.H{
		"success": true,
		"message": "登录成功",
		"data": gin.H{
			"id":       user.ID,
			"email":    user.Email,
			"is_admin": user.IsAdmin,
		},
	})
}

// CreateUserRequest 创建用户请求（管理员）
type CreateUserRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	IsAdmin  bool   `json:"is_admin"`
	Note     string `json:"note"`
}

// CreateUser 管理员创建用户
func CreateUser(c *gin.Context) {
	// TODO: 验证当前用户是否是管理员

	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	if !validatePassword(req.Password) {
		c.JSON(400, gin.H{
			"success": false,
			"message": "密码必须至少包含8个字符，并且包含字母和数字",
		})
		return
	}

	// 检查邮箱是否已存在
	var existingUser models.User
	if err := db.Where("email = ?", strings.ToLower(req.Email)).First(&existingUser).Error; err == nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "该邮箱已被注册",
		})
		return
	}

	user := models.User{
		Email:    strings.ToLower(req.Email),
		Password: hashPassword(req.Password),
		IsAdmin:  req.IsAdmin,
		Note:     req.Note,
	}

	if err := db.Create(&user).Error; err != nil {
		c.JSON(500, gin.H{
			"success": false,
			"message": "创建用户失败: " + err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"success": true,
		"message": "用户创建成功",
		"data": gin.H{
			"id":       user.ID,
			"email":    user.Email,
			"is_admin": user.IsAdmin,
			"note":     user.Note,
		},
	})
}

// GetUsers 获取用户列表（管理员）
func GetUsers(c *gin.Context) {
	var users []models.User
	if err := db.Find(&users).Error; err != nil {
		c.JSON(500, gin.H{
			"success": false,
			"message": "获取用户列表失败: " + err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"success": true,
		"data":    users,
	})
}

// UpdateUserRequest 更新用户请求
type UpdateUserRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password"` // 可选，如果不修改密码则不传
	IsAdmin  bool   `json:"is_admin"`
	Note     string `json:"note"`
}

// UpdateUser 更新用户信息（管理员）
func UpdateUser(c *gin.Context) {
	userID := c.Param("id")
	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	// 检查邮箱是否被其他用户使用
	var existingUser models.User
	if err := db.Where("email = ? AND id != ?", strings.ToLower(req.Email), userID).First(&existingUser).Error; err == nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "该邮箱已被其他用户使用",
		})
		return
	}

	updates := map[string]interface{}{
		"email":    strings.ToLower(req.Email),
		"is_admin": req.IsAdmin,
		"note":     req.Note,
	}

	// 如果提供了新密码，验证并更新密码
	if req.Password != "" {
		if !validatePassword(req.Password) {
			c.JSON(400, gin.H{
				"success": false,
				"message": "密码必须至少包含8个字符，并且包含字母和数字",
			})
			return
		}
		updates["password"] = hashPassword(req.Password)
	}

	if err := db.Model(&models.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
		c.JSON(500, gin.H{
			"success": false,
			"message": "更新用户信息失败: " + err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"success": true,
		"message": "用户信息更新成功",
	})
}

// DeleteUser 删除用户（管理员）
func DeleteUser(c *gin.Context) {
	userID := c.Param("id")

	// 删除用户及其相关权限
	err := db.Transaction(func(tx *gorm.DB) error {
		// 删除用户的服务器权限
		if err := tx.Where("user_id = ?", userID).Delete(&models.UserServerPermission{}).Error; err != nil {
			return err
		}
		// 删除用户的端口权限
		if err := tx.Where("user_id = ?", userID).Delete(&models.UserPortPermission{}).Error; err != nil {
			return err
		}
		// 删除用户
		if err := tx.Delete(&models.User{}, userID).Error; err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		c.JSON(500, gin.H{
			"success": false,
			"message": "删除用户失败: " + err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"success": true,
		"message": "用户删除成功",
	})
}

// GrantServerAccessRequest 授予服务器访问权限请求
type GrantServerAccessRequest struct {
	UserID   uint `json:"user_id" binding:"required"`
	ServerID uint `json:"server_id" binding:"required"`
}

// GrantServerAccess 授予用户服务器访问权限（管理员）
func GrantServerAccess(c *gin.Context) {
	var req GrantServerAccessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	// 检查用户是否存在
	var user models.User
	if err := db.First(&user, req.UserID).Error; err != nil {
		c.JSON(404, gin.H{
			"success": false,
			"message": "用户不存在",
		})
		return
	}

	// 检查服务器是否存在
	var server models.Server
	if err := db.First(&server, req.ServerID).Error; err != nil {
		c.JSON(404, gin.H{
			"success": false,
			"message": "服务器不存在",
		})
		return
	}

	// 检查权限是否已存在
	var existingPermission models.UserServerPermission
	if err := db.Where("user_id = ? AND server_id = ?", req.UserID, req.ServerID).First(&existingPermission).Error; err == nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "该用户已有此服务器的访问权限",
		})
		return
	}

	permission := models.UserServerPermission{
		UserID:   req.UserID,
		ServerID: req.ServerID,
	}

	if err := db.Create(&permission).Error; err != nil {
		c.JSON(500, gin.H{
			"success": false,
			"message": "授予服务器访问权限失败: " + err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"success": true,
		"message": "服务器访问权限授予成功",
	})
}

// GrantPortAccessRequest 授予端口访问权限请求
type GrantPortAccessRequest struct {
	UserID uint `json:"user_id" binding:"required"`
	PortID uint `json:"port_id" binding:"required"`
}

// GrantPortAccess 授予用户端口访问权限（管理员）
func GrantPortAccess(c *gin.Context) {
	var req GrantPortAccessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	// 检查用户是否存在
	var user models.User
	if err := db.First(&user, req.UserID).Error; err != nil {
		c.JSON(404, gin.H{
			"success": false,
			"message": "用户不存在",
		})
		return
	}

	// 检查端口是否存在
	var port models.Port
	if err := db.First(&port, req.PortID).Error; err != nil {
		c.JSON(404, gin.H{
			"success": false,
			"message": "端口不存在",
		})
		return
	}

	// 检查用户是否有对应服务器的访问权限
	var serverPermission models.UserServerPermission
	if err := db.Where("user_id = ? AND server_id = ?", req.UserID, port.ServerID).First(&serverPermission).Error; err != nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "用户没有对应服务器的访问权限，请先授予服务器访问权限",
		})
		return
	}

	// 检查权限是否已存在
	var existingPermission models.UserPortPermission
	if err := db.Where("user_id = ? AND port_id = ?", req.UserID, req.PortID).First(&existingPermission).Error; err == nil {
		c.JSON(400, gin.H{
			"success": false,
			"message": "该用户已有此端口的访问权限",
		})
		return
	}

	permission := models.UserPortPermission{
		UserID: req.UserID,
		PortID: req.PortID,
	}

	if err := db.Create(&permission).Error; err != nil {
		c.JSON(500, gin.H{
			"success": false,
			"message": "授予端口访问权限失败: " + err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"success": true,
		"message": "端口访问权限授予成功",
	})
}

// GetUserPermissions 获取用户的权限信息
func GetUserPermissions(c *gin.Context) {
	userID := c.Param("id")

	// 获取用户的服务器权限
	var serverPermissions []models.UserServerPermission
	if err := db.Where("user_id = ?", userID).Find(&serverPermissions).Error; err != nil {
		c.JSON(500, gin.H{
			"success": false,
			"message": "获取服务器权限失败: " + err.Error(),
		})
		return
	}

	// 获取用户的端口权限
	var portPermissions []models.UserPortPermission
	if err := db.Where("user_id = ?", userID).Find(&portPermissions).Error; err != nil {
		c.JSON(500, gin.H{
			"success": false,
			"message": "获取端口权限失败: " + err.Error(),
		})
		return
	}

	c.JSON(200, gin.H{
		"success": true,
		"data": gin.H{
			"server_permissions": serverPermissions,
			"port_permissions":   portPermissions,
		},
	})
}

// RevokeServerAccess 撤销用户的服务器访问权限
func RevokeServerAccess(c *gin.Context) {
	userID := c.Param("user_id")
	serverID := c.Param("server_id")

	result := db.Where("user_id = ? AND server_id = ?", userID, serverID).Delete(&models.UserServerPermission{})
	if result.Error != nil {
		c.JSON(500, gin.H{
			"success": false,
			"message": "撤销服务器访问权限失败: " + result.Error.Error(),
		})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(404, gin.H{
			"success": false,
			"message": "未找到对应的权限记录",
		})
		return
	}

	c.JSON(200, gin.H{
		"success": true,
		"message": "服务器访问权限已撤销",
	})
}

// RevokePortAccess 撤销用户的端口访问权限
func RevokePortAccess(c *gin.Context) {
	userID := c.Param("user_id")
	portID := c.Param("port_id")

	result := db.Where("user_id = ? AND port_id = ?", userID, portID).Delete(&models.UserPortPermission{})
	if result.Error != nil {
		c.JSON(500, gin.H{
			"success": false,
			"message": "撤销端口访问权限失败: " + result.Error.Error(),
		})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(404, gin.H{
			"success": false,
			"message": "未找到对应的权限记录",
		})
		return
	}

	c.JSON(200, gin.H{
		"success": true,
		"message": "端口访问权限已撤销",
	})
}

// 这里还需要继续添加更多用户管理相关的函数...
