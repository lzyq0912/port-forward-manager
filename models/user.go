package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	Email     string         `json:"email" gorm:"uniqueIndex;not null"`
	Password  string         `json:"-" gorm:"not null"` // json:"-" 确保密码不会在JSON中返回
	IsAdmin   bool           `json:"is_admin" gorm:"default:false"`
	Note      string         `json:"note"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// UserServerPermission 用户对服务器的权限
type UserServerPermission struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	UserID    uint      `json:"user_id" gorm:"not null"`
	ServerID  uint      `json:"server_id" gorm:"not null"`
	CreatedAt time.Time `json:"created_at"`
}

// UserPortPermission 用户对端口的权限
type UserPortPermission struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	UserID    uint      `json:"user_id" gorm:"not null"`
	PortID    uint      `json:"port_id" gorm:"not null"`
	CreatedAt time.Time `json:"created_at"`
}
