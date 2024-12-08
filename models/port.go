package models

type Port struct {
	ID           uint   `json:"id" gorm:"primaryKey"`
	ServerID     uint   `json:"server_id" gorm:"not null"`
	LocalPort    int    `json:"local_port" gorm:"not null"`
	PublicPort   *int   `json:"public_port"`
	Status       string `json:"status" gorm:"not null;default:'未使用'"` // 状态：未使用、已占用
	Function     string `json:"function"`                             // 功能描述
	SpeedLimit   int    `json:"speed_limit"`                          // 限速 (KB/s)
	TrafficUsage int64  `json:"traffic_usage"`                        // 流量使用量 (bytes)
	User         string `json:"user"`                                 // 使用者
}
