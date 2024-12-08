package models

type Server struct {
	ID              uint   `json:"id" gorm:"primaryKey"`
	Name            string `json:"name" gorm:"not null"`
	Address         string `json:"address" gorm:"not null"`
	AnsibleAlias    string `json:"ansible_alias" gorm:"not null"`
	SSHUsername     string `json:"ssh_username" gorm:"not null;default:'root'"`
	SSHHost         string `json:"ssh_host" gorm:"not null"`
	SSHPort         int    `json:"ssh_port" gorm:"not null;default:22"`
	SSHPassword     string `json:"ssh_password"`
	RequireSSHPass  bool   `json:"require_ssh_pass" gorm:"default:true"`
	SudoPassword    string `json:"sudo_password"`
	RequireSudoPass bool   `json:"require_sudo_pass" gorm:"default:true"`
}
