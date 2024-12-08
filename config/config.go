package config

import (
	"fmt"
)

const (
	PostgresHost     = "localhost"
	PostgresPort     = 5432
	PostgresUser     = "postgres"
	PostgresPassword = "123456"
	PostgresDBName   = "port_forward"
	PostgresSSLMode  = "disable"
)

func GetPostgresConnStr() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		PostgresHost, PostgresPort, PostgresUser, PostgresPassword, PostgresDBName, PostgresSSLMode)
}
