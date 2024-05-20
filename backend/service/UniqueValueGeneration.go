package service

import (
	"fmt"
	"math/rand"
	"time"
	//"golang.org/x/crypto/bcrypt"
)



func GenerateUniqueCustomerID() string {
	return fmt.Sprintf("%d%s", time.Now().UnixNano(), GetRandomString(12))
}

func GenerateUniqueAdminID() string {
	return fmt.Sprintf("%d%s", time.Now().UnixNano(), GetRandomString(12))
}

func GenerateUniqueOrderID() string {
	return fmt.Sprintf("%d%s", time.Now().UnixNano(), GetRandomString(12))
}

func GenerateUniqueProductID() string {
	return fmt.Sprintf("%d%s", time.Now().UnixNano(), GetRandomString(12))
}

func GenerateUniqueAuditID() string {
	return fmt.Sprintf("%d%s", time.Now().UnixNano(), GetRandomString(12))
}

func GenerateUniqueFeedBackID() string {
	return fmt.Sprintf("%d%s", time.Now().UnixNano(), GetRandomString(12))
}

func GenerateUniqueCartID() string {
	return fmt.Sprintf("%d%s", time.Now().UnixNano(), GetRandomString(12))
}

func GenerateUniqueProductCartID() string {
	return fmt.Sprintf("%d%s", time.Now().UnixNano(), GetRandomString(12))
}

// Custom function to generate random characters (for demonstration purposes)
func GetRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
} 


func GenerateOTP(length int) string {
	const charset = "0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}


