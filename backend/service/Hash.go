package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"mithuorganics/constants"
)

func HashUserPassword(password string) string {
	h := hmac.New(sha256.New, constants.UserPasswordHashKey)
	h.Write([]byte(password))
	hashedPassword := h.Sum(nil)
	return hex.EncodeToString(hashedPassword)
}

func HashAdminPassword(password string) string {
	h := hmac.New(sha256.New, constants.AdminPasswordHashKey)
	h.Write([]byte(password))
	hashedPassword := h.Sum(nil)
	return hex.EncodeToString(hashedPassword)
}
