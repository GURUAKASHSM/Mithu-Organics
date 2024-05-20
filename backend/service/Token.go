package service

import (
	//"mithuorganics/constants"
	"crypto/aes"
	"crypto/cipher"
	random "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"reflect"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func EncryptToken(jwtToken string, key []byte) (string, error) {
	log.Println("\n ***** Encrypt Token  ***** ")

	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	encryptedPayload := gcm.Seal(nonce, nonce, payload, nil)

	encodedPayload := base64.RawURLEncoding.EncodeToString(encryptedPayload)

	parts[1] = encodedPayload

	encryptedToken := strings.Join(parts, ".")

	return encryptedToken, nil
}

func DecryptToken(encryptedToken string, key []byte) (string, error) {
	log.Println("\n ***** Decrypt Token  ***** ")

	parts := strings.Split(encryptedToken, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid JWT format")
	}

	encodedPayload := parts[1]
	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(payload) < nonceSize {
		return "", errors.New("invalid payload size")
	}
	nonce, encryptedPayload := payload[:nonceSize], payload[nonceSize:]

	decryptedPayload, err := gcm.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return "", err
	}

	// Reconstruct the JWT token with the decrypted payload
	parts[1] = base64.RawURLEncoding.EncodeToString(decryptedPayload)
	decryptedToken := strings.Join(parts, ".")

	return decryptedToken, nil
}
func CreateToken(data interface{}, privateKeyBytes []byte, validtime int64, encryptionkey []byte) (string, error) {
	log.Println("\n ****** Create Encrypted Token with RSA ****** ")

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		log.Println("1", err)
		return "", err
	}

	result := make(map[string]interface{})

	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Struct {
		return "", errors.New("data is not a struct")
	}

	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json") // Get JSON tag
		if tag != "" {
			result[tag] = val.Field(i).Interface() // Set field value to map
		}
	}

	claims := jwt.MapClaims{}
	for key, value := range result {
		claims[key] = value
	}
	claims["exp"] = time.Now().Add(time.Hour * time.Duration(validtime)).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims) // Use RS256

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		log.Println("2", err)
		return "", err
	}

	tokenString, err = EncryptToken(tokenString, encryptionkey)
	if err != nil {
		log.Println("3", err)
		return "", err
	}
	return tokenString, nil
}
func ExtractID(tokenString string, publicKeyBytes []byte, idfeildname string, decryptionkey []byte) (string, error) {
	log.Println("\n ****** Verify Token with RSA ****** ")

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return "", err
	}

	tokenString, err = DecryptToken(tokenString, decryptionkey)
	if err != nil {
		return "", err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", errors.New("invalid token or claims")
	}

	id, ok := claims[idfeildname].(string)
	if !ok {
		return "", errors.New("feild name not found or not a string")
	}

	return id, nil
}

func ExtractDetails(tokenString string, publicKeyBytes []byte, decryptionkey []byte) (jwt.MapClaims, error) {
	log.Println("\n ****** Verify Token with RSA ****** ")

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	tokenString, err = DecryptToken(tokenString, decryptionkey)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

// IsTokenValid checks if a token is valid or not
func IsTokenValid(tokenString string, publicKeyBytes []byte, decryptionkey []byte) bool {
	log.Println("\n ****** Verify Token with RSA ****** ")

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return false
	}

	tokenString, err = DecryptToken(tokenString, decryptionkey)
	if err != nil {
		return false
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil || !token.Valid {
		log.Println("Invalid token:", err)
		return false
	}

	return true
}

func GenerateRSAKeyPair() ([]byte, []byte, error) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(random.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Encode private key to PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode public key to PEM format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return privateKeyPEM, publicKeyPEM, nil
}
