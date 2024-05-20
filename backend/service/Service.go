package service

import (
	"net"
	"regexp"
	"strconv"
)

func isValidNumber(s string) bool {
	numericRegex := regexp.MustCompile("^[0-9]+$")
	return numericRegex.MatchString(s)
}

func countdigits(number int) int {
	count := 0
	for number > 0 {
		count++
		number = number / 10
	}
	return int(count)
}

// func Validatetoken(token, SecretKey string) bool {
// 	_, err := ExtractCustomerID(token, SecretKey)
// 	return err == nil
// }

func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func floatToString(inputFloat float64) string {
	return strconv.FormatFloat(inputFloat, 'f', 2, 64)
}

func IsValidTOTP(totp string) bool {
	const totpRegexPattern = `^\d{6}$`
	totpRegex := regexp.MustCompile(totpRegexPattern)
	return totpRegex.MatchString(totp)
}


func intToString(num int) string {
	return strconv.Itoa(num)
}

func stringToInt(str string) (int, error) {
	num, err := strconv.Atoi(str)
	if err != nil {
		return 0, err
	}
	return num, nil
}
func IsValidEmail(email string) bool {
	const emailRegexPattern = `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`
	emailRegex := regexp.MustCompile(emailRegexPattern)

	return emailRegex.MatchString(email)
}
