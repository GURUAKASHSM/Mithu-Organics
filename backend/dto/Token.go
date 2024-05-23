package dto

// Admin Token Data
type AdminTokenData struct {
	AdminID string `json:"adminid" bson:"adminid"`
	Email   string `json:"email" bson:"email"`
}
