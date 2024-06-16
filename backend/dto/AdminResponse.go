package dto

import (
	"mithuorganics/models"
	"time"
)

// Edit Admin Response
type EditAdminResponse struct {
	Status     string    `bson:"status" json:"status"`
	StatusCode string    `bson:"statuscode" json:"statuscode"`
	Message    string    `bson:"message" json:"message"`
	EditedTime time.Time `bson:"edittime,omitempty" json:"edittime,omitempty"`
	Error      error     `json:"error,omitempty" bson:"error,omitempty"`
}

// Delete Admin Response
type DeleteAdminResponse struct {
	Status      string    `bson:"status" json:"status"`
	StatusCode  string    `bson:"statuscode" json:"statuscode"`
	Message     string    `bson:"message" json:"message"`
	DeletedTime time.Time `bson:"deletetime,omitempty" json:"deletetime,omitempty"`
	Error       error     `json:"error,omitempty" bson:"error,omitempty"`
}

// View Admin Response
type ViewAdminResponse struct {
	Status        string    `bson:"status" json:"status"`
	StatusCode    string    `bson:"statuscode" json:"statuscode"`
	Message       string    `bson:"message" json:"message"`
	ViewedTime    time.Time `bson:"viewtime,omitempty" json:"viewtime,omitempty"`
	Error         error     `json:"error,omitempty" bson:"error,omitempty"`
	AdminName     string    `json:"adminname,omitempty" bson:"adminname,omitempty"`
	AdminID       string    `json:"adminid,omitempty" bson:"adminid,omitempty"`
	Email         string    `json:"email,omitempty" bson:"email,omitempty"`
	IP_Address    string    `json:"ip,omitempty" bson:"ip,omitempty"`
	WrongInput    int       `json:"wronginput,omitempty" bson:"wronginput,omitempty"`
	LoginTime     time.Time `json:"logintime,omitempty" bson:"logintime,omitempty"`
	CreatedTime   time.Time `json:"createdtime,omitempty" bson:"createdtime,omitempty"`
	CanDeleteData bool      `json:"candelete,omitempty" bson:"candelete,omitempty"`
	CanUpdateData bool      `json:"canupdate,omitempty" bson:"canupdate,omitempty"`
	CanAlterAdmin bool      `json:"canalteradmin,omitempty" bson:"canalteradmin,omitempty"`
	CreatedBy     string    `json:"createdby,omitempty" bson:"createdby,omitempty"`
	IsBlocked     bool      `json:"isblocked,omitempty" bson:"isblocked,omitempty"`
}

// Block Admin Response
type BlockorUnblockAdminResponse struct {
	Status                 string    `bson:"status" json:"status"`
	StatusCode             string    `bson:"statuscode" json:"statuscode"`
	Message                string    `bson:"message" json:"message"`
	BlockedorUnblockedTime time.Time `bson:"blockedorunblockedtime,omitempty" json:"blockedorunblockedtime,omitempty"`
	Error                  error     `json:"error,omitempty" bson:"error,omitempty"`
}

// Create Admin Response
type CreateAdminResponse struct {
	Status       string    `bson:"status" json:"status"`
	StatusCode   string    `bson:"statuscode" json:"statuscode"`
	Message      string    `bson:"message" json:"message"`
	CreatingTime time.Time `bson:"createingtime,omitempty" json:"createingtime,omitempty"`
}

// List Deleted Admin Response
type ListDeletedAdminResponse struct {
	Status     string                `bson:"status" json:"status"`
	StatusCode string                `bson:"statuscode" json:"statuscode"`
	Message    string                `bson:"message" json:"message"`
	Error      error                 `bson:"error,omitempty" json:"error,omitempty"`
	Listedtime time.Time             `bson:"listedtime,omitempty" json:"listedtime,omitempty"`
	Data       []models.DeletedAdmin `bson:"data,omitempty" json:"data,omitempty"`
}

// List Blocked Admin Response
type ListBlockedAdminResponse struct {
	Status     string                       `bson:"status" json:"status"`
	StatusCode string                       `bson:"statuscode" json:"statuscode"`
	Message    string                       `bson:"message" json:"message"`
	Error      error                        `bson:"error,omitempty" json:"error,omitempty"`
	Listedtime time.Time                    `bson:"listedtime,omitempty" json:"listedtime,omitempty"`
	Data       []models.BlockorUnblockAdmin `bson:"data,omitempty" json:"data,omitempty"`
}

// Admin Sign in data
type AdminLoginResponse struct {
	Status        string    `bson:"status" json:"status"`
	StatusCode    string    `bson:"statuscode" json:"statuscode"`
	Message       string    `bson:"message" json:"message"`
	Email         string    `bson:"email,omitempty" json:"email,omitempty" `
	AdminName     string    `json:"adminname,omitempty" bson:"adminname,omitempty"`
	PublicKey     string    `json:"publickey,omitempty" bson:"publickey,omitempty"`
	Token         string    `bson:"token,omitempty" json:"token,omitempty"`
	Error         error     `bson:"error,omitempty" json:"error,omitempty"`
	CanDelete     bool      `bson:"candelete,omitempty" json:"candelete,omitempty"`
	CanUpdate     bool      `bson:"canupdate,omitempty" json:"canupdate,omitempty"`
	CanAlterAdmin bool      `bson:"canalteradmin,omitempty" json:"canalteradmin,omitempty"`
	LoginTime     time.Time `bson:"logintime,omitempty" json:"logintime,omitempty"`
}

// List Admin Response
type ListAdminResponse struct {
	Status     string             `bson:"status" json:"status"`
	StatusCode string             `bson:"statuscode" json:"statuscode"`
	Message    string             `bson:"message" json:"message"`
	Error      error              `bson:"error,omitempty" json:"error,omitempty"`
	Listedtime time.Time          `bson:"listedtime,omitempty" json:"listedtime,omitempty"`
	Data       []models.ListAdmin `bson:"data,omitempty" json:"data,omitempty"`
}

// ListAdmin Audit Response
type ListAdminAuditResponse struct {
	Status     string              `bson:"status" json:"status"`
	StatusCode string              `bson:"statuscode" json:"statuscode"`
	Message    string              `bson:"message" json:"message"`
	Error      error               `bson:"error,omitempty" json:"error,omitempty"`
	Listedtime time.Time           `bson:"listedtime,omitempty" json:"listedtime,omitempty"`
	Data       []models.AdminAudit `bson:"data,omitempty" json:"data,omitempty"`
}

// ListDeveloper Audit Response
type ListDeveloperAuditResponse struct {
	Status     string                  `bson:"status" json:"status"`
	StatusCode string                  `bson:"statuscode" json:"statuscode"`
	Message    string                  `bson:"message" json:"message"`
	Error      error                   `bson:"error,omitempty" json:"error,omitempty"`
	Listedtime time.Time               `bson:"listedtime,omitempty" json:"listedtime,omitempty"`
	Data       []models.DeveloperAudit `bson:"data,omitempty" json:"data,omitempty"`
}

// List Edited Admin Response
type ListEditedAdminResponse struct {
	Status     string               `bson:"status" json:"status"`
	StatusCode string               `bson:"statuscode" json:"statuscode"`
	Message    string               `bson:"message" json:"message"`
	Error      error                `bson:"error,omitempty" json:"error,omitempty"`
	Listedtime time.Time            `bson:"listedtime,omitempty" json:"listedtime,omitempty"`
	Data       []models.EditedAdmin `bson:"data,omitempty" json:"data,omitempty"`
}

// Validate Admin Token Response
type ValidateAdminTokenResponse struct {
	Status       string    `bson:"status" json:"status"`
	StatusCode   string    `bson:"statuscode" json:"statuscode"`
	Message      string    `bson:"message" json:"message"`
	Error        error     `bson:"error,omitempty" json:"error,omitempty"`
	Responsetime time.Time `bson:"listedtime,omitempty" json:"listedtime,omitempty"`
	Valid        bool      `json:"valid" bson:"vaild"`
}

// Approve Admin Response
type ApproveAdminResponse struct {
	Status       string    `bson:"status,omitempty" json:"status,omitempty"`
	StatusCode   string    `bson:"statuscode,omitempty" json:"statuscode,omitempty"`
	Message      string    `bson:"message,omitempty" json:"message,omitempty"`
	Error        error     `bson:"error,omitempty" json:"error,omitempty"`
	ApprovedTime time.Time `bson:"approvedtime,omitempty" json:"approvedtime,omitempty"`
}


// Reset Gauth Response
type ResetGauthResponse struct {
	Status       string    `bson:"status,omitempty" json:"status,omitempty"`
	StatusCode   string    `bson:"statuscode,omitempty" json:"statuscode,omitempty"`
	Message      string    `bson:"message,omitempty" json:"message,omitempty"`
	Error        error     `bson:"error,omitempty" json:"error,omitempty"`
	Resetedtime time.Time `bson:"resetedtime,omitempty" json:"resetedtime,omitempty"`
}

// Reset Password Response
type ResetPasswordResponse struct {
	Status       string    `bson:"status,omitempty" json:"status,omitempty"`
	StatusCode   string    `bson:"statuscode,omitempty" json:"statuscode,omitempty"`
	Message      string    `bson:"message,omitempty" json:"message,omitempty"`
	Error        error     `bson:"error,omitempty" json:"error,omitempty"`
	Resetedtime time.Time `bson:"resetedtime,omitempty" json:"resetedtime,omitempty"`
}

