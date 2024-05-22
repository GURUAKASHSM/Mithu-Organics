package dto

import "time"

// Delete Admin Input
type DeleteAdminRequest struct {
	Token     string `json:"token" bson:"token"`
	PublicKey string `json:"publickey" bson:"publickey"`
	Reason    string `json:"reason" bson:"reason"`
	Email     string `json:"email" bson:"email"`
}

// List Input
type ListAdminRequest struct {
	Token         string    `json:"token" bson:"token"`
	PublicKey     string    `json:"publickey" bson:"publickey"`
	NoofData      int64     `json:"noofdata" bson:"noofdata"`
	SortBy        string    `json:"sortby,omitempty" bson:"sortby,omitempty"`
	FromDate      time.Time `json:"fromdate,omitempty" bson:"fromdate,omitempty"`
	ToDate        time.Time `json:"todate,omitempty" bson:"todate,omitempty"`
	SearchBY      string    `json:"searchby,omitempty" bson:"searchby,omitempty"`
	SearchValue   string    `json:"searchvalue,omitempty" bson:"searchvalue,omitempty"`
	IsBlocked     string    `json:"isblocked,omitempty" bson:"isblocked,omitempty"`
	CanUpdate     string    `json:"canupdate,omitempty" bson:"canupdate,omitempty"`
	CanDelete     string    `json:"candelete,omitempty" bson:"candelete,omitempty"`
	CanAlterAdmin string    `json:"canalteradmin" bson:"canalteradmin"`
	SortOrder     int       `json:"sortorder,omitempty" bson:"sortorder,omitempty"`
}

// Edit Admin
type EditAdminRequest struct {
	Token       string      `json:"token" bson:"token"`
	PublicKey   string      `json:"publickey" bson:"publickey"`
	Email       string      `json:"email" bson:"email"`
	UpdateFeild string      `json:"updatefeild" bson:"updatefeild"`
	UpdateValue interface{} `json:"updatevalue" bson:"updatevalue"`
	Reason      string      `json:"reason" bson:"reason"`
}

// View Admin Request
type ViewAdminRequest struct {
	Token      string `json:"token" bson:"token"`
	PublicKey  string `json:"publickey" bson:"publickey"`
	AdminEmail string `json:"adminemail" bson:"adminemail"`
}

// Block Admin Request
type BlockorUnblockAdminRequest struct {
	Token          string `json:"token" bson:"token"`
	PublicKey      string `json:"publickey" bson:"publickey"`
	Email          string `json:"email" bson:"email"`
	Reason         string `json:"reason" bson:"reason"`
	BlockorUnblock string `json:"blockorunblock" bson:"blockorunblock"`
}

// Admin Sign UP data
type CreateAdminRequest struct {
	FromAdminToken     string `json:"fromadmintoken" bson:"fromadmintoken"`
	FromAdminPublicKey string `json:"formadminpublickey" bson:"formadminpublickey"`
	AdminName          string `json:"name,omitempty" bson:"name,omitempty"`
	Email              string `bson:"email,omitempty" json:"email,omitempty"`
	Password           string `bson:"password,omitempty" json:"password,omitempty"`
	ConfirmPassword    string `bson:"confirmpassword,omitempty" json:"confirmpassword,omitempty"`
	IP_Address         string `bson:"ip,omitempty" json:"ip,omitempty"`
	CanDeleteData      bool   `json:"candelete,omitempty" bson:"candelete,omitempty"`
	CanUpdateData      bool   `json:"canupdate,omitempty" bson:"canupdate,omitempty"`
	CanAlterAdmin      bool   `json:"canalteradmin,omitempty" bson:"canalteradmin,omitempty"`
}


// List Deleted Admin Request
type ListDeletedAdminRequest struct {
	Token       string    `json:"token" bson:"token"`
	PublicKey   string    `json:"publickey" bson:"publickey"`
	NoofData    int64     `json:"noofdata,omitempty" bson:"noofdata,omitempty"`
	SortBy      string    `json:"sortby,omitempty" bson:"sortby,omitempty"`
	FromDate    time.Time `json:"fromdate,omitempty" bson:"fromdate,omitempty"`
	ToDate      time.Time `json:"todate,omitempty" bson:"todate,omitempty"`
	SearchBY    string    `json:"searchby,omitempty" bson:"searchby,omitempty"`
	SearchValue string    `json:"searchvalue,omitempty" bson:"searchvalue,omitempty"`
	SortOrder   int       `json:"sortorder,omitempty" bson:"sortorder,omitempty"`
}

// List Blocked Admin Request
type ListBlockedAdminRequest struct {
	Token       string    `json:"token" bson:"token"`
	PublicKey   string    `json:"publickey" bson:"publickey"`
	NoofData    int64     `json:"noofdata,omitempty" bson:"noofdata,omitempty"`
	SortBy      string    `json:"sortby,omitempty" bson:"sortby,omitempty"`
	FromDate    time.Time `json:"fromdate,omitempty" bson:"fromdate,omitempty"`
	ToDate      time.Time `json:"todate,omitempty" bson:"todate,omitempty"`
	SearchBY    string    `json:"searchby,omitempty" bson:"searchby,omitempty"`
	SearchValue string    `json:"searchvalue,omitempty" bson:"searchvalue,omitempty"`
	SortOrder   int       `json:"sortorder,omitempty" bson:"sortorder,omitempty"`
}

// Admin Sign in data
type AdminLoginRequest struct {
	Email      string `bson:"email,omitempty" json:"email,omitempty"`
	Password   string `bson:"password,omitempty" json:"password,omitempty"`
	IP_Address string `bson:"ip,omitempty" json:"ip,omitempty"`
	TOTP       string `json:"totp,omitempty" bson:"totp,omitempty"`
}


// ListAdmin Audit Request
type ListAdminAuditRequest struct {
	Token       string    `json:"token" bson:"token"`
	PublicKey   string    `json:"publickey" bson:"publickey"`
	NoofData    int64     `json:"noofdata,omitempty" bson:"noofdata,omitempty"`
	SortBy      string    `json:"sortby,omitempty" bson:"sortby,omitempty"`
	FromDate    time.Time `json:"fromdate,omitempty" bson:"fromdate,omitempty"`
	ToDate      time.Time `json:"todate,omitempty" bson:"todate,omitempty"`
	SearchBY    string    `json:"searchby,omitempty" bson:"searchby,omitempty"`
	SearchValue string    `json:"searchvalue,omitempty" bson:"searchvalue,omitempty"`
	SortOrder   int       `json:"sortorder,omitempty" bson:"sortorder,omitempty"`
}


// ListDeveloper Audit Request
type ListDeveloperAuditRequest struct {
	Token       string    `json:"token" bson:"token"`
	PublicKey   string    `json:"publickey" bson:"publickey"`
	NoofData    int64     `json:"noofdata" bson:"noofdata"`
	SortBy      string    `json:"sortby,omitempty" bson:"sortby,omitempty"`
	FromDate    time.Time `json:"fromdate,omitempty" bson:"fromdate,omitempty"`
	ToDate      time.Time `json:"todate,omitempty" bson:"todate,omitempty"`
	SearchBY    string    `json:"searchby,omitempty" bson:"searchby,omitempty"`
	SearchValue string    `json:"searchvalue,omitempty" bson:"searchvalue,omitempty"`
	SortOrder   int       `json:"sortorder,omitempty" bson:"sortorder,omitempty"`
}

