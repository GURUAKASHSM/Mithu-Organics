package models

import (
	"time"
)

// EditAdmin DB
type EditedAdmin struct {
	EditID           string      `json:"editid" bson:"editid"`
	EditedByName     string      `json:"editedbyname" bson:"editedbyname"`
	EditedById       string      `json:"editedbyid" bson:"editedbyid"`
	EditedByEmail    string      `json:"editedbyemail" bson:"editedbyemail"`
	FeildUpdated     string      `json:"feildupdated" bson:"feildupdated"`
	NewValueUpdated  interface{} `json:"newvalueupdated" bson:"newvalueupdated"`
	OldValue         interface{} `json:"oldValue" bson:"oldValue"`
	Reason           string      `json:"reason" bson:"reason"`
	AdminEditedID    string      `json:"admineditedid" bson:"admineditedid"`
	AdminEditedEmail string      `json:"admineditedemail" bson:"admineditedemail"`
	EditTime         time.Time   `json:"edittime" bson:"edittime"`
}

// Delete Admin DB
type DeletedAdmin struct {
	DeleteID     string    `json:"deleteid" bson:"deleteid"`
	Deleteddata  Admin     `json:"deleteddata" bson:"deleteddata"`
	DeleterID    string    `json:"deleterid" bson:"deleterid"`
	DeleterName  string    `json:"deletername" bson:"deletername"`
	DeleterEmail string    `json:"deleteremail" bson:"deleteremail"`
	Reason       string    `json:"reason" bson:"reason"`
	DeletedTime  time.Time `json:"deletedtime" bson:"deletedtime"`
}

// Admin Signup Data
type Admin struct {
	AdminName     string    `json:"adminname" bson:"adminname"`
	AdminID       string    `json:"adminid" bson:"adminid"`
	Email         string    `json:"email" bson:"email"`
	Password      string    `json:"password" bson:"password"`
	IP_Address    string    `json:"ip" bson:"ip"`
	SecretKey     string    `json:"secretkey" bson:"secretkey"`
	WrongInput    int       `json:"wronginput" bson:"wronginput"`
	PrivateKey    string    `json:"privatekey" bson:"privatekey"`
	PublicKey     string    `json:"publickey" bson:"publickey"`
	LoginTime     time.Time `json:"logintime" bson:"logintime"`
	CreatedTime   time.Time `json:"createdtime" bson:"createdtime"`
	CanDeleteData bool      `json:"candelete" bson:"candelete"`
	CanUpdateData bool      `json:"canupdate" bson:"canupdate"`
	CanAlterAdmin bool      `json:"canalteradmin" bson:"canalteradmin"`
	CreatedBy     string    `json:"createdby" bson:"createdby"`
	IsBlocked     bool      `json:"isblocked" bson:"isblocked"`
	IsApproved    bool      `json:"isapproved" bson:"isapproved"`
	Token         string    `json:"token" bson:"token"`
}

// Block Admin DB
type BlockorUnblockAdmin struct {
	BlockID                      string    `json:"blockid" bson:"blockid" `
	BlockedorUnblockedByEmail    string    `json:"blockedorunblockedbyemail" bson:"blockedorunblockedbyemail"`
	BlockedorUnblockedByName     string    `json:"blockedorunblockedbyname" bson:"blockedorunblockedbyname"`
	BlockedorUnblockedByID       string    `json:"blockedorunblockedbyid" bson:"blockedorunblockedbyid"`
	BlockedorUnblockedAdminName  string    `json:"blockedorunblockedadminname" bson:"blockedorunblockedadminname"`
	BlockedorUnblockedAdminEmail string    `json:"blockedorunblockedadminemail" bson:"blockedorunblockedadminemail"`
	BlockedorUnblockedAdminId    string    `json:"blockedorunblockedadminid" bson:"blockedorunblockedadminid"`
	BlockedorUnBlocked           string    `json:"blockedorunblocked" bson:"blockedorunblocked"`
	Reason                       string    `json:"reason" bson:"reason"`
	BlockedorUnblockedTime       time.Time `json:"blockedtime" bson:"blockedtime"`
}

// Admin Sign in data
type AdminAudit struct {
	AuditID       string      `bson:"auditid" json:"auditid"`
	AdminID       string      `bson:"adminid,omitempty" json:"adminid,omitempty"`
	Error         error       `bson:"error,omitempty" json:"error,omitempty"`
	Message       string      `bson:"message" json:"message"`
	AuditTime     time.Time   `bson:"audittime" json:"audittime"`
	ServiceName   string      `bson:"servicename" json:"servicename"`
	APIName       string      `bson:"apiname" json:"apiname"`
	Payload       interface{} `bson:"payload" json:"payload"`
	Status        int         `bson:"status" json:"status"`
	StatusMessage string      `bson:"statusmessage" json:"statusmessage"`
}

// List Admin
type ListAdmin struct {
	AdminName     string    `json:"adminname" bson:"adminname"`
	AdminID       string    `json:"adminid" bson:"adminid"`
	Email         string    `json:"email" bson:"email"`
	IP_Address    string    `json:"ip" bson:"ip"`
	WrongInput    int       `json:"wronginput" bson:"wronginput"`
	LoginTime     time.Time `json:"logintime" bson:"logintime"`
	CreatedTime   time.Time `json:"createdtime" bson:"createdtime"`
	CanDeleteData bool      `json:"candelete" bson:"candelete"`
	CanUpdateData bool      `json:"canupdate" bson:"canupdate"`
	CanAlterAdmin bool      `json:"canalteradmin" bson:"canalteradmin"`
	CreatedBy     string    `json:"createdby" bson:"createdby"`
	IsBlocked     bool      `json:"isblocked" bson:"isblocked"`
	IsApproved    bool      `json:"isapproved,omitempty" bson:"isapproved,omitempty"`
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Data Needed for Admin Page
type AdminPageData struct {
	UserCount        int64 `json:"usercount" bson:"usercount"`
	SellerCount      int64 `json:"sellercount" bson:"sellercount"`
	ProductCount     int64 `json:"productcount" bson:"productount"`
	SalesCount       int64 `json:"salescount" bson:"salescount"`
	TotalSalesAmount int32 `json:"totalsalesamount" bson:"totalsalesamount"`
}

// Data Needed for Admin Page -- > Need To Combine Both
type Sales struct {
	TotalSalesAmount int `bson:"totalsalesamount"`
	TotalNoOfSales   int `bson:"totalnoofsales"`
}

// Create Worker
type Workers struct {
	UserName string `bson:"username" json:"username"`
	Email    string `bson:"email" json:"email"`
	Role     string `bson:"role" json:"role"`
	No       string `bson:"no" json:"no"`
	Salary   int64  `bson:"salary" json:"salary"`
	Status   string `bson:"status" json:"status"`
	Image    string `bson:"image" json:"image"`
}

// Get Every Single Data
type Getdata struct {
	Id         string `json:"id" bson:"id"`
	Collection string `json:"collection" bson:"collection"`
}

// Single Data Returing Structure
type ReturnData struct {
	// worker
	UserName string `bson:"username" json:"username"`
	Role     string `bson:"role" json:"role"`
	No       string `bson:"no" json:"no"`
	Salary   int64  `bson:"salary" json:"salary"`
	Status   string `bson:"status" json:"status"`
	// inventory

	ItemCategory    string  `json:"itemcategory" bson:"itemcategory"`
	ItemName        string  `json:"itemname" bson:"itemname"`
	Price           float64 `json:"price" bson:"price"`
	Quantity        string  `json:"quantity" bson:"quantity"`
	Stock_Available int32   `json:"sellerquantity" bson:"sellerquantity"`
	// seller

	Seller_Email string `json:"selleremail" bson:"selleremail"`
	//customer
	CustomerId         string `json:"customerid" bson:"customerid"`
	Name               string `json:"name" bson:"name"`
	IsEmailVerified    bool   `json:"isemailverified" bson:"isemailverified"`
	WrongInput         int    `json:"wronginput" bson:"wronginput"`
	VerificationString string `json:"verification" bson:"verification"`
	BlockedUser        bool   `json:"blockeduser" bson:"blockeduser"`
	//common feilds

	Seller_Name     string `json:"sellername" bson:"sellername"`
	Image           string `json:"image" bson:"image"`
	Email           string `json:"email" bson:"email"`
	SellerId        string `json:"sellerid" bson:"sellerid"`
	Address         string `json:"address" bson:"address"`
	Phone_No        int    `json:"phonenumber" bson:"phonenumber"`
	Password        string `json:"password" bson:"password"`
	ConfirmPassword string `json:"confirmpassword" bson:"confirmpassword"`
}

// Upload Event to Calender
type UploadCalender struct {
	AdminEmail string   `json:"email" bson:"email"`
	Title      string   `json:"title" bson:"title"`
	Start      string   `json:"start" bson:"start"`
	End        string   `json:"end" bson:"end"`
	Todos      []string `json:"todos" bson:"todos"`
}

// Input to Get Email
type GetCalender struct {
	AdminEmail string `json:"email" bson:"email"`
}

// Block User
type Block struct {
	Email      string `json:"email" bson:"email"`
	Collection string `json:"collection" bson:"collection"`
}

// ShutDown
type ShutDown struct {
	Token    string `json:"token" bson:"token"`
	Password string `json:"password" bson:"password"`
}

// ApproveSeller
type ApproveSeller struct {
	Token    string `json:"token" bson:"token"`
	Sellerid string `json:"sellerid" bson:"sellerid"`
}
