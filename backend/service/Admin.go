package service

import (
	"context"
	"log"
	"mithuorganics/config"
	"mithuorganics/constants"
	dto "mithuorganics/dto"
	"mithuorganics/models"
	"time"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

)

// Admin Login
func AdminLogin(login dto.AdminLoginRequest) dto.AdminLoginResponse {
	log.Println( !IsValidEmail(login.Email) , len(login.Password) <= 5 , !IsValidIP(login.IP_Address) , !IsValidTOTP(login.TOTP))
	if !IsValidEmail(login.Email) || len(login.Password) <= 5 || !IsValidIP(login.IP_Address) || !IsValidTOTP(login.TOTP) {
		var response dto.AdminLoginResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Wrong Input Data"
		response.LoginTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AdminLogin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "INVALID INPUT"
		login.Password = ""
		audit.Payload = login
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response

	}
	var correctdata models.Admin
	filter := bson.M{"email": login.Email}
	err := config.Admin_Collection.FindOne(context.Background(), filter).Decode(&correctdata)
	if err != nil {

		var response dto.AdminLoginResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Wrong Username or Password"
		response.Error = err
		response.LoginTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AdminLogin"
		audit.AdminID = "NOT FOUND"
		audit.Error = err
		audit.Message = "ADMIN EMAIL NOT FOUND BUT TRIED TO LOGIN"
		login.Password = ""
		audit.Payload = login
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	if correctdata.IsBlocked {
		var response dto.AdminLoginResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "You are not allowed to login"
		response.LoginTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AdminLogin"
		audit.AdminID = correctdata.AdminID
		audit.Message = "ADMIN ID BLOCKED BUT TRIED TO LOGIN"
		login.Password = ""
		audit.Payload = login
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	if correctdata.WrongInput == 4 {
		var response dto.AdminLoginResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Maximum no of Try Reached"
		response.LoginTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AdminLogin"
		audit.AdminID = correctdata.AdminID
		audit.Message = "MAXIMUM NO OF TRY REACHED"
		login.Password = ""
		audit.Payload = login
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	if !correctdata.IsApproved{
		var response dto.AdminLoginResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "You are not approved yet"
		response.LoginTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AdminLogin"
		audit.AdminID = correctdata.AdminID
		audit.Message = "ADMIN IS NOT APPROVED YET BUT TRIED TO LOGIN BY " + login.Email 
		login.Password = ""
		audit.Payload = login
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}
	if correctdata.IP_Address != login.IP_Address {

		var response dto.AdminLoginResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "It's not your Valid IP to Login"
		response.LoginTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AdminLogin"
		audit.AdminID = correctdata.AdminID
		audit.Message = "NOT A VALID IP TO LOGIN"
		login.Password = ""
		audit.Payload = login
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)

		correctdata.WrongInput++
		update := bson.M{"$set": bson.M{"wronginput": correctdata.WrongInput}}
		config.Admin_Collection.UpdateOne(context.Background(), filter, update)
		return response

	}
	if (correctdata.Password) != HashAdminPassword(login.Password) {
		var response dto.AdminLoginResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Wrong Username or Password"
		response.LoginTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AdminLogin"
		audit.AdminID = correctdata.AdminID
		audit.Message = "INCORRECT PASSWORD"
		login.Password = ""
		audit.Payload = login
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		correctdata.WrongInput++
		update := bson.M{"$set": bson.M{"wronginput": correctdata.WrongInput}}
		config.Admin_Collection.UpdateOne(context.Background(), filter, update)
		return response

	}

	if false && !ValidateOTP(login.TOTP, correctdata.SecretKey) {
		var response dto.AdminLoginResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Invalid TOTP"
		response.LoginTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AdminLogin"
		audit.AdminID = correctdata.AdminID
		audit.Message = "INCORRECT TOTP"
		login.Password = ""
		audit.Payload = login
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)

		correctdata.WrongInput++
		update := bson.M{"$set": bson.M{"wronginput": correctdata.WrongInput}}
		config.Admin_Collection.UpdateOne(context.Background(), filter, update)
		return response

	}

	token, err := CreateToken(dto.AdminTokenData{AdminID: correctdata.AdminID, Email: login.Email}, []byte(correctdata.PrivateKey), 1, constants.AdminTokenKey)
	if err != nil {
		var response dto.AdminLoginResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Error while Processing"
		response.Error = err
		response.LoginTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AdminLogin"
		audit.AdminID = correctdata.AdminID
		audit.Message = "ERROR IN CREATING TOKEN"
		login.Password = ""
		audit.Payload = login
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		audit.Error = err

		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ERROR IN CREATING TOKEN"
		go DeveloperAudit(dev)
		go AdminAudit(audit)

		return response

	}
	var response dto.AdminLoginResponse
	response.StatusCode = "200"
	response.Status = "SUCCESS"
	response.Message = "Login Successfull"
	response.AdminName = correctdata.AdminName
	response.PublicKey = correctdata.PublicKey
	response.Token = token
	response.Email  = correctdata.Email
	response.CanDelete = correctdata.CanDeleteData
	response.CanAlterAdmin  = correctdata.CanAlterAdmin
	response.CanUpdate = correctdata.CanUpdateData
	response.LoginTime = time.Now()

	update := bson.M{
		"$set": bson.M{
			"wronginput": 0,
			"logintime":  time.Now(),
			"token":      token,
		},
	}

	_, err = config.Admin_Collection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		var audit models.AdminAudit
		audit.APIName = "AdminLogin"
		audit.AdminID = correctdata.AdminID
		audit.Message = "ERROR IN UPDATING LOGIN TIME & NO OF WRONG INPUT"
		login.Password = ""
		audit.Payload = login
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		audit.Error = err
		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ERROR IN UPDATEING DATA IN ADMIN COLLECTION"
		go DeveloperAudit(dev)
		go AdminAudit(audit)

	}

	var audit models.AdminAudit
	audit.APIName = "AdminLogin"
	audit.AdminID = correctdata.AdminID
	audit.Message = "LOGIN SUCCESSFULL"
	login.Password = ""
	audit.Payload = login
	audit.ServiceName = "Admin"
	audit.Status = 200
	audit.StatusMessage = "SUCCESS"

	go AdminAudit(audit)

	return response
}

// Create Admin
func CreateAdmin(admin dto.CreateAdminRequest) dto.CreateAdminResponse {
	log.Println(len(admin.FromAdminToken) < 20, len(admin.FromAdminPublicKey) < 30, len(admin.AdminName) <= 4, !IsValidEmail(admin.Email), !IsValidIP(admin.IP_Address), len(admin.Password) <= 5, len(admin.ConfirmPassword) <= 5, len(admin.Password) != len(admin.ConfirmPassword))
	if len(admin.FromAdminToken) < 20 || len(admin.FromAdminPublicKey) < 30 || len(admin.AdminName) <= 4 || !IsValidEmail(admin.Email) || !IsValidIP(admin.IP_Address) || len(admin.Password) <= 5 || len(admin.ConfirmPassword) <= 5 || len(admin.Password) != len(admin.ConfirmPassword) {
		var response dto.CreateAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Wrong Input Data"
		response.CreatingTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AddAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "INVALID INPUT"
		admin.Password = ""
		admin.ConfirmPassword = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}
	id, err := ExtractID(admin.FromAdminToken, []byte(admin.FromAdminPublicKey), "adminid", constants.AdminTokenKey)
	if err != nil {
		var response dto.CreateAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Login Expired"
		response.CreatingTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AddAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "LOGIN EXPIRED"
		admin.Password = ""
		admin.ConfirmPassword = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response

	}
	var fromAdmin models.Admin
	filter := bson.M{"adminid": id}
	projection := bson.M{
		"_id":           0,
		"adminid":       1,
		"adminname":     1,
		"email":         1,
		"canalteradmin": 1,
		"isblocked":     1,
	}
	options := options.FindOne().SetProjection(projection)
	err = config.Admin_Collection.FindOne(context.Background(), filter, options).Decode(&fromAdmin)
	if err != nil {
		var response dto.CreateAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Error in Creating"
		response.CreatingTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AddAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "ERROR IN FINDING ADMIN"
		admin.Password = ""
		admin.ConfirmPassword = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ERROR WHILE FINDING DATA OF ADMIN WITH ADMINID BUT HAS TOKEN"

		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response
	}
	if fromAdmin.IsBlocked {
		var response dto.CreateAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Your ID has been Blocked"
		response.CreatingTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AddAdmin"
		audit.AdminID = fromAdmin.AdminID
		audit.Message = "ADMIN ID HAS BEEN BLOCKED BUT TRYIED TO CREATE ADMIN"
		admin.Password = ""
		admin.ConfirmPassword = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ADMINID HAS BEEN BLOCKED BUT GOT TOKEN"

		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response

	}

	if !fromAdmin.CanAlterAdmin {
		var response dto.CreateAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Access Denied"
		response.CreatingTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AddAdmin"
		audit.AdminID = fromAdmin.AdminID
		audit.Message = "ADMIN DONT HAVE ACCESS TO CREATE , BUT TRY TO CREATE ANOTHER ADMIN"
		admin.Password = ""
		admin.ConfirmPassword = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)

		return response
	}
	if admin.Password != admin.ConfirmPassword {
		var response dto.CreateAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Password Mismatch"
		response.CreatingTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AddAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "PASSWORD & CONFIRM PASSWORD MISMATCH"
		admin.Password = ""
		admin.ConfirmPassword = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	admindata := models.Admin{
		AdminName:     admin.AdminName,
		AdminID:       GenerateUniqueAdminID(),
		Email:         admin.Email,
		Password:      HashAdminPassword(admin.Password),
		IP_Address:    admin.IP_Address,
		WrongInput:    0,
		LoginTime:     time.Time{},
		CreatedTime:   time.Now(),
		CanDeleteData: admin.CanDeleteData,
		CanUpdateData: admin.CanUpdateData,
		CanAlterAdmin: admin.CanAlterAdmin,
		CreatedBy:     fromAdmin.AdminID,
		IsBlocked:     false,
		Token:         "",
		IsApproved: false,
	}
	if fromAdmin.Email == constants.AdminEmail{
		admindata.IsApproved = true
	}
	pvt, pub, err := GenerateRSAKeyPair()
	if err != nil {
		var response dto.CreateAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Error while Processing"
		response.CreatingTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AddAdmin"
		audit.AdminID = fromAdmin.AdminID
		audit.Message = "ERROR IN GENERATING PUBLIC & PRIVATE KEY"
		admin.Password = ""
		admin.ConfirmPassword = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ERROR IN GENERATING PUBLIC & PRIVATE KEY"

		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response
	}
	admindata.PrivateKey = string(pvt)
	admindata.PublicKey = string(pub)
	seceret, err := GenerateSecret()
	if err != nil {
		var response dto.CreateAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Error while Processing"
		response.CreatingTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AddAdmin"
		audit.AdminID = admindata.AdminID
		audit.Message = "ERROR IN GENERATING TOTP SECERET KEY FOR ADMIIN"
		admin.Password = ""
		admin.ConfirmPassword = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ERROR IN TOTP GENERATION"

		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response
	}
	admindata.SecretKey = seceret

	filter = bson.M{
		"$or": []bson.M{
			{"email": admindata.Email},
			{"adminid": admindata.AdminID},
		},
	}

	result := config.Admin_Collection.FindOne(context.Background(), filter)
	if result.Err() == nil {
		var response dto.CreateAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Admin Already exists"
		response.CreatingTime = time.Now()

		var audit models.AdminAudit
		fromAdmin.Password = ""
		audit.APIName = "AddAdmin"
		audit.AdminID = fromAdmin.AdminID
		audit.Error = err
		audit.Message = "ADMIN WITH EMIAL & ADMINID ALREADY EXISTS"
		audit.Payload = fromAdmin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"
		go AdminAudit(audit)
		return response
	} else {
		_, err = config.Admin_Collection.InsertOne(context.Background(), admindata)
		if err != nil {
			var response dto.CreateAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Error while Creating"
			response.CreatingTime = time.Now()

			var audit models.AdminAudit
			audit.APIName = "AddAdmin"
			audit.AdminID = admindata.AdminID
			audit.AuditID = GenerateUniqueAuditID()
			audit.AuditTime = time.Now()
			audit.Error = err
			audit.Message = "ERROR IN CREATING NEW ADMIN"
			admin.Password = ""
			audit.Payload = admin
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			go AdminAudit(audit)
			var dev models.DeveloperAudit
			dev.Audit = audit
			dev.IsCleared = false
			dev.Message = "ERROR IN INSERTING ADMIN TO DB"
			go DeveloperAudit(dev)
			return response
		}
		var response dto.CreateAdminResponse
		response.StatusCode = "200"
		response.Status = "SUCCESS"
		response.Message = "Admin Created Successfully"
		response.CreatingTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "AddAdmin"
		audit.AdminID = admindata.AdminID
		audit.Error = err
		audit.Message = "ADMIN CREATED SUCCESSFULLY " + fromAdmin.Email
		admin.Password = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "SUCCESS"
		//go SendAdminInvitation(admin.Email, admin.AdminName, admin.Password, "https://anon.up.railway.app/admin/", admin.IP, key)
		go AdminAudit(audit)
		return response
	}
}

// List Admin
func ListAdmin(input dto.ListAdminRequest) dto.ListAdminResponse {
	if len(input.Token) < 20 || len(input.PublicKey) < 30 || (input.SearchBY == "" && input.SearchValue != "") || (input.SearchValue == "" && input.SearchBY != "") {
		var response dto.ListAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Wrong Input Data"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "INVALID INPUT"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}
	id, err := ExtractID(input.Token, []byte(input.PublicKey), "adminid", constants.AdminTokenKey)
	if err != nil {
		var response dto.ListAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Login Expired"
		response.Listedtime = time.Now()
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "ListAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "LOGIN EXPIRED"
		audit.Error = err
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)

		return response
	}
	var admin models.Admin
	filter := bson.M{"adminid": id}
	projection := bson.M{
		"_id":           0,
		"adminid":       1,
		"canalteradmin": 1,
		"isblocked":     1,
	}
	option := options.FindOne().SetProjection(projection)
	err = config.Admin_Collection.FindOne(context.Background(), filter, option).Decode(&admin)
	if err != nil {
		var response dto.ListAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Error in Listing"
		response.Listedtime = time.Now()
		response.Error = err
		var audit models.AdminAudit
		audit.APIName = "ListAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "ERROR WHILE PROCESSING"
		audit.Error = err
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ADMIN ID NOT FOUND IN DB BUT HAS TOKEN"

		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response
	}
	if admin.IsBlocked {
		var response dto.ListAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Your ID has been Blocked"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListAdmin"
		audit.AdminID = admin.AdminID
		audit.Message = "ADMIN ID HAS BEEN BLOCKED BUT TRYIED TO LIST ADMIN"
		admin.Password = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ADMINID HAS BEEN BLOCKED BUT GOT TOKEN"

		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response
	}
	if !admin.CanAlterAdmin {
		var response dto.ListAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Access Denied"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListAdmin"
		audit.AdminID = admin.AdminID
		audit.Message = "ADMIN DONT HAVE ACCESS TO ADMIN DATA , BUT TRY TO LIST ADMIN"
		admin.Password = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)

		return response
	}
	var data []models.ListAdmin
	query := bson.D{}

	if !input.FromDate.IsZero() || !input.ToDate.IsZero() {
		if input.ToDate.IsZero() {
			input.ToDate = time.Now()
		} else if input.FromDate.IsZero() {
			input.FromDate = time.Now().AddDate(-1, 0, 0)
		}
		query = append(query, bson.E{Key: "createdtime", Value: bson.M{"$gte": input.FromDate, "$lte": input.ToDate}})
		log.Println("In time Query")
	}
	if input.IsBlocked == "TRUE" {
		query = append(query, bson.E{Key: "isblocked", Value: true})
	} else if input.IsBlocked == "FALSE" {
		query = append(query, bson.E{Key: "isblocked", Value: false})
	}

	if input.CanUpdate == "TRUE" {
		query = append(query, bson.E{Key: "canupdate", Value: true})
	} else if input.CanUpdate == "FALSE" {
		query = append(query, bson.E{Key: "canupdate", Value: false})
	}

	if input.CanDelete == "TRUE" {
		query = append(query, bson.E{Key: "candelete", Value: true})
	} else if input.CanDelete == "FALSE" {
		query = append(query, bson.E{Key: "candelete", Value: false})
	}

	if input.CanAlterAdmin == "TRUE" {
		query = append(query, bson.E{Key: "canalteradmin", Value: true})
	} else if input.CanAlterAdmin == "FALSE" {
		query = append(query, bson.E{Key: "canalteradmin", Value: false})
	}

	if input.SearchBY != "" && input.SearchValue != "" {
		query = append(query, bson.E{Key: input.SearchBY, Value: input.SearchValue})
	}

	findOptions := options.Find()
	if input.SortBy != "" {
		sort := bson.D{{Key: input.SortBy, Value: input.SortOrder}}
		findOptions.SetSort(sort)
	} else {
		sort := bson.D{{Key: "createdtime", Value: -1}}
		findOptions.SetSort(sort)
	}

	if input.NoofData == 0 {
		input.NoofData = 10
	}

	cursor, err := config.Admin_Collection.Find(context.Background(), query, findOptions)
	if err != nil {
		var response dto.ListAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Error while Listing"
		response.Listedtime = time.Now()
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "ListAdmin"
		audit.AdminID = admin.AdminID
		audit.Message = "ERROR WHILE LISTING DATA OF ADMIN"
		admin.Password = ""
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		audit.Error = err

		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ERROR WHILE LISTING DATA OF ADMIN"

		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response
	}
	for cursor.Next(context.Background()) {

		if input.NoofData == 0 {
			break
		}
		input.NoofData--
		var admindata models.ListAdmin
		err = cursor.Decode(&admindata)
		if err != nil {
			var response dto.ListAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Error while Listing"
			response.Listedtime = time.Now()
			response.Error = err

			var audit models.AdminAudit
			audit.APIName = "ListAdmin"
			audit.AdminID = admin.AdminID
			audit.Message = "ERROR WHILE LISTING DATA OF ADMIN"
			admin.Password = ""
			audit.Payload = input
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"
			audit.Error = err

			var dev models.DeveloperAudit
			dev.Audit = audit
			dev.Message = "ERROR WHILE DECODING DATA OF ADMIN"

			go AdminAudit(audit)
			go DeveloperAudit(dev)
			return response
		}
		data = append(data, admindata)

	}

	response := dto.ListAdminResponse{
		Status:     "SUCCESS",
		StatusCode: "200",
		Message:    "Listed Successfully",
		Listedtime: time.Now(),
		Data:       data,
	}

	var audit models.AdminAudit
	audit.APIName = "ListAdmin"
	audit.AdminID = admin.AdminID
	audit.Message = "LISTED SUCCESSFULLY BY " + admin.Email
	audit.Payload = input
	audit.ServiceName = "Admin"
	audit.Status = 200
	audit.StatusMessage = "SUCCESS"
	audit.Error = err
	go AdminAudit(audit)

	return response
}

// Delete Admin
func DeleteAdmin(input dto.DeleteAdminRequest) dto.DeleteAdminResponse {

	if len(input.Token) < 20 || len(input.PublicKey) < 30 || !IsValidEmail(input.Email) || len(input.Reason) < 10 {
		var response dto.DeleteAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Wrong Input Data"
		response.DeletedTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "DeleteAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "INVALID INPUT"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	if input.Email == constants.AdminEmail {
		var response dto.DeleteAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "You can not Delete Super Admin"
		response.DeletedTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "DeleteAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "TRYIED TO DELETE SUPER ADMIN"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	id, err := ExtractID(input.Token, []byte(input.PublicKey), "adminid", constants.AdminTokenKey)
	if err != nil {
		var response dto.DeleteAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Login Expired"
		response.DeletedTime = time.Now()
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "DeleteAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "LOGIN EXPIRED"
		audit.Error = err
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)

		return response
	}
	var admin models.Admin
	filter := bson.M{"adminid": id}
	projection := bson.M{
		"_id":           0,
		"adminid":       1,
		"adminname":     1,
		"canalteradmin": 1,
		"isblocked":     1,
		"email":         1,
	}
	option := options.FindOne().SetProjection(projection)
	err = config.Admin_Collection.FindOne(context.Background(), filter, option).Decode(&admin)
	if err != nil {
		var response dto.DeleteAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Error in Deleting"
		response.DeletedTime = time.Now()
		response.Error = err
		var audit models.AdminAudit
		audit.APIName = "DeleteAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "ERROR WHILE PROCESSING"
		audit.Error = err
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ADMIN ID NOT FOUND IN DB BUT HAS TOKEN"

		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response
	}
	if admin.Email == input.Email {
		var response dto.DeleteAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "You can not Delete YourSelf"
		response.DeletedTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "DeleteAdmin"
		audit.AdminID = id
		audit.Message = "ADMIN TRYIED TO DELETE SAME ADMIN"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}
	if admin.IsBlocked {
		var response dto.DeleteAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Your ID has been Blocked"
		response.DeletedTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "DeleteAdmin"
		audit.AdminID = admin.AdminID
		audit.Message = "ADMIN ID HAS BEEN BLOCKED BUT TRYIED TO DELETE ADMIN"
		admin.Password = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ADMINID HAS BEEN BLOCKED BUT GOT TOKEN"

		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response
	}
	if !admin.CanAlterAdmin {
		var response dto.DeleteAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Access Denied"
		response.DeletedTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "DeleteAdmin"
		audit.AdminID = admin.AdminID
		audit.Message = "ADMIN DONT HAVE ACCESS TO ADMIN DATA , BUT TRY TO DELETE ADMIN"
		admin.Password = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)

		return response
	}
	var deletingadmin models.Admin
	filter = bson.M{"email": input.Email}
	err = config.Admin_Collection.FindOne(context.Background(), filter).Decode(&deletingadmin)
	if err != nil {
		var response dto.DeleteAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Email not found"
		response.DeletedTime = time.Now()
		response.Error = err
		var audit models.AdminAudit
		audit.APIName = "DeleteAdmin"
		audit.AdminID = id
		audit.Message = "ERROR ADMIN WITH THE GIVEN EMAIL NOT FOUND"
		audit.Error = err
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)

		return response
	}
	var deleteAdminDb models.DeletedAdmin
	deleteAdminDb.DeleteID = GenerateUniqueDeleteID()
	deleteAdminDb.DeletedTime = time.Now()
	deleteAdminDb.Deleteddata = deletingadmin
	deleteAdminDb.DeleterEmail = admin.Email
	deleteAdminDb.DeleterID = id
	deleteAdminDb.DeleterName = admin.AdminName
	deleteAdminDb.Reason = input.Reason
	_, err = config.AdminDeleted_Collection.InsertOne(context.Background(), deleteAdminDb)
	if err != nil {
		var response dto.DeleteAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Error in Deleting"
		response.DeletedTime = time.Now()
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "DeleteAdmin"
		audit.AdminID = id
		audit.Message = "ERROR WHILE ADDING DATA TO DELETED ADMIN DATABASE"
		audit.Error = err
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ERROR WHILE INSERTING DATA TO DELETED ADMIN COLLECTION"
		go DeveloperAudit(dev)
		go AdminAudit(audit)
		return response
	}

	_, err = config.Admin_Collection.DeleteOne(context.Background(), filter)
	if err != nil {
		var response dto.DeleteAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Error in Deleting"
		response.DeletedTime = time.Now()
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "DeleteAdmin"
		audit.AdminID = id
		audit.Message = "ERROR WHILE DELETING DATA "
		audit.Error = err
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ERROR WHILE DELETING DATA IN ADMIN COLLECTION"
		go DeveloperAudit(dev)
		go AdminAudit(audit)
		return response
	}

	var response dto.DeleteAdminResponse
	response.StatusCode = "200"
	response.Status = "SUCCESS"
	response.Message = "Admin Deleted Successfully"
	response.DeletedTime = time.Now()

	var audit models.AdminAudit
	audit.APIName = "DeleteAdmin"
	audit.AdminID = id
	audit.Message = "DELETED SUCCESSFULLY BY " + admin.Email
	audit.Payload = input
	audit.ServiceName = "Admin"
	audit.Status = 200
	audit.StatusMessage = "SUCCESS"

	go AdminAudit(audit)
	return response
}

// Edit Admin
func EditAdmin(input dto.EditAdminRequest) dto.EditAdminResponse {
	if len(input.Token) < 20 || len(input.PublicKey) < 30 || !IsValidEmail(input.Email) || len(input.Reason) < 10 || len(input.UpdateFeild) < 1 || input.UpdateValue == "" {
		var response dto.EditAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Wrong Input Data"
		response.EditedTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "EditAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "INVALID INPUT"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	if input.UpdateFeild == "adminname" || input.UpdateFeild == "ip" || input.UpdateFeild == "wronginput" || input.UpdateFeild == "candelete" || input.UpdateFeild == "canupdate" || input.UpdateFeild == "canalteradmin" {

		if input.Email == constants.AdminEmail {
			var response dto.EditAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "You can not Edit Super Admin"
			response.EditedTime = time.Now()

			var audit models.AdminAudit
			audit.APIName = "EditAdmin"
			audit.AdminID = "NOT FOUND"
			audit.Message = "TRYIED TO EDIT SUPER ADMIN"
			audit.Payload = input
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			go AdminAudit(audit)
			return response
		}

		id, err := ExtractID(input.Token, []byte(input.PublicKey), "adminid", constants.AdminTokenKey)
		if err != nil {
			var response dto.EditAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Login Expired"
			response.EditedTime = time.Now()
			response.Error = err

			var audit models.AdminAudit
			audit.APIName = "EditAdmin"
			audit.AdminID = "NOT FOUND"
			audit.Message = "LOGIN EXPIRED"
			audit.Error = err
			audit.Payload = input
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			go AdminAudit(audit)

			return response
		}
		var admin models.Admin
		filter := bson.M{"adminid": id}
		projection := bson.M{
			"_id":           0,
			"adminid":       1,
			"adminname":     1,
			"canalteradmin": 1,
			"isblocked":     1,
			"email":         1,
		}
		option := options.FindOne().SetProjection(projection)
		err = config.Admin_Collection.FindOne(context.Background(), filter, option).Decode(&admin)
		if err != nil {
			var response dto.EditAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Error in Editing"
			response.EditedTime = time.Now()
			response.Error = err
			var audit models.AdminAudit
			audit.APIName = "EditAdmin"
			audit.AdminID = "NOT FOUND"
			audit.Message = "ERROR WHILE EDITING"
			audit.Error = err
			audit.Payload = input
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			var dev models.DeveloperAudit
			dev.Audit = audit
			dev.Message = "ADMIN ID NOT FOUND IN DB BUT HAS TOKEN"

			go AdminAudit(audit)
			go DeveloperAudit(dev)
			return response
		}
		if admin.Email == input.Email {
			var response dto.EditAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "You can not Edit YourSelf"
			response.EditedTime = time.Now()

			var audit models.AdminAudit
			audit.APIName = "EditAdmin"
			audit.AdminID = id
			audit.Message = "ADMIN TRYIED TO EDIT SAME ADMIN"
			audit.Payload = input
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			go AdminAudit(audit)
			return response
		}
		if admin.IsBlocked {
			var response dto.EditAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Your ID has been Blocked"
			response.EditedTime = time.Now()

			var audit models.AdminAudit
			audit.APIName = "EditAdmin"
			audit.AdminID = admin.AdminID
			audit.Message = "ADMIN ID HAS BEEN BLOCKED BUT TRYIED TO EDIT ADMIN"
			admin.Password = ""
			audit.Payload = admin
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			var dev models.DeveloperAudit
			dev.Audit = audit
			dev.Message = "ADMINID HAS BEEN BLOCKED BUT GOT TOKEN"

			go AdminAudit(audit)
			go DeveloperAudit(dev)
			return response
		}
		if !admin.CanAlterAdmin {
			var response dto.EditAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Access Denied"
			response.EditedTime = time.Now()

			var audit models.AdminAudit
			audit.APIName = "EditAdmin"
			audit.AdminID = admin.AdminID
			audit.Message = "ADMIN DONT HAVE ACCESS TO ADMIN DATA , BUT TRY TO EDIT ADMIN"
			admin.Password = ""
			audit.Payload = admin
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			go AdminAudit(audit)

			return response
		}
		var editingadmin models.Admin
		filter = bson.M{"email": input.Email}
		projection = bson.M{
			"_id":             0,
			"adminid":         1,
			"canalteradmin":   1,
			"isblocked":       1,
			"email":           1,
			input.UpdateFeild: 1,
		}
		option = options.FindOne().SetProjection(projection)
		err = config.Admin_Collection.FindOne(context.Background(), filter, option).Decode(&editingadmin)
		if err != nil {
			var response dto.EditAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Email not found"
			response.EditedTime = time.Now()
			response.Error = err
			var audit models.AdminAudit
			audit.APIName = "EditAdmin"
			audit.AdminID = id
			audit.Message = "ERROR ADMIN WITH THE GIVEN EMAIL NOT FOUND"
			audit.Error = err
			audit.Payload = input
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			go AdminAudit(audit)

			return response
		}
		editdata := models.EditedAdmin{
			EditID:           GenerateUniqueEditID(),
			EditedByName:     admin.AdminName,
			EditedById:       admin.AdminID,
			EditedByEmail:    admin.Email,
			FeildUpdated:     input.UpdateFeild,
			NewValueUpdated:  input.UpdateValue,
			Reason:           input.Reason,
			AdminEditedID:    editingadmin.AdminID,
			AdminEditedEmail: editingadmin.Email,
			EditTime:         time.Now(),
		}
		if input.UpdateFeild == "adminname" {
			editdata.OldValue = editingadmin.AdminName
		} else if input.UpdateFeild == "ip" {
			editdata.OldValue = editingadmin.IP_Address
		} else if input.UpdateFeild == "wronginput" {
			editdata.OldValue = editingadmin.WrongInput
		} else if input.UpdateFeild == "canupdate" {
			editdata.OldValue = editingadmin.CanUpdateData
		} else if input.UpdateFeild == "candelete" {
			editdata.OldValue = editingadmin.CanDeleteData
		} else if input.UpdateFeild == "canalteradmin" {
			editdata.OldValue = editingadmin.CanAlterAdmin
		}
		_, err = config.AdminEdited_Collection.InsertOne(context.Background(), editdata)
		if err != nil {
			var response dto.EditAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Error in Editing"
			response.EditedTime = time.Now()
			response.Error = err

			var audit models.AdminAudit
			audit.APIName = "EditAdmin"
			audit.AdminID = id
			audit.Message = "ERROR WHILE ADDING DATA TO EDIT ADMIN DATABASE"
			audit.Error = err
			audit.Payload = input
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			var dev models.DeveloperAudit
			dev.Audit = audit
			dev.Message = "ERROR WHILE INSERTING DATA TO EDIT ADMIN COLLECTION"
			go DeveloperAudit(dev)
			go AdminAudit(audit)
			return response
		}

		filter = bson.M{"adminid": editingadmin.AdminID}
		update := bson.M{"$set": bson.M{input.UpdateFeild: input.UpdateValue}}
		options := options.Update()
		_, err = config.Admin_Collection.UpdateOne(context.Background(), filter, update, options)
		if err != nil {
			var response dto.EditAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Error in Editing"
			response.EditedTime = time.Now()
			response.Error = err

			var audit models.AdminAudit
			audit.APIName = "EditAdmin"
			audit.AdminID = id
			audit.Message = "ERROR WHILE UPDATING DATA"
			audit.Error = err
			audit.Payload = input
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			var dev models.DeveloperAudit
			dev.Audit = audit
			dev.Message = "ERROR WHILE UPDATING DATA IN ADMIN COLLECTION"
			go DeveloperAudit(dev)
			go AdminAudit(audit)
			filter = bson.M{"editid": editdata.EditID}
			_, err = config.AdminEdited_Collection.DeleteOne(context.Background(), editdata)
			if err != nil {
				var response dto.EditAdminResponse
				response.StatusCode = "200"
				response.Status = "FAILED"
				response.Message = "Error in Editing"
				response.EditedTime = time.Now()
				response.Error = err

				var audit models.AdminAudit
				audit.APIName = "EditAdmin"
				audit.AdminID = id
				audit.Message = "ERROR WHILE DELETING DATA IN EDIT ADMIN DB BECAUSE EDIT FAILED"
				audit.Error = err
				audit.Payload = input
				audit.ServiceName = "Admin"
				audit.Status = 200
				audit.StatusMessage = "FAILED"

				var dev models.DeveloperAudit
				dev.Audit = audit
				dev.Message = "ERROR WHILE DELETING DATA IN EDIT ADMIN COLLECTION BECAUSE EDIT ADMIN FAILED"
				go DeveloperAudit(dev)
				go AdminAudit(audit)
			}
			return response
		}
		var response dto.EditAdminResponse
		response.StatusCode = "200"
		response.Status = "SUCCESS"
		response.Message = "Edited Successfully"
		response.EditedTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "EditAdmin"
		audit.AdminID = id
		audit.Message = "EDITED SUCCESSFULLY BY " + admin.Email
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "SUCCESS"

		go AdminAudit(audit)

		return response
	} else {
		var response dto.EditAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Not allowed to update " + input.UpdateFeild
		response.EditedTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "EditAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "NOT ALLOWED TO UPDATE " + input.UpdateFeild
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}
}

// View Admin
func ViewAdmin(input dto.ViewAdminRequest) dto.ViewAdminResponse {
	if !IsValidEmail(input.AdminEmail) || len(input.Token) < 20 || len(input.PublicKey) < 30 {
		var response dto.ViewAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Wrong Input Data"
		response.ViewedTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ViewAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "INVALID INPUT"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	id, err := ExtractID(input.Token, []byte(input.PublicKey), "adminid", constants.AdminTokenKey)
	if err != nil {
		var response dto.ViewAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Login Expired"
		response.ViewedTime = time.Now()
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "ViewAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "LOGIN EXPIRED"
		audit.Error = err
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)

		return response
	}
	var admin models.Admin
	filter := bson.M{"adminid": id}
	projection := bson.M{
		"_id":           0,
		"adminid":       1,
		"adminname":     1,
		"canalteradmin": 1,
		"isblocked":     1,
		"email":         1,
	}
	option := options.FindOne().SetProjection(projection)
	err = config.Admin_Collection.FindOne(context.Background(), filter, option).Decode(&admin)
	if err != nil {
		var response dto.ViewAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Error in Viewing"
		response.ViewedTime = time.Now()
		response.Error = err
		var audit models.AdminAudit
		audit.APIName = "ViewAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "ERROR WHILE VIEWING"
		audit.Error = err
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ADMIN ID NOT FOUND IN DB BUT HAS TOKEN"

		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response
	}

	if admin.IsBlocked {
		var response dto.ViewAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Your ID has been Blocked"
		response.ViewedTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ViewAdmin"
		audit.AdminID = admin.AdminID
		audit.Message = "ADMIN ID HAS BEEN BLOCKED BUT TRYIED TO EDIT ADMIN"
		admin.Password = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ADMINID HAS BEEN BLOCKED BUT GOT TOKEN"

		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response
	}
	if !admin.CanAlterAdmin {
		var response dto.ViewAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Access Denied"
		response.ViewedTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ViewAdmin"
		audit.AdminID = admin.AdminID
		audit.Message = "ADMIN DONT HAVE ACCESS TO ADMIN DATA , BUT TRY TO VIEW ADMIN"
		admin.Password = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)

		return response
	}
	var response dto.ViewAdminResponse
	filter = bson.M{"email": input.AdminEmail}
	err = config.Admin_Collection.FindOne(context.Background(), filter).Decode(&response)
	if err != nil {
		var response dto.ViewAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "No Admin found with that email"
		response.ViewedTime = time.Now()
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "ViewAdmin"
		audit.AdminID = admin.AdminID
		audit.Message = "EMAIL NOT FOUND IN ADMIN DB"
		admin.Password = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
	}
	response.StatusCode = "200"
	response.Status = "SUCCESS"
	response.Message = "View Successfull"
	response.ViewedTime = time.Now()

	var audit models.AdminAudit
	audit.APIName = "ViewAdmin"
	audit.AdminID = admin.AdminID
	audit.Message = "VIEW SUCCESSFULL BY " + admin.Email
	admin.Password = ""
	audit.Payload = admin
	audit.ServiceName = "Admin"
	audit.Status = 200
	audit.StatusMessage = "SUCCESS"

	return response
}

// Block or Unblock Admin
func BlockorUnblockAdmin(input dto.BlockorUnblockAdminRequest) dto.BlockorUnblockAdminResponse {
	if !IsValidEmail(input.Email) || len(input.Token) < 20 || len(input.PublicKey) < 30 || !(input.BlockorUnblock == "BLOCK" || input.BlockorUnblock == "UNBLOCK") {
		var response dto.BlockorUnblockAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Wrong Input Data"
		response.BlockedorUnblockedTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "BlockAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "INVALID INPUT"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}
	if input.Email == constants.AdminEmail {
		var response dto.BlockorUnblockAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "You can not Block Super Admin"
		response.BlockedorUnblockedTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "BlockAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "TRYIED TO BLOCK SUPER ADMIN"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	id, err := ExtractID(input.Token, []byte(input.PublicKey), "adminid", constants.AdminTokenKey)
	if err != nil {
		var response dto.BlockorUnblockAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Login Expired"
		response.BlockedorUnblockedTime = time.Now()
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "BlockAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "LOGIN EXPIRED"
		audit.Error = err
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)

		return response
	}
	var admin models.Admin
	filter := bson.M{"adminid": id}
	projection := bson.M{
		"_id":           0,
		"adminid":       1,
		"adminname":     1,
		"canalteradmin": 1,
		"isblocked":     1,
		"email":         1,
	}
	option := options.FindOne().SetProjection(projection)
	err = config.Admin_Collection.FindOne(context.Background(), filter, option).Decode(&admin)
	if err != nil {
		var response dto.BlockorUnblockAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Error in Editing"
		response.BlockedorUnblockedTime = time.Now()
		response.Error = err
		var audit models.AdminAudit
		audit.APIName = "BlockAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "ERROR WHILE EDITING"
		audit.Error = err
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ADMIN ID NOT FOUND IN DB BUT HAS TOKEN"

		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response
	}
	if admin.Email == input.Email {
		var response dto.BlockorUnblockAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "You can not Block YourSelf"
		response.BlockedorUnblockedTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "BlockAdmin"
		audit.AdminID = id
		audit.Message = "ADMIN TRYIED TO BLOCK SAME ADMIN"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}
	if admin.IsBlocked {
		var response dto.BlockorUnblockAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Your ID has been Blocked"
		response.BlockedorUnblockedTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "BlockAdmin"
		audit.AdminID = admin.AdminID
		audit.Message = "ADMIN ID HAS BEEN BLOCKED BUT TRYIED TO BLOCK ADMIN"
		admin.Password = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ADMINID HAS BEEN BLOCKED BUT GOT TOKEN"

		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response
	}
	if !admin.CanAlterAdmin {
		var response dto.BlockorUnblockAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Access Denied"
		response.BlockedorUnblockedTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "BlockAdmin"
		audit.AdminID = admin.AdminID
		audit.Message = "ADMIN DONT HAVE ACCESS TO ADMIN DATA , BUT TRY TO BLOCK ADMIN"
		admin.Password = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)

		return response
	}
	var blockingadmin models.Admin
	filter = bson.M{"email": input.Email}
	projection = bson.M{
		"_id":           0,
		"adminid":       1,
		"adminname":     1,
		"canalteradmin": 1,
		"isblocked":     1,
		"email":         1,
	}
	option = options.FindOne().SetProjection(projection)
	err = config.Admin_Collection.FindOne(context.Background(), filter, option).Decode(&blockingadmin)
	if err != nil {
		var response dto.BlockorUnblockAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "No Admin found with that email"
		response.BlockedorUnblockedTime = time.Now()
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "BlockAdmin"
		audit.AdminID = admin.AdminID
		audit.Message = "EMAIL NOT FOUND IN ADMIN DB"
		admin.Password = ""
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		audit.Error = err

		go AdminAudit(audit)
		return response
	}
	if blockingadmin.IsBlocked && input.BlockorUnblock == "UNBLOCK" {
		blockData := models.BlockorUnblockAdmin{
			BlockID:                      GenerateUniqueBlockID(),
			BlockedorUnblockedByEmail:    admin.Email,
			BlockedorUnblockedByName:     admin.AdminName,
			BlockedorUnblockedByID:       admin.AdminID,
			BlockedorUnblockedAdminName:  blockingadmin.AdminName,
			BlockedorUnblockedAdminEmail: blockingadmin.Email,
			BlockedorUnblockedAdminId:    blockingadmin.AdminID,
			BlockedorUnBlocked:           "UNBLOCK",
			Reason:                       input.Reason,
			BlockedorUnblockedTime:       time.Now(),
		}
		_, err = config.AdminBlocked_Collection.InsertOne(context.Background(), blockData)
		if err != nil {
			var response dto.BlockorUnblockAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Error while UnBlocking"
			response.BlockedorUnblockedTime = time.Now()
			response.Error = err

			var audit models.AdminAudit
			audit.APIName = "BlockAdmin"
			audit.AdminID = admin.AdminID
			audit.Message = "PROBLEM IN ADDING DATA TO BLOCK ADMIN DATA BASE"
			audit.Payload = admin
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			audit.Error = err

			var dev models.DeveloperAudit
			dev.Audit = audit
			dev.Message = "THERE IS SOME ERROR IN INSERTING DATA TO THE BLOCKED ADMIN COLLECTION"

			go DeveloperAudit(dev)
			go AdminAudit(audit)
			return response
		}
		filter = bson.M{"adminid": blockingadmin.AdminID}
		update := bson.M{"$set": bson.M{"isblocked": false}}
		options := options.Update()
		_, err = config.Admin_Collection.UpdateOne(context.Background(), filter, update, options)
		if err != nil {
			var response dto.BlockorUnblockAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Error while UnBlocking"
			response.BlockedorUnblockedTime = time.Now()
			response.Error = err

			var audit models.AdminAudit
			audit.APIName = "BlockAdmin"
			audit.AdminID = admin.AdminID
			audit.Message = "PROBLEM IN UNBLOCKING ADMIN"
			audit.Payload = admin
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			audit.Error = err

			var dev models.DeveloperAudit
			dev.Audit = audit
			dev.Message = "THERE IS SOME ERROR IN UPDATING DATA IN ADMIN COLLECTION"

			go DeveloperAudit(dev)
			go AdminAudit(audit)

			filter = bson.M{"blockid": blockData.BlockID}
			_, err = config.AdminBlocked_Collection.DeleteOne(context.Background(), filter)
			if err != nil {
				var audit models.AdminAudit
				audit.APIName = "BlockAdmin"
				audit.AdminID = admin.AdminID
				audit.Message = "PROBLEM IN UNBLOCKING ADMIN AND ALSO DELETEING THE DATA IN BLOCK ADMIN COLLECTION"
				audit.Payload = admin
				audit.ServiceName = "Admin"
				audit.Status = 200
				audit.StatusMessage = "FAILED"

				audit.Error = err

				var dev models.DeveloperAudit
				dev.Audit = audit
				dev.Message = "THERE IS SOME ERROR IN UPDATING DATA IN ADMIN COLLECTION & DELETEING THE DATA IN BLOCK ADMIN COLLECTION"

				go DeveloperAudit(dev)
				go AdminAudit(audit)

				return response
			}
			return response
		}
		response := dto.BlockorUnblockAdminResponse{
			Status:                 "SUCCESS",
			StatusCode:             "200",
			Message:                "ADMIN " + input.BlockorUnblock + " SUCCESSFULL",
			BlockedorUnblockedTime: time.Now(),
		}
		audit := models.AdminAudit{
			AdminID:     id,
			Message:     "ADMIN WITH EMAIL " + blockingadmin.Email + " HAS BEEN BLOCKED BY " + admin.Email,
			AuditTime:   time.Now(),
			ServiceName: "Admin",
			APIName:     "BLockorUnblockAdmin",
			Payload:     input,

			Status:        200,
			StatusMessage: "SUCCESS",
		}
		log.Println("In Cond 1")

		AdminAudit(audit)
		return response
	} else if !blockingadmin.IsBlocked && input.BlockorUnblock == "BLOCK" {
		log.Println("In Cond 2")
		blockData := models.BlockorUnblockAdmin{
			BlockID:                      GenerateUniqueBlockID(),
			BlockedorUnblockedByEmail:    admin.Email,
			BlockedorUnblockedByName:     admin.AdminName,
			BlockedorUnblockedByID:       admin.AdminID,
			BlockedorUnblockedAdminName:  blockingadmin.AdminName,
			BlockedorUnblockedAdminEmail: blockingadmin.Email,
			BlockedorUnblockedAdminId:    blockingadmin.AdminID,
			BlockedorUnBlocked:           "BLOCK",
			Reason:                       input.Reason,
			BlockedorUnblockedTime:       time.Now(),
		}
		_, err = config.AdminBlocked_Collection.InsertOne(context.Background(), blockData)
		if err != nil {
			var response dto.BlockorUnblockAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Error while Blocking"
			response.BlockedorUnblockedTime = time.Now()
			response.Error = err

			var audit models.AdminAudit
			audit.APIName = "BlockAdmin"
			audit.AdminID = admin.AdminID
			audit.Message = "PROBLEM IN ADDING DATA TO BLOCK ADMIN DATA BASE"
			audit.Payload = admin
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			audit.Error = err

			var dev models.DeveloperAudit
			dev.Audit = audit
			dev.Message = "THERE IS SOME ERROR IN INSERTING DATA TO THE BLOCKED ADMIN COLLECTION"

			go DeveloperAudit(dev)
			go AdminAudit(audit)
			return response
		}
		filter = bson.M{"adminid": blockingadmin.AdminID}
		update := bson.M{"$set": bson.M{"isblocked": true}}
		options := options.Update()
		_, err = config.Admin_Collection.UpdateOne(context.Background(), filter, update, options)
		if err != nil {
			var response dto.BlockorUnblockAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Error while Blocking"
			response.BlockedorUnblockedTime = time.Now()
			response.Error = err

			var audit models.AdminAudit
			audit.APIName = "BlockAdmin"
			audit.AdminID = admin.AdminID
			audit.Message = "PROBLEM IN BLOCKING ADMIN"
			audit.Payload = admin
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			audit.Error = err

			var dev models.DeveloperAudit
			dev.Audit = audit
			dev.Message = "THERE IS SOME ERROR IN UPDATING DATA IN ADMIN COLLECTION"

			go DeveloperAudit(dev)
			go AdminAudit(audit)

			filter = bson.M{"blockid": blockData.BlockID}
			_, err = config.AdminBlocked_Collection.DeleteOne(context.Background(), filter)
			if err != nil {
				var audit models.AdminAudit
				audit.APIName = "BlockAdmin"
				audit.AdminID = admin.AdminID
				audit.Message = "PROBLEM IN BLOCKING ADMIN AND ALSO DELETEING THE DATA IN BLOCK ADMIN COLLECTION"
				audit.Payload = admin
				audit.ServiceName = "Admin"
				audit.Status = 200
				audit.StatusMessage = "FAILED"

				audit.Error = err

				var dev models.DeveloperAudit
				dev.Audit = audit
				dev.Message = "THERE IS SOME ERROR IN UPDATING DATA IN ADMIN COLLECTION & DELETEING THE DATA IN BLOCK ADMIN COLLECTION"

				go DeveloperAudit(dev)
				go AdminAudit(audit)

				return response
			}
			return response
		}
		response := dto.BlockorUnblockAdminResponse{
			Status:                 "SUCCESS",
			StatusCode:             "200",
			Message:                "ADMIN " + input.BlockorUnblock + " SUCCESSFULL",
			BlockedorUnblockedTime: time.Now(),
		}
		audit := models.AdminAudit{
			AdminID:     id,
			Message:     "ADMIN WITH EMAIL " + blockingadmin.Email + " HAS BEEN BLOCKED BY " + admin.Email,
			AuditTime:   time.Now(),
			ServiceName: "Admin",
			APIName:     "BLockorUnblockAdmin",
			Payload:     input,

			Status:        200,
			StatusMessage: "SUCCESS",
		}
		go AdminAudit(audit)
		return response
	} else if blockingadmin.IsBlocked && input.BlockorUnblock == "BLOCK" {
		response := dto.BlockorUnblockAdminResponse{
			Status:                 "FAILED",
			StatusCode:             "200",
			Message:                "Admin is already blocked",
			BlockedorUnblockedTime: time.Now(),
		}
		audit := models.AdminAudit{
			AdminID:     id,
			Message:     "ADMIN WITH EMAIL " + blockingadmin.Email + " IS ALREADY BLOCKED BUT TRYIED TO BLOCK BY " + admin.Email,
			AuditTime:   time.Now(),
			ServiceName: "Admin",
			APIName:     "BLockorUnblockAdmin",
			Payload:     input,

			Status:        200,
			StatusMessage: "FAILED",
		}

		go AdminAudit(audit)
		return response
	} else {
		response := dto.BlockorUnblockAdminResponse{
			Status:                 "FAILED",
			StatusCode:             "200",
			Message:                "Admin is already Unblocked",
			BlockedorUnblockedTime: time.Now(),
		}
		audit := models.AdminAudit{
			AdminID:     id,
			Message:     "ADMIN WITH EMAIL " + blockingadmin.Email + " IS ALREADY UNBLOCKED BUT TRYIED TO BLOCK BY " + admin.Email,
			AuditTime:   time.Now(),
			ServiceName: "Admin",
			APIName:     "BLockorUnblockAdmin",
			Payload:     input,

			Status:        200,
			StatusMessage: "FAILED",
		}

		go AdminAudit(audit)
		return response

	}
}

// List Admin Audit
func ListAdminAudit(input dto.ListAdminAuditRequest) dto.ListAdminAuditResponse {
	if len(input.Token) < 20 || len(input.PublicKey) < 30 {
		var response dto.ListAdminAuditResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Wrong Input Data"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListAdminAudit"
		audit.AdminID = "NOT FOUND"
		audit.Message = "INVALID INPUT"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}
	email, err := ExtractID(input.Token, []byte(input.PublicKey), "email", constants.AdminTokenKey)
	if err != nil {
		var response dto.ListAdminAuditResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Login Expired"
		response.Listedtime = time.Now()
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "ListAdminAudit"
		audit.AdminID = "NOT FOUND"
		audit.Message = "LOGIN EXPIRED"
		audit.Error = err
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)

		return response
	}
	if email != constants.AdminEmail {
		var response dto.ListAdminAuditResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Access Denied"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListAdminAudit"
		audit.AdminID = "NOT FOUND"
		audit.Message = "TRYIED TO ACCESS LIST ADMIN AUDIT BUT NOT A SUPER ADMIN BY " + email
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	query := bson.D{}

	if !input.FromDate.IsZero() || !input.ToDate.IsZero() {
		if input.ToDate.IsZero() {
			input.ToDate = time.Now()
		} else if input.FromDate.IsZero() {
			input.FromDate = time.Now().AddDate(-1, 0, 0)
		}
		query = append(query, bson.E{Key: "audittime", Value: bson.M{"$gte": input.FromDate, "$lte": input.ToDate}})
		log.Println("In time Query")
	}

	if input.SearchBY != "" && input.SearchValue != "" {
		query = append(query, bson.E{Key: input.SearchBY, Value: input.SearchValue})
	}

	findOptions := options.Find()
	if input.SortBy != "" {
		sort := bson.D{{Key: input.SortBy, Value: input.SortOrder}}
		findOptions.SetSort(sort)
	} else {
		sort := bson.D{{Key: "audittime", Value: -1}}
		findOptions.SetSort(sort)
	}

	if input.NoofData == 0 {
		input.NoofData = 10
	}
	var listaudit []models.AdminAudit
	cursor, err := config.AdminAudit_Collection.Find(context.Background(), query, findOptions)
	if err != nil {
		var response dto.ListAdminAuditResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Error while Processing"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListAdminAudit"
		audit.AdminID = "SUPER ADMIN"
		audit.Message = "ERROR WHILE FETCHING DATA FROM AUDIT DB"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Message = "ERROR WHILE FETCHING DATA FROM AUDIT COLLECTION"
		dev.Audit = audit
		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response
	}
	defer cursor.Close(context.Background())
	for cursor.Next(context.Background()) {
		if input.NoofData == 0 {
			break
		}
		input.NoofData--
		var singleaudit models.AdminAudit
		err = cursor.Decode(&singleaudit)
		if err != nil {
			var response dto.ListAdminAuditResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Error while Processing"
			response.Listedtime = time.Now()

			var audit models.AdminAudit
			audit.APIName = "ListAdminAudit"
			audit.AdminID = "SUPER ADMIN"
			audit.Message = "ERROR WHILE PROCESSING LIST OF ADMIN AUDIT "
			audit.Payload = input
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			var dev models.DeveloperAudit
			dev.Message = "UNABLE TO DECODE AUDIT DATA IN AUDIT COLLECTION"
			dev.Audit = audit
			go AdminAudit(audit)
			go DeveloperAudit(dev)
			return response
		}
		listaudit = append(listaudit, singleaudit)

	}

	response := dto.ListAdminAuditResponse{
		Status:     "SUCCESS",
		StatusCode: "200",
		Message:    "List Successfull",
		Listedtime: time.Now(),
		Data:       listaudit,
	}

	var audit models.AdminAudit
	audit.APIName = "ListAdminAudit"
	audit.AdminID = "SUPER ADMIN"
	audit.Message = "LISTED SUCCESSFULL BY " + email
	audit.Payload = input
	audit.ServiceName = "Admin"
	audit.Status = 200
	audit.StatusMessage = "SUCCESS"

	go AdminAudit(audit)

	return response
}

// List Developer Audit
func ListDeveloperAudit(input dto.ListDeveloperAuditRequest) dto.ListDeveloperAuditResponse {
	if len(input.Token) < 20 || len(input.PublicKey) < 30 {
		var response dto.ListDeveloperAuditResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Wrong Input Data"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListDeveloperAudit"
		audit.AdminID = "NOT FOUND"
		audit.Message = "INVALID INPUT"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}
	email, err := ExtractID(input.Token, []byte(input.PublicKey), "email", constants.AdminTokenKey)
	if err != nil {
		var response dto.ListDeveloperAuditResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Login Expired"
		response.Listedtime = time.Now()
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "ListDeveloperAudit"
		audit.AdminID = "NOT FOUND"
		audit.Message = "LOGIN EXPIRED"
		audit.Error = err
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)

		return response
	}
	if email != constants.AdminEmail {
		var response dto.ListDeveloperAuditResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Access Denied"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListDeveloperAudit"
		audit.AdminID = "NOT FOUND"
		audit.Message = "TRYIED TO ACCESS LIST DEVELOPER AUDIT BUT NOT A SUPER ADMIN BY " + email
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	query := bson.D{}

	if !input.FromDate.IsZero() || !input.ToDate.IsZero() {
		if input.ToDate.IsZero() {
			input.ToDate = time.Now()
		} else if input.FromDate.IsZero() {
			input.FromDate = time.Now().AddDate(-1, 0, 0)
		}
		query = append(query, bson.E{Key: "errortime", Value: bson.M{"$gte": input.FromDate, "$lte": input.ToDate}})
		log.Println("In time Query")
	}

	if input.SearchBY != "" && input.SearchValue != "" {
		query = append(query, bson.E{Key: input.SearchBY, Value: input.SearchValue})
	}

	findOptions := options.Find()
	if input.SortBy != "" {
		sort := bson.D{{Key: input.SortBy, Value: input.SortOrder}}
		findOptions.SetSort(sort)
	} else {
		sort := bson.D{{Key: "errortime", Value: -1}}
		findOptions.SetSort(sort)
	}

	if input.NoofData == 0 {
		input.NoofData = 10
	}
	var listaudit []models.DeveloperAudit
	cursor, err := config.DeveloperAudit_Collection.Find(context.Background(), query, findOptions)
	if err != nil {
		var response dto.ListDeveloperAuditResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Error while Processing"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListDeveloperAudit"
		audit.AdminID = "SUPER ADMIN"
		audit.Message = "ERROR WHILE FETCHING DATA FROM DEVELOPER AUDIT DB"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Message = "ERROR WHILE FETCHING DATA FROM DEVELOPER AUDIT COLLECTION"
		dev.Audit = audit
		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response
	}
	defer cursor.Close(context.Background())
	for cursor.Next(context.Background()) {
		if input.NoofData == 0 {
			break
		}
		input.NoofData--
		var singleaudit models.DeveloperAudit
		err = cursor.Decode(&singleaudit)
		if err != nil {
			var response dto.ListDeveloperAuditResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Error while Processing"
			response.Listedtime = time.Now()

			var audit models.AdminAudit
			audit.APIName = "ListDeveloperAudit"
			audit.AdminID = "SUPER ADMIN"
			audit.Message = "ERROR WHILE PROCESSING LIST OF DEVELOPER AUDIT "
			audit.Payload = input
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			var dev models.DeveloperAudit
			dev.Message = "UNABLE TO DECODE AUDIT DATA IN DEVELOPER AUDIT COLLECTION"
			dev.Audit = audit
			go AdminAudit(audit)
			go DeveloperAudit(dev)
			return response
		}
		listaudit = append(listaudit, singleaudit)

	}

	response := dto.ListDeveloperAuditResponse{
		Status:     "SUCCESS",
		StatusCode: "200",
		Message:    "List Successfull",
		Listedtime: time.Now(),
		Data:       listaudit,
	}

	var audit models.AdminAudit
	audit.APIName = "ListDeveloperAudit"
	audit.AdminID = "SUPER ADMIN"
	audit.Message = "LISTED SUCCESSFULL"
	audit.Payload = input
	audit.ServiceName = "Admin"
	audit.Status = 200
	audit.StatusMessage = "SUCCESS"

	go AdminAudit(audit)

	return response
}

// List Edited Admin
func ListEditedAdmin(input dto.ListEditedAdminRequest) dto.ListEditedAdminResponse {
	if len(input.Token) < 20 || len(input.PublicKey) < 30 {
		var response dto.ListEditedAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Wrong Input Data"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListEditedAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "INVALID INPUT"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}
	email, err := ExtractID(input.Token, []byte(input.PublicKey), "email", constants.AdminTokenKey)
	if err != nil {
		var response dto.ListEditedAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Login Expired"
		response.Listedtime = time.Now()
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "ListEditedAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "LOGIN EXPIRED"
		audit.Error = err
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)

		return response
	}
	if email != constants.AdminEmail {
		var response dto.ListEditedAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Access Denied"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListEditedAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "TRYIED TO ACCESS LIST EDITED ADMIN DATA BUT NOT A SUPER ADMIN BY " + email
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	query := bson.D{}

	if !input.FromDate.IsZero() || !input.ToDate.IsZero() {
		if input.ToDate.IsZero() {
			input.ToDate = time.Now()
		} else if input.FromDate.IsZero() {
			input.FromDate = time.Now().AddDate(-1, 0, 0)
		}
		query = append(query, bson.E{Key: "edittime", Value: bson.M{"$gte": input.FromDate, "$lte": input.ToDate}})
		log.Println("In time Query")
	}

	if input.SearchBY != "" && input.SearchValue != "" {
		query = append(query, bson.E{Key: input.SearchBY, Value: input.SearchValue})
	}

	findOptions := options.Find()
	if input.SortBy != "" {
		sort := bson.D{{Key: input.SortBy, Value: input.SortOrder}}
		findOptions.SetSort(sort)
	} else {
		sort := bson.D{{Key: "edittime", Value: -1}}
		findOptions.SetSort(sort)
	}

	if input.NoofData == 0 {
		input.NoofData = 10
	}
	var listaudit []models.EditedAdmin
	cursor, err := config.AdminEdited_Collection.Find(context.Background(), query, findOptions)
	if err != nil {
		var response dto.ListEditedAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Error while Processing"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListEditedAdmin"
		audit.AdminID = "SUPER ADMIN"
		audit.Message = "ERROR WHILE FETCHING DATA FROM EDITED ADMIN DB"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Message = "ERROR WHILE FETCHING DATA FROM EDITED ADMIN COLLECTION"
		dev.Audit = audit
		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response
	}
	defer cursor.Close(context.Background())
	for cursor.Next(context.Background()) {
		if input.NoofData == 0 {
			break
		}
		input.NoofData--
		var singleaudit models.EditedAdmin
		err = cursor.Decode(&singleaudit)
		if err != nil {
			var response dto.ListEditedAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Error while Processing"
			response.Listedtime = time.Now()

			var audit models.AdminAudit
			audit.APIName = "ListEditedAdmin"
			audit.AdminID = "SUPER ADMIN"
			audit.Message = "ERROR WHILE PROCESSING LIST OF EDITED ADMIN "
			audit.Payload = input
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			var dev models.DeveloperAudit
			dev.Message = "UNABLE TO DECODE EDITED ADMIN DATA IN EDITED ADMIN COLLECTION"
			dev.Audit = audit
			go AdminAudit(audit)
			go DeveloperAudit(dev)
			return response
		}
		listaudit = append(listaudit, singleaudit)

	}

	response := dto.ListEditedAdminResponse{
		Status:     "SUCCESS",
		StatusCode: "200",
		Message:    "List Successfull",
		Listedtime: time.Now(),
		Data:       listaudit,
	}

	var audit models.AdminAudit
	audit.APIName = "ListEditedAdmin"
	audit.AdminID = "SUPER ADMIN"
	audit.Message = "LISTED SUCCESSFULL BY " + email
	audit.Payload = input
	audit.ServiceName = "Admin"
	audit.Status = 200
	audit.StatusMessage = "SUCCESS"

	go AdminAudit(audit)

	return response
}

// List Deleted Admin
func ListDeletedAdmin(input dto.ListDeletedAdminRequest) dto.ListDeletedAdminResponse {
	if len(input.Token) < 20 || len(input.PublicKey) < 30 {
		var response dto.ListDeletedAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Wrong Input Data"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListDeletedAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "INVALID INPUT"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}
	email, err := ExtractID(input.Token, []byte(input.PublicKey), "email", constants.AdminTokenKey)
	if err != nil {
		var response dto.ListDeletedAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Login Expired"
		response.Listedtime = time.Now()
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "ListDeletedAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "LOGIN EXPIRED"
		audit.Error = err
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)

		return response
	}
	if email != constants.AdminEmail {
		var response dto.ListDeletedAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Access Denied"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListDeletedAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "TRYIED TO ACCESS LIST DELETED ADMIN DATA BUT NOT A SUPER ADMIN BY " + email
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	query := bson.D{}

	if !input.FromDate.IsZero() || !input.ToDate.IsZero() {
		if input.ToDate.IsZero() {
			input.ToDate = time.Now()
		} else if input.FromDate.IsZero() {
			input.FromDate = time.Now().AddDate(-1, 0, 0)
		}
		query = append(query, bson.E{Key: "deletedtime", Value: bson.M{"$gte": input.FromDate, "$lte": input.ToDate}})
		log.Println("In time Query")
	}

	if input.SearchBY != "" && input.SearchValue != "" {
		query = append(query, bson.E{Key: input.SearchBY, Value: input.SearchValue})
	}

	findOptions := options.Find()
	if input.SortBy != "" {
		sort := bson.D{{Key: input.SortBy, Value: input.SortOrder}}
		findOptions.SetSort(sort)
	} else {
		sort := bson.D{{Key: "deletedtime", Value: -1}}
		findOptions.SetSort(sort)
	}

	if input.NoofData == 0 {
		input.NoofData = 10
	}
	var listaudit []models.DeletedAdmin
	cursor, err := config.AdminDeleted_Collection.Find(context.Background(), query, findOptions)
	if err != nil {
		var response dto.ListDeletedAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Error while Processing"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListDeletedAdmin"
		audit.AdminID = "SUPER ADMIN"
		audit.Message = "ERROR WHILE FETCHING DATA FROM DELETED ADMIN DB"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Message = "ERROR WHILE FETCHING DATA FROM DELETED ADMIN COLLECTION"
		dev.Audit = audit
		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response
	}
	defer cursor.Close(context.Background())
	for cursor.Next(context.Background()) {
		if input.NoofData == 0 {
			break
		}
		input.NoofData--
		var singleaudit models.DeletedAdmin
		err = cursor.Decode(&singleaudit)
		if err != nil {
			var response dto.ListDeletedAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Error while Processing"
			response.Listedtime = time.Now()

			var audit models.AdminAudit
			audit.APIName = "ListDeletedAdmin"
			audit.AdminID = "SUPER ADMIN"
			audit.Message = "ERROR WHILE PROCESSING LIST OF DELETED ADMIN "
			audit.Payload = input
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			var dev models.DeveloperAudit
			dev.Message = "UNABLE TO DECODE DELETED ADMIN DATA IN DELETED ADMIN COLLECTION"
			dev.Audit = audit
			go AdminAudit(audit)
			go DeveloperAudit(dev)
			return response
		}
		listaudit = append(listaudit, singleaudit)

	}

	response := dto.ListDeletedAdminResponse{
		Status:     "SUCCESS",
		StatusCode: "200",
		Message:    "List Successfull",
		Listedtime: time.Now(),
		Data:       listaudit,
	}

	var audit models.AdminAudit
	audit.APIName = "ListDeletedAdmin"
	audit.AdminID = "SUPER ADMIN"
	audit.Message = "LISTED SUCCESSFULL TO " + email
	audit.Payload = input
	audit.ServiceName = "Admin"
	audit.Status = 200
	audit.StatusMessage = "SUCCESS"

	go AdminAudit(audit)

	return response
}

// List Blocked Admin
func ListBlockedAdmin(input dto.ListBlockedAdminRequest) dto.ListBlockedAdminResponse {
	if len(input.Token) < 20 || len(input.PublicKey) < 30 {
		var response dto.ListBlockedAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Wrong Input Data"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListBlockedAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "INVALID INPUT"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}
	email, err := ExtractID(input.Token, []byte(input.PublicKey), "email", constants.AdminTokenKey)
	if err != nil {
		var response dto.ListBlockedAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Login Expired"
		response.Listedtime = time.Now()
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "ListBlockedAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "LOGIN EXPIRED"
		audit.Error = err
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)

		return response
	}
	if email != constants.AdminEmail {
		var response dto.ListBlockedAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Access Denied"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListBlockedAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "TRYIED TO ACCESS LIST BLOCKED ADMIN DATA BUT NOT A SUPER ADMIN BY " + email
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	query := bson.D{}

	if !input.FromDate.IsZero() || !input.ToDate.IsZero() {
		if input.ToDate.IsZero() {
			input.ToDate = time.Now()
		} else if input.FromDate.IsZero() {
			input.FromDate = time.Now().AddDate(-1, 0, 0)
		}
		query = append(query, bson.E{Key: "blockedtime", Value: bson.M{"$gte": input.FromDate, "$lte": input.ToDate}})
		log.Println("In time Query")
	}

	if input.SearchBY != "" && input.SearchValue != "" {
		query = append(query, bson.E{Key: input.SearchBY, Value: input.SearchValue})
	}

	findOptions := options.Find()
	if input.SortBy != "" {
		sort := bson.D{{Key: input.SortBy, Value: input.SortOrder}}
		findOptions.SetSort(sort)
	} else {
		sort := bson.D{{Key: "blockedtime", Value: -1}}
		findOptions.SetSort(sort)
	}

	if input.NoofData == 0 {
		input.NoofData = 10
	}
	var listaudit []models.BlockorUnblockAdmin
	cursor, err := config.AdminBlocked_Collection.Find(context.Background(), query, findOptions)
	if err != nil {
		var response dto.ListBlockedAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Error while Processing"
		response.Listedtime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ListBlockedAdmin"
		audit.AdminID = "SUPER ADMIN"
		audit.Message = "ERROR WHILE FETCHING DATA FROM BLOCKED ADMIN DB"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		var dev models.DeveloperAudit
		dev.Message = "ERROR WHILE FETCHING DATA FROM BLOCKED ADMIN COLLECTION"
		dev.Audit = audit
		go AdminAudit(audit)
		go DeveloperAudit(dev)
		return response
	}
	defer cursor.Close(context.Background())
	for cursor.Next(context.Background()) {
		if input.NoofData == 0 {
			break
		}
		input.NoofData--
		var singleaudit models.BlockorUnblockAdmin
		err = cursor.Decode(&singleaudit)
		if err != nil {
			var response dto.ListBlockedAdminResponse
			response.StatusCode = "200"
			response.Status = "FAILED"
			response.Message = "Error while Processing"
			response.Listedtime = time.Now()

			var audit models.AdminAudit
			audit.APIName = "ListBlockedAdmin"
			audit.AdminID = "SUPER ADMIN"
			audit.Message = "ERROR WHILE PROCESSING LIST OF BLOCKED ADMIN "
			audit.Payload = input
			audit.ServiceName = "Admin"
			audit.Status = 200
			audit.StatusMessage = "FAILED"

			var dev models.DeveloperAudit
			dev.Message = "UNABLE TO DECODE BLOCKED ADMIN DATA IN BLOCKED ADMIN COLLECTION"
			dev.Audit = audit
			go AdminAudit(audit)
			go DeveloperAudit(dev)
			return response
		}
		listaudit = append(listaudit, singleaudit)

	}

	response := dto.ListBlockedAdminResponse{
		Status:     "SUCCESS",
		StatusCode: "200",
		Message:    "List Successfull",
		Listedtime: time.Now(),
		Data:       listaudit,
	}

	var audit models.AdminAudit
	audit.APIName = "ListBlockedAdmin"
	audit.AdminID = "SUPER ADMIN"
	audit.Message = "LISTED SUCCESSFULL TO " + email
	audit.Payload = input
	audit.ServiceName = "Admin"
	audit.Status = 200
	audit.StatusMessage = "SUCCESS"

	go AdminAudit(audit)

	return response
}

// Validate Admin Token
func ValidateAdminToken(input dto.ValidateAdminTokenRequest) dto.ValidateAdminTokenResponse {
	if len(input.PublicKey) < 30 || len(input.Token) < 20 {
		var response dto.ValidateAdminTokenResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Wrong Input Data"
		response.Responsetime = time.Now()
		response.Valid = false

		var audit models.AdminAudit
		audit.APIName = "ValidateAdminToken"
		audit.AdminID = "NOT FOUND"
		audit.Message = "INVALID INPUT"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	id, err := ExtractID(input.Token, []byte(input.PublicKey), "adminid", constants.AdminTokenKey)
	if err != nil {
		var response dto.ValidateAdminTokenResponse
		response.StatusCode = "200"
		response.Status = "SUCCESS"
		response.Message = "TOKEN HAS BEEN EXPIRED"
		response.Responsetime = time.Now()
		response.Valid = false
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "ValidateAdminToken"
		audit.AdminID = "NOT FOUND"
		audit.Message = "TOKEN HAS BEEN EXPIRED"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.Error = err
		audit.StatusMessage = "SUCCESS"

		go AdminAudit(audit)
		return response
	}
	var response dto.ValidateAdminTokenResponse
	response.StatusCode = "200"
	response.Status = "SUCCESS"
	response.Message = "TOKEN IS VALID"
	response.Responsetime = time.Now()
	response.Valid = true


	var audit models.AdminAudit
	audit.APIName = "ValidateAdminToken"
	audit.AdminID = id
	audit.Message = "TOKEN IS VALID"
	audit.Payload = input
	audit.ServiceName = "Admin"
	audit.Status = 200
	audit.Error = err
	audit.StatusMessage = "SUCCESS"

	go AdminAudit(audit)
	return response
}

// Approve Admin 
func ApproveAdmin(input dto.ApproveAdminRequest)dto.ApproveAdminResponse{
	if len(input.PublicKey) < 30 || len(input.Token) < 20 || !IsValidEmail(input.AdminEmail) {
		var response dto.ApproveAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "Wrong Input Data"
		response.ApprovedTime = time.Now()

		var audit models.AdminAudit
		audit.APIName = "ApproveAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "INVALID INPUT"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	email, err := ExtractID(input.Token, []byte(input.PublicKey), "email", constants.AdminTokenKey)
	if err != nil {
		var response dto.ApproveAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "LOGIN EXPIRED"
		response.ApprovedTime = time.Now()
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "ApproveAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "LOGIN EXPIRED"
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.Error = err
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	if email != constants.AdminEmail{
		var response dto.ApproveAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "ACCESS DENIED"
		response.ApprovedTime = time.Now()
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "ApproveAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "NOT A SUPER ADMIN BUT TRY TO APPROVE ADMIN DONE BY: "+email
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.Error = err
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}
	filter := bson.M{"email":input.AdminEmail}
	var admin models.Admin
	err = config.Admin_Collection.FindOne(context.Background(),filter).Decode(&admin)
	if err != nil{
		var response dto.ApproveAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "ADMIN WITH THE GIVEN EMAIL NOT FOUND"
		response.ApprovedTime = time.Now()
		response.Error = err

		var audit models.AdminAudit
		audit.APIName = "ApproveAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "ADMIN WITH THE GIVEN EMAIL NOT FOUND DONE BY: "+email
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.Error = err
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}

	if admin.IsApproved{
		var response dto.ApproveAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "ADMIN ALREADY APPROVED"
		response.ApprovedTime = time.Now()
	

		var audit models.AdminAudit
		audit.APIName = "ApproveAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "ADMIN ALREADY APPROVED DONE BY: "+email
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"

		go AdminAudit(audit)
		return response
	}
	update := bson.M{"$set": bson.M{"isapproved": true}}
	_,err = config.Admin_Collection.UpdateOne(context.Background(),filter,update)
	if err != nil{
		var response dto.ApproveAdminResponse
		response.StatusCode = "200"
		response.Status = "FAILED"
		response.Message = "APPROVAL FAILED"
		response.ApprovedTime = time.Now()
		response.Error = err
	

		var audit models.AdminAudit
		audit.APIName = "ApproveAdmin"
		audit.AdminID = "NOT FOUND"
		audit.Message = "PROBLEM IN UPDATEING IN ADMIN COLLECTION DONE BY:"+email
		audit.Payload = input
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"
		audit.Error = err

		var dev models.DeveloperAudit
        dev.Audit = audit
		dev.Message = "ERROR IN UPDATEING IN ADMIN COLLECTION"

		
        go DeveloperAudit(dev)
		go AdminAudit(audit)
		return response
	}
	var response dto.ApproveAdminResponse
	response.StatusCode = "200"
	response.Status = "SUCCESS"
	response.Message = "ADMIN APPROVED"
	response.ApprovedTime = time.Now()


	var audit models.AdminAudit
	audit.APIName = "ApproveAdmin"
	audit.AdminID = email
	audit.Message = "ADMIN "+input.AdminEmail+" APPROVED SUCCESSFULLY DONE BY:"+email
	audit.Payload = input
	audit.ServiceName = "Admin"
	audit.Status = 200
	audit.StatusMessage = "SUCCESS"
    
	return response
}

// TO get all Customer
// func GetallCustomerdata() ([]models.Customer, string, error) {
// 	filter := bson.D{}
// 	cursor, err := config.Customer_Collection.Find(context.Background(), filter)
// 	if err != nil {
// 		log.Println(err)
// 	}
// 	defer cursor.Close(context.Background())
// 	var Profiles []models.Customer
// 	for cursor.Next(context.Background()) {
// 		var profile models.Customer
// 		err := cursor.Decode(&profile)
// 		if err != nil {
// 			return nil, "Error in Decode", err
// 		}
// 		Profiles = append(Profiles, profile)
// 	}
// 	return Profiles, "Success", nil
// }

// // Get All Inventory
// func Getinventorydata() []models.Inventory {
// 	filter := bson.D{}
// 	cursor, err := config.Product_Collection.Find(context.Background(), filter)
// 	if err != nil {
// 		log.Println(err)
// 	}
// 	defer cursor.Close(context.Background())
// 	var Inventorydata []models.Inventory
// 	for cursor.Next(context.Background()) {
// 		var inventory models.Inventory
// 		err := cursor.Decode(&inventory)
// 		if err != nil {
// 			log.Println(err)
// 		}
// 		Inventorydata = append(Inventorydata, inventory)
// 	}
// 	return Inventorydata
// }

// // Get All Seller
// func Getallsellerdata() []models.Seller {
// 	filter := bson.D{}
// 	cursor, err := config.Product_Collection.Find(context.Background(), filter)
// 	if err != nil {
// 		log.Println(err)
// 	}
// 	defer cursor.Close(context.Background())
// 	var Seller []models.Seller
// 	for cursor.Next(context.Background()) {
// 		var seller models.Seller
// 		err := cursor.Decode(&seller)
// 		if err != nil {
// 			log.Println(err)
// 		}
// 		Seller = append(Seller, seller)
// 	}
// 	return Seller
// }

// // Create Seller
// func CreateSeller(seller models.Seller) bool {
// 	if seller.Password != seller.ConfirmPassword {
// 		return false
// 	}
// 	filter := bson.M{"selleremail": seller.Seller_Email}
// 	cursor, err := config.Product_Collection.Find(context.Background(), filter)
// 	if err != nil {
// 		log.Println(err)
// 		return false
// 	}
// 	defer cursor.Close(context.Background())

// 	if cursor.RemainingBatchLength() == 0 {
// 		seller.SellerId = GenerateUniqueCustomerID()
// 		seller.BlockedUser = false
// 		seller.WrongInput = 0
// 		seller.IsApproved = true
// 		seller.IsEmailVerified = true
// 		_, err := config.Product_Collection.InsertOne(context.Background(), seller)
// 		if err != nil {
// 			log.Println(err)
// 			return false

// 		}
// 		go SendSellerInvitation(seller.Seller_Email, seller.Seller_Name, seller.Password, "https://anon.up.railway.app/seller/")
// 		return true
// 	}
// 	return false
// }

// // Update Any Data
// func Update(update models.Update) bool {
// 	if update.Collection == "seller" {
// 		filter := bson.M{"selleremail": update.IdName}
// 		update1 := bson.M{"$set": bson.M{update.Field: update.New_Value}}
// 		options := options.Update()
// 		_, err := config.Product_Collection.UpdateOne(context.TODO(), filter, update1, options)
// 		if err != nil {
// 			return false
// 		}
// 		go SendEditDataNotification(update.IdName, update.Field, update.New_Value)
// 		return true
// 	} else if update.Collection == "customer" {
// 		if update.Field == "phonenumber" || update.Field == "age" || update.Field == "pincode" {

// 			intValue, err := strconv.Atoi(update.New_Value)
// 			if err != nil {
// 				return false
// 			} else {
// 				update.New_Value = strconv.Itoa(intValue)
// 			}
// 			if !isValidNumber(update.New_Value) {
// 				return false
// 			}
// 			filter := bson.M{"email": update.IdName}
// 			update1 := bson.M{"$set": bson.M{update.Field: intValue}}
// 			options := options.Update()
// 			_, err1 := config.Customer_Collection.UpdateOne(context.TODO(), filter, update1, options)

// 			if err1 != nil {

// 				return false
// 			}

// 		}

// 		filter := bson.M{"email": update.IdName}
// 		update1 := bson.M{"$set": bson.M{update.Field: update.New_Value}}
// 		options := options.Update()
// 		_, err := config.Customer_Collection.UpdateOne(context.TODO(), filter, update1, options)
// 		fmt.Println("updated")
// 		if err != nil {
// 			return false
// 		}
// 		go SendEditDataNotification(update.IdName, update.Field, update.New_Value)
// 		return true

// 	} else if update.Collection == "inventory" {
// 		if update.Field == "price" {
// 			// Check if New_Value is a valid integer
// 			intValue, err := strconv.Atoi(update.New_Value)
// 			if err != nil {
// 				// Handle the error, e.g., return an error response or log it
// 				return false
// 			}

// 			// Check if the input value is a valid number (numeric characters only)
// 			if !isValidNumber(update.New_Value) {
// 				return false
// 			}

// 			filter := bson.M{"itemname": update.IdName}
// 			update1 := bson.M{"$set": bson.M{update.Field: intValue}}
// 			options := options.Update()
// 			_, err1 := config.Product_Collection.UpdateOne(context.TODO(), filter, update1, options)
// 			return err1 == nil

// 		}

// 		filter := bson.M{"itemname": update.IdName}
// 		update1 := bson.M{"$set": bson.M{update.Field: update.New_Value}}
// 		options := options.Update()
// 		_, err := config.Product_Collection.UpdateOne(context.TODO(), filter, update1, options)
// 		return err != nil
// 	}

// 	return false
// }

// // Delete Any data
// func Delete(delete models.Delete) bool {
// 	if delete.Collection == "customer" {
// 		filter := bson.M{"email": delete.IdValue}
// 		_, err := config.Customer_Collection.DeleteOne(context.Background(), filter)
// 		if err != nil {
// 			log.Println(err)
// 			return false
// 		}
// 		return true
// 	}
// 	if delete.Collection == "seller" {
// 		filter := bson.M{"selleremail": delete.IdValue}
// 		_, err := config.Product_Collection.DeleteOne(context.Background(), filter)
// 		if err != nil {
// 			log.Println(err)
// 			return false
// 		}
// 		return true
// 	}
// 	if delete.Collection == "inventory" {
// 		filter := bson.M{"itemname": delete.IdValue}
// 		_, err := config.Product_Collection.DeleteOne(context.Background(), filter)
// 		if err != nil {
// 			log.Println(err)
// 			return false
// 		}
// 		return true
// 	}
// 	return true
// }

// // Get Dataneed for Admin
// func AdminNeededData() models.AdminPageData {
// 	var adminpagedata models.AdminPageData
// 	var sales models.Sales
// 	adminpagedata.ProductCount, _ = config.Product_Collection.CountDocuments(context.Background(), bson.D{})

// 	adminpagedata.UserCount, _ = config.Customer_Collection.CountDocuments(context.Background(), bson.D{})

// 	adminpagedata.SellerCount, _ = config.Product_Collection.CountDocuments(context.Background(), bson.D{})

// 	config.Product_Collection.FindOne(context.Background(), bson.M{}).Decode(&sales)

// 	adminpagedata.SalesCount = int64(sales.TotalNoOfSales)

// 	adminpagedata.TotalSalesAmount = int32(sales.TotalSalesAmount)

// 	return adminpagedata
// }

// func GetWorkerdata() []models.Workers {
// 	var workers []models.Workers

// 	filter := bson.M{}
// 	cursor, err := config.Product_Collection.Find(context.Background(), filter)
// 	if err != nil {
// 		log.Println(err)
// 	}
// 	for cursor.Next(context.Background()) {
// 		var worker models.Workers
// 		err := cursor.Decode(&worker)
// 		if err != nil {
// 			log.Println(err)
// 		}
// 		workers = append(workers, worker)
// 	}
// 	return workers
// }

// // Create Worker
// func CreateWorker(worker models.Workers) string {
// 	filter := bson.M{"email": worker.Email}
// 	result := config.Product_Collection.FindOne(context.Background(), filter)
// 	if result.Err() == nil {
// 		return "User Already Exists"
// 	}
// 	if result.Err() != nil && result.Err() != mongo.ErrNoDocuments {
// 		return "Error in Query: " + result.Err().Error()
// 	}
// 	_, err := config.Product_Collection.InsertOne(context.Background(), worker)
// 	if err != nil {
// 		return "Error in Creating: " + err.Error()
// 	}
// 	return "Created Successfully"
// }

// // Get Single Data
// func GetData(data models.Getdata) (*models.ReturnData, error) {
// 	var returndata models.ReturnData

// 	if data.Collection == "customer" {
// 		log.Println("In customer")
// 		var profile models.Customer
// 		filter := bson.M{"email": data.Id}
// 		err := config.Customer_Collection.FindOne(context.Background(), filter).Decode(&profile)
// 		if err != nil {
// 			log.Println(err)
// 			return nil, err
// 		}
// 		returndata.Name = profile.Name
// 		returndata.CustomerId = profile.CustomerId
// 		returndata.Address = profile.Address
// 		returndata.Email = profile.Email
// 		returndata.Phone_No = profile.Phone_No
// 		returndata.Password = profile.Password
// 		returndata.IsEmailVerified = profile.IsEmailVerified
// 		returndata.BlockedUser = profile.BlockedUser
// 		returndata.WrongInput = profile.WrongInput
// 		return &returndata, nil

// 	} else if data.Collection == "seller" {
// 		log.Println("In seller")
// 		var profile models.Seller
// 		filter := bson.M{"selleremail": data.Id}
// 		log.Println()
// 		err := config.Product_Collection.FindOne(context.Background(), filter).Decode(&profile)
// 		if err != nil {
// 			log.Println(err)
// 			return nil, err
// 		}
// 		returndata.Seller_Name = profile.Seller_Name
// 		returndata.Phone_No = profile.Phone_No
// 		returndata.Address = profile.Address
// 		returndata.Password = profile.Password
// 		returndata.SellerId = profile.SellerId
// 		returndata.Seller_Email = profile.Seller_Email
// 		returndata.Seller_Name = profile.Seller_Name
// 		returndata.Image = profile.Image
// 		returndata.BlockedUser = profile.BlockedUser
// 		returndata.WrongInput = profile.WrongInput
// 		return &returndata, nil
// 	} else if data.Collection == "inventory" {
// 		log.Println("In inventory")
// 		var profile models.Inventory
// 		filter := bson.M{"itemname": data.Id}
// 		err := config.Product_Collection.FindOne(context.Background(), filter).Decode(&profile)
// 		if err != nil {
// 			log.Println(err)
// 			return nil, err
// 		}
// 		returndata.ItemCategory = profile.ItemCategory
// 		returndata.ItemName = profile.ItemName
// 		returndata.Quantity = profile.Quantity
// 		returndata.Seller_Name = profile.SellerName
// 		returndata.Price = profile.Price
// 		returndata.Stock_Available = profile.Stock_Available
// 		returndata.Image = profile.Image
// 		return &returndata, nil
// 	} else if data.Collection == "worker" {
// 		log.Println("In worker")
// 		var profile models.Workers
// 		filter := bson.M{"email": data.Id}
// 		err := config.Product_Collection.FindOne(context.Background(), filter).Decode(&profile)
// 		if err != nil {
// 			log.Println(err)
// 			return nil, err
// 		}
// 		returndata.Email = profile.Email
// 		returndata.No = profile.No
// 		returndata.Role = profile.Role
// 		returndata.Status = profile.Status
// 		returndata.UserName = profile.UserName
// 		returndata.Salary = profile.Salary
// 		returndata.Image = profile.Image
// 		return &returndata, nil
// 	}
// 	return nil, nil

// }

// // Block User & Admin
// func Block(data models.Block) (string, error) {
// 	if data.Collection == "customer" {
// 		var customer models.Customer
// 		filter := bson.M{"email": data.Email}
// 		err := config.Customer_Collection.FindOne(context.Background(), filter).Decode(&customer)
// 		if err != nil {
// 			log.Println(err)
// 			return "No result Found", err
// 		}
// 		message := ""
// 		if customer.BlockedUser {
// 			customer.BlockedUser = false
// 			message = "Customer has been Unblocked"
// 		} else {
// 			customer.BlockedUser = true
// 			message = "Customer has been Blocked"
// 		}
// 		update := bson.M{"$set": bson.M{"blockeduser": customer.BlockedUser}}
// 		_, err = config.Customer_Collection.UpdateOne(context.Background(), filter, update)
// 		if err != nil {
// 			log.Println(err)
// 			return "Can't Update Data", err
// 		}
// 		go SendBlockingNotification(customer.Email, customer.Name, "Due to improper behaviour")
// 		return message, nil
// 	} else if data.Collection == "seller" {
// 		var Seller models.Seller
// 		filter := bson.M{"selleremail": data.Email}
// 		err := config.Product_Collection.FindOne(context.Background(), filter).Decode(&Seller)
// 		if err != nil {
// 			log.Println(err)
// 			return "No result Found", err
// 		}
// 		message := ""
// 		if Seller.BlockedUser {
// 			Seller.BlockedUser = false
// 			message = "Seller has been Unblocked"
// 		} else {
// 			Seller.BlockedUser = true
// 			message = "Seller has been Blocked"
// 		}
// 		update := bson.M{"$set": bson.M{"blockeduser": Seller.BlockedUser}}
// 		_, err = config.Product_Collection.UpdateOne(context.Background(), filter, update)
// 		if err != nil {
// 			log.Println(err)
// 			return "Can't Update Data", err
// 		}
// 		go SendBlockingNotification(Seller.Seller_Email, Seller.Seller_Name, "Due to improper behaviour")
// 		return message, nil

// 	}
// 	return "Invalid Collection", nil
// }

// // Add Event To Calender
// func AddEvent(upload models.UploadCalender) error {
// 	_, err := config.Product_Collection.InsertOne(context.Background(), upload)
// 	if err != nil {
// 		log.Println(err)
// 		return err
// 	}
// 	return nil
// }

// // Get Event input.FromDate Calender
// input.ToDate func GetEvent(GetData models.GetCalender) ([]models.UploadCalender, error) {
// 	filter := bson.M{"email": GetData.AdminEmail}
// 	cursor, err := config.Product_Collection.Find(context.Background(), filter)
// 	var Data []models.UploadCalender
// 	if err != nil {
// 		log.Println(err)
// 		return nil, err
// 	}

// 	for cursor.Next(context.Background()) {
// 		var data models.UploadCalender
// 		err := cursor.Decode(&data)
// 		if err != nil {
// 			log.Println(err)
// 			return nil, err
// 		}
// 		Data = append(Data, data)
// 	}
// 	return Data, nil
// }

// // ShutDown
// func ShutDown(token models.ShutDown) (string, error) {
// 	if token.Password != "111" {
// 		return "Key Mismatch", nil
// 	}
// 	id, err := ExtractCustomerID(token.Token, "")
// 	if err != nil {
// 		log.Println("Login Exp")
// 		return "Login Expired", err
// 	}
// 	var admin models.AdminData
// 	filter := bson.M{"adminid": id}
// 	err = config.Admin_Collection.FindOne(context.Background(), filter).Decode(&admin)
// 	if err != nil {
// 		return "Login as Admin", err
// 	}

// 	if id != admin.AdminID {
// 		return "Login as Admin", err
// 	}

// 	shutdownComplete := make(chan bool)

// 	go func() {
// 		ShutDownExe()
// 		shutdownComplete <- true
// 	}()

// 	return "Shutdown initiated", nil
// }

// func ShutDownExe() {
// 	time.Sleep(3 * time.Second)
// 	os.Exit(0)
// }

// // Clear DataBase
// func ClearDB(details models.Getdata) (string, error) {
// 	id, err := ExtractCustomerID(details.Id, "")
// 	if err != nil {
// 		return "Login Expired", err
// 	}
// 	var admin models.AdminData
// 	filter := bson.M{"adminid": id}
// 	err = config.Admin_Collection.FindOne(context.Background(), filter).Decode(&admin)
// 	if err != nil {
// 		return "Data not Found", err
// 	}
// 	if admin.Email == "" {
// 		return "Data not Found", nil
// 	}
// 	result, err := DeleteDBCollection(details.Collection)
// 	if err != nil {
// 		return result, err
// 	}
// 	return result, nil
// }

// // Delete colletion
// func DeleteDBCollection(collection string) (string, error) {
// 	if collection == "all" {
// 		err := config.Admin_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Admin Collection", err
// 		}
// 		err = config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Orders Collection", err
// 		}
// 		err = config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Calender Collection", err
// 		}
// 		err = config.Cart_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Cart Collection", err
// 		}
// 		err = config.Customer_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Customers Collection", err
// 		}
// 		err = config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting FeedBack Collection", err
// 		}
// 		err = config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Inventory Collection", err
// 		}
// 		err = config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Sellers Collection", err
// 		}
// 		err = config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Workers Collection", err
// 		}
// 		return "All Database Deleted Successfully", nil
// 	} else if collection == "sellerall" {
// 		err := config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Orders Collection", err
// 		}
// 		err = config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting FeedBack Collection", err
// 		}
// 		err = config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Inventory Collection", err
// 		}
// 		err = config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Sellers Collection", err
// 		}
// 		return "Seller Related Database Deleted Successfully", nil
// 	} else if collection == "customerall" {
// 		err := config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Orders Collection", err
// 		}
// 		err = config.Cart_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Cart Collection", err
// 		}
// 		err = config.Customer_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Customers Collection", err
// 		}
// 		err = config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting FeedBack Collection", err
// 		}
// 		return "Customer Related Database Deleted Successfully", nil
// 	} else if collection == "adminall" {
// 		err := config.Admin_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Admin Collection", err
// 		}
// 		err = config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Calender Collection", err
// 		}
// 		return "Adim related Database Deleted Successfully", nil
// 	} else if collection == "seller" {
// 		err := config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Sellers Collection", err
// 		}
// 		return "Seller Database Deleted Successfully", nil
// 	} else if collection == "inventory" {
// 		err := config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Inventory Collection", err
// 		}
// 		return "Inventory Database Deleted Successfully", nil
// 	} else if collection == "orders" {
// 		err := config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Orders Collection", err
// 		}
// 		return "Order Database Deleted Successfully", nil
// 	} else if collection == "feedback" {
// 		err := config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting FeedBack Collection", err
// 		}
// 		return "Feedback Database Deleted Successfully", nil
// 	} else if collection == "worker" {
// 		err := config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Workers Collection", err
// 		}
// 		return "Worker Database Deleted Successfully", nil
// 	} else if collection == "cart" {
// 		err := config.Cart_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Cart Collection", err
// 		}
// 		return "Cart Database Deleted Successfully", nil
// 	} else if collection == "calender" {
// 		err := config.Product_Collection.Drop(context.Background())
// 		if err != nil {
// 			return "Error in Delting Calender Collection", err
// 		}
// 		return "Calender Database Deleted Successfully", nil
// 	}
// 	return "Collection Not Found", nil

// }

// func GetAllNotApprovedSeller(token models.Token) ([]models.Seller, string, error) {
// 	id, err := ExtractCustomerID(token.Token, "")
// 	if err != nil {
// 		return nil, "Login Expired", err
// 	}
// 	var admin models.AdminData
// 	filter := bson.M{"adminid": id}
// 	err = config.Admin_Collection.FindOne(context.Background(), filter).Decode(&admin)
// 	if err != nil {
// 		return nil, "Data not Found", err
// 	}
// 	if admin.Email == "" {
// 		return nil, "Data not Found", nil
// 	}
// 	var Seller []models.Seller
// 	filter = bson.M{"isapproved": false}
// 	filter2 := bson.M{"isemailverified": true}
// 	filter3 := bson.M{"blockeduser": false}
// 	combinedFilter := bson.M{
// 		"$and": []bson.M{filter, filter2, filter3},
// 	}
// 	cursor, err := config.Product_Collection.Find(context.Background(), combinedFilter)
// 	if err != nil {
// 		return nil, "Error in Finding", err
// 	}
// 	for cursor.Next(context.Background()) {
// 		var seller models.Seller
// 		err := cursor.Decode(&seller)
// 		if err != nil {
// 			log.Println(err)
// 			return nil, "Internal Server Error", err
// 		}
// 		Seller = append(Seller, seller)
// 	}
// 	defer cursor.Close(context.Background())
// 	return Seller, "Success", nil
// }

// func ApproveSeller(details models.ApproveSeller) (string, error) {
// 	id, err := ExtractCustomerID(details.Token, "")
// 	if err != nil {
// 		return "Login Expired", err
// 	}
// 	var admin models.AdminData
// 	filter := bson.M{"adminid": id}
// 	err = config.Admin_Collection.FindOne(context.Background(), filter).Decode(&admin)
// 	if err != nil {
// 		return "Data not Found", err
// 	}
// 	if admin.Email == "" {
// 		return "Data not Found", nil
// 	}
// 	filter = bson.M{"sellerid": details.Sellerid}
// 	update := bson.M{"$set": bson.M{"isapproved": true}}
// 	_, err = config.Product_Collection.UpdateOne(context.Background(), filter, update)
// 	if err != nil {
// 		return "Data Not Found", err
// 	}
// 	return "Seller Verified", nil
// }

// func GetAllOrders(token models.Token) ([]models.AddOrder, string, error) {
// 	id, err := ExtractCustomerID(token.Token, "")
// 	if err != nil {
// 		return nil, "Login Expired", err
// 	}
// 	var admin models.AdminData
// 	filter := bson.M{"adminid": id}
// 	err = config.Admin_Collection.FindOne(context.Background(), filter).Decode(&admin)
// 	if err != nil {
// 		return nil, "Data not Found", err
// 	}
// 	if admin.Email == "" {
// 		return nil, "Data not Found", nil
// 	}
// 	cursor, err := config.Product_Collection.Find(context.Background(), bson.M{})
// 	if err != nil {
// 		return nil, "Error in Finding", err
// 	}
// 	var Order []models.AddOrder
// 	for cursor.Next(context.Background()) {
// 		var order models.AddOrder
// 		err := cursor.Decode(&order)
// 		if err != nil {
// 			log.Println(err)
// 			return nil, "Internal Server Error", err
// 		}
// 		Order = append(Order, order)
// 	}
// 	defer cursor.Close(context.Background())
// 	return Order, "Success", nil

// }

// func GetCustromerOrderforAdmin(details models.GetOrder) (*models.AddOrder, string, error) {
// 	var orderDetails models.AddOrder

// 	id, err := ExtractCustomerID(details.Token, "")
// 	if err != nil {
// 		return nil, "Login Expired", err
// 	}
// 	var admin models.AdminData
// 	filter := bson.M{"adminid": id}
// 	err = config.Admin_Collection.FindOne(context.Background(), filter).Decode(&admin)
// 	if err != nil {
// 		return nil, "Data not Found", err
// 	}
// 	if admin.Email == "" {
// 		return nil, "Data not Found", nil
// 	}
// 	filter = bson.M{"orderid": details.OrderID}
// 	err = config.Product_Collection.FindOne(context.Background(), filter).Decode(&orderDetails)
// 	if err != nil {
// 		return &orderDetails, "No Result found", err
// 	}

// 	return &orderDetails, "Success", nil
// }
