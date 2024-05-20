package service

import (
	"context"
	"mithuorganics/config"
	"mithuorganics/constants"
	"mithuorganics/models"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

func DetailsToDB() {
	go AddDefaultAdmin()

}

func AddDefaultAdmin() {
	admin := models.AdminData{
		AdminName:     constants.AdminName,
		AdminID:       GenerateUniqueAdminID(),
		Email:         constants.AdminEmail,
		Password:       HashAdminPassword(constants.Password),
		IP_Address:    constants.IP,
		WrongInput:    0,
		LoginTime:     time.Time{},
		CreatedTime:   time.Now(),
		CanDeleteData: true,
		CanUpdateData: true,
		CanAlterAdmin: true,
		CreatedBy:     "DEFAULT",
		IsBlocked:     false,
		Token:         "NIL",
	}

	pvt, pub, err := GenerateRSAKeyPair()
	if err != nil {
		var audit models.AdminAudit
		audit.APIName = "AddAdmin"
		audit.AdminID = admin.AdminID
		audit.AuditID = GenerateUniqueAuditID()
		audit.AuditTime = time.Now()
		admin.Password = ""
		audit.Error = err
		audit.Message = "ERROR IN CREATEING PUBLIC & PRIVATE KEY"
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"
		go AdminAudit(audit)
		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.ErrorID = GenerateUniqueAuditID()
		dev.ErrorTime = time.Now()
		dev.IsCleared = false
		dev.Message = "ERROR IN CREATEING PUBLIC & PRIVATE KEY"
		go DeveloperAudit(dev)
		return
	}

	admin.PrivateKey = string(pvt)
	admin.PublicKey = string(pub)

	key, err := GenerateSecret()
	if err != nil {
		var audit models.AdminAudit
		audit.APIName = "AddAdmin"
		admin.Password = ""
		audit.AdminID = admin.AdminID
		audit.AuditID = GenerateUniqueAuditID()
		audit.AuditTime = time.Now()
		audit.Error = err
		audit.Message = "ERROR IN CREATEING SECRET KEY"
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"
		go AdminAudit(audit)
		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.ErrorID = GenerateUniqueAuditID()
		dev.ErrorTime = time.Now()
		dev.IsCleared = false
		dev.Message = "ERROR IN CREATEING SECERET KEY"
		go DeveloperAudit(dev)
		return
	}

	admin.SecretKey = key
	filter := bson.M{
		"$or": []bson.M{
			{"email": admin.Email},
			{"adminid": admin.AdminID},
		},
	}
	var data models.AdminData
	err = config.Admin_Collection.FindOne(context.Background(), filter).Decode(&data)
	if err == nil {
		var audit models.AdminAudit
		admin.Password = ""
		audit.APIName = "AddAdmin"
		audit.AdminID = admin.AdminID
		audit.AuditID = GenerateUniqueAuditID()
		audit.AuditTime = time.Now()
		audit.Error = err
		audit.Message = "ADMIN WITH EMIAL & ADMINID ALREADY EXISTS"
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "FAILED"
		go AdminAudit(audit)
		return

	} else {
		_, err = config.Admin_Collection.InsertOne(context.Background(), admin)
		if err != nil {
			var audit models.AdminAudit
			audit.APIName = "AddAdmin"
			audit.AdminID = admin.AdminID
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
			dev.ErrorID = GenerateUniqueAuditID()
			dev.ErrorTime = time.Now()
			dev.IsCleared = false
			dev.Message = "ERROR IN INSERTING ADMIN TO DB"
			go DeveloperAudit(dev)
			return
		}
		var audit models.AdminAudit
		audit.APIName = "AddAdmin"
		audit.AdminID = admin.AdminID
		audit.AuditID = GenerateUniqueAuditID()
		audit.AuditTime = time.Now()
		audit.Error = err
		admin.Password = ""
		audit.Message = "ADMIN CREATED SUCCESSFULLY"
		audit.Payload = admin
		audit.ServiceName = "Admin"
		audit.Status = 200
		audit.StatusMessage = "SUCCESS"
		go AdminAudit(audit)

	}

}
