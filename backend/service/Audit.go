package service

import (
	"context"
	"mithuorganics/config"
	"mithuorganics/models"
	"time"
)

func AdminAudit(audit models.AdminAudit) {
	audit.AuditTime = time.Now()
	audit.AuditID = GenerateUniqueAuditID()

	_,err := config.AdminAudit_Collection.InsertOne(context.Background(), audit)
	if err != nil{
		var dev models.DeveloperAudit
		dev.Audit = audit
		dev.Message = "ERROR IN STORING DATA IN ADMIN AUDIT"
		go DeveloperAudit(dev)
	}
}

func DeveloperAudit(audit models.DeveloperAudit) {
	audit.IsCleared = false
	audit.ErrorTime = time.Now()
	audit.ErrorID = GenerateUniqueAuditID()
	config.DeveloperAudit_Collection.InsertOne(context.Background(), audit)
}
