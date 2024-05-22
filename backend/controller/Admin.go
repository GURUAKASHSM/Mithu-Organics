package controller

import (
	//"log"
	"mithuorganics/models"
	"mithuorganics/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Admin Login
func AdminLogin(c *gin.Context) {
	var login models.AdminLoginRequest
	if err := c.BindJSON(&login); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
		return
	}

	result := service.AdminLogin(login)
	if result.Status == "FAILED" {
		c.JSON(http.StatusOK, gin.H{"error": result})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": result})
}

// Create Admin
func CreateAdmin(c *gin.Context) {
	var admin models.CreateAdminRequest
	if err := c.BindJSON(&admin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
		return
	}
	result := service.CreateAdmin(admin)
	if result.Status == "FAILED" {
		c.JSON(http.StatusOK, gin.H{"error": result})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": result})
}

// List Admin
func ListAdmin(c *gin.Context) {
	var admin models.ListAdminRequest
	if err := c.BindJSON(&admin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
		return
	}
	result := service.ListAdmin(admin)
	if result.Status == "FAILED" {
		c.JSON(http.StatusOK, gin.H{"error": result})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": result})
}

// Delete Admin
func DeleteAdmin(c *gin.Context) {
	var admin models.DeleteAdminRequest
	if err := c.BindJSON(&admin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
		return
	}
	result := service.DeleteAdmin(admin)
	if result.Status == "FAILED" {
		c.JSON(http.StatusOK, gin.H{"error": result})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": result})
}

// Delete Admin
func EditAdmin(c *gin.Context) {
	var admin models.EditAdminRequest
	if err := c.BindJSON(&admin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
		return
	}
	result := service.EditAdmin(admin)
	if result.Status == "FAILED" {
		c.JSON(http.StatusOK, gin.H{"error": result})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": result})
}

// ViewAdmin Admin
func ViewAdmin(c *gin.Context) {
	var admin models.ViewAdminRequest
	if err := c.BindJSON(&admin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
		return
	}
	result := service.ViewAdmin(admin)
	if result.Status == "FAILED" {
		c.JSON(http.StatusOK, gin.H{"error": result})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": result})
}

// BlockorUnblockAdmin Admin
func BlockorUnblockAdmin(c *gin.Context) {
	var admin models.BlockorUnblockAdminRequest
	if err := c.BindJSON(&admin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
		return
	}
	result := service.BlockorUnblockAdmin(admin)
	if result.Status == "FAILED" {
		c.JSON(http.StatusOK, gin.H{"error": result})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": result})
}

// ListAdminAudit Admin
func ListAdminAudit(c *gin.Context) {
	var admin models.ListAdminAuditRequest
	if err := c.BindJSON(&admin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
		return
	}
	result := service.ListAdminAudit(admin)
	if result.Status == "FAILED" {
		c.JSON(http.StatusOK, gin.H{"error": result})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": result})
}

// ListDeveloperAudit Admin
func ListDeveloperAudit(c *gin.Context) {
	var admin models.ListDeveloperAuditRequest
	if err := c.BindJSON(&admin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
		return
	}
	result := service.ListDeveloperAudit(admin)
	if result.Status == "FAILED" {
		c.JSON(http.StatusOK, gin.H{"error": result})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": result})
}

// ListEditedAdmin Admin
func ListEditedAdmin(c *gin.Context) {
	var admin models.ListEditedAdminRequest
	if err := c.BindJSON(&admin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
		return
	}
	result := service.ListEditedAdmin(admin)
	if result.Status == "FAILED" {
		c.JSON(http.StatusOK, gin.H{"error": result})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": result})
}

// ListDeletedAdmin Admin
func ListDeletedAdmin(c *gin.Context) {
	var admin models.ListDeletedAdminRequest
	if err := c.BindJSON(&admin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
		return
	}
	result := service.ListDeletedAdmin(admin)
	if result.Status == "FAILED" {
		c.JSON(http.StatusOK, gin.H{"error": result})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": result})
}

// ListBlockedAdmin Admin
func ListBlockedAdmin(c *gin.Context) {
	var admin models.ListBlockedAdminRequest
	if err := c.BindJSON(&admin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
		return
	}
	result := service.ListBlockedAdmin(admin)
	if result.Status == "FAILED" {
		c.JSON(http.StatusOK, gin.H{"error": result})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": result})
}

// ValidateAdminToken Admin
func ValidateAdminToken(c *gin.Context) {
	var admin models.ValidateAdminTokenRequest
	if err := c.BindJSON(&admin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
		return
	}
	result := service.ValidateAdminToken(admin)
	if result.Status == "FAILED" {
		c.JSON(http.StatusOK, gin.H{"error": result})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": result})
}

// // Get all Inventory Data
// func Getinventorydata(c *gin.Context) {
// 	Inventorydata := service.Getinventorydata()
// 	c.JSON(http.StatusOK, gin.H{"Inventory": Inventorydata})
// }

// // Get all Customer Data
// func GetallCustomerdata(c *gin.Context) {
// 	alltransaction, message, err := service.GetallCustomerdata()
// 	if err != nil {
// 		c.JSON(http.StatusOK, gin.H{"error": message})
// 		return
// 	}
// 	c.JSON(http.StatusOK, alltransaction)
// }

// // Get all Seller Data
// func Getallsellerdata(c *gin.Context) {
// 	Getallsellerdata := service.Getallsellerdata()
// 	c.JSON(http.StatusOK, gin.H{"seller": Getallsellerdata})

// }

// // Admin Page Details
// func GetAllDetailsForAdmin(c *gin.Context) {
// 	data := service.AdminNeededData()
// 	c.JSON(http.StatusOK, gin.H{"result": data})
// }

// // Get All Workers
// func GetWorkers(c *gin.Context) {
// 	data := service.GetWorkerdata()
// 	c.JSON(http.StatusOK, gin.H{"result": data})

// }

// // Get All FeedBacks
// func GetFeedback(c *gin.Context) {
// 	data := service.GetFeedBacks()
// 	c.JSON(http.StatusOK, gin.H{"result": data})

// }

// // Create Worker
// func CreateWorker(c *gin.Context) {
// 	var worker models.Workers
// 	if err := c.BindJSON(&worker); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
// 		return
// 	}

// 	data := service.CreateWorker(worker)
// 	c.JSON(http.StatusOK, gin.H{"result": data})
// }

// // Create Seller
// func CreateSeller(c *gin.Context) {
// 	var seller models.Seller
// 	if err := c.BindJSON(&seller); err != nil {

// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
// 		return
// 	}
// 	createseller := service.CreateSeller(seller)
// 	c.JSON(http.StatusOK, createseller)

// }

// // Update All things by Admin
// func Update(c *gin.Context) {
// 	var update models.Update
// 	if err := c.BindJSON(&update); err != nil {

// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
// 		return
// 	}
// 	result := service.Update(update)
// 	c.JSON(http.StatusOK, gin.H{"result": result})
// }

// // Delete All Kinds of Data
// func Delete(c *gin.Context) {
// 	var delete models.Delete
// 	if err := c.BindJSON(&delete); err != nil {

// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
// 		return
// 	}
// 	result := service.Delete(delete)
// 	c.JSON(http.StatusOK, result)
// }

// // Delete FeedBack
// func Deletefeedback(c *gin.Context) {
// 	var feedback models.FeedbackDB

// 	if err := c.BindJSON(&feedback); err != nil {

// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
// 		return
// 	}
// 	result := service.Deletefeedback(feedback)
// 	c.JSON(http.StatusOK, result)

// }

// // Get Every Data as Single
// func GetData(c *gin.Context) {
// 	var data models.Getdata
// 	if err := c.BindJSON(&data); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
// 		return
// 	}
// 	log.Println(data)
// 	result, err := service.GetData(data)
// 	if err != nil {
// 		log.Println(err)
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Internal Server Error"})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"message": result})
// }

// // Add Event To Calender
// func AddEvent(c *gin.Context) {
// 	var upload models.UploadCalender
// 	if err := c.BindJSON(&upload); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
// 		return
// 	}
// 	err := service.AddEvent(upload)
// 	if err != nil {
// 		log.Println(err)
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Internal Server Error"})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"message": "Added Successfully"})
// }

// // Get All Calender Events
// func GetEvent(c *gin.Context) {
// 	var GetData models.GetCalender
// 	if err := c.BindJSON(&GetData); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
// 		return
// 	}
// 	data, err := service.GetEvent(GetData)
// 	if err != nil {
// 		log.Println(err)
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Internal Server Error"})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"message": data})
// }

// // BLock Customer & seller
// func Block(c *gin.Context) {
// 	var data models.Block
// 	if err := c.BindJSON(&data); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
// 		return
// 	}
// 	log.Println(data)
// 	result, err := service.Block(data)
// 	if err != nil {
// 		log.Println(err)
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Internal Server Error"})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"message": result})
// }

// // ShutDown
// func ShutDown(c *gin.Context) {
// 	var token models.ShutDown
// 	if err := c.BindJSON(&token); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
// 		return
// 	}
// 	log.Println(token)
// 	result, err := service.ShutDown(token)
// 	if err != nil {
// 		log.Println(err)
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Internal Server Error"})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"message": result})
// }

// // Clear DB
// func ClearDB(c *gin.Context) {
// 	var details models.Getdata
// 	if err := c.BindJSON(&details); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
// 		return
// 	}
// 	result, err := service.ClearDB(details)
// 	if err != nil {
// 		log.Println(err)
// 		c.JSON(http.StatusBadRequest, gin.H{"error": result})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"message": result})
// }

// // Get All Not Approved Seller
// func GetAllNotApprovedSeller(c *gin.Context) {
// 	var token models.Token
// 	if err := c.BindJSON(&token); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
// 		return
// 	}
// 	data, result, err := service.GetAllNotApprovedSeller(token)
// 	if err != nil {
// 		log.Println(err)
// 		c.JSON(http.StatusBadRequest, gin.H{"error": result})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"message": data})
// }

// // Approve Seller
// func ApproveSeller(c *gin.Context) {
// 	var details models.ApproveSeller
// 	if err := c.BindJSON(&details); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
// 		return
// 	}
// 	result, err := service.ApproveSeller(details)
// 	if err != nil {
// 		log.Println(err)
// 		c.JSON(http.StatusBadRequest, gin.H{"error": result})
// 		return
// 	}
// 	c.JSON(http.StatusOK, gin.H{"message": result})
// }

// // Get all Orders
// func GetAllOrders(c *gin.Context) {
// 	var token models.Token
// 	if err := c.BindJSON(&token); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
// 		return
// 	}
// 	data, result, err := service.GetAllOrders(token)
// 	if err != nil {
// 		log.Println(err)
// 		c.JSON(http.StatusBadRequest, gin.H{"error": result})
// 		return
// 	}
// 	log.Println(data)
// 	c.JSON(http.StatusOK, gin.H{"message": data})
// }

// // Get Customer Order
// func GetCustromerOrderforAdmin(c *gin.Context) {
// 	var details models.GetOrder
// 	if err := c.BindJSON(&details); err != nil {
// 		log.Println(err)
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON data"})
// 		return
// 	}
// 	data, message, err := service.GetCustromerOrderforAdmin(details)
// 	if err != nil {
// 		log.Println(err)
// 		c.JSON(http.StatusOK, gin.H{"error": message})
// 		return
// 	}
// 	log.Println(data, message)
// 	c.JSON(http.StatusOK, gin.H{"message": data})
// }
