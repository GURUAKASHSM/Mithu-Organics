package config

import (
	"context"
	"mithuorganics/constants"
	"fmt"
	"log"


	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)


var(
 Admin_Collection *mongo.Collection
 Customer_Collection *mongo.Collection
 Product_Collection *mongo.Collection
 Order_Collection *mongo.Collection
 Cart_Collection *mongo.Collection
 BestSelling_Collection *mongo.Collection
 Favorite_Collection *mongo.Collection
 Instagram_Collection *mongo.Collection
 Trending_Collection *mongo.Collection
 PopularCategories_Collection *mongo.Collection
 ShopPage_Collection *mongo.Collection
 AboutPage_Collection *mongo.Collection
 ContactPage_Collection *mongo.Collection
 SiteData_Collection *mongo.Collection
 FeedBack_Collection *mongo.Collection
 UserAudit_Collection *mongo.Collection
 AdminAudit_Collection *mongo.Collection
 DeveloperAudit_Collection *mongo.Collection

)


func init() {
	log.Println("********** Connecting To DataBase **********")
	
	clientoption := options.Client().ApplyURI(constants.ConnectionString)

	client, err := mongo.Connect(context.TODO(), clientoption)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("********* DataBase Connected Sucessfully **********")
	fmt.Println("********** Creating Collections **********")

	Admin_Collection = client.Database(constants.DataBaseName).Collection(constants.Admin_Collection)
	Customer_Collection = client.Database(constants.DataBaseName).Collection(constants.Customer_Collection)
	Product_Collection = client.Database(constants.DataBaseName).Collection(constants.Product_Collection)
	Order_Collection = client.Database(constants.DataBaseName).Collection(constants.Order_Collection)
	Cart_Collection = client.Database(constants.DataBaseName).Collection(constants.Cart_Collection)
	BestSelling_Collection = client.Database(constants.DataBaseName).Collection(constants.BestSelling_Collection)
	Favorite_Collection = client.Database(constants.DataBaseName).Collection(constants.Favorite_Collection)
	Instagram_Collection = client.Database(constants.DataBaseName).Collection(constants.Instagram_Collection)
	Trending_Collection = client.Database(constants.DataBaseName).Collection(constants.Trending_Collection)
	PopularCategories_Collection = client.Database(constants.DataBaseName).Collection(constants.PopularCategories_Collection)
	ShopPage_Collection = client.Database(constants.DataBaseName).Collection(constants.ShopPage_Collection)
	AboutPage_Collection = client.Database(constants.DataBaseName).Collection(constants.AboutPage_Collection)
	ContactPage_Collection = client.Database(constants.DataBaseName).Collection(constants.ContactPage_Collection)
	SiteData_Collection = client.Database(constants.DataBaseName).Collection(constants.SiteData_Collection)
	FeedBack_Collection = client.Database(constants.DataBaseName).Collection(constants.FeedBack_Collection)
	UserAudit_Collection = client.Database(constants.DataBaseName).Collection(constants.UserAudit_Collection)
	AdminAudit_Collection = client.Database(constants.DataBaseName).Collection(constants.AdminAudit_Collection)
	DeveloperAudit_Collection = client.Database(constants.DataBaseName).Collection(constants.DeveloperAudit_Collection)
	fmt.Println("****** Collections Created ******")
}
