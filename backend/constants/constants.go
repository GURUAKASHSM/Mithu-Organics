package constants

import (
	"log"

	"github.com/spf13/viper"
)

type MongoConfig struct {
	URL      string `mapstructure:"mongourl"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Database string `mapstructure:"database"`

	Email         string `mapstructure:"email"`
	Appcode       string `mapstructure:"appcode"`
	EmailUserName string `mapstructure:"emailusername"`

	AdminEmail string `mapstructure:"adminemail"`
	AdminName  string `mapstructure:"adminname"`
	Password   string `mapstructure:"password"`
	IP         string `mapstructure:"ip"`

	AdminPasswordHashKey string `mapstructure:"adminpasswordkey"`
	UserPasswordHashKey  string `mapstructure:"userpasswordkey"`

	AdminTokenKey string `mapstructure:"admintokenkey"`
	UserTokenKey  string `mapstructure:"usertokenkey"`
}

var mongoConfig MongoConfig
var (
	ConnectionString     string
	DataBaseName         string
	Port                 int
	Host                 string
	Email                string
	Appcode              string
	EmailUserName        string
	AdminPasswordHashKey []byte
	UserPasswordHashKey  []byte
	AdminTokenKey        []byte
	UserTokenKey         []byte

	AdminEmail string
	AdminName  string
	Password   string
	IP         string
)

func init() {
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file, %s", err)
	}

	if err := viper.UnmarshalKey("mongoConfig", &mongoConfig); err != nil {
		log.Fatalf("Unable to decode into struct, %v", err)
	}

	log.Println("** Data from Config File **")
	log.Println(mongoConfig)

	ConnectionString = mongoConfig.URL
	DataBaseName = mongoConfig.Database
	Port = mongoConfig.Port
	Host = mongoConfig.Host

	// Convert string keys to byte slices
	AdminTokenKey = []byte(mongoConfig.AdminTokenKey)
	UserTokenKey = []byte(mongoConfig.UserTokenKey)

	Email = mongoConfig.Email
	Appcode = mongoConfig.Appcode
	EmailUserName = mongoConfig.EmailUserName

	AdminPasswordHashKey = []byte(mongoConfig.AdminPasswordHashKey)
	UserPasswordHashKey = []byte(mongoConfig.UserPasswordHashKey)

	AdminEmail = mongoConfig.AdminEmail
	AdminName = mongoConfig.AdminName
	Password = mongoConfig.Password
	IP = mongoConfig.IP
	log.Println("** --------------------- **")
}

const (
	// Collection Names
	Admin_Collection             = "ADMIN"
	Customer_Collection          = "CUSTOMER"
	Product_Collection           = "PRODUCTS"
	Order_Collection             = "ORDER"
	Cart_Collection              = "CART"
	BestSelling_Collection       = "BESTSELLING"
	Favorite_Collection          = "FAVORITE"
	Instagram_Collection         = "INSTAGRAM"
	Trending_Collection          = "TRENDING"
	PopularCategories_Collection = "POPULARCATEGORIES"
	ShopPage_Collection          = "SHOPPAGE"
	AboutPage_Collection         = "ABOUTPAGE"
	ContactPage_Collection       = "CONTACTPAGE"
	SiteData_Collection          = "SITEDATA"
	FeedBack_Collection          = "FEEDBACK"
	AdminAudit_Collection        = "ADMINAUDIT"
	UserAudit_Collection         = "USERAUDIT"
	DeveloperAudit_Collection    = "DEVELOPERAUDIT"
	AdminDeleted_Collection      = "DELETED_ADMIN"
	UserDeleted_Collection       = "DELETED_USER"
	OrderDeleted_Collection      = "DELETED_ORDER"
	AdminEdited_Collection       = "EDITED_ADMIN"
	UserEdited_Collection        = "EDITED_USER"
	OrderEdited_Collection       = "EDITED_ORDER"
)
