package main

import (
	"fmt"
	"log"
	"mithuorganics/router"
	"mithuorganics/service"
	"os"
)

func main() {
    fmt.Println("***** Requested to start Mithu Organics Server *****")
    service.DetailsToDB()
    r := router.Router()

    port := os.Getenv("PORT")
    if port == "" {
        port = "8080" 
    }
    fmt.Println("Port set to ",port)

    log.Fatal(r.Run("0.0.0.0:" + port))
    fmt.Println("** Server Started and Append running in http://localhost:",port, " **")
}
