package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/mmikhail2001/technopark_security_hw_proxy/pkg/repository"
	"github.com/mmikhail2001/technopark_security_hw_proxy/proxy-server/pkg/mongoclient"
	"github.com/mmikhail2001/technopark_security_hw_proxy/web-api/internal/delivery"
)

const URI = "mongodb://root:root@localhost:27017"

func main() {
	log.SetPrefix("[WEB-API] ")
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	client, closeConn, err := mongoclient.NewMongoClient(URI)
	if err != nil {
		log.Fatal(err)
	}

	defer closeConn()
	repo, err := repository.NewRepository(client)
	if err != nil {
		log.Fatal(err)
	}

	handler := delivery.NewHandler(&repo)

	r := mux.NewRouter()

	r.Use(delivery.Log)

	r.HandleFunc("/requests", handler.Requests)
	r.HandleFunc("/requests/{id}", handler.RequestByID)
	r.HandleFunc("/scan/{id}", handler.ScanByID)
	r.HandleFunc("/repeat/{id}", handler.RepeatByID)

	log.Println("Web-api :8000")
	log.Fatal(http.ListenAndServe(":8000", r))
}
