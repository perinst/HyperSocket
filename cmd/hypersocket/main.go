package main

import (
	"hypersocket/internal/ws"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/ws", ws.Handler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
	})
	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
