package main

import "net/http"

func main() {
	router := http.NewServeMux()
	router.Handle("/", http.FileServer(http.Dir(".")))

	srv := http.Server{
		Addr:    ":8080",
		Handler: router,
	}
	srv.ListenAndServe()
}
