package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/mrjxtr/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
}

func main() {
	godotenv.Load()

	dbURL := os.Getenv("DB_URL")
	pf := os.Getenv("PLATFORM")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}

	apiCfg := &apiConfig{
		dbQueries: database.New(db),
		platform:  pf,
	}

	mux := http.NewServeMux()

	fs := http.FileServer(http.Dir("."))

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", fs)))
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetMetricsHandler)
	mux.HandleFunc("GET /api/healthz", healthHandler)
	mux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)

	mux.HandleFunc("POST /api/users", apiCfg.createUser)

	srv := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	log.Fatal(srv.ListenAndServe())
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func cleanProfanity(text string) string {
	badWords := map[string]struct{}{
		"kerfuffle": {},
		"sharbert":  {},
		"fornax":    {},
	}

	words := strings.Split(text, " ")

	for i, w := range words {
		if _, found := badWords[strings.ToLower(w)]; found {
			words[i] = "****"
		}
	}

	return strings.Join(words, " ")
}

func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	type chirpRequest struct {
		Body string `json:"body"`
	}
	var req chirpRequest

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if len(req.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	cleaned := cleanProfanity(req.Body)

	respondWithJSON(w, http.StatusOK, map[string]string{
		"cleaned_body": cleaned,
	})
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type respBody struct {
		Error string `json:"error"`
	}

	rbody := &respBody{
		Error: msg,
	}
	resp, err := json.Marshal(rbody)
	if err != nil {
		log.Printf("Error marshalling json: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(resp)
}

func respondWithJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("Error encoding json %v", err)
	}
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, `<html>
<body>
<h1>Welcome, Chirpy Admin</h1>
<p>Chirpy has been visited %d times!</p>
</body>
</html>`, cfg.fileserverHits.Load())
}

func (cfg *apiConfig) resetMetricsHandler(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		respondWithError(w, http.StatusForbidden, "Forbidden endpoint")
		return
	}

	w.WriteHeader(http.StatusOK)
	cfg.fileserverHits = atomic.Int32{}
}

func (cfg *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email string `json:"email"`
	}

	params := parameters{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request paylaod")
		return
	}

	user, err := cfg.dbQueries.CreateUser(r.Context(), params.Email)
	if err != nil {
		respondWithError(
			w,
			http.StatusBadRequest,
			fmt.Sprintf("Error Creating User %v", err),
		)
		return
	}

	respondWithJSON(w, http.StatusCreated, map[string]any{
		"id":         user.ID,
		"created_at": user.CreatedAt,
		"updated_at": user.UpdatedAt,
		"email":      user.Email,
	})
}
