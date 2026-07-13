package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/mrjxtr/chirpy/internal/auth"
	"github.com/mrjxtr/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
	jwtSecret      string
}

func main() {
	godotenv.Load()

	dbURL := os.Getenv("DB_URL")
	pf := os.Getenv("PLATFORM")
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET must be set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}

	apiCfg := &apiConfig{
		dbQueries: database.New(db),
		platform:  pf,
		jwtSecret: jwtSecret,
	}

	mux := http.NewServeMux()

	fs := http.FileServer(http.Dir("."))

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", fs)))
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetMetricsHandler)
	mux.HandleFunc("GET /api/healthz", healthHandler)

	mux.HandleFunc("POST /api/users", apiCfg.createUser)
	mux.HandleFunc("POST /api/login", apiCfg.login)
	mux.HandleFunc("POST /api/refresh", apiCfg.refresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.revoke)
	mux.HandleFunc("POST /api/chirps", apiCfg.createChirp)
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirp)

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

// resetMetricsHandler zeroes the hit counter and wipes every user. Chirps go
// with them via the ON DELETE CASCADE on chirps.user_id. Dev only.
func (cfg *apiConfig) resetMetricsHandler(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		respondWithError(w, http.StatusForbidden, "Forbidden endpoint")
		return
	}

	if err := cfg.dbQueries.DeleteUsers(r.Context()); err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			fmt.Sprintf("Error resetting users: %v", err),
		)
		return
	}

	cfg.fileserverHits = atomic.Int32{}
	w.WriteHeader(http.StatusOK)
}

// createUser hashes the incoming password before storing it. The hash never
// leaves the server, so it's kept out of the response.
func (cfg *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	params := parameters{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			fmt.Sprintf("Error hashing password: %v", err),
		)
		return
	}

	user, err := cfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPassword,
	})
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

const (
	// accessTokenExpiry is how long a JWT stays good for. Short on purpose: a
	// leaked access token stops working quickly.
	accessTokenExpiry = time.Hour
	// refreshTokenExpiry is how long a refresh token stays good for. Long, but
	// revocable, since it lives in the db.
	refreshTokenExpiry = 60 * 24 * time.Hour
)

// login checks an email/password pair against the stored hash and hands back a
// short-lived access token plus a long-lived refresh token. A missing user and
// a wrong password both return the same 401, so the response can't be used to
// probe which emails are registered.
func (cfg *apiConfig) login(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	params := parameters{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	user, err := cfg.dbQueries.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	match, err := auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil || !match {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	accessToken, err := auth.MakeJWT(user.ID, cfg.jwtSecret, accessTokenExpiry)
	if err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			fmt.Sprintf("Error creating token: %v", err),
		)
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			fmt.Sprintf("Error creating refresh token: %v", err),
		)
		return
	}

	_, err = cfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().UTC().Add(refreshTokenExpiry),
	})
	if err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			fmt.Sprintf("Error storing refresh token: %v", err),
		)
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]any{
		"id":            user.ID,
		"created_at":    user.CreatedAt,
		"updated_at":    user.UpdatedAt,
		"email":         user.Email,
		"token":         accessToken,
		"refresh_token": refreshToken,
	})
}

// refresh swaps a valid refresh token for a fresh access token. The lookup
// query already filters out revoked and expired tokens, so any miss is a 401.
func (cfg *apiConfig) refresh(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	user, err := cfg.dbQueries.GetUserFromRefreshToken(r.Context(), refreshToken)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	accessToken, err := auth.MakeJWT(user.ID, cfg.jwtSecret, accessTokenExpiry)
	if err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			fmt.Sprintf("Error creating token: %v", err),
		)
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]any{
		"token": accessToken,
	})
}

// revoke marks a refresh token as revoked so it can't mint any more access
// tokens. Returns 204 with no body.
func (cfg *apiConfig) revoke(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if err := cfg.dbQueries.RevokeRefreshToken(r.Context(), refreshToken); err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			fmt.Sprintf("Error revoking refresh token: %v", err),
		)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// createChirp takes the author from the bearer token, not the request body, so
// a caller can only ever chirp as themselves.
func (cfg *apiConfig) createChirp(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	type parameters struct {
		Body string `json:"body"`
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	params := parameters{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if len(params.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	chirp, err := cfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   cleanProfanity(params.Body),
		UserID: userID,
	})
	if err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			fmt.Sprintf("Error creating chirp: %v", err),
		)
		return
	}

	respondWithJSON(w, http.StatusCreated, map[string]any{
		"id":         chirp.ID,
		"created_at": chirp.CreatedAt,
		"updated_at": chirp.UpdatedAt,
		"body":       chirp.Body,
		"user_id":    chirp.UserID,
	})
}

// getChirps returns every chirp in the db, oldest first (by created_at).
func (cfg *apiConfig) getChirps(w http.ResponseWriter, r *http.Request) {
	chirps, err := cfg.dbQueries.GetChirps(r.Context())
	if err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			fmt.Sprintf("Error getting chirps: %v", err),
		)
		return
	}

	// build explicitly so an empty table still marshals as [] instead of null
	resp := make([]map[string]any, 0, len(chirps))
	for _, chirp := range chirps {
		resp = append(resp, map[string]any{
			"id":         chirp.ID,
			"created_at": chirp.CreatedAt,
			"updated_at": chirp.UpdatedAt,
			"body":       chirp.Body,
			"user_id":    chirp.UserID,
		})
	}

	respondWithJSON(w, http.StatusOK, resp)
}

// getChirp looks up a single chirp by the {chirpID} path param. 404s on a bad
// uuid or a missing row, since both mean "no such chirp" to the caller.
func (cfg *apiConfig) getChirp(w http.ResponseWriter, r *http.Request) {
	chirpID, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Chirp not found")
		return
	}

	chirp, err := cfg.dbQueries.GetChirp(r.Context(), chirpID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, http.StatusNotFound, "Chirp not found")
			return
		}
		respondWithError(
			w,
			http.StatusInternalServerError,
			fmt.Sprintf("Error getting chirp: %v", err),
		)
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]any{
		"id":         chirp.ID,
		"created_at": chirp.CreatedAt,
		"updated_at": chirp.UpdatedAt,
		"body":       chirp.Body,
		"user_id":    chirp.UserID,
	})
}
