-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email)
VALUES (gen_random_uuid(), now(), now(), $1)
RETURNING *;

-- name: DeleteUsers :exec
DELETE FROM users;
