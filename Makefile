.PHONY: run build test lint migrate-up migrate-down dev docker-up docker-down

run:
	go run ./cmd/api

build:
	go build -o bin/api ./cmd/api

test:
	go test ./... -race -count=1

lint:
	go vet ./...
	gofmt -l . | tee /dev/stderr | (! read)

# Requires golang-migrate: brew install golang-migrate
migrate-up:
	migrate -path migrations -database "$(DATABASE_URL)" up

migrate-down:
	migrate -path migrations -database "$(DATABASE_URL)" down 1

docker-up:
	docker compose up -d

docker-down:
	docker compose down
