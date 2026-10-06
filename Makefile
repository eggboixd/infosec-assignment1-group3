.PHONY: run build test lint up down logs gen-key

BIN := bin/server
GOSEC_VERSION := v2.29.0

## run: run the server locally, reading variables from .env
run:
	@test -f .env || { echo ".env not found; copy .env.example"; exit 1; }
	set -a && . ./.env && set +a && go run ./cmd/server

## build: compile the server binary into bin/
build:
	CGO_ENABLED=0 go build -trimpath -o $(BIN) ./cmd/server

## test: run all tests with the race detector
test:
	go test -race ./...

## lint: check formatting, run go vet and gosec
lint:
	@unformatted=$$(gofmt -l .); if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	go vet ./...
	go run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) -quiet ./...

## up: build and start all services in the background
up:
	docker compose up --build -d

## down: stop all services (data volumes are kept)
down:
	docker compose down

## logs: follow logs from all services
logs:
	docker compose logs -f

## gen-key: print a random base64-encoded 32-byte key
gen-key:
	@head -c 32 /dev/urandom | base64
