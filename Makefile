run:
	go run ./cmd/main.go

run-race:
	go run -race ./cmd/main.go

build:
	go build ./cmd/main.go -o go-network-client