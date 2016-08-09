default: test build
test:
	godep go test ./...
build:
	go build
